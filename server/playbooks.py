"""SOAR-lite playbooks: YAML-defined automated response.

Schema (playbooks/<name>.yaml):
  name: block-ssh-bruteforce
  description: ...
  on_rule: ARG-1001        # or: on_severity: critical
  steps:
    - action: block_ip     # block_ip|unblock_ip|quarantine|isolate|run|webhook|notify
      params: {ip: "{entities.src_ip}"}
      target: agent        # agent | server
    - action: notify
      params: {channel: soc, message: "{alert.title}"}

Templating: {entities.x}, {alert.title}, {alert.severity}, {agent_id}, {hostname}.
Agent-targeted containment actions are enqueued for the alert's agent.
"""
import ipaddress
import json
import os
import re
import urllib.request
from pathlib import Path

import yaml

from .rules import get_field

TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_.]+)\}")


ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def render(value, ctx):
    if isinstance(value, str):
        def repl(m):
            v = get_field(ctx, m.group(1))
            return str(v) if v is not None else m.group(0)
        value = TEMPLATE_RE.sub(repl, value)
        # ${SOME_ENV_VAR} expands from the server environment (empty if unset,
        # so a webhook without a configured URL is skipped, not mis-sent).
        return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


def load_playbooks(directory: str):
    books = {}
    d = Path(directory)
    if d.exists():
        for path in sorted(d.glob("*.yaml")):
            with open(path, encoding="utf-8") as f:
                pb = yaml.safe_load(f) or {}
            if pb.get("name"):
                books[pb["name"]] = pb
    return books


AGENT_ACTIONS = {"block_ip", "unblock_ip", "quarantine", "isolate", "release", "unisolate", "run"}


# Addresses a playbook must never auto-block: loopback/link-local/multicast/
# reserved space (often the gateway, DNS or the server itself when an
# attacker spoofs a source IP), plus anything the operator lists in
# ARGUS_NEVER_BLOCK (comma-separated IPs/CIDRs).
NEVER_BLOCK = [ipaddress.ip_network(n) for n in
               ("127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10",
                "224.0.0.0/4", "ff00::/8", "0.0.0.0/8", "::/128")]
for _extra in os.environ.get("ARGUS_NEVER_BLOCK", "").split(","):
    _extra = _extra.strip()
    if _extra:
        try:
            NEVER_BLOCK.append(ipaddress.ip_network(_extra, strict=False))
        except ValueError:
            pass


def _never_block(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None  # not an IP at all; caller treats separately
    return any(addr in net for net in NEVER_BLOCK)


def run_playbook(db, notify, pb: dict, alert: dict):
    """Execute playbook steps. notify(frame) pushes a WS notification."""
    ctx = {"entities": alert.get("entities", {}), "alert": alert,
           "agent_id": alert.get("agent_id"), "hostname": alert.get("hostname")}
    results = []
    for step in pb.get("steps", []):
        action = step.get("action")
        params = render(step.get("params", {}), ctx)
        target = step.get("target", "agent" if action in AGENT_ACTIONS else "server")
        # A leftover "{entities.x}" means the alert had no such entity; never
        # send a literal template string to an agent as an IP/path/command.
        flat = json.dumps(params, default=str)
        if action in AGENT_ACTIONS and TEMPLATE_RE.search(flat):
            results.append({"action": action, "status": "skipped_unrendered_template"})
            continue
        if action == "block_ip":
            ip_ok = _never_block(str(params.get("ip", "")))
            if ip_ok is None:
                results.append({"action": action, "status": "skipped_invalid_ip"})
                continue
            if ip_ok:
                results.append({"action": action, "status": "skipped_never_block"})
                continue
        try:
            if action in AGENT_ACTIONS and target == "agent" and alert.get("agent_id"):
                aid = db.enqueue_action(alert["agent_id"], action, params)
                results.append({"action": action, "status": "enqueued", "action_id": aid})
            elif action == "webhook":
                url = params.get("url")
                if url:
                    body = json.dumps({"alert": alert, "playbook": pb.get("name")}).encode()
                    req = urllib.request.Request(url, data=body,
                                                 headers={"content-type": "application/json"})
                    urllib.request.urlopen(req, timeout=5).read()
                    results.append({"action": "webhook", "status": "sent"})
                else:
                    results.append({"action": "webhook", "status": "skipped_no_url"})
            elif action == "notify":
                notify({"type": "notification",
                        "channel": params.get("channel", "soc"),
                        "message": params.get("message", alert.get("title")),
                        "severity": alert.get("severity")})
                results.append({"action": "notify", "status": "sent"})
            else:
                results.append({"action": action, "status": "skipped"})
        except Exception as e:
            results.append({"action": action, "status": "failed", "error": str(e)[:200]})
    return results


NOTIFY_ONLY_ACTIONS = {"notify", "webhook"}


def playbooks_for(alert: dict, books: dict, rule: dict | None = None):
    """Pick playbooks for an alert, safest first.

    1. The playbook the rule itself declares (``playbook:`` in the rule YAML)
       runs in full — the rule author chose that response for that detection.
    2. Playbooks bound with ``on_rule:`` run in full.
    3. Severity-wide playbooks (``on_severity:``) are NOTIFY-ONLY: matching a
       severity is not proof enough to isolate a host or block an IP, so
       containment steps are stripped and only notify/webhook steps run.
    """
    matched: list = []
    seen: set = set()

    def _add(pb, full: bool):
        name = pb.get("name")
        if not name or name in seen:
            return
        if full:
            matched.append(pb)
            seen.add(name)
        else:
            steps = [st for st in pb.get("steps", [])
                     if st.get("action") in NOTIFY_ONLY_ACTIONS]
            if steps:
                matched.append({**pb, "steps": steps})
                seen.add(name)

    if rule and rule.get("playbook"):
        pb = books.get(rule["playbook"])
        if pb:
            _add(pb, full=True)
    for pb in books.values():
        if pb.get("on_rule") and pb.get("on_rule") == alert.get("rule_id"):
            _add(pb, full=True)
    for pb in books.values():
        if pb.get("on_severity") and not pb.get("on_rule") \
                and pb.get("on_severity") == alert.get("severity"):
            _add(pb, full=False)
    return matched
