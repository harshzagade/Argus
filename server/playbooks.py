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
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

from .rules import get_field

TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_.]+)\}")


ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def render(value, ctx):
    if isinstance(value, str):
        # ${SOME_ENV_VAR} expands FIRST, from the raw operator-written
        # template only (empty if unset, so a webhook without a
        # configured URL is skipped, not mis-sent). Alert data is
        # substituted afterwards with any "${" inside it defused, so
        # attacker-controlled text (a honeypot command line, a username)
        # can never trigger a second round of env expansion and leak
        # server secrets into notifications or webhooks.
        value = ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)

        def repl(m):
            v = get_field(ctx, m.group(1))
            if v is None:
                return m.group(0)
            return str(v).replace("${", "$ {")
        return TEMPLATE_RE.sub(repl, value)
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


def _validate_params(action, params, raw_params):
    """Rendered playbook values come from alert data, and attackers
    influence alert data (usernames, file paths, IPs in the triggering
    event). Validate every action's parameters AFTER rendering and
    BEFORE anything is enqueued or sent. Returns a reason or None.

    This closes the template-injection gap: substitution itself is not
    the problem (values are data), the problem was sinks consuming them
    unvalidated. block_ip already validates its IP; this covers the rest.
    """
    for v in params.values():
        if isinstance(v, str):
            # Oversized values are rejected for anything an agent or a
            # webhook will consume. notify is the exception: its text is
            # display data and is truncated to a safe length when sent.
            if len(v) > 1024 and action != "notify":
                return "param_too_long"
            if any(ord(c) < 32 for c in v):
                return "param_control_chars"
    if action == "quarantine":
        path = str(params.get("path", ""))
        if not path.startswith("/") or path == "/" or ".." in path.split("/"):
            return "unsafe_quarantine_path"
    if action == "run":
        # A shell command must be an operator-written constant from the
        # playbook file; event data may never flow into it. Identity
        # fields ({agent_id}, {hostname}) are assigned by the server,
        # not by the event, so playbooks may use those (evidence
        # snapshots name their output files by agent).
        cmd = str((raw_params or {}).get("command", ""))
        refs = {"{" + m + "}" for m in TEMPLATE_RE.findall(cmd)}
        if refs - {"{agent_id}", "{hostname}"}:
            return "run_command_uses_alert_data"
    if action == "webhook":
        url = str(params.get("url", ""))
        if url:
            p = urllib.parse.urlparse(url)
            if p.scheme not in ("http", "https") or not p.hostname:
                return "unsafe_webhook_url"
            try:
                ip = ipaddress.ip_address(p.hostname)
                if ip.version == 6 and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
                if (ip.is_loopback or ip.is_link_local or ip.is_multicast
                        or ip.is_private or ip.is_reserved):
                    return "unsafe_webhook_url"
            except ValueError:
                pass  # a hostname, not an IP literal
    return None


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
        invalid = _validate_params(action, params, step.get("params", {}))
        if invalid:
            results.append({"action": action, "status": f"skipped_{invalid}"})
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
                        "channel": str(params.get("channel", "soc"))[:50],
                        "message": str(params.get("message", alert.get("title") or ""))[:500],
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
