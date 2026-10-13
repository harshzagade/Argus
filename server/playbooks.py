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
import json
import re
import urllib.request
from pathlib import Path

import yaml

from .rules import get_field

TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_.]+)\}")


def render(value, ctx):
    if isinstance(value, str):
        def repl(m):
            v = get_field(ctx, m.group(1))
            return str(v) if v is not None else m.group(0)
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
            with open(path) as f:
                pb = yaml.safe_load(f) or {}
            if pb.get("name"):
                books[pb["name"]] = pb
    return books


AGENT_ACTIONS = {"block_ip", "unblock_ip", "quarantine", "isolate", "run"}


def run_playbook(db, notify, pb: dict, alert: dict):
    """Execute playbook steps. notify(frame) pushes a WS notification."""
    ctx = {"entities": alert.get("entities", {}), "alert": alert,
           "agent_id": alert.get("agent_id"), "hostname": alert.get("hostname")}
    results = []
    for step in pb.get("steps", []):
        action = step.get("action")
        params = render(step.get("params", {}), ctx)
        target = step.get("target", "agent" if action in AGENT_ACTIONS else "server")
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


def playbooks_for(alert: dict, books: dict):
    matched = []
    for name, pb in books.items():
        if pb.get("on_rule") == alert.get("rule_id"):
            matched.append(pb)
        elif pb.get("on_severity") == alert.get("severity") and not pb.get("on_rule"):
            matched.append(pb)
    return matched
