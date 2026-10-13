"""Incident correlation: group related alerts into incidents.

Two alerts join the same incident when they share the agent and at least one
entity value (IP, user, hash, path...) within a 30-minute sliding window.
Incident severity = max severity of its alerts.
"""
import json
from datetime import datetime, timedelta, timezone

from .rules import SEVERITY_RANK

WINDOW = timedelta(minutes=30)


def _parse(ts):
    return datetime.fromisoformat(ts)


def correlate(db, alert: dict) -> str:
    """Attach alert to a matching open incident or create one. Returns incident id."""
    now = datetime.now(timezone.utc)
    alert_entities = alert.get("entities", {}) or {}
    entity_values = {str(v) for v in alert_entities.values() if v}

    best = None
    for inc in db.open_incidents():
        updated = _parse(inc["updated"])
        if now - updated > WINDOW:
            continue
        agents = json.loads(inc["agents_json"] or "[]")
        if alert.get("agent_id") and alert["agent_id"] not in agents:
            continue
        inc_entities = json.loads(inc["entities_json"] or "{}")
        inc_values = set()
        for v in inc_entities.values():
            inc_values.update(str(x) for x in (v if isinstance(v, list) else [v]))
        if entity_values & inc_values:
            best = inc
            break

    if best:
        iid = best["id"]
        alert_ids = json.loads(best["alert_ids_json"] or "[]")
        alert_ids.append(alert["id"])
        agents = json.loads(best["agents_json"] or "[]")
        if alert.get("agent_id") and alert["agent_id"] not in agents:
            agents.append(alert["agent_id"])
        entities = json.loads(best["entities_json"] or "{}")
        for k, v in alert_entities.items():
            cur = entities.get(k)
            if cur is None:
                entities[k] = v
            elif isinstance(cur, list):
                if v not in cur:
                    cur.append(v)
            elif cur != v:
                entities[k] = [cur, v]
        mitre = sorted(set(json.loads(best["mitre_json"] or "[]")) | set(alert.get("mitre", [])))
        sev = best["severity"]
        if SEVERITY_RANK.get(alert["severity"], 0) > SEVERITY_RANK.get(sev, 0):
            sev = alert["severity"]
        db.update_incident(
            iid,
            severity=sev,
            agents_json=json.dumps(agents),
            alert_ids_json=json.dumps(alert_ids),
            entities_json=json.dumps(entities),
            mitre_json=json.dumps(mitre),
        )
        return iid

    iid = db.insert_incident({
        "title": alert.get("title") or alert.get("rule_name"),
        "severity": alert.get("severity", "medium"),
        "agents": [alert["agent_id"]] if alert.get("agent_id") else [],
        "alert_ids": [alert["id"]],
        "entities": alert_entities,
        "mitre": alert.get("mitre", []),
        "triage_summary": (alert.get("triage") or {}).get("summary"),
    })
    return iid
