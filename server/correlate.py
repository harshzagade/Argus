"""Incident correlation: group related alerts into incidents.

Join rules (within a 30-minute sliding window):
  - same agent + any shared non-generic entity value, or
  - different agents + a shared STRONG entity (attacker IP, hash, domain,
    URL) — one campaign hitting two machines is one case, not two.
Generic values (user "root", ports, "unknown") never join anything by
themselves, and matching is by (key, value) pair so a user named "22" can
never collide with port 22. Open AND acknowledged incidents absorb new
alerts; only closed ones stop growing.
Incident severity = max severity of its alerts.
"""
import json
from datetime import datetime, timedelta, timezone

from .rules import SEVERITY_RANK

WINDOW = timedelta(minutes=30)

STRONG_KEYS = {"src_ip", "dst_ip", "ip", "hash", "sha256", "md5", "domain", "url"}
GENERIC_VALUES = {"", "none", "null", "unknown", "root", "www-data", "nobody",
                  "daemon", "bin", "sys", "sshd", "system", "auth", "-",
                  "0", "22", "80", "443"}


def _pairs(entities) -> set:
    """(key, value) pairs worth joining on; generic values removed."""
    out = set()
    for k, v in (entities or {}).items():
        for x in (v if isinstance(v, list) else [v]):
            if x is None:
                continue
            sv = str(x)
            if sv.strip().lower() in GENERIC_VALUES:
                continue
            out.add((k, sv))
    return out


def _parse(ts):
    return datetime.fromisoformat(ts)


def correlate(db, alert: dict) -> str:
    """Attach alert to a matching open incident or create one. Returns incident id."""
    alert_entities = alert.get("entities", {}) or {}
    alert_pairs = _pairs(alert_entities)
    now = datetime.now(timezone.utc)
    if alert.get("ts"):
        try:
            now = _parse(alert["ts"])
            if not now.tzinfo:
                now = now.replace(tzinfo=timezone.utc)
        except Exception:
            now = datetime.now(timezone.utc)

    candidates = list(db.open_incidents())
    candidates += db.list_incidents(status="acknowledged", limit=500)
    best = None
    for inc in candidates:
        updated = _parse(inc["updated"])
        if not updated.tzinfo:
            updated = updated.replace(tzinfo=timezone.utc)
        if now - updated > WINDOW:
            continue
        shared = alert_pairs & _pairs(json.loads(inc["entities_json"] or "{}"))
        if not shared:
            continue
        agents = json.loads(inc["agents_json"] or "[]")
        same_agent = not alert.get("agent_id") or alert["agent_id"] in agents
        strong = any(k in STRONG_KEYS for k, _ in shared)
        if same_agent or strong:
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
