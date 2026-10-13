"""UEBA-lite anomaly baselines. No ML libraries: per-entity behavioral profiles
in SQLite kv store. Emits ARG-90xx alerts (ai_triage=True)."""
from collections import deque
from datetime import datetime, timedelta, timezone

SUSPICIOUS_EXE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/")


def _hour(ts_iso):
    try:
        return datetime.fromisoformat(ts_iso).hour
    except Exception:
        return datetime.now(timezone.utc).hour


def analyze(db, event: dict):
    """Return list of anomaly alert dicts for one normalized event."""
    alerts = []
    src = event.get("source")
    ev = event.get("event", {}) or {}
    agent = event.get("agent_id")
    ts = event.get("ts")

    if src == "process" and ev.get("action") == "started":
        exe = ev.get("exe") or ""
        key = f"fs:exe:{agent}:{exe}"
        if db.kv_get(key) is None:
            db.kv_set(key, {"first_seen": ts})
            if exe.startswith(SUSPICIOUS_EXE_DIRS):
                alerts.append(_mk(
                    "ARG-9002", "First-seen binary in suspicious location", "high",
                    f"Never-before-seen executable started from a writable temp path: {exe}",
                    event, {"exe": exe}, ["T1059"], "medium"))

    if src == "auth":
        user = ev.get("user")
        result = ev.get("result")
        ip = ev.get("src_ip")
        if user and result == "success":
            # unusual login hour
            hk = f"login_hours:{agent}:{user}"
            prof = db.kv_get(hk) or {"hours": {}}
            h = str(_hour(ts))
            hours = prof["hours"]
            total = sum(hours.values())
            if total >= 5 and hours.get(h, 0) == 0 and 0 <= int(h) <= 5:
                alerts.append(_mk(
                    "ARG-9003", "Login at unusual hour", "medium",
                    f"User '{user}' logged in at {h}:00, outside their observed profile",
                    event, {"user": user}, ["T1078"], "medium"))
            hours[h] = hours.get(h, 0) + 1
            db.kv_set(hk, {"hours": hours})
            # concurrent distinct source IPs
            ik = f"login_ips:{agent}:{user}"
            seen = db.kv_get(ik) or []
            now = datetime.now(timezone.utc)
            seen = [s for s in seen
                    if now - datetime.fromisoformat(s["ts"]) < timedelta(minutes=10)]
            if ip and all(s["ip"] != ip for s in seen) and seen:
                alerts.append(_mk(
                    "ARG-9001", "Concurrent logins from distinct IPs", "high",
                    f"User '{user}' authenticated from {ip} and "
                    f"{seen[-1]['ip']} within 10 minutes",
                    event, {"user": user, "src_ip": ip}, ["T1078"], "high"))
            if ip:
                seen.append({"ip": ip, "ts": now.isoformat()})
                db.kv_set(ik, seen[-20:])
        if result == "failed":
            fk = f"failburst:{agent}"
            dq = deque(db.kv_get(fk) or [], maxlen=50)
            now = datetime.now(timezone.utc)
            dq.append(now.isoformat())
            dq = deque([t for t in dq
                        if now - datetime.fromisoformat(t) < timedelta(minutes=5)], maxlen=50)
            db.kv_set(fk, list(dq))
            last = db.kv_get(fk + ":fired")
            if len(dq) >= 10 and (not last or
                    now - datetime.fromisoformat(last) > timedelta(minutes=15)):
                db.kv_set(fk + ":fired", now.isoformat())
                alerts.append(_mk(
                    "ARG-9004", "Authentication failure burst", "high",
                    f"{len(dq)} failed authentications on {agent} in 5 minutes",
                    event, {"user": user}, ["T1110"], "medium"))

    return alerts


def _mk(rule_id, name, severity, desc, event, entities, mitre, confidence):
    return {
        "rule_id": rule_id,
        "rule_name": name,
        "severity": severity,
        "agent_id": event.get("agent_id"),
        "hostname": event.get("hostname"),
        "title": f"{name} on {event.get('hostname')}",
        "description": desc,
        "mitre": mitre,
        "compliance": {"pci_dss": ["10.2.4", "11.4"], "nist_800_53": ["AU-6", "SI-4"]},
        "entities": entities,
        "event_ids": [],
        "event_count": 1,
        "ai_triage": True,
        "_confidence": confidence,
    }
