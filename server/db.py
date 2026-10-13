"""SQLite storage for Argus. Thread-safe, stdlib only."""
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    hostname TEXT,
    os TEXT,
    source TEXT,
    event_json TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT,
    severity TEXT NOT NULL,
    agent_id TEXT,
    hostname TEXT,
    title TEXT,
    description TEXT,
    mitre_json TEXT,
    compliance_json TEXT,
    entities_json TEXT,
    event_ids_json TEXT,
    event_count INTEGER DEFAULT 1,
    enrichment_json TEXT,
    triage_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    status TEXT DEFAULT 'open',
    created TEXT,
    updated TEXT,
    agents_json TEXT,
    alert_ids_json TEXT,
    entities_json TEXT,
    mitre_json TEXT,
    triage_summary TEXT,
    note TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    os TEXT,
    last_seen TEXT,
    version TEXT,
    risk_score REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    params_json TEXT,
    status TEXT DEFAULT 'pending',
    created TEXT,
    acked_at TEXT,
    output TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_agent ON actions(agent_id, status);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value_json TEXT,
    updated TEXT
);
"""


def now_iso():
    return datetime.now(timezone.utc).isoformat()


class DB:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.commit()

    # ---------- generic ----------
    def _exec(self, sql, params=()):
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def _query(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    # ---------- events ----------
    def insert_event(self, ev: dict) -> str:
        eid = uuid.uuid4().hex[:16]
        self._exec(
            "INSERT INTO events (id, ts, agent_id, hostname, os, source, event_json, raw)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (eid, ev.get("ts") or now_iso(), ev.get("agent_id"), ev.get("hostname"),
             ev.get("os"), ev.get("source"), json.dumps(ev.get("event", {})),
             ev.get("raw")),
        )
        return eid

    # ---------- alerts ----------
    def insert_alert(self, a: dict) -> str:
        aid = uuid.uuid4().hex[:16]
        self._exec(
            "INSERT INTO alerts (id, ts, rule_id, rule_name, severity, agent_id, hostname,"
            " title, description, mitre_json, compliance_json, entities_json,"
            " event_ids_json, event_count, enrichment_json, triage_json)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (aid, a.get("ts") or now_iso(), a["rule_id"], a.get("rule_name"),
             a["severity"], a.get("agent_id"), a.get("hostname"), a.get("title"),
             a.get("description"), json.dumps(a.get("mitre", [])),
             json.dumps(a.get("compliance", {})), json.dumps(a.get("entities", {})),
             json.dumps(a.get("event_ids", [])), a.get("event_count", 1),
             json.dumps(a.get("enrichment", {})), json.dumps(a.get("triage", {}))),
        )
        return aid

    def list_alerts(self, severity=None, rule_id=None, agent_id=None, limit=100, since=None):
        sql = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if severity:
            sql += " AND severity=?"; params.append(severity)
        if rule_id:
            sql += " AND rule_id=?"; params.append(rule_id)
        if agent_id:
            sql += " AND agent_id=?"; params.append(agent_id)
        if since:
            sql += " AND ts>=?"; params.append(since)
        sql += " ORDER BY ts DESC LIMIT ?"; params.append(limit)
        return [dict(r) for r in self._query(sql, params)]

    def get_alert(self, aid):
        rows = self._query("SELECT * FROM alerts WHERE id=?", (aid,))
        return dict(rows[0]) if rows else None

    def count_alerts(self, severity=None, rule_id=None, agent_id=None, since=None):
        """Count alerts matching the same filters as list_alerts (pre-limit)."""
        sql = "SELECT COUNT(*) c FROM alerts WHERE 1=1"
        params = []
        if severity:
            sql += " AND severity=?"; params.append(severity)
        if rule_id:
            sql += " AND rule_id=?"; params.append(rule_id)
        if agent_id:
            sql += " AND agent_id=?"; params.append(agent_id)
        if since:
            sql += " AND ts>=?"; params.append(since)
        rows = self._query(sql, params)
        return rows[0]["c"]

    def update_alert(self, aid, **fields):
        sets = ", ".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE alerts SET {sets} WHERE id=?", (*fields.values(), aid))

    # ---------- incidents ----------
    def insert_incident(self, inc: dict) -> str:
        iid = uuid.uuid4().hex[:12]
        ts = now_iso()
        self._exec(
            "INSERT INTO incidents (id, title, severity, status, created, updated,"
            " agents_json, alert_ids_json, entities_json, mitre_json, triage_summary)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (iid, inc.get("title"), inc.get("severity", "medium"), "open", ts, ts,
             json.dumps(inc.get("agents", [])), json.dumps(inc.get("alert_ids", [])),
             json.dumps(inc.get("entities", {})), json.dumps(inc.get("mitre", [])),
             inc.get("triage_summary")),
        )
        return iid

    def update_incident(self, iid, **fields):
        fields["updated"] = now_iso()
        sets = ", ".join(f"{k}=?" for k in fields)
        self._exec(f"UPDATE incidents SET {sets} WHERE id=?", (*fields.values(), iid))

    def get_incident(self, iid):
        rows = self._query("SELECT * FROM incidents WHERE id=?", (iid,))
        return dict(rows[0]) if rows else None

    def list_incidents(self, status=None, limit=100):
        sql = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if status:
            sql += " AND status=?"; params.append(status)
        sql += " ORDER BY updated DESC LIMIT ?"; params.append(limit)
        return [dict(r) for r in self._query(sql, params)]

    def open_incidents(self):
        return self.list_incidents(status="open", limit=500)

    # ---------- agents ----------
    def upsert_agent(self, agent_id, hostname=None, os=None, version=None):
        with self._lock:
            row = self.conn.execute("SELECT id FROM agents WHERE id=?", (agent_id,)).fetchone()
            if row:
                self.conn.execute(
                    "UPDATE agents SET hostname=COALESCE(?,hostname), os=COALESCE(?,os),"
                    " version=COALESCE(?,version), last_seen=? WHERE id=?",
                    (hostname, os, version, now_iso(), agent_id))
            else:
                self.conn.execute(
                    "INSERT INTO agents (id, hostname, os, last_seen, version, risk_score)"
                    " VALUES (?,?,?,?,?,0)",
                    (agent_id, hostname, os, now_iso(), version))
            self.conn.commit()

    def set_risk(self, agent_id, score):
        self._exec("UPDATE agents SET risk_score=? WHERE id=?", (score, agent_id))

    def list_agents(self):
        return [dict(r) for r in self._query("SELECT * FROM agents ORDER BY last_seen DESC")]

    # ---------- actions ----------
    def enqueue_action(self, agent_id, action, params) -> str:
        aid = uuid.uuid4().hex[:12]
        self._exec(
            "INSERT INTO actions (id, agent_id, action, params_json, status, created)"
            " VALUES (?,?,?,?, 'pending', ?)",
            (aid, agent_id, action, json.dumps(params or {}), now_iso()))
        return aid

    def pending_actions(self, agent_id):
        rows = self._query(
            "SELECT id, agent_id, action, params_json, status, created"
            " FROM actions WHERE agent_id=? AND status='pending' ORDER BY created",
            (agent_id,))
        out = []
        for r in rows:
            try:
                params = json.loads(r["params_json"]) if r["params_json"] else {}
            except (ValueError, TypeError):
                params = {}
            out.append({"action_id": r["id"], "agent_id": r["agent_id"],
                        "action": r["action"], "params": params,
                        "status": r["status"], "created": r["created"]})
        return out

    def ack_action(self, action_id, status, output):
        self._exec("UPDATE actions SET status=?, acked_at=?, output=? WHERE id=?",
                   (status, now_iso(), output, action_id))

    # ---------- kv (baselines, intel cache) ----------
    def kv_get(self, key):
        rows = self._query("SELECT value_json FROM kv WHERE key=?", (key,))
        return json.loads(rows[0]["value_json"]) if rows else None

    def kv_set(self, key, value):
        self._exec("INSERT INTO kv (key, value_json, updated) VALUES (?,?,?)"
                   " ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,"
                   " updated=excluded.updated",
                   (key, json.dumps(value), now_iso()))

    # ---------- stats ----------
    def count(self, table, where="1=1", params=()):
        rows = self._query(f"SELECT COUNT(*) c FROM {table} WHERE {where}", params)
        return rows[0]["c"]

    def alerts_by(self, column):
        rows = self._query(f"SELECT {column} k, COUNT(*) c FROM alerts GROUP BY {column}"
                           f" ORDER BY c DESC LIMIT 20")
        return [{"key": r["k"], "count": r["c"]} for r in rows]
