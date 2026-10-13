"""Argus server: ingest -> detect -> enrich -> triage -> correlate -> respond."""
import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .anomaly import analyze as anomaly_analyze
from .correlate import correlate
from .db import DB, now_iso
from .enrich import enrich
from .playbooks import load_playbooks, playbooks_for, run_playbook
from .rules import RuleEngine, SEVERITY_RANK
from .triage import triage

BASE = Path(__file__).resolve().parent.parent
API_KEY = os.environ.get("ARGUS_API_KEY", "argus-dev-key")
AGENT_KEY = os.environ.get("ARGUS_AGENT_KEY", API_KEY)
DB_PATH = os.environ.get("ARGUS_DB", str(BASE / "argus.db"))
RULES_DIR = os.environ.get("ARGUS_RULES_DIR", str(BASE / "rules"))
PLAYBOOKS_DIR = os.environ.get("ARGUS_PLAYBOOKS_DIR", str(BASE / "playbooks"))

db = DB(DB_PATH)
engine = RuleEngine(RULES_DIR)
playbooks = load_playbooks(PLAYBOOKS_DIR)

app = FastAPI(title="Argus", version="0.1.0")

subscribers: set[WebSocket] = set()
notifications: list = []


async def broadcast(frame: dict):
    dead = set()
    for ws in subscribers:
        try:
            await ws.send_json(frame)
        except Exception:
            dead.add(ws)
    subscribers.difference_update(dead)


def notify(frame: dict):
    frame.setdefault("ts", now_iso())
    notifications.append(frame)
    del notifications[:-50]
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(broadcast(frame))
    except RuntimeError:
        pass


def check_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid API key")


def check_agent_key(x_agent_key: str | None):
    if x_agent_key != AGENT_KEY:
        raise HTTPException(status_code=401, detail="invalid agent key")


def normalize_event(raw: dict) -> dict:
    ev = dict(raw)
    if not ev.get("agent_id"):
        raise HTTPException(status_code=422, detail="event missing agent_id")
    ev.setdefault("hostname", ev["agent_id"])
    ev.setdefault("os", "linux")
    ev.setdefault("source", "syslog")
    ev.setdefault("event", {})
    ts = ev.get("ts")
    if not ts:
        ev["ts"] = now_iso()
    else:
        try:
            datetime.fromisoformat(ts)
        except Exception:
            ev["ts"] = now_iso()
    # Derive the local hour of the event timestamp so time-based rules
    # (e.g. off-hours logins) work without agents sending it explicitly.
    try:
        if isinstance(ev.get("event"), dict):
            ev["event"].setdefault("hour", datetime.fromisoformat(ev["ts"]).hour)
    except Exception:
        pass
    return ev


def process_alert(alert: dict, event_ids: list):
    """Enrich -> triage -> store -> correlate -> playbooks -> broadcast."""
    alert["event_ids"] = event_ids
    if alert.get("ai_triage"):
        alert["enrichment"] = enrich(db, alert)
        alert["triage"] = triage(alert, alert["enrichment"])
    else:
        alert["enrichment"] = enrich(db, alert)
        alert["triage"] = {}
    aid = db.insert_alert(alert)
    alert["id"] = aid
    iid = correlate(db, alert)
    update_risk(alert.get("agent_id"))
    for pb in playbooks_for(alert, playbooks):
        run_playbook(db, notify, pb, alert)
    return aid, iid


def update_risk(agent_id):
    if not agent_id:
        return
    since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    weights = {"low": 1, "medium": 2, "high": 5, "critical": 10}
    score = 0
    for a in db.list_alerts(agent_id=agent_id, limit=500, since=since):
        score += weights.get(a["severity"], 1)
    db.set_risk(agent_id, min(100, score))


class IngestBody(BaseModel):
    events: list[dict] = Field(min_length=1, max_length=5000)


@app.post("/api/v1/events")
async def ingest(body: IngestBody, x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    accepted = 0
    new_alerts = 0
    for raw in body.events:
        ev = normalize_event(raw)
        eid = db.insert_event(ev)
        db.upsert_agent(ev["agent_id"], ev.get("hostname"), ev.get("os"), ev.get("agent_version"))
        candidates = anomaly_analyze(db, ev) + engine.process(ev)
        for alert in candidates:
            aid, iid = process_alert(alert, [eid])
            new_alerts += 1
            await broadcast({"type": "alert", "alert": alert})
            inc = db.get_incident(iid)
            if inc:
                await broadcast({"type": "incident", "incident": inc})
        accepted += 1
    await broadcast({"type": "ingest", "accepted": accepted, "new_alerts": new_alerts})
    return {"accepted": accepted, "new_alerts": new_alerts}


@app.get("/api/v1/alerts")
def get_alerts(severity: str = None, rule_id: str = None, agent_id: str = None,
               limit: int = 100, since: str = None,
               x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    total = db.count_alerts(severity, rule_id, agent_id, since)
    return {"alerts": db.list_alerts(severity, rule_id, agent_id, min(limit, 1000), since),
            "total": total}


@app.get("/api/v1/alerts/{aid}")
def get_alert(aid: str, x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    a = db.get_alert(aid)
    if not a:
        raise HTTPException(404, "alert not found")
    return a


@app.get("/api/v1/incidents")
def get_incidents(status: str = None, limit: int = 100,
                  x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    return {"incidents": db.list_incidents(status, min(limit, 500))}


@app.get("/api/v1/incidents/{iid}")
def get_incident(iid: str, x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    inc = db.get_incident(iid)
    if not inc:
        raise HTTPException(404, "incident not found")
    alert_ids = json.loads(inc["alert_ids_json"] or "[]")
    inc["alerts"] = [db.get_alert(a) for a in alert_ids if db.get_alert(a)]
    return inc


@app.post("/api/v1/incidents/{iid}/ack")
def ack_incident(iid: str, body: dict = None,
                 x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    if not db.get_incident(iid):
        raise HTTPException(404, "incident not found")
    db.update_incident(iid, status="acknowledged",
                       note=(body or {}).get("note", ""))
    return {"ok": True}


@app.post("/api/v1/incidents/{iid}/close")
def close_incident(iid: str, body: dict = None,
                   x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    if not db.get_incident(iid):
        raise HTTPException(404, "incident not found")
    db.update_incident(iid, status="closed", note=(body or {}).get("note", ""))
    return {"ok": True}


@app.get("/api/v1/agents")
def get_agents(x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    agents = db.list_agents()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
    for a in agents:
        a["online"] = (a.get("last_seen") or "") >= cutoff
    return {"agents": agents}


class ActionBody(BaseModel):
    action: str
    params: dict = {}


@app.post("/api/v1/agents/{agent_id}/actions")
def enqueue(agent_id: str, body: ActionBody,
            x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    aid = db.enqueue_action(agent_id, body.action, body.params)
    return {"action_id": aid}


@app.get("/api/v1/agents/{agent_id}/actions")
def poll_actions(agent_id: str, x_agent_key: str | None = Header(default=None)):
    check_agent_key(x_agent_key)
    return {"actions": db.pending_actions(agent_id)}


@app.post("/api/v1/agents/{agent_id}/actions/{action_id}/ack")
def ack_action(agent_id: str, action_id: str, body: dict,
               x_agent_key: str | None = Header(default=None)):
    check_agent_key(x_agent_key)
    db.ack_action(action_id, body.get("status", "done"), body.get("output", ""))
    return {"ok": True}


@app.get("/api/v1/stats")
def stats(x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    mitre_counts = {}
    for a in db.list_alerts(limit=1000):
        for t in json.loads(a.get("mitre_json") or "[]"):
            mitre_counts[t] = mitre_counts.get(t, 0) + 1
    return {
        "events": db.count("events"),
        "alerts": db.count("alerts"),
        "incidents_open": db.count("incidents", "status='open'"),
        "agents": db.count("agents"),
        "by_severity": db.alerts_by("severity"),
        "by_rule": db.alerts_by("rule_id"),
        "by_mitre": sorted(mitre_counts.items(), key=lambda x: -x[1])[:15],
    }


@app.get("/api/v1/coverage")
def coverage(x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    cov = {}
    for r in engine.rules:
        for t in r.get("mitre", []):
            cov.setdefault(t, []).append(r["id"])
    return {"techniques": len(cov), "coverage": cov,
            "rules": [{"id": r["id"], "name": r.get("name"), "severity": r.get("severity"),
                       "mitre": r.get("mitre", [])} for r in engine.rules]}


@app.get("/api/v1/rules")
def list_rules(x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    return {"rules": engine.rules, "count": len(engine.rules)}


@app.post("/api/v1/rules/reload")
def reload_rules(x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    global playbooks
    n = engine.reload()
    playbooks = load_playbooks(PLAYBOOKS_DIR)
    return {"rules": n, "playbooks": len(playbooks)}


@app.get("/api/v1/notifications")
def get_notifications(x_api_key: str | None = Header(default=None)):
    check_api_key(x_api_key)
    return {"notifications": notifications[-50:]}


@app.websocket("/ws/feed")
async def feed(ws: WebSocket):
    await ws.accept()
    subscribers.add(ws)
    try:
        await ws.send_json({"type": "hello", "rules": len(engine.rules)})
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        subscribers.discard(ws)


@app.get("/api/v1/health")
def health():
    return {"ok": True, "rules": len(engine.rules), "playbooks": len(playbooks),
            "ts": now_iso()}


# Dashboard static files (dashboard/ built by the frontend task)
_dashboard_dir = BASE / "dashboard"
if _dashboard_dir.exists():
    app.mount("/", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")
