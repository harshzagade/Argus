"""Argus Threat Intelligence Platform — FastAPI application.

Exposes a REST API inspired by MISP's data model but much simpler and
purpose-built to integrate with the Argus SIEM ecosystem.

Endpoints:
    GET  /api/ti/v1/health
    GET  /api/ti/v1/stats
    GET  /api/ti/v1/iocs           list/search IOCs
    GET  /api/ti/v1/iocs/{id}
    POST /api/ti/v1/iocs           add single IOC
    POST /api/ti/v1/iocs/bulk      add many IOCs at once
    POST /api/ti/v1/iocs/lookup    look up values against the DB
    DELETE /api/ti/v1/iocs/{id}
    GET  /api/ti/v1/events         threat events
    POST /api/ti/v1/events
    GET  /api/ti/v1/events/{id}
    POST /api/ti/v1/events/{id}/publish
    GET  /api/ti/v1/feeds          configured feeds
    POST /api/ti/v1/feeds          add feed
    POST /api/ti/v1/feeds/{id}/run trigger manual run
    GET  /api/ti/v1/feeds/{id}/runs
    GET  /api/ti/v1/tags
    GET  /api/ti/v1/export/csv     export all active IOCs as CSV
    GET  /api/ti/v1/export/stix    export as STIX 2.1 bundle
"""
import hmac
import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field

from .db import ThreatIntelDB, _now
from .feeds import FeedScheduler, classify_value

BASE = Path(__file__).resolve().parent.parent
TI_API_KEY = os.environ.get("SENTINEL_API_KEY", os.environ.get("ARGUS_API_KEY", "argus-dev-key"))
TI_DB_PATH = (os.environ.get("ARGUS_TI_DB") or os.environ.get("SENTINEL_TI_DB")
              or str(BASE / "argus-ti.db"))
TI_FEED_INTERVAL = float(os.environ.get("ARGUS_TI_FEED_INTERVAL") or os.environ.get("SENTINEL_TI_FEED_INTERVAL", "3600"))

ti_db = ThreatIntelDB(TI_DB_PATH)
scheduler = FeedScheduler(ti_db, default_interval=TI_FEED_INTERVAL)

app = FastAPI(title="Argus Threat Intelligence Platform", version="1.0.0")


def check_key(x_api_key: str | None):
    if not (x_api_key and hmac.compare_digest(x_api_key, TI_API_KEY)):
        raise HTTPException(401, "invalid API key")


@app.on_event("startup")
async def startup():
    scheduler.start()


@app.on_event("shutdown")
async def shutdown():
    scheduler.stop()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/api/ti/v1/health")
def health():
    stats = ti_db.ioc_stats()
    return {"ok": True, "total_iocs": stats["total"], "ts": _now()}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@app.get("/api/ti/v1/stats")
def stats(x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    s = ti_db.ioc_stats()
    feeds = ti_db.list_feeds()
    events = ti_db.list_events(limit=1000)
    s["feeds"] = len(feeds)
    s["events"] = len(events)
    return s


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------

class IOCCreate(BaseModel):
    type: str | None = None        # auto-detect if omitted
    value: str
    score: int = Field(default=70, ge=0, le=100)
    reputation: str = "unknown"    # malicious|suspicious|clean|unknown
    confidence: str = "medium"
    description: str = ""
    tlp: str = "white"
    tags: list[str] = []
    context: dict = {}
    event_id: str | None = None
    source: str = "manual"


class BulkIOCCreate(BaseModel):
    iocs: list[IOCCreate] = Field(min_length=1, max_length=10000)
    source: str = "bulk-upload"


class LookupRequest(BaseModel):
    values: list[str] = Field(min_length=1, max_length=1000)


@app.get("/api/ti/v1/iocs")
def list_iocs(
    ioc_type: str = None, reputation: str = None, source: str = None,
    min_score: int = None, limit: int = 500, offset: int = 0,
    x_api_key: str | None = Header(default=None)
):
    check_key(x_api_key)
    total = ti_db.count_iocs(ioc_type=ioc_type, reputation=reputation)
    iocs = ti_db.list_iocs(ioc_type=ioc_type, reputation=reputation,
                            source=source, min_score=min_score,
                            limit=min(limit, 2000), offset=offset)
    return {"iocs": iocs, "total": total}


@app.get("/api/ti/v1/iocs/{iid}")
def get_ioc(iid: str, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    row = ti_db._query("SELECT * FROM iocs WHERE id=?", (iid,))
    if not row:
        raise HTTPException(404, "IOC not found")
    ioc = ti_db._row(row[0])
    ioc["correlations"] = ti_db.correlations_for_ioc(ioc["value"])
    return ioc


@app.post("/api/ti/v1/iocs", status_code=201)
def create_ioc(body: IOCCreate, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    ioc_type = body.type or classify_value(body.value)
    if not ioc_type:
        raise HTTPException(422, f"Cannot auto-detect IOC type for value: {body.value!r}")
    iid = ti_db.upsert_ioc(
        ioc_type=ioc_type, value=body.value, score=body.score,
        reputation=body.reputation, confidence=body.confidence,
        source=body.source, tlp=body.tlp, tags=body.tags,
        context=body.context, description=body.description,
        event_id=body.event_id,
    )
    return {"id": iid, "type": ioc_type, "value": body.value}


@app.post("/api/ti/v1/iocs/bulk", status_code=201)
def bulk_create_iocs(body: BulkIOCCreate, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    added = updated = errors = 0
    for ioc in body.iocs:
        try:
            ioc_type = ioc.type or classify_value(ioc.value)
            if not ioc_type:
                errors += 1
                continue
            existing = ti_db.lookup(ioc.value)
            ti_db.upsert_ioc(
                ioc_type=ioc_type, value=ioc.value, score=ioc.score,
                reputation=ioc.reputation, confidence=ioc.confidence,
                source=body.source, tlp=ioc.tlp, tags=ioc.tags,
                context=ioc.context, description=ioc.description,
            )
            if existing:
                updated += 1
            else:
                added += 1
        except Exception:
            errors += 1
    return {"added": added, "updated": updated, "errors": errors}


@app.post("/api/ti/v1/iocs/lookup")
def lookup_iocs(body: LookupRequest, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    result = ti_db.bulk_lookup(body.values)
    return {"results": result, "hits": len(result), "total_queried": len(body.values)}


@app.delete("/api/ti/v1/iocs/{iid}")
def revoke_ioc(iid: str, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    ti_db.revoke_ioc(iid)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Threat Events
# ---------------------------------------------------------------------------

class EventCreate(BaseModel):
    title: str
    description: str = ""
    severity: str = "medium"
    threat_actor: str = ""
    malware_family: str = ""
    campaign: str = ""
    tlp: str = "white"
    tags: list[str] = []
    source: str = "manual"


@app.get("/api/ti/v1/events")
def list_events(severity: str = None, limit: int = 100,
                x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    return {"events": ti_db.list_events(severity=severity, limit=min(limit, 500))}


@app.post("/api/ti/v1/events", status_code=201)
def create_event(body: EventCreate, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    eid = ti_db.create_event(
        title=body.title, description=body.description, severity=body.severity,
        threat_actor=body.threat_actor, malware_family=body.malware_family,
        campaign=body.campaign, tlp=body.tlp, tags=body.tags, source=body.source,
    )
    return {"id": eid, "title": body.title}


@app.get("/api/ti/v1/events/{eid}")
def get_event(eid: str, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    ev = ti_db.get_event(eid)
    if not ev:
        raise HTTPException(404, "Event not found")
    return ev


@app.post("/api/ti/v1/events/{eid}/publish")
def publish_event(eid: str, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    ti_db.publish_event(eid)
    return {"ok": True}


# ---------------------------------------------------------------------------
# Feeds
# ---------------------------------------------------------------------------

class FeedCreate(BaseModel):
    name: str
    url: str
    format: str = "txt"
    ioc_type: str | None = None
    enabled: bool = True
    cron: str = "0 */6 * * *"
    headers: dict = {}


@app.get("/api/ti/v1/feeds")
def list_feeds(x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    return {"feeds": ti_db.list_feeds()}


@app.post("/api/ti/v1/feeds", status_code=201)
def add_feed(body: FeedCreate, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    fid = ti_db.upsert_feed(
        name=body.name, url=body.url, fmt=body.format,
        ioc_type=body.ioc_type, enabled=body.enabled,
        cron=body.cron, headers=body.headers,
    )
    return {"id": fid, "name": body.name}


@app.post("/api/ti/v1/feeds/{fid}/run")
def run_feed(fid: str, x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    result = scheduler.run_feed(fid)
    return result


@app.get("/api/ti/v1/feeds/{fid}/runs")
def get_feed_runs(fid: str, limit: int = 20,
                  x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    return {"runs": ti_db.list_feed_runs(feed_id=fid, limit=min(limit, 100))}


@app.post("/api/ti/v1/feeds/run-all")
def run_all_feeds(x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    results = scheduler.run_all_now()
    return {"results": results}


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

@app.get("/api/ti/v1/tags")
def list_tags(x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    return {"tags": ti_db.list_tags()}


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@app.get("/api/ti/v1/export/csv")
def export_csv(reputation: str = None,
               x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    iocs = ti_db.list_iocs(reputation=reputation, limit=100000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "type", "value", "score", "reputation", "confidence",
        "source", "first_seen", "last_seen", "tlp", "description"
    ])
    writer.writeheader()
    for ioc in iocs:
        writer.writerow({k: ioc.get(k, "") for k in writer.fieldnames})
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinel-iocs.csv"}
    )


@app.get("/api/ti/v1/export/stix")
def export_stix(reputation: str = None,
                x_api_key: str | None = Header(default=None)):
    check_key(x_api_key)
    iocs = ti_db.list_iocs(reputation=reputation, limit=50000)
    objects = []

    stix_type_map = {
        "ip": "ipv4-addr",
        "domain": "domain-name",
        "url": "url",
        "email": "email-addr",
        "hash_sha256": "file",
        "hash_md5": "file",
        "hash_sha1": "file",
    }
    hash_field_map = {
        "hash_sha256": "SHA-256",
        "hash_md5": "MD5",
        "hash_sha1": "SHA-1",
    }

    for ioc in iocs:
        ioc_type = ioc.get("type", "")
        stix_type = stix_type_map.get(ioc_type)
        if not stix_type:
            continue
        value = ioc.get("value", "")
        iid = ioc.get("id", "")

        if ioc_type in hash_field_map:
            hash_field = hash_field_map[ioc_type]
            pattern = f"[file:hashes.'{hash_field}' = '{value}']"
        elif ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ioc_type == "domain":
            pattern = f"[domain-name:value = '{value}']"
        elif ioc_type == "url":
            pattern = f"[url:value = '{value}']"
        elif ioc_type == "email":
            pattern = f"[email-addr:value = '{value}']"
        else:
            pattern = f"[{stix_type}:value = '{value}']"

        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"argus-ioc:{ioc_type}:{value}")),
            "created": ioc.get("first_seen", _now()),
            "modified": ioc.get("last_seen", _now()),
            "name": f"{ioc_type}:{value}",
            "description": ioc.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get("first_seen", _now()),
            "confidence": ioc.get("score", 50),
            "labels": [ioc.get("reputation", "unknown")],
        }
        objects.append(obj)

    bundle = {
        "type": "bundle",
        "id": "bundle--sentinel-export",
        "spec_version": "2.1",
        "objects": objects,
    }
    return JSONResponse(content=bundle, media_type="application/stix+json")


# ---------------------------------------------------------------------------
# Argus enrichment bridge (called by server/enrich.py)
# ---------------------------------------------------------------------------

@app.post("/api/ti/v1/enrich")
def enrich_entities(body: LookupRequest, x_api_key: str | None = Header(default=None)):
    """Bridge for Argus enrichment layer: returns enrichment dicts by value."""
    check_key(x_api_key)
    results = ti_db.bulk_lookup(body.values)
    enriched = {}
    for value, ioc in results.items():
        enriched[value] = {
            "type": ioc.get("type"),
            "reputation": ioc.get("reputation", "unknown"),
            "score": ioc.get("score", 0),
            "sources": [ioc.get("source", "sentinel-ti")],
            "confidence": ioc.get("confidence", "medium"),
            "description": ioc.get("description", ""),
            "tlp": ioc.get("tlp", "white"),
            "context": ioc.get("context", {}),
        }
    return {"enrichment": enriched}
