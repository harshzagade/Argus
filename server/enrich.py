"""Threat-intel auto-enrichment. Query order:
  1. Argus TI Platform — local IOC database, in-process first
  2. AbuseIPDB (if ABUSEIPDB_KEY is set)
  3. VirusTotal (if VT_KEY is set)
  4. GreyNoise (always tried, free tier)
  5. Deterministic offline mock fallback
All results cached 24h in the kv table.
"""
import hashlib
import ipaddress
import json
import os
import re
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")


DEMO_BAD_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.")


def _is_demo_bad(v):
    return v.startswith(DEMO_BAD_PREFIXES)


def _is_routable(v):
    # Enrichable: anything not RFC1918/private, loopback, or multicast,
    # plus our demo "known-bad" documentation ranges (treated as private
    # by newer Python ipaddress versions, but we want intel on them).
    try:
        ip = ipaddress.ip_address(v)
        return _is_demo_bad(v) or not (ip.is_private or ip.is_loopback or ip.is_multicast)
    except ValueError:
        return False


def _mock_ip(v):
    # TEST-NET ranges are our demo "known bad"
    if _is_demo_bad(v):
        return {"type": "ip", "reputation": "malicious", "score": 95,
                "sources": ["mock"], "note": "Known-bad demo infrastructure"}
    h = int(hashlib.sha256(v.encode()).hexdigest(), 16) % 100
    if h < 5:
        return {"type": "ip", "reputation": "malicious", "score": 88, "sources": ["mock"]}
    if h < 15:
        return {"type": "ip", "reputation": "suspicious", "score": 55, "sources": ["mock"]}
    return {"type": "ip", "reputation": "clean", "score": 5, "sources": ["mock"]}


def _mock_domain(v):
    h = int(hashlib.sha256(v.encode()).hexdigest(), 16) % 100
    rep = "suspicious" if h < 10 else "clean"
    return {"type": "domain", "reputation": rep, "score": 60 if rep != "clean" else 5,
            "sources": ["mock"]}


def _mock_hash(v):
    h = int(hashlib.sha256(v.encode()).hexdigest(), 16) % 100
    rep = "malicious" if h < 8 else "clean"
    return {"type": "hash", "reputation": rep, "score": 90 if rep != "clean" else 2,
            "sources": ["mock"]}


def _http_json(url, headers=None, timeout=5):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# --- Argus TI Platform adapter ---

_local_ti_db = None


def _local_ti(value: str) -> dict | None:
    """Query the local TI database in-process (no HTTP self-call).

    In the unified deployment the TI store lives in the same process; the
    old HTTP call to our own server could deadlock/timeout and silently
    degrade enrichment. Falls back to None when no local DB is present.
    """
    global _local_ti_db
    try:
        if _local_ti_db is None:
            from pathlib import Path as _P
            base = _P(__file__).resolve().parent.parent
            path = (os.environ.get("ARGUS_TI_DB") or os.environ.get("SENTINEL_TI_DB")
                    or str(base / "argus-ti.db"))
            if not _P(path).exists():
                return None
            from threatintel.db import ThreatIntelDB
            _local_ti_db = ThreatIntelDB(path)
        hit = _local_ti_db.lookup(value)
        if not hit:
            return None
        return {
            "type": hit.get("type", ""),
            "reputation": hit.get("reputation", "unknown"),
            "score": hit.get("score", 0),
            "sources": [hit.get("source", "argus-ti")],
            "confidence": hit.get("confidence", "medium"),
            "description": hit.get("description", ""),
            "tlp": hit.get("tlp", "white"),
            "context": hit.get("context", {}),
        }
    except Exception:
        return None


def _argus_ti(value: str, kind: str) -> dict | None:
    """Query the local Argus Threat Intel Platform for an IOC."""
    local = _local_ti(value)
    if local is not None:
        return local
    base_url = (os.environ.get("ARGUS_TI_URL") or os.environ.get("SENTINEL_TI_URL", "")).rstrip("/")
    if not base_url:
        return None
    api_key = os.environ.get("SENTINEL_API_KEY", os.environ.get("ARGUS_API_KEY", "argus-dev-key"))
    try:
        body = json.dumps({"values": [value]}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/ti/v1/enrich",
            data=body,
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read().decode())
        enrichment = data.get("enrichment", {})
        if value in enrichment:
            hit = enrichment[value]
            # Normalize to Argus enrichment format
            return {
                "type": hit.get("type", kind),
                "reputation": hit.get("reputation", "unknown"),
                "score": hit.get("score", 0),
                "sources": hit.get("sources", ["sentinel-ti"]),
                "confidence": hit.get("confidence", "medium"),
                "description": hit.get("description", ""),
                "tlp": hit.get("tlp", "white"),
                "context": hit.get("context", {}),
            }
    except Exception:
        pass
    return None


def _abuseipdb(v):
    key = os.environ.get("ABUSEIPDB_KEY")
    if not key:
        return None
    try:
        data = _http_json(
            "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode(
                {"ipAddress": v, "maxAgeInDays": 90}),
            {"Key": key, "Accept": "application/json"})
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        rep = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        return {"type": "ip", "reputation": rep, "score": score, "sources": ["abuseipdb"],
                "reports": d.get("totalReports"), "country": d.get("countryCode")}
    except Exception:
        return None


def _virustotal(v, is_ip):
    key = os.environ.get("VT_KEY")
    if not key:
        return None
    try:
        path = f"ip_addresses/{v}" if is_ip else f"domains/{v}"
        data = _http_json(f"https://www.virustotal.com/api/v3/{path}",
                          {"x-apikey": key})
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        rep = "malicious" if mal >= 5 else "suspicious" if mal >= 1 else "clean"
        return {"type": "ip" if is_ip else "domain", "reputation": rep,
                "score": min(100, mal * 10), "sources": ["virustotal"],
                "detections": mal}
    except Exception:
        return None


def _greynoise(v):
    # Opt-in only: GreyNoise receives every enriched IP by default otherwise,
    # which leaks the addresses an organization is investigating.
    if os.environ.get("ARGUS_GREYNOISE", "") != "1":
        return None
    try:
        data = _http_json(f"https://api.greynoise.io/v3/community/{v}", timeout=5)
        cls = data.get("classification", "unknown")
        rep = {"malicious": "malicious", "benign": "clean"}.get(cls, "suspicious")
        return {"type": "ip", "reputation": rep,
                "score": 90 if rep == "malicious" else 10,
                "sources": ["greynoise"], "name": data.get("name")}
    except Exception:
        return None


def enrich(db, alert: dict) -> dict:
    """Enrich entity values (IPs, domains, hashes). Returns {entity_name: intel}."""
    out = {}
    for name, value in (alert.get("entities") or {}).items():
        v = str(value)
        kind = None
        if IP_RE.match(v) and _is_routable(v):
            kind = "ip"
        elif HASH_RE.match(v):
            kind = "hash"
        elif DOMAIN_RE.match(v) and "." in v and not IP_RE.match(v):
            kind = "domain"
        if not kind:
            continue
        ckey = f"intel:{kind}:{v}"
        cached = db.kv_get(ckey)
        if cached and datetime.now(timezone.utc) - datetime.fromisoformat(cached["at"]) < timedelta(hours=24):
            out[name] = cached["intel"]
            continue
        intel = None
        demo = os.environ.get("ARGUS_DEMO_INTEL", "") == "1"
        if kind == "ip":
            intel = _argus_ti(v, "ip") or _abuseipdb(v) or _virustotal(v, True) or _greynoise(v) or (_mock_ip(v) if demo else None)
        elif kind == "domain":
            intel = _argus_ti(v, "domain") or _virustotal(v, False) or (_mock_domain(v) if demo else None)
        else:
            intel = _argus_ti(v, kind) or (_mock_hash(v) if demo else None)
        if intel is None:
            # Honest unknown: no source had data. Do NOT fabricate a verdict
            # and do NOT cache it for 24h — a real source may answer later.
            out[name] = {"type": kind, "reputation": "unknown", "score": 0, "sources": []}
            continue
        db.kv_set(ckey, {"at": datetime.now(timezone.utc).isoformat(), "intel": intel})
        out[name] = intel
    return out
