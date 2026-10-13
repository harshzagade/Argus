"""Threat-intel auto-enrichment. Real adapters (AbuseIPDB, VirusTotal, GreyNoise)
when API keys are present; deterministic offline mock otherwise. 24h cache."""
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
        if kind == "ip":
            intel = _abuseipdb(v) or _virustotal(v, True) or _greynoise(v) or _mock_ip(v)
        elif kind == "domain":
            intel = _virustotal(v, False) or _mock_domain(v)
        else:
            intel = _mock_hash(v)
        db.kv_set(ckey, {"at": datetime.now(timezone.utc).isoformat(), "intel": intel})
        out[name] = intel
    return out
