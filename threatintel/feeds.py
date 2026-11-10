"""Threat Intelligence feed ingestion engine.

Pulls IOCs from configured feeds (plain-text IP lists, URL lists, CSV, JSON,
and a simplified STIX-2.1 subset). Inspired by MISP feed workers.

Feed formats supported:
    txt     — one IOC per line (IPs, domains, URLs, hashes)
    csv     — configurable column mapping
    json    — JSON array of objects or flat array of values
    stix    — STIX 2.1 bundle JSON (extracts indicators)
    misp    — MISP event JSON export

Auto-detection: type guessed from value format (IP, domain, hash, URL).
"""

import hashlib
import ipaddress
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from .db import ThreatIntelDB

log = logging.getLogger("sentinel.threatintel.feeds")

# --- value classification ---------------------------------------------------

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")

COMMENT_RE = re.compile(r"#.*$")


def classify_value(value: str) -> str | None:
    v = value.strip()
    if _URL_RE.match(v):
        return "url"
    if _IP_RE.match(v):
        return "ip"
    if _CIDR_RE.match(v):
        return "cidr"
    if _SHA256_RE.match(v):
        return "hash_sha256"
    if _SHA1_RE.match(v):
        return "hash_sha1"
    if _MD5_RE.match(v):
        return "hash_md5"
    if _EMAIL_RE.match(v):
        return "email"
    if _DOMAIN_RE.match(v) and "." in v:
        return "domain"
    return None


def is_routable_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


# --- parsers ----------------------------------------------------------------

def parse_txt(content: str, forced_type: str = None) -> list[dict]:
    """Parse plain-text IOC list: one value per line, comments with #."""
    iocs = []
    for line in content.splitlines():
        line = COMMENT_RE.sub("", line).strip()
        if not line or line.startswith(";"):
            continue
        # Some feeds use comma-separated; split on first comma/tab
        value = re.split(r"[,\t]", line)[0].strip()
        ioc_type = forced_type or classify_value(value)
        if not ioc_type:
            continue
        if ioc_type == "ip" and not is_routable_ip(value):
            continue
        iocs.append({"type": ioc_type, "value": value})
    return iocs


def parse_csv(content: str, value_col: int = 0, type_col: int = None,
              skip_header: bool = True, forced_type: str = None) -> list[dict]:
    """Parse CSV. value_col/type_col are 0-based column indices."""
    iocs = []
    lines = content.splitlines()
    if skip_header and lines:
        lines = lines[1:]
    for line in lines:
        parts = line.split(",")
        if len(parts) <= value_col:
            continue
        value = parts[value_col].strip().strip('"')
        ioc_type = forced_type
        if type_col is not None and len(parts) > type_col:
            ioc_type = parts[type_col].strip().strip('"').lower()
        if not ioc_type:
            ioc_type = classify_value(value)
        if not ioc_type or not value:
            continue
        iocs.append({"type": ioc_type, "value": value})
    return iocs


def parse_json_feed(content: str, forced_type: str = None) -> list[dict]:
    """Parse JSON feed — flat array of strings or array of objects."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        log.warning("JSON parse error: %s", e)
        return []

    iocs = []
    if isinstance(data, list):
        items = data
        warning_name = None
    else:
        items = data.get("data", data.get("indicators", data.get("list", [])))
        # MISP warninglist shape: {"name": ..., "list": [...]} — these are
        # known-legitimate ranges, NOT malicious indicators.
        warning_name = data.get("name") if "list" in data else None

    for item in items:
        if isinstance(item, str):
            ioc_type = forced_type or classify_value(item)
            if ioc_type:
                entry = {"type": ioc_type, "value": item}
                if warning_name is not None:
                    entry["score"] = 0
                    entry["context"] = {"warninglist": warning_name}
                iocs.append(entry)
        elif isinstance(item, dict):
            value = (item.get("indicator") or item.get("value") or
                     item.get("ip") or item.get("domain") or item.get("url") or
                     item.get("hash") or "")
            ioc_type = forced_type or item.get("type") or classify_value(value)
            if value and ioc_type:
                context = {k: v for k, v in item.items()
                           if k not in ("indicator", "value", "type") and isinstance(v, (str, int, float))}
                iocs.append({"type": ioc_type, "value": value,
                              "score": item.get("score", 50),
                              "context": context,
                              "description": item.get("description", "")})
    return iocs


def parse_stix(content: str) -> list[dict]:
    """Extract IOCs from a STIX 2.1 bundle JSON."""
    try:
        bundle = json.loads(content)
    except json.JSONDecodeError as e:
        log.warning("STIX parse error: %s", e)
        return []

    stix_type_map = {
        "ipv4-addr": "ip", "ipv6-addr": "ip",
        "domain-name": "domain",
        "url": "url",
        "email-addr": "email",
        "file": "hash_sha256",
    }

    iocs = []
    objects = bundle.get("objects", [])
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        confidence = obj.get("confidence", 50)
        description = obj.get("description", "")
        labels = obj.get("labels", [])

        # Parse STIX pattern: [ipv4-addr:value = '1.2.3.4']
        for stix_type, sentinel_type in stix_type_map.items():
            matches = re.findall(
                rf"\[{re.escape(stix_type)}:[\w.]+ \w+ '([^']+)'\]",
                pattern
            )
            for m in matches:
                iocs.append({
                    "type": sentinel_type,
                    "value": m,
                    "score": min(100, confidence),
                    "description": description,
                    "context": {"stix_labels": labels},
                })
        # Also catch hash patterns: [file:hashes.'SHA-256' = '...']
        hash_matches = re.findall(r"hashes\.'SHA-256' \w+ '([a-fA-F0-9]{64})'", pattern)
        for h in hash_matches:
            iocs.append({"type": "hash_sha256", "value": h, "score": 80,
                          "description": description})
    return iocs


def parse_misp_event(content: str) -> list[dict]:
    """Parse MISP event JSON export."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    # MISP export can be a single event or wrapped in a list
    if isinstance(data, list):
        events = data
    elif "Event" in data:
        events = [data]
    else:
        events = [data]

    misp_type_map = {
        "ip-dst": "ip", "ip-src": "ip", "ip-dst|port": "ip",
        "domain": "domain", "hostname": "domain",
        "url": "url", "link": "url",
        "md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256",
        "email-src": "email", "email-dst": "email",
        "filename|md5": "hash_md5", "filename|sha256": "hash_sha256",
    }

    iocs = []
    for event_wrapper in events:
        event = event_wrapper.get("Event", event_wrapper)
        attrs = event.get("Attribute", [])
        for attr in attrs:
            misp_type = attr.get("type", "")
            sentinel_type = misp_type_map.get(misp_type)
            if not sentinel_type:
                continue
            value = attr.get("value", "")
            if "|" in value:
                value = value.split("|")[0]
            if not value:
                continue
            iocs.append({
                "type": sentinel_type,
                "value": value,
                "score": 75 if attr.get("to_ids") else 40,
                "description": attr.get("comment", ""),
                "context": {"misp_category": attr.get("category", "")},
            })
    return iocs


# --- feed runner ------------------------------------------------------------

PARSERS = {
    "txt": parse_txt,
    "csv": parse_csv,
    "json": parse_json_feed,
    "stix": parse_stix,
    "misp": parse_misp_event,
}

_SCORE_MAP = {
    "malicious": 90,
    "suspicious": 55,
    "clean": 5,
}


class FeedRunner:
    """Fetches and ingests one feed run."""

    def __init__(self, db: ThreatIntelDB, timeout: int = 30):
        self.db = db
        self.timeout = timeout

    def run(self, feed: dict) -> dict:
        """Execute one feed. Returns run summary."""
        run_id = self.db.start_feed_run(feed["id"])
        log.info("starting feed run %s for %s", run_id, feed["name"])

        try:
            content = self._fetch(feed)
            iocs = self._parse(feed, content)
            added, updated, errors = self._ingest(iocs, feed["name"])
            self.db.finish_feed_run(run_id, "ok", added, updated, errors,
                                    f"ingested {added+updated} IOCs")
            log.info("feed %s done: added=%d updated=%d errors=%d",
                     feed["name"], added, updated, errors)
            return {"run_id": run_id, "status": "ok",
                    "added": added, "updated": updated, "errors": errors}
        except Exception as e:
            self.db.finish_feed_run(run_id, "error", 0, 0, 1, str(e)[:500])
            log.warning("feed %s failed: %s", feed["name"], e)
            return {"run_id": run_id, "status": "error", "message": str(e)}

    def _fetch(self, feed: dict) -> str:
        headers = json.loads(feed.get("headers_json") or "{}")
        req = urllib.request.Request(feed["url"], headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read()
            return raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RuntimeError(f"fetch failed: {e}") from e

    def _parse(self, feed: dict, content: str) -> list[dict]:
        fmt = feed.get("format", "txt")
        forced_type = feed.get("ioc_type")
        parser = PARSERS.get(fmt, parse_txt)
        try:
            if fmt == "txt":
                return parser(content, forced_type)
            elif fmt == "csv":
                return parser(content, forced_type=forced_type)
            elif fmt == "json":
                return parser(content, forced_type)
            else:
                return parser(content)
        except Exception as e:
            log.warning("parse error for feed %s: %s", feed["name"], e)
            return []

    def _ingest(self, iocs: list[dict], source: str) -> tuple[int, int, int]:
        added = updated = errors = 0
        for ioc in iocs:
            try:
                value = ioc.get("value", "")
                ioc_type = ioc.get("type", "")
                if not value or not ioc_type:
                    continue
                score = ioc.get("score", 70)
                reputation = ("malicious" if score >= 75 else
                              "suspicious" if score >= 40 else "clean")
                existing = self.db.lookup(value)
                self.db.upsert_ioc(
                    ioc_type=ioc_type,
                    value=value,
                    score=score,
                    reputation=reputation,
                    confidence="medium",
                    source=source,
                    context=ioc.get("context", {}),
                    description=ioc.get("description", ""),
                )
                if existing:
                    updated += 1
                else:
                    added += 1
            except Exception as e:
                log.debug("ingest error for %s: %s", ioc, e)
                errors += 1
        return added, updated, errors


class FeedScheduler:
    """Background scheduler that runs feeds on a configurable interval."""

    def __init__(self, db: ThreatIntelDB, default_interval: float = 3600.0):
        self.db = db
        self.default_interval = default_interval
        self._runner = FeedRunner(db)
        self._thread = threading.Thread(target=self._loop, daemon=True, name="feed-scheduler")
        self._stop = threading.Event()

    def start(self):
        self._thread.start()
        log.info("feed scheduler started (interval=%.0fs)", self.default_interval)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=15)

    def run_all_now(self) -> list[dict]:
        """Force-run all enabled feeds immediately. Returns run summaries."""
        results = []
        for feed in self.db.list_feeds():
            if not feed.get("enabled"):
                continue
            results.append(self._runner.run(feed))
        return results

    def run_feed(self, feed_id: str) -> dict:
        feed = self.db.get_feed(feed_id)
        if not feed:
            return {"status": "error", "message": "feed not found"}
        return self._runner.run(feed)

    def _loop(self):
        while not self._stop.is_set():
            try:
                feeds = self.db.list_feeds()
                now = datetime.now(timezone.utc)
                for feed in feeds:
                    if not feed.get("enabled"):
                        continue
                    last_run = feed.get("last_run")
                    if last_run:
                        delta = now - datetime.fromisoformat(last_run)
                        if delta < timedelta(seconds=self.default_interval):
                            continue
                    log.info("scheduled run for feed: %s", feed["name"])
                    self._runner.run(feed)
            except Exception:
                log.exception("scheduler loop error")
            self._stop.wait(60)  # check every minute
