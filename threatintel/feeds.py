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
import socket
import threading
import time
import urllib.error
import urllib.parse
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
    import csv as _csv
    import io as _io
    iocs = []
    rows = list(_csv.reader(_io.StringIO(content)))
    if skip_header and rows:
        rows = rows[1:]
    for parts in rows:
        if len(parts) <= value_col:
            continue
        value = parts[value_col].strip()
        ioc_type = forced_type
        if type_col is not None and len(parts) > type_col:
            ioc_type = parts[type_col].strip().lower()
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


MAX_FEED_BYTES = 32 * 1024 * 1024

# Explicit deny-list (not ip.is_global): proxied/corporate DNS legitimately
# answers with shared ranges like 198.18.0.0/15, so "not global" would break
# every real feed there. What must never be reachable is internal space:
# loopback, RFC1918, link-local (incl. the cloud metadata address),
# multicast and reserved ranges.
_BLOCKED_NETS = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "fe80::/10", "fc00::/7", "ff00::/8",
    )
]


def _validate_feed_url(url: str):
    """SSRF guard for feed fetching. Feeds are operator-configured, but the
    API accepts new feeds at runtime, so a feed URL must never be able to
    read local files (file://) or reach internal services (cloud metadata,
    localhost, LAN addresses). Only public http(s) targets are allowed."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        raise RuntimeError(f"feed URL scheme not allowed: {p.scheme or '(none)'}")
    host = p.hostname
    if not host:
        raise RuntimeError("feed URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as e:
        raise RuntimeError(f"feed host DNS failed ({host}): {e}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if any(ip in net for net in _BLOCKED_NETS):
            raise RuntimeError(
                f"feed host {host} resolves to a blocked internal address ({ip})")


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect target with the same SSRF guard."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_feed_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_guarded_opener = urllib.request.build_opener(_GuardedRedirectHandler)


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
        _validate_feed_url(feed["url"])
        req = urllib.request.Request(feed["url"], headers=headers)
        try:
            with _guarded_opener.open(req, timeout=self.timeout) as r:
                chunks, total = [], 0
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_FEED_BYTES:
                        raise RuntimeError(
                            f"feed response exceeds {MAX_FEED_BYTES} bytes")
                    chunks.append(chunk)
            return b"".join(chunks).decode("utf-8", errors="replace")
        except RuntimeError:
            raise
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
        """Bulk-ingest parsed IOCs in ONE database transaction.

        The old loop did a lookup + upsert + commit per IOC, which made a
        20k-line feed take minutes. Rows are de-duplicated first (feeds
        repeat values), then written by ThreatIntelDB.bulk_upsert_iocs.
        """
        rows, seen, errors = [], set(), 0
        for ioc in iocs:
            try:
                value = ioc.get("value", "")
                ioc_type = ioc.get("type", "")
                if not value or not ioc_type:
                    continue
                if (value, ioc_type) in seen:
                    continue
                seen.add((value, ioc_type))
                score = ioc.get("score", feed.get("default_score") or 70)
                reputation = ("malicious" if score >= 75 else
                              "suspicious" if score >= 40 else "clean")
                rows.append({
                    "type": ioc_type, "value": value, "score": score,
                    "reputation": reputation, "confidence": "medium",
                    "source": source, "context": ioc.get("context", {}),
                    "description": ioc.get("description", ""),
                })
            except Exception as e:
                log.debug("ingest error for %s: %s", ioc, e)
                errors += 1
        if not rows:
            return 0, 0, errors
        try:
            added, updated = self.db.bulk_upsert_iocs(rows)
        except Exception as e:
            log.warning("bulk ingest failed for %s: %s", source, e)
            return 0, 0, errors + len(rows)
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
