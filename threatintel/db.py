"""Threat Intelligence Platform — SQLite backend.

Stores IOCs (Indicators of Compromise), threat events, and feed sources.
Modeled after MISP (github.com/MISP/MISP, ~5k stars) but lightweight and
embeddable into the Argus ecosystem.

Tables:
    iocs        — individual indicators (IP, domain, hash, URL, email)
    ti_events   — threat events grouping related IOCs (like MISP events)
    tags        — many-to-many tags on IOCs and events
    feeds       — configured threat feed sources
    feed_runs   — feed ingestion history
"""
import urllib.parse
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,   -- ip, domain, hash_md5, hash_sha1, hash_sha256, url, email, cidr
    value       TEXT NOT NULL,
    score       INTEGER DEFAULT 50,   -- 0-100 maliciousness score
    reputation  TEXT DEFAULT 'unknown',  -- malicious, suspicious, clean, unknown
    confidence  TEXT DEFAULT 'medium',   -- high, medium, low
    source      TEXT,            -- feed name or 'manual'
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    expiry      TEXT,            -- ISO timestamp; NULL = never expires
    tlp         TEXT DEFAULT 'white',  -- traffic-light-protocol: white, green, amber, red
    tags_json   TEXT DEFAULT '[]',
    context_json TEXT DEFAULT '{}',    -- extra context (country, ASN, malware family, etc.)
    description TEXT DEFAULT '',
    event_id    TEXT,            -- link to ti_events
    active      INTEGER DEFAULT 1  -- 1=active, 0=expired/revoked
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_score ON iocs(score);
CREATE INDEX IF NOT EXISTS idx_iocs_source ON iocs(source);

CREATE TABLE IF NOT EXISTS ti_events (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity    TEXT DEFAULT 'medium',
    threat_actor TEXT DEFAULT '',
    malware_family TEXT DEFAULT '',
    campaign    TEXT DEFAULT '',
    tlp         TEXT DEFAULT 'white',
    created     TEXT NOT NULL,
    updated     TEXT NOT NULL,
    published   INTEGER DEFAULT 0,   -- 0=draft, 1=published
    tags_json   TEXT DEFAULT '[]',
    ioc_count   INTEGER DEFAULT 0,
    source      TEXT DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_tievents_severity ON ti_events(severity);

CREATE TABLE IF NOT EXISTS tags (
    id      TEXT PRIMARY KEY,
    name    TEXT UNIQUE NOT NULL,
    color   TEXT DEFAULT '#6b7280',
    created TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ioc_tags (
    ioc_id  TEXT NOT NULL,
    tag_id  TEXT NOT NULL,
    PRIMARY KEY (ioc_id, tag_id)
);

CREATE TABLE IF NOT EXISTS feeds (
    id          TEXT PRIMARY KEY,
    name        TEXT UNIQUE NOT NULL,
    url         TEXT NOT NULL,
    format      TEXT DEFAULT 'txt',  -- txt, csv, json, stix, misp
    ioc_type    TEXT,                -- NULL = auto-detect
    enabled     INTEGER DEFAULT 1,
    cron        TEXT DEFAULT '0 */6 * * *',  -- every 6 hours
    last_run    TEXT,
    last_count  INTEGER DEFAULT 0,
    headers_json TEXT DEFAULT '{}',
    created     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS feed_runs (
    id          TEXT PRIMARY KEY,
    feed_id     TEXT NOT NULL,
    started     TEXT NOT NULL,
    finished    TEXT,
    status      TEXT DEFAULT 'running',  -- running, ok, error
    added       INTEGER DEFAULT 0,
    updated     INTEGER DEFAULT 0,
    errors      INTEGER DEFAULT 0,
    message     TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_feedruns_feed ON feed_runs(feed_id);

CREATE TABLE IF NOT EXISTS correlations (
    id          TEXT PRIMARY KEY,
    ioc_value   TEXT NOT NULL,
    event_id    TEXT NOT NULL,   -- Argus alert ID
    matched_at  TEXT NOT NULL,
    rule_matched TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_corr_ioc ON correlations(ioc_value);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatIntelDB:
    """Thread-safe SQLite backend for the Threat Intel Platform."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.commit()
        self._seed_default_feeds()

    def _exec(self, sql, params=()):
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def _query(self, sql, params=()):
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def upsert_ioc(self, ioc_type: str, value: str, score: int = 50,
                   reputation: str = "unknown", confidence: str = "medium",
                   source: str = "manual", expiry: str = None,
                   tlp: str = "white", tags: list = None, context: dict = None,
                   description: str = "", event_id: str = None) -> str:
        """Insert or update an IOC. Returns the IOC id."""
        existing = self._query("SELECT id FROM iocs WHERE value=? AND type=?", (value, ioc_type))
        tags_json = json.dumps(tags or [])
        context_json = json.dumps(context or {})
        now = _now()

        if existing:
            iid = existing[0]["id"]
            self._exec(
                "UPDATE iocs SET score=?, reputation=?, confidence=?, source=?,"
                " last_seen=?, expiry=?, tlp=?, tags_json=?, context_json=?,"
                " description=?, event_id=COALESCE(?,event_id), active=1 WHERE id=?",
                (score, reputation, confidence, source, now, expiry, tlp,
                 tags_json, context_json, description, event_id, iid)
            )
            return iid

        iid = uuid.uuid4().hex[:16]
        self._exec(
            "INSERT INTO iocs (id, type, value, score, reputation, confidence, source,"
            " first_seen, last_seen, expiry, tlp, tags_json, context_json, description, event_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (iid, ioc_type, value, score, reputation, confidence, source,
             now, now, expiry, tlp, tags_json, context_json, description, event_id)
        )
        return iid

    def bulk_upsert_iocs(self, rows: list[dict]) -> tuple[int, int]:
        """Insert/update many IOCs in a single transaction.

        Same end state as calling upsert_ioc per row, but with one commit
        instead of one commit per row (the difference between seconds and
        minutes on a large feed). Returns (added, updated).
        """
        added = updated = 0
        now = _now()
        with self._lock:
            cur = self.conn.cursor()
            try:
                cur.execute("BEGIN")
                for row in rows:
                    ex = cur.execute(
                        "SELECT id FROM iocs WHERE value=? AND type=?",
                        (row["value"], row["type"])).fetchone()
                    if ex:
                        cur.execute(
                            "UPDATE iocs SET score=?, reputation=?, confidence=?,"
                            " source=?, last_seen=?, context_json=?, description=?,"
                            " active=1 WHERE id=?",
                            (row.get("score", 50), row.get("reputation", "unknown"),
                             row.get("confidence", "medium"), row.get("source", "feed"),
                             now, json.dumps(row.get("context", {})),
                             row.get("description", ""), ex[0]))
                        updated += 1
                    else:
                        cur.execute(
                            "INSERT INTO iocs (id, type, value, score, reputation,"
                            " confidence, source, first_seen, last_seen, expiry, tlp,"
                            " tags_json, context_json, description, event_id)"
                            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (uuid.uuid4().hex[:16], row["type"], row["value"],
                             row.get("score", 50), row.get("reputation", "unknown"),
                             row.get("confidence", "medium"), row.get("source", "feed"),
                             now, now, None, "white", "[]",
                             json.dumps(row.get("context", {})),
                             row.get("description", ""), None))
                        added += 1
                self.conn.commit()
            except Exception:
                self.conn.rollback()
                raise
        return added, updated

    def prune_feed_runs(self, days: int) -> int:
        """Delete feed-run history older than `days` (retention)."""
        if days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        cur = self._exec("DELETE FROM feed_runs WHERE started < ?", (cutoff,))
        return cur.rowcount

    def lookup(self, value: str) -> dict | None:
        """Look up a single value (any type). Returns the best match or None."""
        rows = self._query(
            "SELECT * FROM iocs WHERE value=? AND active=1 ORDER BY score DESC LIMIT 1",
            (value,)
        )
        if rows:
            return self._row(rows[0])
        # Domain <-> URL cross-match: a known-bad URL indicts its host domain
        # (an analyst pasting the bare domain must not get a false CLEAN),
        # and a known-bad domain indicts URLs hosted on it.
        host = None
        if "://" in value:
            host = urllib.parse.urlparse(value).hostname
        elif "." in value and "/" not in value and " " not in value:
            host = value
        if host:
            if host != value:
                rows = self._query(
                    "SELECT * FROM iocs WHERE value=? AND active=1 ORDER BY score DESC LIMIT 1",
                    (host,)
                )
                if rows:
                    return self._row(rows[0])
            for r in self._url_host_index().get(host, []):
                return r
        return None

    def _url_host_index(self) -> dict:
        """Host -> URL IOC rows, built lazily and rebuilt when the URL
        IOC count changes. lookup() used to scan and urlparse EVERY url
        row on every miss (every unknown IP, every enrichment) - an
        authenticated DoS and a drag on the hot path."""
        n = self._query(
            "SELECT COUNT(*) AS c FROM iocs WHERE type='url' AND active=1",
            ())[0]["c"]
        if getattr(self, "_uhi", None) is not None and self._uhi_count == n:
            return self._uhi
        idx: dict = {}
        for r in self._query(
                "SELECT * FROM iocs WHERE type='url' AND active=1 ORDER BY score DESC",
                ()):
            h = urllib.parse.urlparse(r["value"]).hostname
            if h:
                idx.setdefault(h.lower(), []).append(self._row(r))
        self._uhi = idx
        self._uhi_count = n
        return idx

    def bulk_lookup(self, values: list[str]) -> dict[str, dict]:
        """Look up multiple values. Returns {value: ioc_dict}."""
        if not values:
            return {}
        placeholders = ",".join("?" * len(values))
        rows = self._query(
            f"SELECT * FROM iocs WHERE value IN ({placeholders}) AND active=1"
            " ORDER BY score DESC",
            values
        )
        result = {}
        for row in rows:
            d = self._row(row)
            v = d["value"]
            # Keep highest score for duplicates
            if v not in result or d["score"] > result[v]["score"]:
                result[v] = d
        # Cross-match fallback for values with no exact hit (domain vs URL).
        for v in values:
            if v not in result:
                hit = self.lookup(v)
                if hit:
                    result[v] = hit
        return result

    def list_iocs(self, ioc_type: str = None, reputation: str = None,
                  source: str = None, min_score: int = None,
                  active_only: bool = True, limit: int = 500,
                  offset: int = 0) -> list[dict]:
        sql = "SELECT * FROM iocs WHERE 1=1"
        params = []
        if active_only:
            sql += " AND active=1"
        if ioc_type:
            sql += " AND type=?"; params.append(ioc_type)
        if reputation:
            sql += " AND reputation=?"; params.append(reputation)
        if source:
            sql += " AND source=?"; params.append(source)
        if min_score is not None:
            sql += " AND score>=?"; params.append(min_score)
        sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return [self._row(r) for r in self._query(sql, params)]

    def count_iocs(self, ioc_type=None, reputation=None, active_only=True) -> int:
        sql = "SELECT COUNT(*) c FROM iocs WHERE 1=1"
        params = []
        if active_only:
            sql += " AND active=1"
        if ioc_type:
            sql += " AND type=?"; params.append(ioc_type)
        if reputation:
            sql += " AND reputation=?"; params.append(reputation)
        rows = self._query(sql, params)
        return rows[0]["c"] if rows else 0

    def revoke_ioc(self, iid: str):
        self._exec("UPDATE iocs SET active=0 WHERE id=?", (iid,))

    def ioc_stats(self) -> dict:
        by_type = self._query(
            "SELECT type, COUNT(*) c FROM iocs WHERE active=1 GROUP BY type ORDER BY c DESC"
        )
        by_rep = self._query(
            "SELECT reputation, COUNT(*) c FROM iocs WHERE active=1 GROUP BY reputation ORDER BY c DESC"
        )
        by_src = self._query(
            "SELECT source, COUNT(*) c FROM iocs WHERE active=1 GROUP BY source ORDER BY c DESC LIMIT 10"
        )
        return {
            "total": self.count_iocs(),
            "by_type": [{"type": r["type"], "count": r["c"]} for r in by_type],
            "by_reputation": [{"reputation": r["reputation"], "count": r["c"]} for r in by_rep],
            "by_source": [{"source": r["source"], "count": r["c"]} for r in by_src],
        }

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def create_event(self, title: str, description: str = "",
                     severity: str = "medium", threat_actor: str = "",
                     malware_family: str = "", campaign: str = "",
                     tlp: str = "white", tags: list = None,
                     source: str = "manual") -> str:
        eid = uuid.uuid4().hex[:16]
        now = _now()
        self._exec(
            "INSERT INTO ti_events (id, title, description, severity, threat_actor,"
            " malware_family, campaign, tlp, created, updated, tags_json, source)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, title, description, severity, threat_actor, malware_family,
             campaign, tlp, now, now, json.dumps(tags or []), source)
        )
        return eid

    def get_event(self, eid: str) -> dict | None:
        rows = self._query("SELECT * FROM ti_events WHERE id=?", (eid,))
        if not rows:
            return None
        d = dict(rows[0])
        d["tags"] = json.loads(d.get("tags_json") or "[]")
        d["iocs"] = self.list_iocs_for_event(eid)
        return d

    def list_events(self, severity=None, limit=100) -> list[dict]:
        sql = "SELECT * FROM ti_events WHERE 1=1"
        params = []
        if severity:
            sql += " AND severity=?"; params.append(severity)
        sql += " ORDER BY updated DESC LIMIT ?"
        params.append(limit)
        rows = self._query(sql, params)
        out = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags_json") or "[]")
            out.append(d)
        return out

    def list_iocs_for_event(self, event_id: str) -> list[dict]:
        rows = self._query("SELECT * FROM iocs WHERE event_id=? AND active=1 ORDER BY score DESC", (event_id,))
        return [self._row(r) for r in rows]

    def publish_event(self, eid: str):
        self._exec("UPDATE ti_events SET published=1, updated=? WHERE id=?", (_now(), eid))

    def update_event_ioc_count(self, eid: str):
        count = self._query("SELECT COUNT(*) c FROM iocs WHERE event_id=? AND active=1", (eid,))
        n = count[0]["c"] if count else 0
        self._exec("UPDATE ti_events SET ioc_count=?, updated=? WHERE id=?", (n, _now(), eid))

    # ------------------------------------------------------------------
    # Tags
    # ------------------------------------------------------------------

    def ensure_tag(self, name: str, color: str = "#6b7280") -> str:
        existing = self._query("SELECT id FROM tags WHERE name=?", (name,))
        if existing:
            return existing[0]["id"]
        tid = uuid.uuid4().hex[:12]
        self._exec("INSERT INTO tags (id, name, color, created) VALUES (?,?,?,?)",
                   (tid, name, color, _now()))
        return tid

    def list_tags(self) -> list[dict]:
        rows = self._query("SELECT * FROM tags ORDER BY name")
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Feeds
    # ------------------------------------------------------------------

    def upsert_feed(self, name: str, url: str, fmt: str = "txt",
                    ioc_type: str = None, enabled: bool = True,
                    cron: str = "0 */6 * * *", headers: dict = None) -> str:
        existing = self._query("SELECT id FROM feeds WHERE name=?", (name,))
        if existing:
            fid = existing[0]["id"]
            self._exec(
                "UPDATE feeds SET url=?, format=?, ioc_type=?, enabled=?, cron=?,"
                " headers_json=? WHERE id=?",
                (url, fmt, ioc_type, int(enabled), cron,
                 json.dumps(headers or {}), fid)
            )
            return fid
        fid = uuid.uuid4().hex[:12]
        self._exec(
            "INSERT INTO feeds (id, name, url, format, ioc_type, enabled, cron, headers_json, created)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (fid, name, url, fmt, ioc_type, int(enabled), cron,
             json.dumps(headers or {}), _now())
        )
        return fid

    def list_feeds(self) -> list[dict]:
        rows = self._query("SELECT * FROM feeds ORDER BY name")
        return [dict(r) for r in rows]

    def get_feed(self, fid: str) -> dict | None:
        rows = self._query("SELECT * FROM feeds WHERE id=?", (fid,))
        return dict(rows[0]) if rows else None

    def start_feed_run(self, feed_id: str) -> str:
        run_id = uuid.uuid4().hex[:12]
        self._exec(
            "INSERT INTO feed_runs (id, feed_id, started, status) VALUES (?,?,?,'running')",
            (run_id, feed_id, _now())
        )
        return run_id

    def finish_feed_run(self, run_id: str, status: str, added: int,
                        updated: int, errors: int, message: str = ""):
        self._exec(
            "UPDATE feed_runs SET finished=?, status=?, added=?, updated=?, errors=?, message=? WHERE id=?",
            (_now(), status, added, updated, errors, message[:500], run_id)
        )
        # Update feed last_run
        rows = self._query("SELECT feed_id FROM feed_runs WHERE id=?", (run_id,))
        if rows:
            fid = rows[0]["feed_id"]
            self._exec("UPDATE feeds SET last_run=?, last_count=? WHERE id=?",
                       (_now(), added + updated, fid))

    def list_feed_runs(self, feed_id: str = None, limit: int = 50) -> list[dict]:
        if feed_id:
            rows = self._query(
                "SELECT * FROM feed_runs WHERE feed_id=? ORDER BY started DESC LIMIT ?",
                (feed_id, limit)
            )
        else:
            rows = self._query(
                "SELECT * FROM feed_runs ORDER BY started DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Correlations (IOC hits against Argus alerts)
    # ------------------------------------------------------------------

    def add_correlation(self, ioc_value: str, argus_event_id: str, rule: str = ""):
        cid = uuid.uuid4().hex[:12]
        self._exec(
            "INSERT INTO correlations (id, ioc_value, event_id, matched_at, rule_matched)"
            " VALUES (?,?,?,?,?)",
            (cid, ioc_value, argus_event_id, _now(), rule)
        )

    def correlations_for_ioc(self, ioc_value: str) -> list[dict]:
        rows = self._query(
            "SELECT * FROM correlations WHERE ioc_value=? ORDER BY matched_at DESC LIMIT 50",
            (ioc_value,)
        )
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _row(self, row) -> dict:
        d = dict(row)
        d["tags"] = json.loads(d.get("tags_json") or "[]")
        d["context"] = json.loads(d.get("context_json") or "{}")
        return d

    def _ensure_feed_score_column(self):
        try:
            self._exec("ALTER TABLE feeds ADD COLUMN default_score INTEGER")
        except Exception:
            pass  # column already exists

    def _seed_default_feeds(self):
        self._ensure_feed_score_column()
        """Register well-known public threat intel feeds."""
        # Migrate installs whose stored feeds still point at retired URLs:
        # abuse.ch ended anonymous URLhaus downloads (HTTP 410 Gone) and the
        # MISP warninglists repo renamed microsoft-azure-us to microsoft-azure.
        # Runs before the insert-missing pass so a migrated feed is not
        # duplicated under its new name. Enabled/disabled state is untouched.
        self._exec(
            "UPDATE feeds SET name=?, url=?, ioc_type=NULL WHERE url IN (?,?,?)",
            ("URLhaus Malicious Domains",
             "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
             "https://urlhaus.abuse.ch/downloads/text/",
             "https://urlhaus.abuse.ch/downloads/text_recent/",
             "https://urlhaus.abuse.ch/downloads/csv_recent/"))
        self._exec(
            "UPDATE feeds SET url=? WHERE url=?",
            ("https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/microsoft-azure/list.json",
             "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/microsoft-azure-us/list.json"))
        default_feeds = [
            {
                "name": "Feodo Tracker C2",
                "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
                "format": "txt",
                "ioc_type": "ip",
            },
            {
                # abuse.ch retired anonymous URLhaus downloads (HTTP 410);
                # this community mirror republishes the same URLhaus data.
                "name": "URLhaus Malicious Domains",
                "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
                "format": "txt",
                "ioc_type": None,
            },
            {
                "name": "OpenPhish Phishing URLs",
                "url": "https://openphish.com/feed.txt",
                "format": "txt",
                "ioc_type": "url",
            },
            {
                "name": "Emerging Threats Compromised IPs",
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "format": "txt",
                "ioc_type": "ip",
            },
            {
                "name": "MISP Warning Lists",
                "url": "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/microsoft-azure/list.json",
                "format": "json",
                "ioc_type": "cidr",
            },
        ]
        existing = {row["name"] for row in self._query("SELECT name FROM feeds", ())}
        for f in default_feeds:
            # Seed only missing feeds: re-seeding an existing feed would
            # silently re-enable one the operator disabled.
            if f["name"] not in existing:
                self.upsert_feed(f["name"], f["url"], fmt=f["format"], ioc_type=f["ioc_type"])
        # Curated malicious feeds carry a high-confidence default: their
        # rows used to land at score 70 = "suspicious", under the 75
        # "malicious" line, understating every verdict.
        self._exec(
            "UPDATE feeds SET default_score=85 WHERE default_score IS NULL"
            " AND name IN ('Feodo Tracker C2', 'URLhaus Malicious Domains',"
            " 'OpenPhish Phishing URLs', 'Emerging Threats Compromised IPs',"
            " 'Blocklist.de All')")
