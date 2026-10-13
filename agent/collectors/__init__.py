"""Argus agent collectors.

Each collector exposes ``collect(snapshot=False) -> list[dict]`` returning
events that already conform to the ARCHITECTURE.md event schema
(agent_id, hostname, os, ts, source, event, raw).
"""

import logging
import os
from datetime import datetime, timezone

log = logging.getLogger("argus.collector")

# Version reported by every agent event; shown in the dashboard Devices table.
AGENT_VERSION = "0.1.0"


def now_iso():
    """Current time as ISO8601 with timezone offset, e.g. 2026-09-24T17:05:00+05:30."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class BaseCollector:
    """Common envelope builder for all collectors."""

    def __init__(self, agent_id, hostname):
        self.agent_id = agent_id
        self.hostname = hostname

    def make_event(self, source, fields, raw=None):
        event = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os": "linux",
            "agent_version": AGENT_VERSION,
            "ts": now_iso(),
            "source": source,
            "event": fields,
        }
        if raw is not None:
            event["raw"] = raw
        return event

    def collect(self, snapshot=False):
        """Return new events. snapshot=True bypasses cadence/baselining (--once)."""
        raise NotImplementedError


class TailReader:
    """Incremental tail of a text log file.

    Tracks inode + offset so log rotation is handled. Missing files are
    tolerated: a warning is logged once and reads return [].
    """

    def __init__(self, path, encoding="utf-8", errors="replace"):
        self.path = path
        self.encoding = encoding
        self.errors = errors
        self._offset = 0
        self._inode = None
        self._missing_warned = False

    def _stat(self):
        try:
            return os.stat(self.path)
        except FileNotFoundError:
            if not self._missing_warned:
                log.warning("log file not found (will retry): %s", self.path)
                self._missing_warned = True
            return None
        except OSError as exc:
            log.warning("cannot stat %s: %s", self.path, exc)
            return None

    def read_new_lines(self):
        """Return lines appended since the last call."""
        st = self._stat()
        if st is None:
            return []
        self._missing_warned = False
        # Rotation / truncation: inode changed or file shrank -> start over.
        if self._inode != st.st_ino or st.st_size < self._offset:
            self._inode = st.st_ino
            self._offset = 0
        if st.st_size == self._offset:
            return []
        lines = []
        try:
            with open(self.path, "r", encoding=self.encoding, errors=self.errors) as fh:
                fh.seek(self._offset)
                lines = fh.read().splitlines()
                self._offset = fh.tell()
        except OSError as exc:
            log.warning("cannot read %s: %s", self.path, exc)
            return []
        return lines

    def read_last_lines(self, n=200):
        """Return up to the last n lines of the file (for --once / testing)."""
        st = self._stat()
        if st is None:
            return []
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                block = 8192
                data = b""
                # Walk backwards until we have n+1 newlines or hit BOF.
                while size > 0 and data.count(b"\n") <= n:
                    step = min(block, size)
                    size -= step
                    fh.seek(size)
                    data = fh.read(step) + data
            text = data.decode(self.encoding, errors=self.errors)
            lines = text.splitlines()
            return lines[-n:]
        except OSError as exc:
            log.warning("cannot read %s: %s", self.path, exc)
            return []
