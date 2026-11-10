"""Event shipper: batches events and POSTs them to the Argus server.

On failure it spools events to local disk (JSONL files) and retries with
exponential backoff. Spool files are drained oldest-first on recovery.
"""

import glob
import json
import logging
import os
import time
import urllib.error
import urllib.request

log = logging.getLogger("argus.shipper")

_BATCH_SIZE = 500
_BUFFER_CAP = 20000
_SPOOL_GLOB = "spool-*.jsonl"
_MAX_SPOOL_FILES_PER_FLUSH = 10


def _safe_unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


class Shipper:
    def __init__(self, server, api_key, spool_dir="/tmp/argus-spool", timeout=10):
        self.server = server.rstrip("/")
        self.api_key = api_key or ""
        self.spool_dir = spool_dir
        self.timeout = timeout
        self.buffer = []
        self._fail_count = 0
        self._next_retry = 0.0
        try:
            os.makedirs(self.spool_dir, exist_ok=True)
            os.chmod(self.spool_dir, 0o700)  # spool holds raw telemetry
        except OSError as exc:
            log.warning("cannot create spool dir %s: %s", self.spool_dir, exc)

    # -- public API --------------------------------------------------------
    def enqueue(self, events):
        if not events:
            return
        self.buffer.extend(events)
        if len(self.buffer) > _BUFFER_CAP:
            drop = len(self.buffer) - _BUFFER_CAP
            del self.buffer[:drop]
            log.warning("event buffer full; dropped %d oldest events", drop)

    def flush(self):
        """Try to ship buffered + spooled events. Returns True if all sent."""
        if time.monotonic() < self._next_retry:
            return False
        # 1) drain spool files, oldest first (they predate the buffer)
        spool_files = sorted(glob.glob(os.path.join(self.spool_dir, _SPOOL_GLOB)))
        for path in spool_files[:_MAX_SPOOL_FILES_PER_FLUSH]:
            events = self._read_spool_file(path)
            if events is None:
                continue
            if not events:
                _safe_unlink(path)
                continue
            if self._post(events):
                _safe_unlink(path)
                log.info("drained spool file %s (%d events)", path, len(events))
            else:
                self._note_failure()
                return False
        # 2) send the in-memory buffer in chunks
        while self.buffer:
            batch = self.buffer[:_BATCH_SIZE]
            if self._post(batch):
                del self.buffer[: len(batch)]
            else:
                self._spool_buffer()
                self._note_failure()
                return False
        self._fail_count = 0
        return True

    # -- internals ---------------------------------------------------------
    def _post(self, events):
        """POST one batch. True = accepted (or parked in dead-letter); False = retry."""
        url = self.server + "/api/v1/events"
        payload = json.dumps({"events": events}).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
            try:
                accepted = json.loads(body).get("accepted", len(events))
            except ValueError:
                accepted = len(events)
            log.debug("shipped %d events (server accepted %s)", len(events), accepted)
            return True
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8", errors="replace")[:500]
            except Exception:
                body = ""
            if exc.code == 429 or exc.code >= 500:
                # Transient: server busy/down — keep the events and retry.
                log.warning("server unavailable: HTTP %s; will retry. %s",
                            exc.code, body)
                return False
            # Permanent rejection (401/403 bad key, 400/422 bad batch):
            # retrying the same bytes will never succeed, but deleting them
            # loses telemetry silently. Park the batch in a dead-letter file
            # the operator can inspect and requeue, then keep the queue moving.
            log.error("server rejected batch permanently: HTTP %s; "
                      "moved to dead-letter. %s", exc.code, body)
            self._deadletter(events, "http-%d" % exc.code)
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("ship failed (%s); spooling", exc)
            return False

    def _deadletter(self, events, reason):
        """Park an undeliverable batch on disk instead of deleting it."""
        name = "deadletter-%d-%d-%s.jsonl" % (int(time.time()), os.getpid(), reason)
        path = os.path.join(self.spool_dir, name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps(event) + "\n")
            log.error("dead-lettered %d events to %s (reason: %s)",
                      len(events), path, reason)
        except OSError as exc:
            log.error("cannot write dead-letter file %s: %s; %d events lost",
                      path, exc, len(events))

    def _read_spool_file(self, path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return [json.loads(line) for line in fh if line.strip()]
        except (OSError, ValueError) as exc:
            # Corrupt spool: quarantine it for inspection, do not delete.
            bad = path + ".bad"
            log.error("cannot read spool file %s: %s (quarantined as %s)",
                      path, exc, bad)
            try:
                os.replace(path, bad)
            except OSError:
                pass
            return None

    def _spool_buffer(self):
        """Persist the unsent buffer to a new spool file."""
        if not self.buffer:
            return
        name = "spool-%d-%d.jsonl" % (int(time.time()), os.getpid())
        path = os.path.join(self.spool_dir, name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for event in self.buffer:
                    fh.write(json.dumps(event) + "\n")
            log.info("spooled %d events to %s", len(self.buffer), path)
            self.buffer = []
        except OSError as exc:
            log.error("cannot write spool file %s: %s; dropping %d events",
                      path, exc, len(self.buffer))
            self.buffer = []

    def _note_failure(self):
        self._fail_count += 1
        delay = min(300, 2 ** min(self._fail_count, 8))  # 2,4,8,... capped 300s
        self._next_retry = time.monotonic() + delay
        log.warning("backing off %.0fs after %d consecutive failures",
                    delay, self._fail_count)
