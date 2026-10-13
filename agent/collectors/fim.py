"""File integrity monitoring collector.

Polls watched files/directories on a cadence, compares sha256 hashes against
in-memory state (persisted to a small JSON state file), and emits
created|modified|deleted events -> source "fim".
"""

import hashlib
import json
import logging
import os
import pwd
import time

from . import BaseCollector

log = logging.getLogger("argus.fim")

_CHUNK = 65536
_MAX_EVENTS_PER_SCAN = 500


def _sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _owner_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return str(uid)


class FimCollector(BaseCollector):
    def __init__(self, agent_id, hostname, paths, state_file, interval=30):
        super().__init__(agent_id, hostname)
        self.paths = [p for p in paths if p]
        self.state_file = state_file
        self.interval = interval
        self._next_run = 0.0
        self._state = {}  # path -> {"sha256", "size", "mtime", "uid"}
        self._unreadable_warned = set()
        self._load_state()

    # -- state persistence -------------------------------------------------
    def _load_state(self):
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._state = data
                log.info("loaded FIM state for %d paths from %s",
                         len(self._state), self.state_file)
        except FileNotFoundError:
            pass  # first run: baseline below
        except (OSError, ValueError) as exc:
            log.warning("cannot load FIM state %s: %s", self.state_file, exc)

    def _save_state(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
            tmp = self.state_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._state, fh)
            os.replace(tmp, self.state_file)
        except OSError as exc:
            log.warning("cannot save FIM state %s: %s", self.state_file, exc)

    # -- scanning ----------------------------------------------------------
    def _iter_watch_files(self):
        """Yield every regular file under the watched paths."""
        for watch in self.paths:
            try:
                if os.path.isdir(watch) and not os.path.islink(watch):
                    for root, _dirs, files in os.walk(watch):
                        for name in files:
                            yield os.path.join(root, name)
                elif os.path.isfile(watch) or os.path.islink(watch):
                    yield watch
                elif not os.path.lexists(watch):
                    continue  # missing path: handled as deletion below
                else:
                    continue
            except OSError as exc:
                log.warning("cannot walk %s: %s", watch, exc)

    def _fingerprint(self, path):
        """Return (sha256, size, mtime, uid) or None if unreadable/missing."""
        try:
            st = os.stat(path)  # follows symlinks, like the file's real content
            if not os.path.isfile(path):
                return None
            digest = _sha256_of(path)
            return {"sha256": digest, "size": st.st_size,
                    "mtime": st.st_mtime, "uid": st.st_uid}
        except FileNotFoundError:
            return None
        except PermissionError:
            if path not in self._unreadable_warned:
                log.warning("FIM cannot read %s (permission denied); skipping", path)
                self._unreadable_warned.add(path)
            return None
        except OSError as exc:
            log.warning("FIM cannot stat %s: %s", path, exc)
            return None

    def _scan(self):
        current = {}
        for path in self._iter_watch_files():
            fp = self._fingerprint(path)
            if fp is not None:
                current[path] = fp
        return current

    def _emit(self, action, path, fp):
        fields = {"path": path, "action": action}
        if fp:
            fields["sha256"] = fp["sha256"]
            fields["size"] = fp["size"]
            fields["user"] = _owner_name(fp["uid"])
        raw = "%s %s" % (action, path)
        return self.make_event("fim", fields, raw=raw)

    def collect(self, snapshot=False):
        now = time.monotonic()
        if not snapshot and now < self._next_run:
            return []
        self._next_run = now + self.interval

        current = self._scan()
        events = []

        if not self._state and not snapshot:
            # First ever run: establish baseline silently, persist, emit nothing.
            self._state = current
            self._save_state()
            log.info("FIM baseline established for %d files", len(current))
            return []

        for path, fp in current.items():
            old = self._state.get(path)
            if old is None:
                events.append(self._emit("created", path, fp))
            elif old.get("sha256") != fp.get("sha256"):
                events.append(self._emit("modified", path, fp))
        for path in self._state:
            if path not in current:
                events.append(self._emit("deleted", path, None))

        if len(events) > _MAX_EVENTS_PER_SCAN:
            log.warning("FIM scan produced %d events; capping at %d",
                        len(events), _MAX_EVENTS_PER_SCAN)
            events = events[:_MAX_EVENTS_PER_SCAN]

        self._state = current
        self._save_state()
        return events
