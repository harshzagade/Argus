"""Process collector: snapshots /proc and emits newly-started processes."""

import logging
import os
import pwd
import time

from . import BaseCollector

log = logging.getLogger("argus.process")

_MAX_EVENTS_PER_CYCLE = 500


def _read_status(pid):
    """Return (name, ppid, uid) from /proc/<pid>/status, or None."""
    name = ppid = uid = None
    try:
        with open("/proc/%s/status" % pid, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("PPid:"):
                    ppid = int(line.split(":", 1)[1].strip())
                elif line.startswith("Uid:"):
                    uid = int(line.split(":", 1)[1].split()[0])
                if name is not None and ppid is not None and uid is not None:
                    break
    except (OSError, ValueError):
        return None
    return name, ppid, uid


def _user_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError, TypeError):
        return str(uid)


class ProcessCollector(BaseCollector):
    def __init__(self, agent_id, hostname, interval=60):
        super().__init__(agent_id, hostname)
        self.interval = interval
        self._next_run = 0.0
        self._prev = None  # pid -> proc info dict

    def _snapshot(self):
        procs = {}
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError as exc:
            log.warning("cannot list /proc: %s", exc)
            return procs
        for pid in pids:
            status = _read_status(pid)
            if status is None:
                continue  # process exited or unreadable
            name, ppid, uid = status
            try:
                exe = os.readlink("/proc/%s/exe" % pid)
            except OSError:
                exe = ""
            try:
                with open("/proc/%s/cmdline" % pid, "rb") as fh:
                    raw = fh.read().split(b"\x00")
                cmdline = " ".join(
                    part.decode("utf-8", errors="replace") for part in raw if part
                )
            except OSError:
                cmdline = ""
            procs[int(pid)] = {
                "pid": int(pid), "ppid": ppid, "exe": exe,
                "cmdline": cmdline, "user": _user_name(uid), "name": name,
            }
        return procs

    def collect(self, snapshot=False):
        now = time.monotonic()
        if not snapshot and now < self._next_run:
            return []
        self._next_run = now + self.interval

        current = self._snapshot()

        if self._prev is None and not snapshot:
            self._prev = current  # baseline: emit nothing on first run
            log.info("process baseline established (%d processes)", len(current))
            return []

        prev = self._prev or {}
        events = []
        for pid, info in current.items():
            if pid not in prev:
                fields = {
                    "pid": info["pid"], "ppid": info["ppid"], "exe": info["exe"],
                    "cmdline": info["cmdline"], "user": info["user"],
                    "action": "started",
                }
                raw = "started pid=%d ppid=%d user=%s cmd=%s" % (
                    info["pid"], info["ppid"], info["user"],
                    info["cmdline"] or info["exe"] or info["name"] or "?")
                events.append(self.make_event("process", fields, raw=raw))

        if len(events) > _MAX_EVENTS_PER_CYCLE:
            log.warning("process scan found %d new processes; capping at %d",
                        len(events), _MAX_EVENTS_PER_CYCLE)
            events = events[:_MAX_EVENTS_PER_CYCLE]

        self._prev = current
        return events
