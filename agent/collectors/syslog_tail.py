"""Generic syslog tail collector: program/level/message -> source "syslog"."""

import logging
import re

from . import BaseCollector, TailReader

log = logging.getLogger("argus.syslog")

# Sep 24 16:59:36 myhost sshd[1234]: Accepted password for harsh ...
# Sep 24 16:59:36 myhost kernel: [12345.678] usb 1-1: new device
_RE_LINE = re.compile(
    r"^\w{3}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+([^:\s\[]+)(?:\[(\d+)\])?:\s*(.*)$"
)

# Best-effort facility guess from program name (plain syslog files carry no
# facility field). Rules should rely on program/message, not this.
_FACILITY_HINTS = {
    "kernel": "kern", "auth": "auth", "sshd": "auth", "sudo": "auth",
    "su": "auth", "login": "auth", "cron": "cron", "crond": "cron",
    "mail": "mail", "postfix": "mail", "daemon": "daemon", "systemd": "daemon",
}

_LEVEL_KEYWORDS = (
    (("critical", "crit:", "panic", "emerg"), "critical"),
    (("error", "failed", "failure", "denied", "refused", "timeout"), "error"),
    (("warn",), "warning"),
    (("debug",), "debug"),
)


def _guess_level(message):
    lowered = message.lower()
    for keywords, level in _LEVEL_KEYWORDS:
        if any(k in lowered for k in keywords):
            return level
    return "info"


class SyslogCollector(BaseCollector):
    """Tails /var/log/syslog and emits generic program/message events."""

    def __init__(self, agent_id, hostname, path="/var/log/syslog"):
        super().__init__(agent_id, hostname)
        self.tail = TailReader(path)

    def _parse_line(self, line):
        m = _RE_LINE.match(line)
        if not m:
            return None
        program, pid, message = m.groups()
        fields = {"program": program, "level": _guess_level(message), "message": message}
        if pid:
            fields["pid"] = int(pid)
        facility = _FACILITY_HINTS.get(program)
        if facility:
            fields["facility"] = facility
        return self.make_event("syslog", fields, raw=line)

    def collect(self, snapshot=False):
        lines = self.tail.read_last_lines(200) if snapshot else self.tail.read_new_lines()
        events = []
        for line in lines:
            try:
                event = self._parse_line(line)
            except Exception as exc:
                log.warning("parse error on syslog line: %s", exc)
                continue
            if event is not None:
                events.append(event)
        return events
