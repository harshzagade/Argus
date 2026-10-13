"""Auth log collector: sshd, sudo, useradd, su events from /var/log/auth.log."""

import logging
import re

from . import BaseCollector, TailReader

log = logging.getLogger("argus.auth")

# sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
_RE_SSH_FAILED = re.compile(
    r"sshd\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)"
)
# sshd[1234]: Accepted password for harsh from 198.51.100.7 port 51235 ssh2
_RE_SSH_OK = re.compile(
    r"sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)"
)
# sudo: harsh : TTY=pts/0 ; PWD=/home/harsh ; USER=root ; COMMAND=/usr/bin/apt update
_RE_SUDO_CMD = re.compile(
    r"sudo:\s+(\S+)\s*:\s*TTY=(\S+)\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.+?)\s*$"
)
# sudo: harsh : user NOT in sudoers ; TTY=pts/0 ; ...
_RE_SUDO_DENIED = re.compile(r"sudo:\s+(\S+)\s*:\s*user NOT in sudoers")
# useradd[23456]: new user: name=testuser, UID=1001, GID=1001, home=..., shell=...
_RE_USERADD = re.compile(r"useradd\[\d+\]: new user: name=([^,\s]+), UID=(\d+)(?:, GID=(\d+))?")
# su[34567]: Successful su for root by harsh
_RE_SU_OK = re.compile(r"\bsu\[\d+\]: Successful su for (\S+) by (\S+)")
# su[34567]: pam_unix(su:auth): authentication failure; ... ruser=harsh ... user=root
_RE_SU_FAIL = re.compile(
    r"pam_unix\(su:auth\): authentication failure;.*?ruser=(\S+).*?\buser=(\S+)\s*$"
)


class AuthCollector(BaseCollector):
    """Tails the auth log and parses authentication-related events."""

    def __init__(self, agent_id, hostname, path="/var/log/auth.log"):
        super().__init__(agent_id, hostname)
        self.tail = TailReader(path)

    def _parse_line(self, line):
        m = _RE_SSH_FAILED.search(line)
        if m:
            user, src_ip, src_port = m.groups()
            return self.make_event(
                "auth",
                {"service": "sshd", "user": user, "src_ip": src_ip,
                 "src_port": int(src_port), "result": "failed"},
                raw=line,
            )
        m = _RE_SSH_OK.search(line)
        if m:
            user, src_ip, src_port = m.groups()
            return self.make_event(
                "auth",
                {"service": "sshd", "user": user, "src_ip": src_ip,
                 "src_port": int(src_port), "result": "success"},
                raw=line,
            )
        m = _RE_SUDO_DENIED.search(line)
        if m:
            (user,) = m.groups()
            return self.make_event(
                "auth",
                {"service": "sudo", "user": user, "result": "failed",
                 "reason": "user not in sudoers"},
                raw=line,
            )
        m = _RE_SUDO_CMD.search(line)
        if m:
            user, tty, pwd, run_as, command = m.groups()
            return self.make_event(
                "auth",
                {"service": "sudo", "user": user, "run_as": run_as,
                 "command": command, "tty": tty, "pwd": pwd, "result": "success"},
                raw=line,
            )
        m = _RE_USERADD.search(line)
        if m:
            name, uid, gid = m.groups()
            fields = {"service": "useradd", "user": name, "uid": int(uid),
                      "result": "success", "action": "user_created"}
            if gid:
                fields["gid"] = int(gid)
            return self.make_event("auth", fields, raw=line)
        m = _RE_SU_OK.search(line)
        if m:
            target, by = m.groups()
            return self.make_event(
                "auth",
                {"service": "su", "user": target, "src_user": by, "result": "success"},
                raw=line,
            )
        m = _RE_SU_FAIL.search(line)
        if m:
            ruser, target = m.groups()
            return self.make_event(
                "auth",
                {"service": "su", "user": target, "src_user": ruser, "result": "failed"},
                raw=line,
            )
        return None

    def collect(self, snapshot=False):
        lines = self.tail.read_last_lines(200) if snapshot else self.tail.read_new_lines()
        events = []
        for line in lines:
            try:
                event = self._parse_line(line)
            except Exception as exc:  # never let one bad line kill the loop
                log.warning("parse error on auth line: %s", exc)
                continue
            if event is not None:
                events.append(event)
        return events
