"""Agent action executor: polls the server for pending actions and runs them.

Supported actions (per ARCHITECTURE.md):
  block_ip   params: {"ip": "1.2.3.4"}      -> iptables INPUT DROP
  unblock_ip params: {"ip": "1.2.3.4"}      -> iptables INPUT DROP removal
  quarantine params: {"path": "/tmp/x"}     -> chmod 000 + move to quarantine dir
  isolate    params: {}                     -> drop new outbound except server
  run        params: {"command": "..."}     -> subprocess with timeout

Privileged actions execute for real only as root and only without --dry-run;
otherwise they are logged as DRY-RUN and acked as done. Every action is acked
to POST /api/v1/agents/{id}/actions/{action_id}/ack.
"""

import ipaddress
import json
import logging
import os
import shlex
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("argus.actions")

_OUTPUT_CAP = 4096
_RUN_TIMEOUT = 60
_IPTABLES_TIMEOUT = 30
_QUARANTINE_DIR = "/tmp/argus-quarantine"
# Never quarantine anything under these prefixes (foot-gun guard).
_PROTECTED_PREFIXES = ("/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64",
                       "/boot", "/dev", "/proc", "/sys")


class ActionPoller:
    def __init__(self, server, agent_id, agent_key, dry_run=False,
                 quarantine_dir=_QUARANTINE_DIR, timeout=10):
        self.server = server.rstrip("/")
        self.agent_id = agent_id
        self.agent_key = agent_key or ""
        self.dry_run = dry_run
        self.quarantine_dir = quarantine_dir
        self.timeout = timeout
        self._handlers = {
            "block_ip": self._block_ip,
            "unblock_ip": self._unblock_ip,
            "quarantine": self._quarantine,
            "isolate": self._isolate,
            "release": self._release,
            "unisolate": self._release,
            "run": self._run,
        }

    # -- polling -----------------------------------------------------------
    def poll(self):
        """Fetch pending actions, execute each, ack the result."""
        url = "%s/api/v1/agents/%s/actions" % (
            self.server, urllib.parse.quote(self.agent_id, safe=""))
        req = urllib.request.Request(url, headers={"X-Agent-Key": self.agent_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            log.warning("action poll failed: %s", exc)
            return
        if isinstance(data, list):
            actions = data
        elif isinstance(data, dict):
            actions = data.get("actions", [])
        else:
            actions = []
        for action in actions:
            if not isinstance(action, dict):
                continue
            self._handle(action)

    def _handle(self, action):
        action_id = action.get("action_id", "?")
        name = action.get("action", "")
        params = action.get("params") or {}
        log.info("executing action %s (%s) params=%s", action_id, name, params)
        handler = self._handlers.get(name)
        try:
            if handler is None:
                status, output = "failed", "unknown action: %r" % (name,)
            else:
                status, output = handler(params)
        except Exception as exc:  # never let one action kill the poller
            log.exception("action %s raised", action_id)
            status, output = "failed", "%s: %s" % (type(exc).__name__, exc)
        self._ack(action_id, status, output[:_OUTPUT_CAP])
        log.info("action %s -> %s: %s", action_id, status, output[:200])

    def _ack(self, action_id, status, output):
        url = "%s/api/v1/agents/%s/actions/%s/ack" % (
            self.server, urllib.parse.quote(self.agent_id, safe=""),
            urllib.parse.quote(str(action_id), safe=""))
        payload = json.dumps({"status": status, "output": output}).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json", "X-Agent-Key": self.agent_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout):
                pass
        except Exception as exc:
            log.warning("ack for action %s failed: %s", action_id, exc)

    # -- helpers -----------------------------------------------------------
    def _privileged(self):
        """True if we may actually execute privileged commands."""
        return not self.dry_run and os.geteuid() == 0

    def _exec_priv(self, cmd, description):
        """Run a privileged command, or log it as dry-run when not permitted."""
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
        if not self._privileged():
            reason = "--dry-run" if self.dry_run else "not running as root"
            log.info("DRY-RUN (%s): %s", reason, cmd_str)
            return "dry_run", "DRY-RUN (%s): %s" % (reason, cmd_str)
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=_IPTABLES_TIMEOUT)
        out = (proc.stdout + proc.stderr).strip()
        if proc.returncode != 0:
            return "failed", "%s -> rc=%d: %s" % (cmd_str, proc.returncode, out)
        return "done", out or ("%s ok" % description)

    @staticmethod
    def _valid_ip(value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("invalid IP address: %r" % (value,))

    # -- actions -----------------------------------------------------------
    def _fw_tool(self, ip):
        return "ip6tables" if ":" in ip else "iptables"

    def _never_block(self, ip):
        """Refuse to block loopback or the Argus server itself."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if addr.is_loopback or addr.is_unspecified:
            return True
        host = urllib.parse.urlparse(self.server).hostname or ""
        try:
            if host and socket.gethostbyname(host) == ip:
                return True
        except Exception:
            pass
        return False

    def _block_ip(self, params):
        ip = self._valid_ip(params.get("ip", ""))
        if self._never_block(ip):
            return "failed", "refusing to block loopback/server address %s" % ip
        tool = self._fw_tool(ip)
        # Idempotent: skip if the rule already exists; insert at the TOP of
        # the chain so the DROP is evaluated before any earlier ACCEPT.
        try:
            check = subprocess.run([tool, "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                   capture_output=True, text=True)
            exists = check.returncode == 0
        except OSError:
            exists = False
        if exists:
            return "done", "%s already blocked" % ip
        return self._exec_priv(
            [tool, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
            "blocked %s" % ip)

    def _unblock_ip(self, params):
        ip = self._valid_ip(params.get("ip", ""))
        tool = self._fw_tool(ip)
        # Remove every duplicate copy of the rule, not just the first.
        removed = 0
        while removed < 50:
            st, out = self._exec_priv(
                [tool, "-D", "INPUT", "-s", ip, "-j", "DROP"],
                "unblocked %s" % ip)
            if st == "dry_run":
                return st, out
            if st == "failed":
                break
            removed += 1
        if removed == 0:
            return "failed", "no block rule found for %s" % ip
        return "done", "unblocked %s (%d rule(s) removed)" % (ip, removed)

    def _quarantine(self, params):
        path = params.get("path", "")
        if not path or not os.path.isfile(path):
            return "failed", "no such file: %r" % (path,)
        real = os.path.realpath(path)
        if real.startswith(_PROTECTED_PREFIXES):
            return "failed", "refusing to quarantine protected path: %s" % real
        if not self._privileged():
            reason = "--dry-run" if self.dry_run else "not running as root"
            msg = "DRY-RUN (%s): chmod 000 + move %s -> %s/" % (reason, real, self.quarantine_dir)
            log.info(msg)
            return "dry_run", msg
        os.makedirs(self.quarantine_dir, exist_ok=True)
        dest = os.path.join(
            self.quarantine_dir,
            "%s.%d" % (os.path.basename(real), int(time.time())))
        os.chmod(real, 0o000)
        shutil.move(real, dest)
        return "done", "quarantined %s -> %s" % (real, dest)

    def _isolate(self, params):
        """Drop all NEW outbound traffic except to the Argus server.

        Appends (not inserts) OUTPUT rules; run once per incident. Re-running
        appends duplicates, so playbooks should guard against repeats.
        """
        host = urllib.parse.urlparse(self.server).hostname or "localhost"
        try:
            server_ip = socket.gethostbyname(host)
        except socket.gaierror as exc:
            return "failed", "cannot resolve server %s: %s" % (host, exc)
        cmds = [
            (["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
             "allow loopback"),
            (["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate",
              "ESTABLISHED,RELATED", "-j", "ACCEPT"], "allow established"),
            (["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53",
              "-j", "ACCEPT"], "allow DNS (udp)"),
            (["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53",
              "-j", "ACCEPT"], "allow DNS (tcp)"),
            (["iptables", "-A", "OUTPUT", "-d", server_ip, "-j", "ACCEPT"],
             "allow server %s" % server_ip),
            (["iptables", "-A", "OUTPUT", "-j", "DROP"], "drop other outbound"),
        ]
        outputs = []
        saw_dry = False
        for cmd, desc in cmds:
            # Idempotent: skip rules that already exist.
            try:
                chk = subprocess.run([cmd[0], "-C"] + cmd[2:],
                                     capture_output=True, text=True)
                exists = chk.returncode == 0
            except OSError:
                exists = False
            if exists:
                outputs.append("%s: already present" % desc)
                continue
            status, out = self._exec_priv(cmd, desc)
            outputs.append(out)
            if status == "failed":
                return "failed", "; ".join(outputs)
            if status == "dry_run":
                saw_dry = True
        return ("dry_run" if saw_dry else "done"), "; ".join(outputs)

    def _release(self, params):
        """Undo _isolate: delete the isolation OUTPUT rules (best effort)."""
        host = urllib.parse.urlparse(self.server).hostname or "localhost"
        try:
            server_ip = socket.gethostbyname(host)
        except socket.gaierror:
            server_ip = None
        rules = [
            ["iptables", "-D", "OUTPUT", "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
            ["iptables", "-D", "OUTPUT", "-m", "conntrack", "--ctstate",
             "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            ["iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        ]
        if server_ip:
            rules.insert(0, ["iptables", "-D", "OUTPUT", "-d", server_ip, "-j", "ACCEPT"])
        outputs = []
        saw_dry = False
        for cmd in rules:
            for _ in range(10):  # delete duplicates too
                st, out = self._exec_priv(cmd, "release")
                outputs.append(out)
                if st == "dry_run":
                    saw_dry = True
                if st != "done":
                    break
        return ("dry_run" if saw_dry else "done"), "isolation released: " + "; ".join(outputs[:3])

    def _run(self, params):
        command = params.get("command", "")
        if not command:
            return "failed", "missing 'command' param"
        if os.environ.get("ARGUS_ALLOW_RUN", "") != "1":
            return "failed", ("run action is disabled on this agent; "
                              "set ARGUS_ALLOW_RUN=1 on the agent to enable it")
        if not self._privileged():
            reason = "--dry-run" if self.dry_run else "not running as root"
            msg = "DRY-RUN (%s): %s" % (reason, command)
            log.info(msg)
            return "dry_run", msg
        proc = subprocess.run(command, shell=True, capture_output=True,
                              text=True, timeout=_RUN_TIMEOUT)
        out = (proc.stdout + proc.stderr).strip()
        return ("done" if proc.returncode == 0 else "failed",
                "rc=%d\n%s" % (proc.returncode, out))
