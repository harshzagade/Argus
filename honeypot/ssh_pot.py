"""Argus SSH Honeypot — inspired by Cowrie (github.com/cowrie/cowrie, ~6k stars).

Emulates an SSH server that accepts any credentials after N failures, logs every
command the attacker runs, captures file uploads, and ships all sessions as
structured events to the Argus ingest endpoint.

Architecture:
    AsyncSSHServer (asyncio, paramiko socket shim)
    -> SessionHandler (per-connection state machine)
    -> CommandEmulator (fake filesystem responses)
    -> SessionStore (in-memory + JSONL on disk)
    -> ArgusShipper (batches events -> POST /api/v1/events)

Requires: paramiko>=3.0
"""
import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.honeypot.ssh")

# ---------------------------------------------------------------------------
# Fake filesystem and command emulator
# ---------------------------------------------------------------------------

FAKE_FS = {
    "/": ["bin", "dev", "etc", "home", "lib", "proc", "root", "tmp", "usr", "var"],
    "/etc": ["passwd", "shadow", "hostname", "hosts", "ssh", "cron.d", "sudoers"],
    "/etc/ssh": ["sshd_config", "ssh_host_rsa_key.pub"],
    "/home": ["ubuntu", "admin", "user"],
    "/root": [".bashrc", ".bash_history", ".ssh"],
    "/root/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub"],
    "/tmp": [],
    "/var": ["log", "www", "run"],
    "/var/log": ["auth.log", "syslog", "kern.log"],
    "/usr": ["bin", "lib", "local", "sbin"],
    "/usr/bin": ["python3", "wget", "curl", "nc", "ncat", "bash", "sh"],
    "/proc": ["cpuinfo", "meminfo", "version", "net"],
}

FAKE_ENV = {
    "HOME": "/root",
    "USER": "root",
    "SHELL": "/bin/bash",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TERM": "xterm-256color",
    "LANG": "en_US.UTF-8",
}

UNAME = "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"

MOTD = """\
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: {ts} from {ip}
"""


class FakeFS:
    """Minimal fake filesystem for command responses."""

    def __init__(self):
        self._files = dict(FAKE_FS)
        self._cwd = "/root"
        self._uploaded: dict[str, bytes] = {}

    def ls(self, path=None) -> str:
        target = path or self._cwd
        target = self._resolve(target)
        if target in self._files:
            return "  ".join(self._files[target])
        if target in self._uploaded:
            return os.path.basename(target)
        return f"ls: cannot access '{target}': No such file or directory"

    def cd(self, path) -> str:
        new = self._resolve(path) if path else "/root"
        if new in self._files:
            self._cwd = new
            return ""
        return f"-bash: cd: {path}: No such file or directory"

    def pwd(self) -> str:
        return self._cwd

    def cat(self, path) -> str:
        full = self._resolve(path)
        if full == "/etc/passwd":
            return "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n"
        if full == "/etc/hostname":
            return "ubuntu-server"
        if full in self._uploaded:
            return f"[binary data: {len(self._uploaded[full])} bytes]"
        return f"cat: {path}: No such file or directory"

    def _resolve(self, path: str) -> str:
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        parts = self._cwd.split("/") + path.split("/")
        out = []
        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                if out:
                    out.pop()
            else:
                out.append(p)
        return "/" + "/".join(out)

    def write_file(self, path: str, data: bytes):
        full = self._resolve(path)
        self._uploaded[full] = data
        parent = "/".join(full.split("/")[:-1]) or "/"
        name = full.split("/")[-1]
        if parent in self._files and name not in self._files[parent]:
            self._files[parent].append(name)
        log.warning("uploaded file written to fake path %s (%d bytes)", full, len(data))


class CommandEmulator:
    """Interprets attacker commands and returns realistic fake output."""

    def __init__(self, fs: FakeFS, attacker_ip: str, session_id: str):
        self.fs = fs
        self.ip = attacker_ip
        self.sid = session_id
        self._env = dict(FAKE_ENV)

    def run(self, cmd: str) -> tuple[str, str]:
        """Returns (output, category) where category tags the intent."""
        cmd = cmd.strip()
        if not cmd or cmd.startswith("#"):
            return ("", "noop")
        parts = cmd.split()
        prog = parts[0]

        if prog in ("exit", "logout", "quit"):
            return ("", "exit")
        if prog == "whoami":
            return ("root", "recon")
        if prog == "id":
            return ("uid=0(root) gid=0(root) groups=0(root)", "recon")
        if prog == "uname":
            if "-a" in parts:
                return (UNAME, "recon")
            return ("Linux", "recon")
        if prog == "hostname":
            return ("ubuntu-server", "recon")
        if prog == "pwd":
            return (self.fs.pwd(), "recon")
        if prog in ("ls", "dir"):
            path = parts[1] if len(parts) > 1 and not parts[1].startswith("-") else None
            return (self.fs.ls(path), "recon")
        if prog == "cd":
            path = parts[1] if len(parts) > 1 else "/root"
            out = self.fs.cd(path)
            return (out, "recon")
        if prog == "cat":
            path = parts[1] if len(parts) > 1 else ""
            return (self.fs.cat(path), "recon")
        if prog == "echo":
            text = cmd[len("echo"):].strip().strip('"').strip("'")
            return (text, "noop")
        if prog == "env" or prog == "printenv":
            return ("\n".join(f"{k}={v}" for k, v in self._env.items()), "recon")
        if prog in ("wget", "curl"):
            url = next((p for p in parts[1:] if p.startswith("http")), "")
            if url:
                log.info("[%s] download attempt: %s", self.sid, url)
                return (f"--2023-11-14 14:22:33--  {url}\nResolved: 1.2.3.4\nConnecting...\n200 OK\nLength: 12345\nSaving to 'payload'\npayload             100%[=====>]  12.3K  45.1KB/s    in 0.3s\n2023-11-14 14:22:34 (45.1 KB/s) - 'payload' saved [12345/12345]", "download")
            return ("", "noop")
        if prog in ("nc", "ncat", "netcat"):
            return ("", "c2")
        if prog == "python3" or prog == "python":
            script = cmd
            if "-c" in parts:
                script = cmd
            if "import socket" in script or "/dev/tcp" in script:
                return ("", "c2")
            return ("Python 3.10.12 (main, Nov 20 2023, 15:14:05)\n>>>", "execution")
        if prog in ("bash", "sh") and ("-i" in parts or ">&" in cmd):
            return ("", "c2")
        if prog in ("chmod", "chown", "chattr"):
            return ("", "evasion")
        if prog in ("rm", "shred"):
            if "-rf" in cmd or "/var/log" in cmd:
                return ("", "evasion")
            return ("", "noop")
        if prog in ("crontab", "cron"):
            return ("no crontab for root", "persistence")
        if prog in ("ps", "top", "htop"):
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:01 systemd\n"
                "  612 ?        00:00:00 sshd\n"
                " 1024 pts/0    00:00:00 bash\n", "recon")
        if prog in ("netstat", "ss"):
            return (
                "Proto Recv-Q Send-Q Local Address   Foreign Address  State\n"
                "tcp        0      0 0.0.0.0:22      0.0.0.0:*        LISTEN\n"
                "tcp        0      0 0.0.0.0:80      0.0.0.0:*        LISTEN\n", "recon")
        if prog in ("ifconfig", "ip"):
            return (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.1.15  netmask 255.255.255.0  broadcast 10.0.1.255\n"
                "        inet6 fe80::215:5dff:fe01:1234  prefixlen 64  scopeid 0x20<link>\n", "recon")
        if prog in ("history", "cat") and ".bash_history" in cmd:
            return ("", "recon")
        if prog in ("sudo", "su"):
            return ("", "privesc")
        if prog in ("useradd", "adduser"):
            return ("", "persistence")
        return (f"-bash: {prog}: command not found", "unknown")


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class HoneypotSession:
    """Tracks one attacker connection from connect to disconnect."""

    def __init__(self, session_id: str, src_ip: str, src_port: int,
                 honeypot_id: str, protocol: str = "ssh"):
        self.id = session_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.honeypot_id = honeypot_id
        self.protocol = protocol
        self.start_ts = _now()
        self.end_ts: str | None = None
        self.duration: float = 0.0

        self.login_attempts: list[dict] = []
        self.commands: list[dict] = []
        self.downloads: list[dict] = []
        self.uploads: list[dict] = []
        self.success_user: str | None = None
        self.success_pass: str | None = None

        self.categories: set[str] = set()

    def add_attempt(self, user: str, password: str, success: bool):
        if len(self.login_attempts) >= 200:
            return  # bounded: a flood session must not grow memory forever
        self.login_attempts.append({
            "ts": _now(), "user": user, "password": password,
            "success": success
        })
        if success and not self.success_user:
            self.success_user = user
            self.success_pass = password

    def add_command(self, cmd: str, output: str, category: str):
        if len(self.commands) >= 500:
            return  # bounded: a flood session must not grow memory forever
        self.commands.append({
            "ts": _now(), "cmd": cmd, "output": output[:200],
            "category": category
        })
        self.categories.add(category)

    def add_download(self, url: str):
        self.downloads.append({"ts": _now(), "url": url})

    def add_upload(self, filename: str, size: int, sha256: str):
        self.uploads.append({"ts": _now(), "filename": filename,
                              "size": size, "sha256": sha256})

    def close(self):
        self.end_ts = _now()
        start = datetime.fromisoformat(self.start_ts)
        end = datetime.fromisoformat(self.end_ts)
        self.duration = (end - start).total_seconds()

    def to_dict(self) -> dict:
        return {
            "session_id": self.id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "honeypot_id": self.honeypot_id,
            "protocol": self.protocol,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration": self.duration,
            "success": self.success_user is not None,
            "success_user": self.success_user,
            "success_pass": self.success_pass,
            "login_attempts": self.login_attempts,
            "commands": self.commands,
            "downloads": self.downloads,
            "uploads": self.uploads,
            "categories": sorted(self.categories),
        }


# ---------------------------------------------------------------------------
# Session store (in-memory + JSONL spool)
# ---------------------------------------------------------------------------

class SessionStore:
    def __init__(self, spool_dir: str = "/tmp/sentinel-honeypot"):
        self.spool_dir = Path(spool_dir)
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, HoneypotSession] = {}
        self._lock = threading.Lock()
        self._closed: list[dict] = []

    def new_session(self, src_ip: str, src_port: int, honeypot_id: str,
                    protocol: str = "ssh") -> HoneypotSession:
        sid = _sid()
        sess = HoneypotSession(sid, src_ip, src_port, honeypot_id, protocol)
        with self._lock:
            self._sessions[sid] = sess
        log.info("[%s] new %s session from %s:%d", sid, protocol, src_ip, src_port)
        return sess

    def close_session(self, sess: HoneypotSession):
        sess.close()
        with self._lock:
            self._sessions.pop(sess.id, None)
            self._closed.append(sess.to_dict())
        self._spool(sess.to_dict())
        log.info("[%s] session closed (duration=%.1fs, cmds=%d, success=%s)",
                 sess.id, sess.duration, len(sess.commands), sess.success_user)

    def pop_closed(self) -> list[dict]:
        with self._lock:
            out = list(self._closed)
            self._closed.clear()
        return out

    def _spool(self, sess: dict):
        try:
            path = self.spool_dir / f"session-{sess['session_id']}.json"
            path.write_text(json.dumps(sess, indent=2))
        except OSError as e:
            log.warning("spool write failed: %s", e)


# ---------------------------------------------------------------------------
# Argus shipper: converts closed sessions -> Argus events
# ---------------------------------------------------------------------------

class _ConnLimiter:
    """Per-IP connection flood control for the honeypots: caps concurrent
    sessions per source IP, new connections per minute per IP, and total
    concurrent sessions. Excess connections are dropped at accept time,
    before any session state exists (slowloris / connection-flood guard).
    """

    def __init__(self, per_ip_concurrent: int = 4, global_concurrent: int = 64,
                 per_ip_per_minute: int = 30):
        self.per_ip_concurrent = per_ip_concurrent
        self.global_concurrent = global_concurrent
        self.per_ip_per_minute = per_ip_per_minute
        self._lock = threading.Lock()
        self._conc: dict = {}
        self._window: dict = {}
        self._total = 0

    def allow(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            hits = [t for t in self._window.get(ip, []) if now - t < 60]
            self._window[ip] = hits
            if len(hits) >= self.per_ip_per_minute:
                return False
            if self._conc.get(ip, 0) >= self.per_ip_concurrent:
                return False
            if self._total >= self.global_concurrent:
                return False
            hits.append(now)
            self._conc[ip] = self._conc.get(ip, 0) + 1
            self._total += 1
            return True

    def release(self, ip: str):
        with self._lock:
            if self._conc.get(ip, 0) > 0:
                self._conc[ip] -= 1
            if self._total > 0:
                self._total -= 1


class HoneypotShipper:
    """Converts honeypot sessions to Argus events and ships them reliably.

    Durability contract (same policy as the agent shipper):
      * Events are written to a disk queue BEFORE any send attempt.
      * A queued batch is deleted only after the server confirms (2xx).
      * Server down / timeout / 5xx / 429 -> the batch stays queued and is
        retried on the next cycle. Nothing is lost to an outage.
      * A permanent rejection (other 4xx, e.g. a wrong API key) parks the
        batch in deadletter/ instead of retrying it forever.
      * Session files left on disk by a previous run (the process died
        before draining them) are replayed once at startup.
      * The queue is size-capped; the oldest batches are dropped past the
        cap so a long outage cannot fill the disk.
    """

    MAX_QUEUE_BYTES = 50 * 1024 * 1024

    def __init__(self, server: str, api_key: str, honeypot_id: str,
                 store: SessionStore, interval: float = 5.0):
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.honeypot_id = honeypot_id
        self.store = store
        self.interval = interval
        self.queue_dir = store.spool_dir / "queue"
        self.dead_dir = store.spool_dir / "deadletter"
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.dead_dir.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._replayed_ids: set = set()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="hp-shipper")
        self._stop = threading.Event()

    def start(self):
        self._replay_legacy_sessions()
        self._thread.start()
        log.info("honeypot shipper started -> %s (queue: %s)", self.server, self.queue_dir)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)

    # -- durable queue ---------------------------------------------------
    def _enqueue(self, events: list[dict]):
        if not events:
            return
        self._seq += 1
        name = f"q-{int(time.time() * 1000)}-{os.getpid()}-{self._seq:06d}.jsonl"
        tmp = self.queue_dir / (name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev) + "\n")
            f.flush()
            os.fsync(f.fileno())
        tmp.rename(self.queue_dir / name)
        self._enforce_cap()

    def _enforce_cap(self):
        files = sorted(self.queue_dir.glob("q-*.jsonl"))
        total = sum(f.stat().st_size for f in files)
        dropped = 0
        while total > self.MAX_QUEUE_BYTES and files:
            victim = files.pop(0)
            try:
                total -= victim.stat().st_size
                victim.unlink()
                dropped += 1
            except OSError:
                break
        if dropped:
            log.warning("honeypot queue over cap: dropped %d oldest batch(es)", dropped)

    def _replay_legacy_sessions(self):
        """SessionStore spools every closed session to session-<id>.json as
        a crash fallback. Files still on disk at startup belong to sessions
        that were never drained (this process died first): convert them,
        queue them, and remove the file so each ships exactly once. The
        rename claims the file, so two shippers sharing a spool dir (SSH +
        HTTP pots) cannot replay the same session twice."""
        for path in sorted(self.store.spool_dir.glob("session-*.json")):
            claimed = path.with_name(path.name + ".replay")
            try:
                path.rename(claimed)
            except OSError:
                continue
            try:
                sess = json.loads(claimed.read_text())
                if sess.get("session_id"):
                    self._replayed_ids.add(sess["session_id"])
                events = self._to_events(sess)
                if events:
                    self._enqueue(events)
                    log.info("replayed spooled session %s (%d events)",
                             sess.get("session_id"), len(events))
            except Exception as e:
                log.warning("legacy session replay failed for %s: %s", path.name, e)
                try:
                    claimed.rename(self.dead_dir / claimed.name)
                except OSError:
                    pass
                continue
            claimed.unlink(missing_ok=True)

    def _loop(self):
        while not self._stop.is_set():
            try:
                for sess_dict in self.store.pop_closed():
                    if sess_dict.get("session_id") in self._replayed_ids:
                        # Already queued by the startup replay of its
                        # crash-fallback file; ship exactly once.
                        self._replayed_ids.discard(sess_dict.get("session_id"))
                        continue
                    self._enqueue(self._to_events(sess_dict))
                    # The durable queue owns the session now; remove the
                    # per-session crash-fallback file.
                    try:
                        (self.store.spool_dir /
                         f"session-{sess_dict['session_id']}.json").unlink(missing_ok=True)
                    except OSError:
                        pass
                self._flush()
            except Exception:
                log.exception("shipper loop error")
            self._stop.wait(self.interval)

    def _flush(self):
        for path in sorted(self.queue_dir.glob("q-*.jsonl"))[:20]:
            claimed = path.with_name(path.name + ".sending")
            try:
                path.rename(claimed)
            except OSError:
                continue  # another shipper is flushing it
            try:
                events = [json.loads(l) for l in
                          claimed.read_text().splitlines() if l.strip()]
            except Exception:
                claimed.rename(self.dead_dir / claimed.name)
                continue
            if not events:
                claimed.unlink(missing_ok=True)
                continue
            status = self._post(events)
            if status == "ok":
                claimed.unlink(missing_ok=True)
            elif status == "dead":
                claimed.rename(self.dead_dir / claimed.name)
                log.warning("honeypot batch permanently rejected; parked: %s",
                            claimed.name)
            else:  # retry on a later cycle; nothing is lost
                claimed.rename(path)

    def _post(self, events: list[dict]) -> str:
        """'ok' = server confirmed; 'retry' = transient failure, keep the
        batch; 'dead' = permanent rejection, park it in deadletter/."""
        body = json.dumps({"events": events}).encode("utf-8")
        req = urllib.request.Request(
            self.server + "/api/v1/events", data=body,
            headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            log.info("shipped %d honeypot events -> %s alerts",
                     len(events), data.get("new_alerts", 0))
            return "ok"
        except urllib.error.HTTPError as e:
            if e.code == 429 or e.code >= 500:
                log.warning("honeypot ship deferred (HTTP %d); batch kept", e.code)
                return "retry"
            log.warning("honeypot ship rejected (HTTP %d)", e.code)
            return "dead"
        except Exception as e:
            log.warning("honeypot ship failed (will retry): %s", e)
            return "retry"

    def _to_events(self, sess: dict) -> list[dict]:
        """Turn one closed honeypot session into Argus event stream."""
        events = []
        hp = self.honeypot_id

        # 1. Auth events — one per login attempt
        for attempt in sess.get("login_attempts", []):
            events.append({
                "agent_id": hp,
                "hostname": hp,
                "os": "honeypot",
                "ts": attempt["ts"],
                "source": "auth",
                "event": {
                    "service": "sshd",
                    "user": attempt["user"],
                    "src_ip": sess["src_ip"],
                    "src_port": sess["src_port"],
                    "result": "success" if attempt["success"] else "failed",
                    "port": 22,
                    "honeypot": True,
                    "session_id": sess["session_id"],
                },
                "raw": f"[honeypot] {sess['src_ip']} tried {attempt['user']}:{attempt['password']}"
            })

        # 2. Process events — one per command
        for cmd_entry in sess.get("commands", []):
            events.append({
                "agent_id": hp,
                "hostname": hp,
                "os": "honeypot",
                "ts": cmd_entry["ts"],
                "source": "process",
                "event": {
                    "action": "started",
                    "exe": cmd_entry["cmd"].split()[0] if cmd_entry["cmd"] else "",
                    "cmdline": cmd_entry["cmd"],
                    "user": sess.get("success_user", "unknown"),
                    "pid": 0,
                    "ppid": 0,
                    "src_ip": sess["src_ip"],
                    "src_port": sess["src_port"],
                    "honeypot": True,
                    "session_id": sess["session_id"],
                    "category": cmd_entry.get("category", "unknown"),
                },
                "raw": f"[honeypot] cmd: {cmd_entry['cmd']}"
            })

        # 3. Network events — one per download attempt
        for dl in sess.get("downloads", []):
            events.append({
                "agent_id": hp,
                "hostname": hp,
                "os": "honeypot",
                "ts": dl["ts"],
                "source": "network",
                "event": {
                    "proto": "tcp",
                    "src_ip": sess["src_ip"],
                    "src_port": sess["src_port"],
                    "dst_ip": dl.get("url", "").split("/")[2] if "://" in dl.get("url", "") else "",
                    "dst_port": 80,
                    "direction": "inbound",
                    "action": "allowed",
                    "bytes": 0,
                    "url": dl.get("url"),
                    "honeypot": True,
                    "session_id": sess["session_id"],
                },
                "raw": f"[honeypot] download: {dl['url']}"
            })

        # 4. FIM events — one per upload
        for up in sess.get("uploads", []):
            events.append({
                "agent_id": hp,
                "hostname": hp,
                "os": "honeypot",
                "ts": up["ts"],
                "source": "fim",
                "event": {
                    "action": "created",
                    "path": up["filename"],
                    "sha256": up["sha256"],
                    "user": sess.get("success_user", "unknown"),
                    "size": up["size"],
                    "honeypot": True,
                    "session_id": sess["session_id"],
                },
                "raw": f"[honeypot] upload: {up['filename']} {up['sha256']}"
            })

        # 5. Summary syslog event for the session
        cats = sess.get("categories", [])
        summary = (
            f"[honeypot] session {sess['session_id']} from {sess['src_ip']} "
            f"duration={sess['duration']:.1f}s cmds={len(sess['commands'])} "
            f"success={sess.get('success_user')} categories={','.join(cats)}"
        )
        events.append({
            "agent_id": hp,
            "hostname": hp,
            "os": "honeypot",
            "ts": sess.get("end_ts") or _now(),
            "source": "syslog",
            "event": {
                "program": "cowrie",
                "level": "info",
                "message": summary,
                "honeypot": True,
                "session_id": sess["session_id"],
                "categories": cats,
                "downloads": len(sess.get("downloads", [])),
                "uploads": len(sess.get("uploads", [])),
                # Structured session record so the dashboard can show the
                # real session instead of reconstructing it from alerts.
                "src_ip": sess["src_ip"],
                "protocol": sess.get("protocol", "ssh"),
                "success_user": sess.get("success_user"),
                "login_attempts": len(sess.get("login_attempts", [])),
                "duration_s": round(sess.get("duration", 0), 1),
                "command_count": len(sess.get("commands", [])),
                "commands": [c.get("cmd", "") for c in sess.get("commands", [])][:50],
            },
            "raw": summary
        })

        return events

# ---------------------------------------------------------------------------
# SSH server (paramiko-based)
# ---------------------------------------------------------------------------

try:
    import paramiko  # type: ignore
    _HAS_PARAMIKO = True
except ImportError:
    _HAS_PARAMIKO = False
    log.warning("paramiko not installed; SSH honeypot disabled (pip install paramiko)")


def _generate_host_key(path: str) -> "paramiko.RSAKey":
    import paramiko
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key


class _SSHServerInterface(paramiko.ServerInterface if _HAS_PARAMIKO else object):
    """Handles authentication decisions for one SSH connection."""

    def __init__(self, sess: HoneypotSession, max_tries: int = 3):
        self.sess = sess
        self.max_tries = max_tries
        self._tries = 0
        self.exec_command = None       # set by check_channel_exec_request
        self.shell_requested = False   # set by check_channel_shell_request
        self.pty_requested = False     # set by check_channel_pty_request
        self.term_size = (80, 24)

    def check_channel_request(self, kind, chanid):
        import paramiko
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        import paramiko
        self._tries += 1
        success = (self._tries > self.max_tries)  # accept after N failures
        self.sess.add_attempt(username, password, success)
        # The password itself lives in the session record (the capture
        # is the point of a honeypot); it does not belong in stdout /
        # container logs, which get shipped to far more places.
        log.info("[%s] auth attempt %d: %s:*** -> %s",
                 self.sess.id, self._tries, username,
                 "success" if success else "failed")
        return paramiko.AUTH_SUCCESSFUL if success else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        import paramiko
        self.sess.add_attempt(username, f"pubkey:{key.get_fingerprint().hex()}", False)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.pty_requested = True
        self.term_size = (width, height)
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        self.term_size = (width, height)
        return True

    def check_channel_shell_request(self, channel):
        self.shell_requested = True
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = (command.decode("utf-8", errors="replace")
                             if isinstance(command, bytes) else str(command))
        return True


_SHELL_COMMANDS = ["whoami", "id", "pwd", "ls", "dir", "cd", "cat", "echo",
                   "env", "printenv", "hostname", "uname", "wget", "curl",
                   "python", "python3", "history", "clear", "exit",
                   "logout", "quit"]


def _hp_prompt(fs) -> bytes:
    cwd = fs.pwd()
    disp = "~" if cwd == "/root" else cwd
    return f"root@ubuntu-server:{disp}# ".encode()


def _hp_run_line(sess, emulator, line: str):
    """Run one command through the emulator and record it on the session."""
    output, category = emulator.run(line)
    sess.add_command(line, output, category)
    if category == "download":
        for u in re.findall(r"https?://[^\s]+", line):
            sess.add_download(u)
    return output, category


def _exec_once(chan, sess, emulator, command: str):
    """Answer an SSH exec channel: run the command, send its output and an
    exit status, close. (Exec requests used to be accepted and ignored, so
    scripted clients hung — a classic honeypot fingerprint.)"""
    output, _category = _hp_run_line(sess, emulator, command)
    if output:
        chan.sendall((output + "\n").encode())
    try:
        chan.send_exit_status(0)
    except Exception:
        pass
    chan.close()


def _line_mode_shell(chan, sess, emulator, fs):
    """Shell without a PTY (bots and scripts): no echo, line-buffered."""
    ts_str = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    chan.sendall(MOTD.format(ts=ts_str, ip=sess.src_ip).encode())
    chan.sendall(_hp_prompt(fs))
    buf = b""
    while True:
        try:
            data = chan.recv(1024)
        except Exception:
            return
        if not data:
            return
        buf += data
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                chan.sendall(b"\r\n" + _hp_prompt(fs))
                continue
            output, category = _hp_run_line(sess, emulator, line)
            chan.sendall(f"\r\n{output}\r\n".encode() if output else b"\r\n")
            if category == "exit":
                chan.sendall(b"logout\r\n")
                return
            chan.sendall(_hp_prompt(fs))


def _interactive_shell(chan, sess, emulator, fs):
    """A real terminal line discipline: server-side echo, backspace,
    cursor movement, history recall, Ctrl+C/U/K/W/L/A/E and tab
    completion. Scanners fingerprint honeypots on exactly these
    behaviors; a shell where typing does not echo is not a shell."""
    ts_str = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    chan.sendall(MOTD.format(ts=ts_str, ip=sess.src_ip).encode())
    history: list = []
    line: list = []
    cur = 0
    hist_idx = None
    saved_line: list = []

    def redraw():
        out = b"\r\x1b[K" + _hp_prompt(fs) + "".join(line).encode()
        back = len(line) - cur
        if back:
            out += f"\x1b[{back}D".encode()
        chan.sendall(out)

    def submit() -> bool:
        nonlocal line, cur, hist_idx
        cmd = "".join(line).strip()
        chan.sendall(b"\r\n")
        line, cur, hist_idx = [], 0, None
        if not cmd:
            chan.sendall(_hp_prompt(fs))
            return False
        history.append(cmd)
        if cmd == "clear":
            chan.sendall(b"\x1b[2J\x1b[H" + _hp_prompt(fs))
            return False
        if cmd == "history":
            text = "\r\n".join(f"{i + 1:5d}  {h}" for i, h in enumerate(history))
            chan.sendall(text.encode() + b"\r\n" + _hp_prompt(fs))
            return False
        output, category = _hp_run_line(sess, emulator, cmd)
        if output:
            chan.sendall(output.replace("\n", "\r\n").encode() + b"\r\n")
        if category == "exit":
            chan.sendall(b"logout\r\n")
            return True
        chan.sendall(_hp_prompt(fs))
        return False

    def complete():
        nonlocal line, cur
        text = "".join(line)
        upto = text[:cur]
        token = upto.rsplit(" ", 1)[-1] if " " in upto else upto
        if not token:
            chan.sendall(b"\a")
            return
        if " " not in upto:  # completing the command name
            cands = [c for c in _SHELL_COMMANDS if c.startswith(token)]
        else:                # completing a name in the fake filesystem
            entries = fs._files.get(fs.pwd(), [])
            cands = [e for e in entries if e.startswith(token)]
        if len(cands) == 1:
            ins = cands[0][len(token):] + (" " if " " not in upto else "")
            for ch in ins:
                line.insert(cur, ch)
                cur += 1
            redraw()
        elif len(cands) > 1:
            common = os.path.commonprefix(cands)
            if len(common) > len(token):
                for ch in common[len(token):]:
                    line.insert(cur, ch)
                    cur += 1
                redraw()
            else:
                chan.sendall(b"\a")
        else:
            chan.sendall(b"\a")

    chan.sendall(_hp_prompt(fs))
    pending = b""
    while True:
        try:
            data = chan.recv(1024)
        except Exception:
            return
        if not data:
            return
        data = pending + data
        pending = b""
        i = 0
        while i < len(data):
            b = data[i]
            if b == 0x1B:  # escape sequence (cursor keys etc.)
                rest = data[i:]
                m = re.match(rb"\x1b\[([0-9;]*)([~ABCDFH])", rest)
                if not m:
                    if re.match(rb"\x1b(\[[0-9;]*)?$", rest):
                        pending = rest  # sequence split across packets
                        i = len(data)
                    else:
                        i += 2          # unknown escape: swallow it
                    continue
                params = m.group(1).decode()
                final = chr(m.group(2)[0])
                i += m.end()
                if final == "A" and history:            # Up: older history
                    if hist_idx is None:
                        saved_line = list(line)
                        hist_idx = len(history) - 1
                    elif hist_idx > 0:
                        hist_idx -= 1
                    line = list(history[hist_idx])
                    cur = len(line)
                    redraw()
                elif final == "B" and hist_idx is not None:  # Down
                    hist_idx += 1
                    if hist_idx >= len(history):
                        hist_idx = None
                        line = list(saved_line)
                    else:
                        line = list(history[hist_idx])
                    cur = len(line)
                    redraw()
                elif final == "C":                      # Right
                    if cur < len(line):
                        cur += 1
                        redraw()
                elif final == "D":                      # Left
                    if cur > 0:
                        cur -= 1
                        redraw()
                elif final == "H":
                    cur = 0
                    redraw()
                elif final == "F":
                    cur = len(line)
                    redraw()
                elif final == "~" and params == "3":    # Delete key
                    if cur < len(line):
                        del line[cur]
                        redraw()
                elif final == "~" and params in ("1", "7"):
                    cur = 0
                    redraw()
                elif final == "~" and params in ("4", "8"):
                    cur = len(line)
                    redraw()
                continue
            if b in (0x0D, 0x0A):                       # Enter
                if b == 0x0D and i + 1 < len(data) and data[i + 1] == 0x0A:
                    i += 1
                i += 1
                if submit():
                    return
                continue
            if b == 0x03:                               # Ctrl+C
                line, cur, hist_idx = [], 0, None
                chan.sendall(b"^C\r\n" + _hp_prompt(fs))
            elif b == 0x04:                             # Ctrl+D
                if not line:
                    chan.sendall(b"logout\r\n")
                    return
                if cur < len(line):
                    del line[cur]
                    redraw()
            elif b == 0x15:                             # Ctrl+U
                line, cur = [], 0
                redraw()
            elif b == 0x0B:                             # Ctrl+K
                line = line[:cur]
                redraw()
            elif b == 0x17:                             # Ctrl+W
                while cur > 0 and line[cur - 1] == " ":
                    del line[cur - 1]
                    cur -= 1
                while cur > 0 and line[cur - 1] != " ":
                    del line[cur - 1]
                    cur -= 1
                redraw()
            elif b == 0x01:                             # Ctrl+A
                cur = 0
                redraw()
            elif b == 0x05:                             # Ctrl+E
                cur = len(line)
                redraw()
            elif b == 0x0C:                             # Ctrl+L
                chan.sendall(b"\x1b[2J\x1b[H")
                redraw()
            elif b in (0x7F, 0x08):                     # Backspace
                if cur > 0:
                    del line[cur - 1]
                    cur -= 1
                    redraw()
            elif b == 0x09:                             # Tab
                complete()
            elif 0x20 <= b < 0x7F:                      # printable char
                line.insert(cur, chr(b))
                cur += 1
                redraw()
            i += 1


def _handle_ssh_client_thread(sock, addr, store: SessionStore,
                               honeypot_id: str, host_key,
                               max_login_tries: int, limiter=None):
    """Threaded handler for one incoming SSH TCP connection.

    Runs paramiko directly on the raw socket — no asyncio shim needed,
    so the SSH banner exchange completes reliably.
    """
    import paramiko
    import re as _re
    src_ip, src_port = addr[0], addr[1]
    sess = store.new_session(src_ip, src_port, honeypot_id, "ssh")
    fs = FakeFS()
    emulator = CommandEmulator(fs, src_ip, sess.id)
    transport = None
    try:
        transport = paramiko.Transport(sock)
        # Paramiko's default banner ("SSH-2.0-paramiko_x.y") fingerprints
        # the honeypot instantly; present as a stock Ubuntu OpenSSH.
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
        transport.add_server_key(host_key)
        server_iface = _SSHServerInterface(sess, max_tries=max_login_tries)
        transport.start_server(server=server_iface)

        # Serve channels until the client goes away: one connection can
        # carry several exec channels (scripts, Ansible) or a shell.
        first = True
        while transport.is_active():
            server_iface.exec_command = None
            server_iface.shell_requested = False
            server_iface.pty_requested = False
            chan = transport.accept(timeout=20 if first else 5)
            if chan is None:
                if first:
                    log.warning("[%s] no channel opened (client disconnected during auth)", sess.id)
                break
            first = False
            # The channel request (exec vs shell vs pty) lands just after
            # the channel opens; give it a moment to answer the right one.
            for _ in range(20):
                if server_iface.exec_command is not None or server_iface.shell_requested:
                    break
                time.sleep(0.05)
            if server_iface.exec_command is not None:
                _exec_once(chan, sess, emulator, server_iface.exec_command)
            elif server_iface.pty_requested:
                _interactive_shell(chan, sess, emulator, fs)
            else:
                _line_mode_shell(chan, sess, emulator, fs)

    except Exception as e:
        log.warning("[%s] SSH handler error: %s", sess.id, e)
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            sock.close()
        except Exception:
            pass
        store.close_session(sess)
        if limiter is not None:
            limiter.release(addr[0])


class SSHHoneypot:
    """
    Medium-interaction SSH honeypot inspired by Cowrie.
    Accepts any credential after max_login_tries failed attempts,
    emulates a bash shell, logs every command, and ships sessions to Argus.

    Runs as a plain threaded TCP server — one thread per connection.
    Paramiko operates directly on the raw socket so the SSH handshake
    completes reliably without asyncio interference.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 2222,
                 honeypot_id: str = "honeypot-ssh-01",
                 host_key_path: str = "/tmp/sentinel-ssh-host-key",
                 sentinel_server: str = "http://localhost:8000",
                 sentinel_api_key: str = "argus-dev-key",
                 spool_dir: str = "/tmp/sentinel-honeypot",
                 max_login_tries: int = 3):
        self.host = host
        self.port = port
        self.honeypot_id = honeypot_id
        self.host_key_path = host_key_path
        self.sentinel_server = sentinel_server
        self.sentinel_api_key = sentinel_api_key
        self.spool_dir = spool_dir
        self.max_login_tries = max_login_tries

        self._limiter = _ConnLimiter()
        self.store = SessionStore(spool_dir)
        self.shipper = HoneypotShipper(sentinel_server, sentinel_api_key,
                                       honeypot_id, self.store)
        self._host_key = None

    def start(self):
        if not _HAS_PARAMIKO:
            log.error("Cannot start SSH honeypot: paramiko not installed")
            return
        self._host_key = _generate_host_key(self.host_key_path)
        self.shipper.start()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(100)
        log.info("SSH honeypot listening on %s:%d", self.host, self.port)

        while True:
            try:
                conn, addr = srv.accept()
            except Exception as e:
                log.warning("SSH accept error: %s", e)
                break
            if not self._limiter.allow(addr[0]):
                log.info("connection rate limit: dropping %s", addr[0])
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            t = threading.Thread(
                target=_handle_ssh_client_thread,
                args=(conn, addr, self.store, self.honeypot_id,
                      self._host_key, self.max_login_tries, self._limiter),
                daemon=True,
            )
            t.start()


# ---------------------------------------------------------------------------
# HTTP Honeypot
# ---------------------------------------------------------------------------

async def _read_http_request(reader, cap: int = 65536) -> bytes:
    """Read one HTTP request: headers, then the body per Content-Length,
    bounded by cap. The old single read(4096) lost split headers and
    every body past the first chunk."""
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < cap:
        chunk = await asyncio.wait_for(reader.read(8192), timeout=10)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    m = re.search(rb"content-length:\s*(\d+)", head.lower())
    if m:
        want = min(int(m.group(1)), cap - len(rest))
        while len(rest) < want:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=5)
            if not chunk:
                break
            rest += chunk
    return head + b"\r\n\r\n" + rest


class HTTPHoneypot:
    """
    Low-interaction HTTP honeypot.
    Emulates common web application login pages and admin panels,
    captures credentials and payloads, ships to Argus.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 honeypot_id: str = "honeypot-http-01",
                 sentinel_server: str = "http://localhost:8000",
                 sentinel_api_key: str = "argus-dev-key",
                 spool_dir: str = "/tmp/sentinel-honeypot"):
        self.host = host
        self.port = port
        self.honeypot_id = honeypot_id
        self.sentinel_server = sentinel_server.rstrip("/")
        self.sentinel_api_key = sentinel_api_key
        self._limiter = _ConnLimiter()
        self.store = SessionStore(spool_dir)
        self.shipper = HoneypotShipper(sentinel_server, sentinel_api_key,
                                       honeypot_id, self.store)
        self._sessions_by_ip: dict[str, HoneypotSession] = {}

    def start(self):
        self.shipper.start()
        asyncio.run(self._serve())

    async def _serve(self):
        server = await asyncio.start_server(self._handle, self.host, self.port)
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        log.info("HTTP honeypot listening on %s", addrs)
        async with server:
            await server.serve_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername", ("0.0.0.0", 0))
        src_ip, src_port = addr[0], addr[1]
        if not self._limiter.allow(src_ip):
            try:
                writer.write(b"HTTP/1.1 429 Too Many Requests\r\n"
                             b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
            except Exception:
                pass
            return
        sess = self.store.new_session(src_ip, src_port, self.honeypot_id, "http")
        try:
            data = await _read_http_request(reader)
            request = data.decode("utf-8", errors="replace")
            lines = request.split("\r\n")
            req_line = lines[0] if lines else ""
            method, path, *_ = (req_line.split() + ["", ""])[:3]

            # Extract User-Agent and other headers
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    k, v = line.split(": ", 1)
                    headers[k.lower()] = v

            # Extract POST body credentials
            body = ""
            if "\r\n\r\n" in request:
                body = request.split("\r\n\r\n", 1)[1]

            category = self._classify_request(method, path, body)
            cmd_str = f"{method} {path}"
            if body:
                cmd_str += f" body={body[:100]}"
            sess.add_command(cmd_str, "", category)

            # Log any download/probe attempts
            if path.endswith((".php", ".asp", ".aspx", ".jsp", ".cgi")):
                category = "webshell-probe"
                sess.add_command(f"GET {path}", "", "webshell-probe")

            response = self._fake_response(method, path, body, headers, src_ip)
            writer.write(response.encode())
            await writer.drain()

        except asyncio.TimeoutError:
            pass
        except Exception as e:
            log.debug("[%s] HTTP error: %s", sess.id, e)
        finally:
            self.store.close_session(sess)
            self._limiter.release(src_ip)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _classify_request(self, method: str, path: str, body: str) -> str:
        p = path.lower()
        b = body.lower()
        if any(x in p for x in (".php", ".asp", ".jsp", ".cgi")):
            return "webshell-probe"
        if any(x in b for x in ("select ", "union ", "drop ", "insert ", "' or ")):
            return "sqli"
        if any(x in b for x in ("<script", "javascript:", "onerror=", "onload=")):
            return "xss"
        if any(x in p for x in ("/admin", "/wp-login", "/phpmyadmin", "/.env", "/config")):
            return "admin-probe"
        if any(x in p for x in ("/../", "/etc/passwd", "/etc/shadow", "/proc/")):
            return "path-traversal"
        if "username" in b or "password" in b or "passwd" in b or "login" in b:
            return "credential-submission"
        if method == "POST":
            return "post-data"
        return "recon"

    def _fake_response(self, method: str, path: str, body: str,
                       headers: dict, src_ip: str) -> str:
        p = path.lower()
        if p in ("/", "/index.html", "/index.php"):
            html = ("<html><head><title>Login</title></head><body>"
                    "<form method='POST' action='/login'>"
                    "<input name='username'><input name='password' type='password'>"
                    "<input type='submit' value='Login'></form></body></html>")
            return (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    f"Content-Length: {len(html)}\r\n\r\n{html}")
        if p in ("/login", "/wp-login.php"):
            return "HTTP/1.1 302 Found\r\nLocation: /?error=1\r\n\r\n"
        if p.endswith((".php", ".asp", ".aspx")):
            return "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden"
        if p in ("/.env", "/config.php", "/config.yml"):
            return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        return "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sid() -> str:
    return hashlib.sha256(
        f"{time.time_ns()}{os.getpid()}".encode()
    ).hexdigest()[:16]
