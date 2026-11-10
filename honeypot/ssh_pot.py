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
        self.login_attempts.append({
            "ts": _now(), "user": user, "password": password,
            "success": success
        })
        if success and not self.success_user:
            self.success_user = user
            self.success_pass = password

    def add_command(self, cmd: str, output: str, category: str):
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

class HoneypotShipper:
    """Converts honeypot sessions to Argus events and ships them."""

    def __init__(self, server: str, api_key: str, honeypot_id: str,
                 store: SessionStore, interval: float = 5.0):
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.honeypot_id = honeypot_id
        self.store = store
        self.interval = interval
        self._thread = threading.Thread(target=self._loop, daemon=True, name="hp-shipper")
        self._stop = threading.Event()

    def start(self):
        self._thread.start()
        log.info("honeypot shipper started -> %s", self.server)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)

    def _loop(self):
        while not self._stop.is_set():
            try:
                sessions = self.store.pop_closed()
                if sessions:
                    events = []
                    for s in sessions:
                        events.extend(self._to_events(s))
                    if events:
                        self._post(events)
            except Exception:
                log.exception("shipper loop error")
            self._stop.wait(self.interval)

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

    def _post(self, events: list[dict]):
        body = json.dumps({"events": events}).encode("utf-8")
        req = urllib.request.Request(
            self.server + "/api/v1/events", data=body,
            headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
            log.info("shipped %d honeypot events -> %s alerts", len(events), data.get("new_alerts", 0))
        except Exception as e:
            log.warning("honeypot ship failed: %s", e)


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
        log.info("[%s] auth attempt %d: %s:%s -> %s",
                 self.sess.id, self._tries, username, password,
                 "success" if success else "failed")
        return paramiko.AUTH_SUCCESSFUL if success else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        import paramiko
        self.sess.add_attempt(username, f"pubkey:{key.get_fingerprint().hex()}", False)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


def _handle_ssh_client_thread(sock, addr, store: SessionStore,
                               honeypot_id: str, host_key,
                               max_login_tries: int):
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
        transport.add_server_key(host_key)
        server_iface = _SSHServerInterface(sess, max_tries=max_login_tries)
        transport.start_server(server=server_iface)

        chan = transport.accept(timeout=20)
        if chan is None:
            log.warning("[%s] no channel opened (client disconnected during auth)", sess.id)
            return

        # Send MOTD
        ts_str = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
        chan.send(MOTD.format(ts=ts_str, ip=src_ip).encode())
        chan.send(b"root@ubuntu-server:~# ")

        buf = b""
        while transport.is_active():
            try:
                data = chan.recv(1024)
            except Exception:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf or b"\r" in buf:
                nl = buf.find(b"\n")
                cr = buf.find(b"\r")
                idx = min(x for x in [nl, cr] if x >= 0)
                line = buf[:idx].decode("utf-8", errors="replace").strip()
                buf = buf[idx + 1:]
                if not line:
                    chan.send(b"\r\nroot@ubuntu-server:~# ")
                    continue
                output, category = emulator.run(line)
                sess.add_command(line, output, category)
                if output:
                    chan.send(f"\r\n{output}\r\n".encode())
                else:
                    chan.send(b"\r\n")
                if category == "exit":
                    chan.send(b"logout\r\n")
                    chan.close()
                    break
                if category == "download":
                    for u in _re.findall(r"https?://[^\s]+", line):
                        sess.add_download(u)
                chan.send(b"root@ubuntu-server:~# ")

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
            t = threading.Thread(
                target=_handle_ssh_client_thread,
                args=(conn, addr, self.store, self.honeypot_id,
                      self._host_key, self.max_login_tries),
                daemon=True,
            )
            t.start()


# ---------------------------------------------------------------------------
# HTTP Honeypot
# ---------------------------------------------------------------------------

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
        sess = self.store.new_session(src_ip, src_port, self.honeypot_id, "http")
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=10)
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
