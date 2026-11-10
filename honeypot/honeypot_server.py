#!/usr/bin/env python3
"""Argus Honeypot runner — starts SSH + HTTP honeypots in threads.

Usage:
    python honeypot_server.py
    python honeypot_server.py --ssh-port 2222 --http-port 8080

Config via environment:
    ARGUS_SERVER            Argus server base URL (default http://localhost:8000)
    ARGUS_API_KEY           API key (default argus-dev-key)
    ARGUS_HONEYPOT_ID       Agent ID reported to Argus (default honeypot-01)
    HONEYPOT_SSH_PORT       SSH listen port (default 2222)
    HONEYPOT_HTTP_PORT      HTTP listen port (default 8080)
    HONEYPOT_HOST           Bind address (default 0.0.0.0)
    HONEYPOT_SPOOL_DIR      Spool directory (default /tmp/sentinel-honeypot)
    HONEYPOT_MAX_LOGIN_TRIES Attempts before accepting (default 3)
"""

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path

# Ensure project root is on sys.path so `honeypot` package is importable
# whether this file is run directly or as `python -m honeypot.honeypot_server`.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

log = logging.getLogger("sentinel.honeypot")


def _env(k, default):
    return os.environ.get(k, default)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Argus honeypot runner")
    p.add_argument("--server", default=_env("ARGUS_SERVER", _env("SENTINEL_SERVER", "http://localhost:8000")))
    p.add_argument("--api-key", default=_env("ARGUS_API_KEY", _env("SENTINEL_API_KEY", "argus-dev-key")))
    p.add_argument("--honeypot-id", default=_env("ARGUS_HONEYPOT_ID", _env("SENTINEL_HONEYPOT_ID", "honeypot-01")))
    p.add_argument("--ssh-port", type=int, default=int(_env("HONEYPOT_SSH_PORT", "2222")))
    p.add_argument("--http-port", type=int, default=int(_env("HONEYPOT_HTTP_PORT", "8080")))
    p.add_argument("--host", default=_env("HONEYPOT_HOST", "0.0.0.0"))
    p.add_argument("--spool-dir", default=_env("HONEYPOT_SPOOL_DIR", "/tmp/sentinel-honeypot"))
    p.add_argument("--max-login-tries", type=int,
                   default=int(_env("HONEYPOT_MAX_LOGIN_TRIES", "3")))
    p.add_argument("--no-ssh", action="store_true", help="Disable SSH honeypot")
    p.add_argument("--no-http", action="store_true", help="Disable HTTP honeypot")
    p.add_argument("--log-level", default=_env("HONEYPOT_LOG_LEVEL", "INFO"),
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,
    )

    from honeypot.ssh_pot import SSHHoneypot, HTTPHoneypot

    threads = []
    stop_event = threading.Event()

    if not args.no_http:
        http_pot = HTTPHoneypot(
            host=args.host,
            port=args.http_port,
            honeypot_id=f"{args.honeypot_id}-http",
            sentinel_server=args.server,
            sentinel_api_key=args.api_key,
            spool_dir=args.spool_dir,
        )
        t = threading.Thread(target=http_pot.start, name="http-honeypot", daemon=True)
        t.start()
        threads.append(t)
        log.info("HTTP honeypot started on %s:%d", args.host, args.http_port)

    if not args.no_ssh:
        ssh_pot = SSHHoneypot(
            host=args.host,
            port=args.ssh_port,
            honeypot_id=f"{args.honeypot_id}-ssh",
            host_key_path=f"{args.spool_dir}/host-key",
            sentinel_server=args.server,
            sentinel_api_key=args.api_key,
            spool_dir=args.spool_dir,
            max_login_tries=args.max_login_tries,
        )
        t = threading.Thread(target=ssh_pot.start, name="ssh-honeypot", daemon=True)
        t.start()
        threads.append(t)
        log.info("SSH honeypot started on %s:%d", args.host, args.ssh_port)

    log.info("Argus honeypot running. Press Ctrl+C to stop.")

    def _stop(sig, frame):
        log.info("shutdown signal received")
        stop_event.set()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    stop_event.wait()
    log.info("honeypot stopped")


if __name__ == "__main__":
    main()
