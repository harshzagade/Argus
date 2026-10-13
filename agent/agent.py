#!/usr/bin/env python3
"""Argus lightweight Linux agent.

Collectors -> shipper -> server; polls the server for response actions.

  python3 agent.py                      # run with env config
  python3 agent.py --once               # run collectors once, print JSON, exit
  python3 agent.py --dry-run            # log actions instead of executing them

Config via environment (CLI flags override):
  ARGUS_SERVER        server base URL (default http://localhost:8000)
  ARGUS_API_KEY       server API key for ingest (default "argus-dev-key")
  ARGUS_AGENT_ID      agent id (default: hostname)
  ARGUS_AGENT_KEY     per-agent key for the action channel
  ARGUS_BATCH_INTERVAL      seconds between collection cycles (default 5)
  ARGUS_ACTION_INTERVAL     seconds between action polls (default 10)
  ARGUS_FIM_PATHS     comma-separated watch paths
  ARGUS_FIM_INTERVAL  FIM scan cadence seconds (default 30)
  ARGUS_PROC_INTERVAL process scan cadence seconds (default 60)
  ARGUS_NET_INTERVAL  network scan cadence seconds (default 60)
  ARGUS_AUTH_LOG      auth log path (default /var/log/auth.log)
  ARGUS_SYSLOG        syslog path (default /var/log/syslog)
  ARGUS_SPOOL_DIR     disk spool dir (default /tmp/argus-spool)
  ARGUS_FIM_STATE     FIM state file (default <spool>/fim-state.json)
"""

import argparse
import json
import logging
import os
import signal
import socket
import sys
import time

# Allow running as `python3 agent.py` from the agent/ directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from actions import ActionPoller  # noqa: E402
from collectors import auth as auth_mod  # noqa: E402
from collectors import fim as fim_mod  # noqa: E402
from collectors import netstat as netstat_mod  # noqa: E402
from collectors import process as process_mod  # noqa: E402
from collectors import syslog_tail as syslog_mod  # noqa: E402
from shipper import Shipper  # noqa: E402

log = logging.getLogger("argus.agent")

_DEFAULT_FIM_PATHS = "/etc/passwd,/etc/shadow,/etc/ssh/sshd_config,/etc/cron.d,/etc/crontab"


def _env(name, default):
    return os.environ.get(name, default)


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Argus lightweight Linux agent")
    p.add_argument("--server", default=_env("ARGUS_SERVER", "http://localhost:8000"))
    p.add_argument("--api-key", default=_env("ARGUS_API_KEY", "argus-dev-key"))
    p.add_argument("--agent-id", default=_env("ARGUS_AGENT_ID", socket.gethostname()))
    p.add_argument("--agent-key", default=_env("ARGUS_AGENT_KEY", ""))
    p.add_argument("--interval", type=float,
                   default=_env_float("ARGUS_BATCH_INTERVAL", 5),
                   help="seconds between collection cycles")
    p.add_argument("--action-interval", type=float,
                   default=_env_float("ARGUS_ACTION_INTERVAL", 10),
                   help="seconds between action polls")
    p.add_argument("--fim-paths", default=_env("ARGUS_FIM_PATHS", _DEFAULT_FIM_PATHS),
                   help="comma-separated files/dirs to watch")
    p.add_argument("--fim-interval", type=float, default=_env_float("ARGUS_FIM_INTERVAL", 30))
    p.add_argument("--proc-interval", type=float, default=_env_float("ARGUS_PROC_INTERVAL", 60))
    p.add_argument("--net-interval", type=float, default=_env_float("ARGUS_NET_INTERVAL", 60))
    p.add_argument("--auth-log", default=_env("ARGUS_AUTH_LOG", "/var/log/auth.log"))
    p.add_argument("--syslog", default=_env("ARGUS_SYSLOG", "/var/log/syslog"))
    p.add_argument("--spool-dir", default=_env("ARGUS_SPOOL_DIR", "/tmp/argus-spool"))
    p.add_argument("--fim-state", default=_env("ARGUS_FIM_STATE", ""),
                   help="FIM state JSON file (default: <spool-dir>/fim-state.json)")
    p.add_argument("--dry-run", action="store_true",
                   help="log response actions instead of executing them")
    p.add_argument("--once", action="store_true",
                   help="run all collectors once, print events as JSON, exit")
    p.add_argument("--log-level", default=_env("ARGUS_LOG_LEVEL", "INFO"),
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args(argv)


def build_collectors(args, agent_id, hostname):
    fim_state = args.fim_state or os.path.join(args.spool_dir, "fim-state.json")
    fim_paths = [p.strip() for p in args.fim_paths.split(",") if p.strip()]
    return [
        ("auth", auth_mod.AuthCollector(agent_id, hostname, path=args.auth_log)),
        ("syslog", syslog_mod.SyslogCollector(agent_id, hostname, path=args.syslog)),
        ("fim", fim_mod.FimCollector(agent_id, hostname, paths=fim_paths,
                                    state_file=fim_state, interval=args.fim_interval)),
        ("process", process_mod.ProcessCollector(agent_id, hostname,
                                                 interval=args.proc_interval)),
        ("network", netstat_mod.NetstatCollector(agent_id, hostname,
                                                 interval=args.net_interval)),
    ]


def run_once(args):
    """Test mode: run every collector in snapshot mode, print JSON, exit."""
    agent_id = args.agent_id
    hostname = socket.gethostname()
    collectors = build_collectors(args, agent_id, hostname)
    events = []
    for name, collector in collectors:
        try:
            found = collector.collect(snapshot=True)
            log.info("%s: %d events", name, len(found))
            events.extend(found)
        except Exception:
            log.exception("collector %s failed", name)
    json.dump(events, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def run_loop(args):
    agent_id = args.agent_id
    hostname = socket.gethostname()
    if not args.agent_key:
        # Server default: action channel accepts the API key unless a
        # dedicated agent key is configured on both sides.
        args.agent_key = args.api_key
    collectors = build_collectors(args, agent_id, hostname)
    shipper = Shipper(args.server, args.api_key, spool_dir=args.spool_dir)
    poller = ActionPoller(args.server, agent_id, args.agent_key, dry_run=args.dry_run)

    running = {"yes": True}

    def _stop(_signum, _frame):
        log.info("shutdown signal received")
        running["yes"] = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    log.info("agent %s starting (server=%s, interval=%.0fs, dry_run=%s)",
             agent_id, args.server, args.interval, args.dry_run)
    if os.geteuid() != 0:
        log.warning("not running as root: collection works, actions run as DRY-RUN")

    next_action_poll = 0.0
    # Opportunistically drain any spool left by a previous run.
    try:
        shipper.flush()
    except Exception:
        log.exception("initial spool drain failed")

    while running["yes"]:
        cycle_start = time.monotonic()
        events = []
        for name, collector in collectors:
            try:
                events.extend(collector.collect())
            except Exception:
                # A collector must never crash the loop.
                log.exception("collector %s failed", name)
        if events:
            log.debug("collected %d events", len(events))
            shipper.enqueue(events)
        try:
            shipper.flush()
        except Exception:
            log.exception("shipper flush failed")

        now = time.monotonic()
        if now >= next_action_poll:
            try:
                poller.poll()
            except Exception:
                log.exception("action poll failed")
            next_action_poll = now + args.action_interval

        elapsed = time.monotonic() - cycle_start
        time.sleep(max(0.1, args.interval - elapsed))

    # Final flush on shutdown.
    try:
        shipper.flush()
    except Exception:
        log.exception("final flush failed")
    log.info("agent stopped")
    return 0


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        stream=sys.stderr,
    )
    if args.once:
        return run_once(args)
    return run_loop(args)


if __name__ == "__main__":
    sys.exit(main())
