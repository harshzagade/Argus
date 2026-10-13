# Argus Agent

Lightweight Linux agent for the Argus SIEM prototype. Collects security
telemetry, ships it to the server, and executes response actions polled from
the server. Pure Python 3.10+, standard library only.

## Install

No dependencies to install. Needs Python 3.10+ on Linux.

```bash
cd ~/workspace/argus/agent
chmod +x agent.py
python3 agent.py --once        # smoke test: print one collection pass as JSON
```

## Run

```bash
# Foreground (collection works without root; actions become dry-run)
python3 agent.py

# With explicit config
ARGUS_SERVER=http://192.0.2.10:8000 \
ARGUS_API_KEY=secret-ingest-key \
ARGUS_AGENT_ID=web-01 \
ARGUS_AGENT_KEY=secret-agent-key \
python3 agent.py

# Dry-run response actions (log only, never execute)
python3 agent.py --dry-run

# As a service (example systemd unit fragment)
# ExecStart=/usr/bin/python3 /opt/argus/agent/agent.py
# Restart=always
```

## Flags / environment

| Flag | Env | Default | Purpose |
|---|---|---|---|
| `--server` | `ARGUS_SERVER` | `http://localhost:8000` | Server base URL |
| `--api-key` | `ARGUS_API_KEY` | `argus-dev-key` | `X-API-Key` for event ingest |
| `--agent-id` | `ARGUS_AGENT_ID` | hostname | Agent identity |
| `--agent-key` | `ARGUS_AGENT_KEY` | (empty) | `X-Agent-Key` for action channel |
| `--interval` | `ARGUS_BATCH_INTERVAL` | `5` | Seconds between collection cycles |
| `--action-interval` | `ARGUS_ACTION_INTERVAL` | `10` | Seconds between action polls |
| `--fim-paths` | `ARGUS_FIM_PATHS` | `/etc/passwd,/etc/shadow,/etc/ssh/sshd_config,/etc/cron.d,/etc/crontab` | FIM watch list (comma-separated) |
| `--fim-interval` | `ARGUS_FIM_INTERVAL` | `30` | FIM scan cadence (s) |
| `--proc-interval` | `ARGUS_PROC_INTERVAL` | `60` | Process scan cadence (s) |
| `--net-interval` | `ARGUS_NET_INTERVAL` | `60` | Network scan cadence (s) |
| `--auth-log` | `ARGUS_AUTH_LOG` | `/var/log/auth.log` | Auth log path (e.g. `/var/log/secure` on RHEL) |
| `--syslog` | `ARGUS_SYSLOG` | `/var/log/syslog` | Syslog path |
| `--spool-dir` | `ARGUS_SPOOL_DIR` | `/tmp/argus-spool` | Disk spool dir + FIM state home |
| `--fim-state` | `ARGUS_FIM_STATE` | `<spool>/fim-state.json` | FIM baseline state file |
| `--dry-run` | - | off | Log actions instead of executing |
| `--once` | - | off | Collect once, print JSON, exit (testing) |
| `--log-level` | `ARGUS_LOG_LEVEL` | `INFO` | DEBUG/INFO/WARNING/ERROR |

CLI flags override environment variables.

## What it collects

| Source | Collector | Cadence | Notes |
|---|---|---|---|
| `auth` | `collectors/auth.py` | every cycle (tail) | sshd Accepted/Failed password, sudo COMMAND (and sudoers denials), useradd new users, su success/failure. Missing log file: warning, continues. |
| `syslog` | `collectors/syslog_tail.py` | every cycle (tail) | Generic `program`/`level`/`message`; level is a best-effort keyword guess (error/warning/info). |
| `fim` | `collectors/fim.py` | 30 s | sha256 of watched files/dirs; emits `created`/`modified`/`deleted` with sha256, size, owner. Baseline is established silently on first run; state persists in `<spool>/fim-state.json`. Unreadable files (e.g. `/etc/shadow` without root) are skipped with a warning. |
| `process` | `collectors/process.py` | 60 s | New PIDs since last snapshot via `/proc`: pid, ppid, exe, cmdline, user, `action: started`. Baseline silent on first run. |
| `network` | `collectors/netstat.py` | 60 s | New outbound TCP connections from `/proc/net/tcp`+`tcp6`: proto, src/dst ip/port, `direction: outbound`. Outbound = local port in ephemeral range (>= 32768); loopback and listeners skipped. Baseline silent on first run. |

All events follow the ARCHITECTURE.md envelope
(`agent_id`, `hostname`, `os: linux`, ISO8601 `ts` with timezone, `source`,
`event`, `raw`). A failing collector is logged and skipped; the loop never
crashes on a collector exception.

## Response actions

Every 10 s the agent GETs `/api/v1/agents/{id}/actions` (auth: `X-Agent-Key`)
and acks each result to `.../actions/{action_id}/ack` with
`{"status": "done|failed", "output": "..."}`.

| Action | Params | Effect |
|---|---|---|
| `block_ip` | `{"ip": "1.2.3.4"}` | `iptables -A INPUT -s IP -j DROP` (IP validated) |
| `unblock_ip` | `{"ip": "1.2.3.4"}` | `iptables -D INPUT -s IP -j DROP` |
| `quarantine` | `{"path": "/tmp/x"}` | `chmod 000` + move to `/tmp/argus-quarantine/`; refuses paths under `/bin /sbin /usr /etc /lib /boot /dev /proc /sys` |
| `isolate` | `{}` | Appends OUTPUT rules: allow ESTABLISHED, allow server IP, DROP the rest (new outbound only). Appends, so guard against repeats in playbooks. |
| `run` | `{"command": "..."}` | Subprocess with 60 s timeout; stdout+stderr captured (capped at 4 KB in the ack) |

## Privileges

- **Collection** works without root (FIM may skip root-only files like
  `/etc/shadow`; `/proc` reads of other users' processes degrade gracefully).
- **Actions** execute for real only as root. As non-root, or with `--dry-run`,
  every action is logged as `DRY-RUN` and acked `done` without executing.
- For full capability, run as root (or via systemd); for safe testing, use
  `--dry-run`.

## Offline behavior

If the server is unreachable, events are spooled as JSONL files in
`/tmp/argus-spool/` and retried with exponential backoff (2 s, 4 s, 8 s, ...
capped at 300 s). On recovery, spool files drain oldest-first, then the live
buffer ships. HTTP 4xx responses are logged and dropped (retrying won't help).
