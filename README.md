# Argus — Unified Open-Source Cybersecurity Ecosystem

Argus is a full-stack, open-source cybersecurity platform built by combining three high-impact GitHub projects into one unified ecosystem:

| Component | Inspired by | Stars | What it does |
|---|---|---|---|
| **Argus SIEM/XDR** | (this repo) | — | Rule engine, UEBA, AI triage, SOAR playbooks, incident correlation |
| **Honeypot** | [Cowrie](https://github.com/cowrie/cowrie) | ~6k ⭐ | SSH + HTTP deception sensors, attacker session capture |
| **Threat Intel** | [MISP](https://github.com/MISP/MISP) | ~5k ⭐ | IOC database, feed ingestion, STIX export, enrichment API |

Everything runs on a **single port (8000)** — one dashboard, one API key, one Docker command.

```
argus/
├── server/          Argus SIEM/XDR — FastAPI, rule engine, SOAR, WebSocket
│   └── argus_app.py   ← unified entry point (mounts SIEM + TI)
├── honeypot/        Cowrie-inspired SSH/HTTP deception sensors
│   ├── ssh_pot.py       medium-interaction SSH honeypot (paramiko)
│   └── honeypot_server.py
├── threatintel/     MISP-inspired Threat Intelligence Platform
│   ├── db.py            IOC store (SQLite): iocs, events, feeds, tags
│   ├── feeds.py         Feed runner + scheduler (txt/csv/json/STIX/MISP)
│   └── app.py           FastAPI REST API for TI
├── rules/           YAML detections (ARG-1001 to ARG-1036, 36 total)
│   └── arg-1029-*.yaml  8 new honeypot-specific rules
├── playbooks/       SOAR automated response
│   ├── auto-block-honeypot-attacker.yaml  ← new
│   ├── honeypot-c2-response.yaml          ← new
│   └── ti-enriched-block.yaml            ← new
├── dashboard/       Real-time SOC dashboard (vanilla JS, no framework)
│   ├── index.html       + Honeypot + Threat Intel views
│   └── app.js           + all Argus-specific JS
├── simulator/       Attack scenario replay (+ honeypot + TI scenarios)
└── docker-compose.yml   argus + honeypot + simulator services
```

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         Argus Dashboard (port 8000)   │
                    │  Overview · Alerts · Cases · Devices     │
                    │  Coverage · Rules · Honeypots · ThreatIntel│
                    └──────────────┬──────────────────────────┘
                                   │ REST + WebSocket
              ┌────────────────────┼──────────────────┐
              │                    │                  │
    ┌─────────▼──────┐  ┌──────────▼────────┐  ┌─────▼──────────────────┐
    │  Argus SIEM/XDR│  │  Threat Intel      │  │  Argus Honeypot     │
    │  /api/v1/*     │  │  /api/ti/v1/*      │  │  port 2222 (SSH)       │
    │                │  │                    │  │  port 8080 (HTTP)      │
    │  Rule engine   │  │  IOC database      │  │                        │
    │  UEBA baselines│◄─┤  Feed ingestion    │  │  Fake shell emulator   │
    │  AI triage     │  │  STIX/MISP export  │  │  Session recorder      │
    │  Correlation   │  │  Enrichment bridge │  │  HoneypotShipper       │
    │  Playbooks     │  │  (5 default feeds) │  │  ships events to SIEM  │
    └────────┬───────┘  └────────────────────┘  └────────────────────────┘
             │ enrich()
             └──► Argus TI first, then AbuseIPDB/VT/GreyNoise/mock
```

**Data flow:**
1. Argus agents (Linux) + Honeypot sensors ship events → `POST /api/v1/events`
2. Rule engine + UEBA baselines fire alerts
3. Enrichment queries **Argus TI first** (local IOC DB), then external APIs
4. AI triage (Claude / GPT / heuristic) explains each alert
5. Correlation groups alerts → incidents
6. Playbooks auto-respond (block IP, quarantine, isolate, notify, webhook)
7. Dashboard shows everything live over WebSocket

---

## Quickstart (local)

```bash
# 1. Install dependencies
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Start the Argus server (SIEM + TI on port 8000)
.venv/bin/uvicorn server.argus_app:app --port 8000

# 3. (Optional) Start the honeypot in another terminal
.venv/bin/python -m honeypot.honeypot_server \
  --server http://localhost:8000 \
  --api-key argus-dev-key \
  --ssh-port 2222 --http-port 8080

# 4. Replay all attack scenarios (including honeypot + TI seeding)
.venv/bin/python simulator/simulate.py --all

# 5. Open http://localhost:8000  →  dashboard with all 8 views
```

API key: `argus-dev-key` (enter once in the dashboard settings modal).

---

## Quickstart (Docker — all three components)

```bash
# Full stack: Argus + Honeypot
docker compose up --build -d

# Ports:
#   8000 → Argus dashboard + REST API
#   2222 → SSH honeypot (try: ssh root@localhost -p 2222)
#   8080 → HTTP honeypot (try: curl http://localhost:8080/wp-login.php)

# With attack scenarios demo:
docker compose --profile demo up simulator
```

---

## Argus Threat Intel Platform

The TI platform is a lightweight MISP-inspired IOC management system.

### Pre-configured feeds (auto-run every hour)
| Feed | Type | Format |
|---|---|---|
| Feodo Tracker C2 | IP | txt |
| URLhaus Malware URLs | URL | txt |
| OpenPhish Phishing URLs | URL | txt |
| Emerging Threats Compromised IPs | IP | txt |
| MISP Warning Lists | CIDR | JSON |

### API highlights
```bash
# Look up an IOC
curl -H "X-API-Key: argus-dev-key" \
  -d '{"values":["203.0.113.5","evil.example.com"]}' \
  -H "Content-Type: application/json" \
  http://localhost:8000/api/ti/v1/iocs/lookup

# Trigger all feed syncs
curl -X POST -H "X-API-Key: argus-dev-key" \
  http://localhost:8000/api/ti/v1/feeds/run-all

# Export all malicious IOCs as STIX 2.1
curl -H "X-API-Key: argus-dev-key" \
  "http://localhost:8000/api/ti/v1/export/stix?reputation=malicious"

# Export as CSV
curl -H "X-API-Key: argus-dev-key" \
  "http://localhost:8000/api/ti/v1/export/csv" -o iocs.csv
```

---

## Argus Honeypot

The honeypot is a medium-interaction deception sensor inspired by Cowrie.

### SSH honeypot
- Accepts any credential after `N` failed attempts (N = `HONEYPOT_MAX_LOGIN_TRIES`, default 3)
- Emulates a realistic Ubuntu bash shell with fake filesystem, `ls`, `cat`, `ps`, `id`, `uname`, `wget`, `curl`, `nc`, `python3`, `crontab`, etc.
- Logs every command with session ID, timestamps, and intent category (`recon`, `c2`, `download`, `persistence`, `privesc`, `evasion`)
- Captures download URLs as live IOCs
- Ships all sessions as structured events to the Argus ingest endpoint

### HTTP honeypot
- Low-interaction web server emulating login pages, `/wp-login.php`, `/admin`, `/.env`
- Classifies requests: `credential-submission`, `sqli`, `xss`, `webshell-probe`, `path-traversal`, `admin-probe`
- Ships per-request events

### Honeypot detection rules (8 new rules: ARG-1029 to ARG-1036)
| Rule | Severity | What it detects |
|---|---|---|
| ARG-1029 | **Critical** | Successful honeypot login (zero FP) |
| ARG-1030 | **Critical** | Reverse shell / C2 attempt on honeypot |
| ARG-1031 | High | Recon command burst (>10 in 5 min) |
| ARG-1032 | **Critical** | Payload download from honeypot |
| ARG-1033 | High | Persistence attempt (cron/keys/useradd) |
| ARG-1034 | Medium | HTTP credential stuffing burst |
| ARG-1035 | Medium | SQL injection probe burst |
| ARG-1036 | Medium | Path traversal / LFI probe |

---

## New playbooks

| Playbook | Trigger | Response |
|---|---|---|
| `auto-block-honeypot-attacker` | ARG-1029 | Block attacker IP + SOC notify |
| `honeypot-c2-response` | ARG-1030 | Block IP + SOC notify with command evidence |
| `ti-enriched-block` | Any critical | Block IP + SOC notify |

---

## Full API reference

### Argus SIEM/XDR (`/api/v1/*`)
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full contract.

### Argus TI (`/api/ti/v1/*`)
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/ti/v1/health` | Health check |
| GET | `/api/ti/v1/stats` | IOC counts by type/reputation/source |
| GET | `/api/ti/v1/iocs` | List IOCs with filters |
| POST | `/api/ti/v1/iocs` | Add single IOC |
| POST | `/api/ti/v1/iocs/bulk` | Add many IOCs |
| POST | `/api/ti/v1/iocs/lookup` | Look up values |
| DELETE | `/api/ti/v1/iocs/{id}` | Revoke IOC |
| GET | `/api/ti/v1/events` | Threat events |
| POST | `/api/ti/v1/events` | Create threat event |
| GET | `/api/ti/v1/events/{id}` | Event detail + IOCs |
| POST | `/api/ti/v1/events/{id}/publish` | Publish event |
| GET | `/api/ti/v1/feeds` | List feeds |
| POST | `/api/ti/v1/feeds` | Add feed |
| POST | `/api/ti/v1/feeds/{id}/run` | Trigger feed run |
| GET | `/api/ti/v1/feeds/{id}/runs` | Feed run history |
| POST | `/api/ti/v1/feeds/run-all` | Sync all feeds now |
| GET | `/api/ti/v1/tags` | List tags |
| GET | `/api/ti/v1/export/csv` | Export IOCs as CSV |
| GET | `/api/ti/v1/export/stix` | Export IOCs as STIX 2.1 |
| POST | `/api/ti/v1/enrich` | Enrichment bridge for Argus |

### Argus health (`/api/argus/*`)
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/argus/health` | All-component health check |

---

## What's in the detection pack (36 rules)

```
ARG-1001  SSH brute force                    high
ARG-1002  SSH login after brute force        critical
ARG-1003  Sudo shell escalation              high
ARG-1004  Sudoers file modified              high
ARG-1005  New user created                   medium
ARG-1006  Webshell one-liner                 critical
ARG-1007  Reverse shell pattern              critical
ARG-1008  Executable in /tmp                 high
ARG-1009  Credential store modified          high
ARG-1010  sshd_config changed                high
ARG-1011  Cron persistence                   high
ARG-1012  Outbound rare port                 medium
ARG-1013  Large outbound transfer            high
ARG-1014  DNS tunneling                      high
ARG-1015  auditd disabled                    critical
ARG-1016  Logs cleared                       critical
ARG-1017  Kernel module load                 high
ARG-1018  Docker socket escape               critical
ARG-1019  Mimikatz keywords                  critical
ARG-1020  Ransomware burst                   critical
ARG-1021  su to root                         medium
ARG-1022  systemd persistence                high
ARG-1023  authorized_keys changed            high
ARG-1024  SSH password spraying              high
ARG-1025  systemd timer persistence          high
ARG-1026  Webshell user shell                critical
ARG-1027  hosts file modified                medium
ARG-1028  SSH unusual hour                   medium
ARG-1029  Honeypot successful login          critical  ← new
ARG-1030  Honeypot reverse shell / C2        critical  ← new
ARG-1031  Honeypot recon burst               high      ← new
ARG-1032  Honeypot malware download          critical  ← new
ARG-1033  Honeypot persistence attempt       high      ← new
ARG-1034  HTTP honeypot credential burst     medium    ← new
ARG-1035  HTTP honeypot SQLi probe           medium    ← new
ARG-1036  HTTP honeypot path traversal       medium    ← new
ARG-9001  Concurrent logins distinct IPs     high      (UEBA)
ARG-9002  First-seen binary suspicious dir   high      (UEBA)
ARG-9003  Login at unusual hour              medium    (UEBA)
ARG-9004  Authentication failure burst       high      (UEBA)
```

---

## Configuration reference

| Variable | Default | Purpose |
|---|---|---|
| `ARGUS_API_KEY` | `argus-dev-key` | Shared API key for SIEM |
| `ARGUS_DB` | `./argus.db` | SIEM SQLite database |
| `ARGUS_API_KEY` | same as ARGUS_API_KEY | TI platform API key |
| `ARGUS_TI_DB` | `./argus-ti.db` | TI SQLite database |
| `ARGUS_TI_URL` | _(empty)_ | If set, enrichment queries this TI URL first |
| `ARGUS_TI_FEED_INTERVAL` | `3600` | Seconds between feed refreshes |
| `ANTHROPIC_API_KEY` | _(empty)_ | Claude for AI alert triage |
| `OPENAI_API_KEY` | _(empty)_ | GPT-4o-mini fallback triage |
| `ABUSEIPDB_KEY` | _(empty)_ | AbuseIPDB enrichment |
| `VT_KEY` | _(empty)_ | VirusTotal enrichment |
| `HONEYPOT_SSH_PORT` | `2222` | SSH honeypot port |
| `HONEYPOT_HTTP_PORT` | `8080` | HTTP honeypot port |
| `HONEYPOT_MAX_LOGIN_TRIES` | `3` | Auth attempts before accepting |

---

## Tests

```bash
.venv/bin/python -m pytest tests/ -q
```

---

## Project layout

```
docs/
  ARCHITECTURE.md    — event/alert/incident/playbook schemas (Argus)
  AGENT.md           — agent install and configuration
  RULE_AUTHORING.md  — write your own YAML detection rules
  WAZUH_COMPARISON.md — feature gap vs Wazuh
```
