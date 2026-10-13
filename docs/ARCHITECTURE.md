# Argus — Architecture & Contracts

Argus is a next-gen open SIEM/XDR prototype: a lightweight, modern alternative to
Wazuh with features Wazuh lacks natively: incident correlation, UEBA-lite anomaly
baselines, threat-intel auto-enrichment, AI alert triage, SOAR-lite playbooks,
MITRE ATT&CK coverage view, and a real-time WebSocket dashboard.

## Components

```
agent/        Python lightweight agent: collectors -> shipper -> server; polls actions
server/       FastAPI: ingest, rule engine, correlation, anomaly, enrich, triage, playbooks
dashboard/    Single-page app (static, served by server at /)
rules/        YAML detection rules (ARG-xxxx)
playbooks/    YAML automated-response playbooks
simulator/    Attack-scenario replay script (demo data generator)
docs/         README, comparison vs Wazuh, rule-authoring guide
```

## Event schema (agent -> server)

POST /api/v1/events  body: {"events": [event, ...]}
Header: X-API-Key: <server API key>

event:
{
  "agent_id": "web-01",            # required
  "hostname": "web-01",            # required
  "os": "linux",                   # linux | windows | macos
  "ts": "2026-09-24T17:05:00+05:30",  # ISO8601; server fills now() if absent
  "source": "auth",                # auth | syslog | fim | process | network | audit
  "event": { ... },                # source-specific fields (flat-ish JSON)
  "raw": "original log line"       # optional
}

Source field reference:
- auth:    {service: sshd|sudo|login, user, src_ip, src_port, result: success|failed, port}
- syslog:  {program, level, facility, message}
- fim:     {path, action: created|modified|deleted, sha256, user, size}
- process:{pid, ppid, exe, cmdline, user, action: started|stopped}
- network:{proto, src_ip, src_port, dst_ip, dst_port, direction: inbound|outbound, action: allowed|blocked, bytes}
- audit:   {type, ...free-form}

Field access in rules uses dotted paths, e.g. "event.src_ip", "event.result".
Top-level fields: agent_id, hostname, os, ts, source, raw.

## Rule schema (rules/*.yaml)

```yaml
- id: ARG-1001
  name: SSH brute force
  description: Multiple failed SSH logins from one source IP.
  severity: high                 # critical | high | medium | low
  mitre: [T1110.001]             # ATT&CK technique IDs
  compliance:                    # requirement IDs the rule evidences
    pci_dss: ["8.3.6", "10.2.4"]
    gdpr: ["Art.32"]
  source: auth                   # event source this rule evaluates
  match:                         # all | any | none -> list of conditions
    all:
      - {field: "event.service", equals: "sshd"}
      - {field: "event.result", equals: "failed"}
  group_by: ["agent_id", "event.src_ip"]   # for threshold counting
  threshold: {count: 5, window: 300}       # N matches in W seconds; omit = fire per event
  cooldown: 600                  # min seconds between alerts for same group (omit = 0)
  entities: ["event.src_ip", "event.user"]  # extracted entity fields
  title: "SSH brute force from {event.src_ip} against {agent_id}"
  playbook: block-ssh-bruteforce # optional playbooks/<name>.yaml
  ai_triage: true                # generate AI/plain-English triage for this alert
```

Condition operators: equals, not_equals, contains, not_contains, regex,
in (list), not_in, gt, gte, lt, lte, exists (bool), startswith, endswith.
Values may reference other fields with "$field.path".

Title/description support {dotted.path} templating from the triggering event(s).

## Alert schema (server-produced)

{
  "id": "uuid", "ts": iso, "rule_id": "ARG-1001", "rule_name": "...",
  "severity": "high", "agent_id": "web-01", "hostname": "web-01",
  "title": "...", "description": "...",
  "mitre": ["T1110.001"], "compliance": {"pci_dss": [...]},
  "entities": {"src_ip": "1.2.3.4", "user": "root"},
  "event_ids": ["uuid", ...], "event_count": 5,
  "enrichment": {"src_ip": {"reputation": "malicious", "source": "mock", ...}},
  "triage": {"summary": "...", "why_it_matters": "...",
             "remediation": ["..."], "confidence": "high"}
}

## Incident schema (correlation output)

{
  "id": "uuid", "title": "...", "severity": "high",
  "status": "open|acknowledged|closed",
  "created": iso, "updated": iso,
  "agents": ["web-01"], "alert_ids": ["..."],
  "entities": {"src_ip": [...], "user": [...]},
  "mitre": ["T1110.001", ...],
  "triage_summary": "..."
}

Correlation: alerts sharing (agent_id + any entity value) within 30 min join
one incident. Incident severity = max(alert severities).

## Server REST API (FastAPI, base /api/v1)

- POST /events                ingest batch {"events": [...]} -> {"accepted": n}
- GET  /alerts                ?severity=&rule_id=&agent_id=&limit=100&since=iso
- GET  /alerts/{id}
- GET  /incidents              ?status=open&limit=100
- GET  /incidents/{id}         detail + alerts + timeline
- POST /incidents/{id}/ack    {"note": "..."} | POST /incidents/{id}/close
- GET  /agents                 inventory: id, hostname, os, last_seen, risk_score, version
- POST /agents/{id}/actions    enqueue action -> {"action_id": ...}
- GET  /agents/{id}/actions    agent long-polls pending actions (agent auth: X-Agent-Key)
- POST /agents/{id}/actions/{action_id}/ack  {"status": "done|failed", "output": "..."}
- GET  /stats                  counts, alerts by severity/rule, top MITRE, agents online
- GET  /coverage               MITRE technique -> rules covering it
- WS   /ws/feed                live JSON frames: {"type":"alert"|"incident"|"event"|"agent", ...}

Auth: X-API-Key header for ingest/query (single server key via ARGUS_API_KEY env).
Agent action channel uses X-Agent-Key: per-agent key (ARGUS_AGENT_KEY_<id> or shared).

## Agent action schema (server -> agent)

{"action_id": "uuid", "action": "block_ip|unblock_ip|quarantine|isolate|run",
 "params": {"ip": "1.2.3.4"} | {"path": "/tmp/x"} | {"command": "..."} | {}}

Agent executes with least privilege available and acks with output.
Playbooks may enqueue these automatically.

## Config (env)

- ARGUS_API_KEY        server API key (default "argus-dev-key" for local demo)
- ARGUS_DB             sqlite path (default ./argus.db)
- ARGUS_RULES_DIR      default ./rules
- ARGUS_PLAYBOOKS_DIR  default ./playbooks
- ANTHROPIC_API_KEY / OPENAI_API_KEY   optional: real LLM triage; else heuristic
- ABUSEIPDB_KEY / VT_KEY / GREYNOISE_KEY  optional: real intel; else mock/offline

## Ports

- 8000: server (REST + WS + dashboard static)

## Naming

- Project: Argus. Rule IDs: ARG-xxxx. Playbook files: playbooks/<name>.yaml.
