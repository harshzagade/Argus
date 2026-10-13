# Argus — 5-minute demo script

A live walkthrough of every "beyond Wazuh" feature. Run the server first:

```bash
cd argus
.venv/bin/uvicorn server.app:app --port 8000   # terminal 1
```

## Act 1 — The attack (2 min)

```bash
.venv/bin/python simulator/simulate.py --all --delay 0.3   # terminal 2
```

Watch the terminal: 7 scenarios, ~90 events, ~16 alerts. Then open
http://localhost:8000 (API key `argus-dev-key`).

Talking points while it replays:
- The agent that would produce these events is ~1,300 lines of stdlib Python —
  no compiled installer, no root needed for collection.

## Act 2 — Beyond flat alerts (1 min)

Open **Incidents**: the 16 alerts are already grouped into ~7 incidents
(brute-force + follow-on login merged into one; webshell chain merged into one).
Wazuh shows a flat alert list — Argus correlates.

Open the SSH incident: note the MITRE tags (T1110.001, T1078), the entities
(IP, user), and the linked alert timeline.

## Act 3 — AI triage + intel (1 min)

Open any alert detail:
- **Enrichment**: the attacker IP is flagged `malicious` with a score — automatic,
  on every alert (AbuseIPDB/VirusTotal/GreyNoise when keys are set, offline mock
  otherwise).
- **AI triage**: plain-English summary, why-it-matters, and remediation steps.
  Backed by an LLM when `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` is set, heuristic
  otherwise — it never fails closed.

## Act 4 — Auto-response (30 sec)

The brute-force playbook already fired: check
`GET /api/v1/agents/web-01/actions` — a `block_ip` action is queued for the
agent, and the SOC got a notification (bell icon / notifications view).
Show `playbooks/block-ssh-bruteforce.yaml` — the whole SOAR flow is 10 lines
of YAML.

## Act 5 — Coverage (30 sec)

Open **Coverage**: 28 MITRE ATT&CK techniques mapped to the 23 rules, each rule
also tagged with PCI DSS 4.0 / GDPR / NIST 800-53 requirements. Close with the
honest slide: prototype, single-node SQLite — for labs and learning, while
Wazuh remains the production choice.

## One-liner reset

```bash
rm argus.db* && .venv/bin/uvicorn server.app:app --port 8000
```
