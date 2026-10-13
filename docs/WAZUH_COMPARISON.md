# Argus vs Wazuh — feature gap analysis

Wazuh is a mature, production-grade platform (50k+ commits). Argus is a
prototype that explores what a greenfield design adds. This table is the
"personalized and updated features" brief: everything in the right column is
either absent from Wazuh or significantly weaker there.

## Detection & triage

| Capability | Wazuh (2026) | Argus |
|---|---|---|
| Signature rules (decoders + rules) | Yes, mature XML ruleset | Yes, YAML rules with the same expressiveness |
| Alert grouping into incidents | No — flat alert stream; analysts group manually | **Yes — correlation engine** (shared entities + 30-min window) |
| Behavioral anomaly detection | Limited (rootcheck anomalies) | **UEBA-lite baselines**: per-user login hours, first-seen binaries, concurrent-IP logins, auth bursts |
| Threat-intel enrichment | Via paid integrations / manual | **Built-in auto-enrichment** on every alert (AbuseIPDB, VirusTotal, GreyNoise; offline mock for labs) |
| Alert explanation | Raw rule description | **AI triage**: summary, why-it-matters, remediation steps (LLM when configured, heuristic fallback) |
| MITRE ATT&CK mapping | Partial (some rules tagged) | **Every rule tagged** + coverage view (technique -> rules) |
| Compliance mapping | Dashboards for PCI/GDPR | **Per-rule requirement tags** (PCI DSS 4.0, GDPR, NIST 800-53) |
| Risk scoring | No asset risk score | **Per-agent risk score** from 7-day alert history |

## Response automation

| Capability | Wazuh | Argus |
|---|---|---|
| Active response | Yes — fixed set (firewall drop, etc.) | **Playbook engine**: YAML multi-step playbooks (block, quarantine, isolate, run, webhook, notify) triggered per rule or severity |
| SOAR integration | External (Shuffle etc.) | Playbooks + webhooks built in |
| One-click containment from UI | No | Enqueue agent actions from the dashboard API |

## Platform & operations

| Capability | Wazuh | Argus |
|---|---|---|
| Agent | C agent, full installer | **Stdlib-only Python agent** (~600 lines), runs without root for collection |
| Backend store | OpenSearch/Elasticsearch cluster | **Single SQLite file** — zero-ops for labs |
| Dashboard updates | Polling | **WebSocket live feed** |
| API style | REST (mature) | REST + WebSocket, OpenAPI via FastAPI |
| Rule language | XML | **YAML** with `all/any/none`, 14 operators, field references, templating |

## Honest limitations of Argus (prototype)

- Single node; no clustering, no multi-tenancy.
- SQLite caps out at modest event volumes (fine for labs, not for 10k EPS).
- Anomaly baselines are heuristic, not ML models.
- Agent collectors are Linux-focused; Windows/macOS coverage is minimal.
- No long-term rule QA like Wazuh's ruleset team; expect tuning.

## When to choose which

- **Learn / demo / small lab / showcase project**: Argus — runs in one
  container, attack simulator included, modern UX.
- **Production enterprise SOC**: Wazuh — battle-tested scale, huge
  community ruleset, compliance certifications.
