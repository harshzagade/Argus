# Argus Rule Authoring Guide

Detection content lives in `rules/*.yaml`. Each file holds a YAML list of one
or more rule objects. Playbooks live in `playbooks/*.yaml`. See
`docs/ARCHITECTURE.md` for the full contract; this guide covers the day-to-day
workflow.

## Rule anatomy

Every rule needs: `id` (ARG-xxxx, unique), `name`, `description`, `severity`
(critical | high | medium | low), `mitre` (real ATT&CK technique IDs),
`compliance` (real requirement IDs under `pci_dss`, `gdpr`, `nist_800_53`),
`source` (one of `auth`, `syslog`, `fim`, `process`, `network`, `audit`),
`match` (a `all` / `any` / `none` block of conditions), and a `title` with
`{dotted.path}` templating from the triggering event.

Optional but recommended: `group_by` + `threshold: {count, window}` for
count-based rules, `cooldown` (seconds between repeat alerts for one group),
`entities` (dotted fields copied onto the alert), `playbook`
(name of a file in `playbooks/`), and `ai_triage: true`.

Condition operators: `equals`, `not_equals`, `contains`, `not_contains`,
`regex`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `exists`, `startswith`,
`endswith`. Fields use dotted paths: top-level (`agent_id`, `hostname`, `os`,
`ts`, `source`) or source-specific (`event.src_ip`, `event.result`,
`event.cmdline`, ...). Only reference fields that exist for the rule's
`source`; a rule with `source: auth` cannot match on `event.cmdline`.

## Design checklist

1. Pick the narrowest `source` that carries the signal.
2. Prefer `all` (AND) for precision; use `any` (OR) for variant coverage.
3. Add `threshold` + `group_by` whenever one event alone is too noisy
   (brute force, port scans, file churn).
4. Set `cooldown` so a sustained attack yields one alert, not one per minute.
5. Map to real MITRE technique IDs (e.g. T1110.001, not T1110) and real
   compliance IDs (PCI DSS 4.0 like 10.2.4, GDPR Art.32, NIST 800-53 like
   SI-4). Wrong IDs poison the coverage dashboard.
6. Test the regexes against both a malicious and a benign sample before
   committing.

## Worked example 1: failed sudo password attempts

Goal: catch password guessing against sudo on a host.

```yaml
- id: ARG-1101
  name: Sudo password guessing
  description: Three or more failed sudo authentication attempts by one user within ten minutes.
  severity: medium
  mitre: [T1110.001]
  compliance:
    pci_dss: ["8.3.6", "10.2.4"]
    nist_800_53: ["AC-7", "AU-2"]
  source: syslog
  match:
    all:
      - {field: "event.program", equals: "sudo"}
      - {field: "event.message", contains: "authentication failure"}
  group_by: ["agent_id", "event.message"]
  threshold: {count: 3, window: 600}
  cooldown: 1800
  entities: ["event.message"]
  title: "Sudo password guessing on {agent_id}"
  ai_triage: true
```

Why this shape: a single `authentication failure` line is normal user error,
so `threshold` (3 in 600 s) separates guessing from typos. `group_by` keeps
counts per host. `program: sudo` + `contains` is cheaper and more readable
than a regex here.

## Worked example 2: outbound connection to a known C2 port

Goal: flag beaconing to port 4444 (classic Metasploit default).

```yaml
- id: ARG-1102
  name: Outbound connection to port 4444
  description: Outbound traffic to TCP/4444, a port strongly associated with Meterpreter and other C2 frameworks.
  severity: high
  mitre: [T1071]
  compliance:
    pci_dss: ["10.2.4"]
    nist_800_53: ["SC-7", "SI-4"]
  source: network
  match:
    all:
      - {field: "event.direction", equals: "outbound"}
      - {field: "event.dst_port", equals: 4444}
  group_by: ["agent_id", "event.dst_ip"]
  threshold: {count: 3, window: 300}
  cooldown: 3600
  entities: ["event.dst_ip", "event.dst_port"]
  title: "Possible C2 beacon to {event.dst_ip}:4444 from {agent_id}"
  playbook: isolate-host
  ai_triage: true
```

Why this shape: `direction: outbound` excludes inbound scans hitting the port.
`threshold` avoids firing on a single stray packet, and the rule hands off to
the `isolate-host` playbook because a confirmed C2 channel justifies
containment. `dst_port` is numeric in the event schema, so `equals: 4444` is
unquoted.

## Testing a rule

1. Craft 2-4 sample events (one malicious, one benign) matching the event
   schema in `docs/ARCHITECTURE.md`.
2. POST them to `/api/v1/events` and confirm an alert appears at
   `GET /api/v1/alerts?rule_id=ARG-xxxx` only for the malicious ones.
3. Check the title renders (no raw `{...}` left) and the MITRE technique
   shows up under `GET /api/v1/coverage`.
4. If the rule is noisy in practice, raise `threshold.count`, add a
   `not_contains`/`not_in` exclusion, or narrow the regex before widening it.
