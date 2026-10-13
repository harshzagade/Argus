"""AI alert triage. Uses an LLM (Anthropic/OpenAI) when keys are configured,
otherwise a heuristic explainer grounded in MITRE technique knowledge."""
import json
import os
import urllib.request

MITRE_INFO = {
    "T1110": ("Brute Force", "Attackers guessing credentials suggest exposed services and weak lockout policy.",
              ["Enforce account lockout / rate limiting on the exposed service",
               "Require MFA for all remote access", "Block the source IP at the perimeter"]),
    "T1110.001": ("Password Guessing", "Repeated password guesses indicate an active credential attack.",
              ["Block the source IP", "Force password reset for targeted accounts", "Enable MFA"]),
    "T1059": ("Command and Scripting Interpreter", "Script interpreters are the top LOLBin for payload execution.",
              ["Isolate the host and capture the script payload", "Review command history for the user",
               "Block the interpreter's network egress if unjustified"]),
    "T1078": ("Valid Accounts", "Use of legitimate credentials is hard to detect and implies prior compromise.",
              ["Force credential rotation for the account", "Review how the credential was obtained",
               "Check for persistence mechanisms on the host"]),
    "T1547.001": ("Registry/Startup Persistence", "Persistence means the attacker plans to return.",
              ["Remove the persistence artifact", "Hunt for the same artifact fleet-wide",
               "Reimage if root-level persistence is confirmed"]),
    "T1003": ("Credential Dumping", "Credential theft enables lateral movement across the estate.",
              ["Isolate the host immediately", "Reset credentials for accounts present in memory",
               "Enable Credential Guard / LSA protection"]),
    "T1048": ("Exfiltration Over Alternative Protocol", "Data leaving over odd channels suggests active exfiltration.",
              ["Block the destination at the egress point", "Identify what data was accessed",
               "Review DLP coverage for the data type"]),
    "T1070.004": ("File Deletion / Log Tampering", "Clearing logs is anti-forensics: assume the worst about intent.",
              ["Preserve remaining logs immediately", "Correlate with other alerts in the window",
               "Restore tamper protection on logging"]),
    "T1053": ("Scheduled Task/Job", "Scheduled tasks are a classic persistence and execution vector.",
              ["Inspect and remove the malicious task", "Trace the task creator process",
               "Audit scheduled tasks fleet-wide"]),
    "T1136": ("Create Account", "New accounts outside change control are a persistence red flag.",
              ["Disable the account pending review", "Confirm with the change owner",
               "Review account creation logs for siblings"]),
    "T1562": ("Impair Defenses", "Disabling defenses precedes destructive or stealthy action.",
              ["Re-enable the defense control", "Treat the host as potentially compromised",
               "Alert on defense-disable attempts fleet-wide"]),
    "T1021": ("Remote Services", "Abuse of remote services enables lateral movement.",
              ["Verify the session is legitimate", "Restrict remote service exposure",
               "Require MFA / jump-host for remote access"]),
    "T1486": ("Data Encrypted for Impact", "Mass encryption is the ransomware endgame.",
              ["Isolate affected hosts NOW", "Activate the ransomware playbook",
               "Do NOT pay before engaging IR leadership"]),
}


def _heuristic(alert, enrichment):
    mitre = (alert.get("mitre") or [None])[0]
    name, why, remediation = MITRE_INFO.get(mitre, (
        "Suspicious activity",
        "The observed behavior deviates from the expected baseline for this asset.",
        ["Investigate the entities involved", "Contain the asset if malicious intent is confirmed",
         "Tune the detection if this is benign in your environment"]))
    intel_bits = []
    worst = None
    for ename, intel in (enrichment or {}).items():
        rep = intel.get("reputation")
        intel_bits.append(f"{ename}={intel.get('type')}:{rep} (score {intel.get('score')})")
        if rep == "malicious":
            worst = "malicious"
        elif rep == "suspicious" and worst != "malicious":
            worst = "suspicious"
    confidence = alert.pop("_confidence", None) or (
        "high" if worst == "malicious" or (alert.get("event_count", 1) or 1) >= 5 else "medium")
    summary = (f"{alert.get('title')} — {alert.get('event_count', 1)} related event(s) on "
               f"{alert.get('hostname')}. Technique: {mitre or 'n/a'} ({name}).")
    if intel_bits:
        summary += " Intel: " + "; ".join(intel_bits) + "."
    return {
        "summary": summary,
        "why_it_matters": why,
        "remediation": remediation,
        "confidence": confidence,
        "model": "heuristic-v1",
    }


def _llm(prompt, system):
    """Try Anthropic, then OpenAI. Returns text or None."""
    timeout = 20
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            body = json.dumps({"model": "claude-sonnet-4-5-20250929", "max_tokens": 400,
                               "system": system,
                               "messages": [{"role": "user", "content": prompt}]}).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages", data=body,
                headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                         "anthropic-version": "2023-06-01",
                         "content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode())
            return "".join(b.get("text", "") for b in data.get("content", []))
        except Exception:
            pass
    if os.environ.get("OPENAI_API_KEY"):
        try:
            body = json.dumps({"model": "gpt-4o-mini", "max_tokens": 400,
                               "messages": [{"role": "system", "content": system},
                                            {"role": "user", "content": prompt}]}).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions", data=body,
                headers={"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"],
                         "content-type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read().decode())
            return data["choices"][0]["message"]["content"]
        except Exception:
            pass
    return None


def triage(alert: dict, enrichment: dict) -> dict:
    base = _heuristic(alert, enrichment)
    system = ("You are a SOC analyst assistant. Given a security alert JSON, reply with "
              "exactly three sections: SUMMARY (2 sentences), WHY IT MATTERS (1-2 sentences), "
              "REMEDIATION (3 bullet steps). No preamble.")
    prompt = ("Alert: " + json.dumps({
        "title": alert.get("title"), "severity": alert.get("severity"),
        "rule": alert.get("rule_id"), "mitre": alert.get("mitre"),
        "entities": alert.get("entities"), "event_count": alert.get("event_count"),
        "intel": enrichment, "host": alert.get("hostname")}))
    text = _llm(prompt, system)
    if not text:
        return base
    # best-effort parse of the three sections
    out = dict(base)
    out["summary"] = text.strip()[:1500]
    out["model"] = "llm"
    return out
