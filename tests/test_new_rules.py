"""Unit tests for the new Argus detection rules (ARG-1024..ARG-1028).

Loads the real YAML rule files and feeds synthetic events through the rule
engine. Run: .venv/bin/python -m pytest tests/ -q
"""
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.rules import RuleEngine, match_block  # noqa: E402

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

NEW_RULE_IDS = ["ARG-1024", "ARG-1025", "ARG-1026", "ARG-1027", "ARG-1028"]


def _load_all_rules():
    rules = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        with open(path) as f:
            for r in yaml.safe_load(f) or []:
                rules.append(r)
    return rules


def _rule(rule_id):
    for r in _load_all_rules():
        if r["id"] == rule_id:
            return r
    raise AssertionError(f"rule {rule_id} not found in rules/")


def _engine_with(rules):
    eng = RuleEngine("/nonexistent-dir")
    eng.rules = rules
    return eng


def _auth(user="root", src_ip="203.0.113.9", result="failed", hour=14):
    return {"agent_id": "web-01", "hostname": "web-01", "source": "auth",
            "event": {"service": "sshd", "user": user, "src_ip": src_ip,
                      "result": result, "port": 22, "hour": hour}}


# ---------- rule-pack sanity ----------

def test_new_rules_exist_and_schema_valid():
    rules = _load_all_rules()
    assert len(rules) == 28, f"expected 28 rules, got {len(rules)}"
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rid in NEW_RULE_IDS:
        r = _rule(rid)
        for field in ("id", "name", "description", "severity", "mitre", "source", "match", "title"):
            assert field in r, f"{rid} missing {field}"
        assert r["severity"] in ("low", "medium", "high", "critical")
        for t in r["mitre"]:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", t), f"{rid} bad technique {t}"


def test_combined_all_any_block():
    block = {"all": [{"field": "a", "equals": 1}],
             "any": [{"field": "b", "equals": 2}, {"field": "b", "equals": 3}]}
    assert match_block({"a": 1, "b": 2}, block)
    assert match_block({"a": 1, "b": 3}, block)
    assert not match_block({"a": 1, "b": 9}, block)   # all ok, any fails
    assert not match_block({"a": 9, "b": 2}, block)   # all fails
    assert not match_block({"a": 1, "b": 2}, {})      # empty block never matches
    # single-key blocks keep old behavior
    assert match_block({"a": 1}, {"all": [{"field": "a", "equals": 1}]})
    assert match_block({"b": 3}, {"any": [{"field": "b", "equals": 3}]})
    assert not match_block({"b": 3}, {"none": [{"field": "b", "equals": 3}]})


# ---------- ARG-1024: SSH password spraying ----------

def _spray_events(n, src_ip="203.0.113.9", result="failed", agent="web-01"):
    users = ["admin", "root", "oracle", "postgres", "test", "guest",
             "ubuntu", "user", "ftp", "git", "deploy", "backup"]
    return [dict(_auth(user=users[i % len(users)], src_ip=src_ip,
                       result=result, hour=14), agent_id=agent, hostname=agent)
            for i in range(n)]


def test_spraying_fires_at_threshold():
    eng = _engine_with([_rule("ARG-1024")])
    evs = _spray_events(9)
    for ev in evs:
        assert eng.process(ev) == []
    alerts = eng.process(_spray_events(1)[0])
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ARG-1024"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["event_count"] == 10
    # cooldown suppresses immediate re-fire
    assert eng.process(_spray_events(1)[0]) == []


def test_spraying_negative_cases():
    eng = _engine_with([_rule("ARG-1024")])
    # successes don't count
    for ev in _spray_events(10, result="success"):
        assert eng.process(ev) == []
    # non-sshd service ignored
    ev = _auth(result="failed")
    ev["event"] = dict(ev["event"], service="telnetd")
    assert eng.process(ev) == []
    # different source IP per attempt -> never reaches threshold per group
    for i in range(12):
        ev = _spray_events(1, src_ip=f"198.51.100.{i}")[0]
        assert eng.process(ev) == []


# ---------- ARG-1025: systemd timer persistence ----------

def _fim(path, action="created", user="root"):
    return {"agent_id": "web-01", "hostname": "web-01", "source": "fim",
            "event": {"path": path, "action": action, "user": user}}


def test_systemd_timer_positive():
    eng = _engine_with([_rule("ARG-1025")])
    alerts = eng.process(_fim("/etc/systemd/system/evil.timer", "created"))
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "ARG-1025"
    assert alerts[0]["mitre"] == ["T1053.006"]
    assert "/etc/systemd/system/evil.timer" in alerts[0]["title"]


def test_systemd_timer_negative():
    eng = _engine_with([_rule("ARG-1025")])
    # .service units belong to ARG-1022, not this rule
    assert eng.process(_fim("/etc/systemd/system/evil.service", "created")) == []
    # timer modified (not created) -> no fire
    assert eng.process(_fim("/etc/systemd/system/evil.timer", "modified")) == []
    # timer outside system dir -> no fire
    assert eng.process(_fim("/home/u/evil.timer", "created")) == []


# ---------- ARG-1026: web account shell ----------

def _proc(user, cmdline, exe="/bin/bash"):
    return {"agent_id": "web-01", "hostname": "web-01", "source": "process",
            "event": {"user": user, "exe": exe, "cmdline": cmdline,
                      "pid": 4242, "action": "started"}}


def test_web_user_shell_positive():
    eng = _engine_with([_rule("ARG-1026")])
    for user, cmd in [("www-data", "bash -i"),
                      ("www-data", "/bin/bash"),
                      ("nginx", "sh -c 'id'"),
                      ("apache", "/usr/bin/dash")]:
        alerts = eng.process(_proc(user, cmd))
        assert len(alerts) == 1, f"no alert for {user}: {cmd}"
        assert alerts[0]["severity"] == "critical"


def test_web_user_shell_negative():
    eng = _engine_with([_rule("ARG-1026")])
    # root running bash is normal
    assert eng.process(_proc("root", "/bin/bash")) == []
    # web user running its normal binary is fine
    assert eng.process(_proc("www-data", "php-fpm: pool www", exe="/usr/sbin/php-fpm")) == []
    assert eng.process(_proc("nginx", "/usr/sbin/nginx -g daemon off", exe="/usr/sbin/nginx")) == []


# ---------- ARG-1027: hosts file modified ----------

def test_hosts_file_positive():
    eng = _engine_with([_rule("ARG-1027")])
    for action in ("created", "modified"):
        alerts = eng.process(_fim("/etc/hosts", action))
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "ARG-1027"
        assert alerts[0]["mitre"] == ["T1557"]


def test_hosts_file_negative():
    eng = _engine_with([_rule("ARG-1027")])
    assert eng.process(_fim("/etc/hosts", "deleted")) == []     # not in [created, modified]
    assert eng.process(_fim("/etc/hostname", "modified")) == []  # different file
    assert eng.process(_fim("/etc/hosts.allow", "modified")) == []


# ---------- ARG-1028: off-hours SSH login ----------

def test_unusual_hour_positive():
    eng = _engine_with([_rule("ARG-1028")])
    for hour in (0, 3, 5, 22, 23):
        alerts = eng.process(_auth(result="success", hour=hour))
        assert len(alerts) == 1, f"no alert for hour={hour}"
        assert alerts[0]["rule_id"] == "ARG-1028"
        assert alerts[0]["severity"] == "medium"


def test_unusual_hour_negative():
    eng = _engine_with([_rule("ARG-1028")])
    for hour in (6, 9, 14, 21):
        assert eng.process(_auth(result="success", hour=hour)) == [], f"fired at hour={hour}"
    # failed logins at 3am are brute force territory, not this rule
    assert eng.process(_auth(result="failed", hour=3)) == []
    # non-sshd success ignored
    ev = _auth(result="success", hour=2)
    ev["event"] = dict(ev["event"], service="su")
    assert eng.process(ev) == []
