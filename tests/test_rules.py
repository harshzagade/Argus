"""Unit tests for the Argus rule engine. Run: .venv/bin/python -m pytest tests/ -q"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server.rules import RuleEngine, get_field, match_condition, render_template  # noqa: E402


def _engine_with(rules):
    eng = RuleEngine("/nonexistent-dir")
    eng.rules = rules
    return eng


def test_get_field():
    ev = {"agent_id": "web-01", "event": {"src_ip": "1.2.3.4"}}
    assert get_field(ev, "event.src_ip") == "1.2.3.4"
    assert get_field(ev, "event.missing") is None
    assert get_field(ev, "agent_id") == "web-01"


def test_operators():
    ev = {"event": {"user": "root", "port": 22, "msg": "Failed password for root"}}
    assert match_condition(ev, {"field": "event.user", "equals": "root"})
    assert not match_condition(ev, {"field": "event.user", "equals": "admin"})
    assert match_condition(ev, {"field": "event.msg", "contains": "Failed"})
    assert match_condition(ev, {"field": "event.msg", "regex": r"Failed \w+ for"})
    assert match_condition(ev, {"field": "event.port", "gt": 21})
    assert match_condition(ev, {"field": "event.port", "in": [22, 80]})
    assert match_condition(ev, {"field": "event.missing", "exists": False})
    assert match_condition(ev, {"field": "event.user", "startswith": "ro"})
    # field reference
    ev2 = {"event": {"a": "x", "b": "x"}}
    assert match_condition(ev2, {"field": "event.a", "equals": "$event.b"})


def test_threshold_and_cooldown():
    rule = {
        "id": "ARG-T1", "name": "t", "severity": "high", "source": "auth",
        "match": {"all": [{"field": "event.result", "equals": "failed"}]},
        "group_by": ["event.src_ip"],
        "threshold": {"count": 3, "window": 300},
        "cooldown": 600,
        "title": "brute from {event.src_ip}",
        "entities": ["event.src_ip"],
    }
    eng = _engine_with([rule])
    ev = {"agent_id": "a", "hostname": "a", "source": "auth",
          "event": {"result": "failed", "src_ip": "9.9.9.9"}}
    assert eng.process(ev) == []
    assert eng.process(ev) == []
    alerts = eng.process(ev)
    assert len(alerts) == 1
    assert alerts[0]["title"] == "brute from 9.9.9.9"
    assert alerts[0]["entities"] == {"src_ip": "9.9.9.9"}
    # cooldown suppresses immediate re-fire
    assert eng.process(ev) == []
    # different group fires independently
    ev2 = dict(ev, event={"result": "failed", "src_ip": "8.8.8.8"})
    eng.process(ev2); eng.process(ev2)
    assert len(eng.process(ev2)) == 1


def test_source_filter_and_logic():
    rule = {
        "id": "ARG-T2", "name": "t", "severity": "low", "source": "fim",
        "match": {"any": [
            {"field": "event.path", "equals": "/etc/passwd"},
            {"field": "event.path", "equals": "/etc/shadow"}]},
        "title": "critical file changed",
    }
    eng = _engine_with([rule])
    fim = {"agent_id": "a", "source": "fim", "event": {"path": "/etc/shadow", "action": "modified"}}
    assert len(eng.process(fim)) == 1
    auth = {"agent_id": "a", "source": "auth", "event": {"path": "/etc/shadow"}}
    assert eng.process(auth) == []  # wrong source


def test_render_template_missing_field():
    assert render_template("hi {event.nope}", {"event": {}}) == "hi {event.nope}"
