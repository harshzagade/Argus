"""YAML rule engine for Argus. Loads rules/*.yaml, evaluates events."""
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def get_field(obj: dict, path: str):
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _resolve(value, event):
    if isinstance(value, str) and value.startswith("$"):
        return get_field(event, value[1:])
    return value


def match_condition(event: dict, cond: dict) -> bool:
    field = cond.get("field")
    actual = get_field(event, field)
    for op, expected in cond.items():
        if op == "field":
            continue
        exp = _resolve(expected, event)
        if op == "equals":
            if actual != exp:
                return False
        elif op == "not_equals":
            if actual == exp:
                return False
        elif op == "contains":
            if exp not in str(actual or ""):
                return False
        elif op == "not_contains":
            if exp in str(actual or ""):
                return False
        elif op == "regex":
            if not re.search(str(exp), str(actual or "")):
                return False
        elif op == "in":
            if actual not in (exp or []):
                return False
        elif op == "not_in":
            if actual in (exp or []):
                return False
        elif op in ("gt", "gte", "lt", "lte"):
            try:
                a, e = float(actual), float(exp)
            except (TypeError, ValueError):
                return False
            if op == "gt" and not a > e:
                return False
            if op == "gte" and not a >= e:
                return False
            if op == "lt" and not a < e:
                return False
            if op == "lte" and not a <= e:
                return False
        elif op == "exists":
            if (actual is not None) != bool(exp):
                return False
        elif op == "startswith":
            if not str(actual or "").startswith(str(exp)):
                return False
        elif op == "endswith":
            if not str(actual or "").endswith(str(exp)):
                return False
        else:
            raise ValueError(f"Unknown operator: {op}")
    return True


def match_block(event: dict, block: dict) -> bool:
    # A block may combine keys; all present keys must pass (AND semantics).
    # Blocks that use exactly one key behave exactly as before.
    if not block:
        return False
    if "all" in block and not all(match_condition(event, c) for c in block["all"]):
        return False
    if "any" in block and not any(match_condition(event, c) for c in block["any"]):
        return False
    if "none" in block and any(match_condition(event, c) for c in block["none"]):
        return False
    return True


TEMPLATE_RE = re.compile(r"\{([a-zA-Z0-9_.$]+)\}")


def render_template(tpl: str, event: dict) -> str:
    def repl(m):
        v = get_field(event, m.group(1))
        return str(v) if v is not None else m.group(0)
    return TEMPLATE_RE.sub(repl, tpl or "")


class RuleEngine:
    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self._hits = defaultdict(deque)   # (rule_id, group_key) -> deque[datetime]
        self._last_fire = {}              # (rule_id, group_key) -> datetime
        self.reload()

    def reload(self):
        rules = []
        if self.rules_dir.exists():
            for path in sorted(self.rules_dir.glob("*.yaml")):
                with open(path, encoding="utf-8") as f:
                    docs = yaml.safe_load(f) or []
                for r in docs:
                    r["_file"] = path.name
                    rules.append(r)
        self.rules = rules
        return len(rules)

    def _group_key(self, rule, event):
        parts = []
        for g in rule.get("group_by", []):
            parts.append(str(get_field(event, g)))
        return "|".join(parts) if parts else "__all__"

    def process(self, event: dict):
        """Evaluate one normalized event. Returns list of alert dicts (no id/ts)."""
        alerts = []
        now = datetime.now(timezone.utc)
        for rule in self.rules:
            if rule.get("source") and rule["source"] != event.get("source"):
                continue
            try:
                matched = match_block(event, rule.get("match", {}))
            except Exception:
                continue
            if not matched:
                continue
            key = (rule["id"], self._group_key(rule, event))
            dq = self._hits[key]
            dq.append(now)
            while dq and (now - dq[0]) > timedelta(seconds=3600):
                dq.popleft()
            # Cross-rule requirement: e.g. ARG-1002 (successful login) only
            # fires when the same group recently produced enough ARG-1001
            # brute-force hits. A normal admin login stays silent.
            req = rule.get("requires")
            if req:
                rkey = (req.get("rule_id"), key[1])
                within = timedelta(seconds=req.get("within", 1800))
                recent = sum(1 for t in self._hits.get(rkey, ()) if (now - t) <= within)
                if recent < req.get("count", 1):
                    continue
            threshold = rule.get("threshold")
            if threshold:
                window = timedelta(seconds=threshold.get("window", 300))
                event_count = sum(1 for t in dq if (now - t) <= window)
                if event_count < threshold.get("count", 5):
                    continue
            else:
                event_count = 1
            # Cooldown applies to every rule, not just threshold rules.
            cooldown = rule.get("cooldown", 0)
            if cooldown:
                last = self._last_fire.get(key)
                if last and (now - last) < timedelta(seconds=cooldown):
                    continue
                self._last_fire[key] = now
            alerts.append(self._build_alert(rule, event, event_count))
        # Bound memory: drop stale groups when the state map grows too large
        # (group keys can be attacker-controlled, e.g. source IPs).
        if len(self._hits) > 5000:
            stale = [k for k, v in self._hits.items()
                     if not v or (now - v[-1]) > timedelta(seconds=3600)]
            for k in stale:
                del self._hits[k]
        return alerts

    def _build_alert(self, rule, event, event_count):
        entities = {}
        for e in rule.get("entities", []):
            v = get_field(event, e)
            if v is not None:
                entities[e.split(".")[-1]] = v
        return {
            "rule_id": rule["id"],
            "rule_name": rule.get("name", rule["id"]),
            "severity": rule.get("severity", "medium"),
            "agent_id": event.get("agent_id"),
            "hostname": event.get("hostname"),
            "title": render_template(rule.get("title", rule.get("name", "")), event),
            "description": render_template(rule.get("description", ""), event),
            "mitre": rule.get("mitre", []),
            "compliance": rule.get("compliance", {}),
            "entities": entities,
            "event_ids": [],
            "event_count": event_count,
            "playbook": rule.get("playbook"),
            "ai_triage": bool(rule.get("ai_triage", False)),
        }
