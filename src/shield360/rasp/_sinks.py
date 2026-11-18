"""Sink rules (README "Sink rules"): data from the built-in list or the
verified signed config that points an existing detector at a library
function the SDK does not hook itself. No rule carries code: a rule names a
module, a dotted path to a function, an argument and one of the checks.

This part parses and validates rules and keeps the rule set in force;
``_hooks/sinks.py`` applies it (wraps the named functions) while RASP is on.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any, Callable, List, Optional

from shield360.rasp._detect import DESER_FORMATS, FILE_OPS
from shield360.rasp._lexers import SQL_DIALECTS

MAX_RULES = 64
# Rule ids: dot-separated words, short enough that the event sink "rule:<id>" fits its 64 characters.
_RULE_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*", re.ASCII)
_SEGMENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*", re.ASCII)
# A package as Node loads it (the contract's shared form) or a Python dotted module (_pickle, yaml.constructor).
_NPM_MODULE = re.compile(r"(@[a-z0-9][\w.\-]*/)?[a-z0-9][\w.\-]*(/[\w.\-]+)*", re.IGNORECASE | re.ASCII)
_PY_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", re.ASCII)
_CHECKS = frozenset(("sql", "nosql", "command", "path", "ssrf", "code", "deser", "xml"))
_REFUSED_SEGMENTS = frozenset(("__proto__", "constructor"))


@dataclass(frozen=True)
class SinkRule:  # pylint: disable=too-many-instance-attributes
    id: str
    module: str
    target: str
    check: str
    arg: int = 0
    action: str = "monitor"
    title: Optional[str] = None
    field: Optional[str] = None
    dialect: Optional[str] = None
    op: Optional[str] = None
    format: Optional[str] = None
    resolves_external: bool = False


def _module_ok(m: Any) -> bool:
    return isinstance(m, str) and len(m) <= 200 and (_NPM_MODULE.fullmatch(m) is not None or _PY_MODULE.fullmatch(m) is not None)


def _segment_ok(s: str) -> bool:
    # Python's equivalents of __proto__ (dunder attributes such as __class__ or __globals__) are refused too.
    return bool(_SEGMENT.fullmatch(s)) and s not in _REFUSED_SEGMENTS and not (s.startswith("__") and s.endswith("__"))


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def parse_sink_rule(raw: Any) -> Optional[SinkRule]:
    """One rule, checked field by field; None drops it (never the whole list)."""
    if not isinstance(raw, dict):
        return None
    rid = raw.get("id")
    if not isinstance(rid, str) or len(rid) > 59 or not _RULE_ID.fullmatch(rid):
        return None
    if not _module_ok(raw.get("module")):
        return None
    target = raw.get("target")
    if not isinstance(target, str):
        return None
    segments = target.split(".")
    if not segments or len(segments) > 4 or not all(_segment_ok(s) for s in segments):
        return None
    check = raw.get("check")
    if not isinstance(check, str) or check not in _CHECKS:
        return None
    runtimes = raw.get("runtimes")
    if runtimes is not None and not (isinstance(runtimes, list) and all(isinstance(x, str) for x in runtimes)):
        return None
    if isinstance(runtimes, list) and "python" not in runtimes:
        return None
    arg = raw.get("arg", 0)
    if not _is_int(arg) or not 0 <= arg <= 16:
        return None
    field = raw.get("field")
    if field is not None and not (isinstance(field, str) and _segment_ok(field)):
        return None
    if raw.get("dialect") is not None and raw.get("dialect") not in SQL_DIALECTS:
        return None
    if raw.get("op") is not None and raw.get("op") not in FILE_OPS:
        return None
    if check == "deser" and raw.get("format") not in DESER_FORMATS:
        return None
    action = raw.get("action", "monitor")
    if action not in ("monitor", "block"):
        return None
    title = raw.get("title")
    return SinkRule(
        id=rid,
        module=raw["module"],
        target=target,
        check=check,
        arg=arg,
        action=action,
        title=title if isinstance(title, str) else None,
        field=field,
        dialect=raw.get("dialect"),
        op=raw.get("op"),
        format=raw.get("format"),
        resolves_external=raw.get("resolvesExternal") is True,
    )


def parse_sink_rules(raw: Any) -> List[SinkRule]:
    """A list: at most 64 rules, invalid ones dropped, duplicate ids keep the first."""
    if not isinstance(raw, list):
        return []
    out: List[SinkRule] = []
    ids = set()
    for item in raw:
        if len(out) >= MAX_RULES:
            break
        rule = parse_sink_rule(item)
        if rule is not None and rule.id not in ids:
            ids.add(rule.id)
            out.append(rule)
    return out


def _load_built_in() -> List[SinkRule]:
    data = json.loads(resources.files("shield360.rasp").joinpath("data", "default-sinks.json").read_text(encoding="utf-8"))
    return parse_sink_rules(data.get("sinks") if isinstance(data, dict) else None)


BUILT_IN_SINKS: List[SinkRule] = _load_built_in()

_active: List[SinkRule] = list(BUILT_IN_SINKS)
# The sink hook while installed: told the rule set in force now and on every change.
_listener: Optional[Callable[[List[SinkRule]], None]] = None


def set_sink_rules(rules: List[SinkRule]) -> None:
    """The rule set in force (the signed config's ``sinks`` replace the built-in list). Applied by the sink hook at once."""
    global _active
    _active = list(rules)
    listener = _listener
    if listener is not None:
        listener(list(_active))


def set_listener(listener: Optional[Callable[[List[SinkRule]], None]]) -> None:
    """Installs (or, with None, removes) the sink hook's listener, telling it the rule set in force now."""
    global _listener
    _listener = listener
    if listener is not None:
        listener(list(_active))


def sink_rules() -> List[SinkRule]:
    return list(_active)
