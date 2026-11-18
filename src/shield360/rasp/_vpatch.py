"""Virtual patches (README "Virtual patches"): rules that match the documented
request shape of a public advisory. The one place RASP matches request
signatures; every other check is structural. Run once per request, when its
input is captured, before the handler.

The built-in list is ``data/default-rules.json``, a byte-identical copy of
``sdk/rasp/rules/default-rules.json`` (a test says so). The signed config's
``rules`` replace it when present.
"""

from __future__ import annotations

import json
import platform
import re
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Dict, List, Optional, Sequence, Union

from shield360.rasp._types import Finding

MAX_VP_TEXT = 64 * 1024
_MAX_PATTERN = 1024
RUNTIME = "python"


@dataclass
class VpRequest:
    """The request as the rules see it. Header names are lower-case."""

    method: str = "GET"
    path: str = "/"
    # The raw query string, without '?'.
    query: str = ""
    headers: Dict[str, Union[str, List[str]]] = field(default_factory=dict)
    # The raw Cookie header.
    cookie: str = ""
    # The raw body text, or the JSON of a parsed body; '' when unknown.
    body: str = ""


def _load_rules() -> Dict[str, Any]:
    return json.loads(resources.files("shield360.rasp").joinpath("data", "default-rules.json").read_text(encoding="utf-8"))


_BUILT_IN = _load_rules()
BUILT_IN_RULES: List[Dict[str, Any]] = list(_BUILT_IN.get("rules", []))
BUILT_IN_VERSION: str = str(_BUILT_IN.get("version", ""))

_LEADING_INT = re.compile(r"\s*([+-]?\d+)", re.ASCII)


def _version_part(x: str) -> int:
    # As parseInt: the leading integer, else 0.
    m = _LEADING_INT.match(x)
    return int(m.group(1)) if m else 0


def _cmp_version(a: str, b: str) -> int:
    pa = [_version_part(x) for x in a.split(".")]
    pb = [_version_part(x) for x in b.split(".")]
    for i in range(max(len(pa), len(pb))):
        d = (pa[i] if i < len(pa) else 0) - (pb[i] if i < len(pb) else 0)
        if d:
            return d
    return 0


def rule_applies(rule: Dict[str, Any], runtime: str = RUNTIME, version: Optional[str] = None) -> bool:
    """Whether the rule applies in this runtime and version (``[from, to)`` ranges)."""
    if version is None:
        version = platform.python_version()
    runtimes = rule.get("runtimes")
    if isinstance(runtimes, list) and runtime not in runtimes:
        return False
    versions = rule.get("runtimeVersions")
    ranges = versions.get(runtime) if isinstance(versions, dict) else None
    if isinstance(ranges, list):
        return any(
            isinstance(r, list) and len(r) >= 2 and _cmp_version(version, str(r[1])) < 0 <= _cmp_version(version, str(r[0]))
            for r in ranges
        )
    return True


def needs_body(rule: Dict[str, Any]) -> bool:
    """Whether a rule reads the body (it can only be judged once the body is known)."""
    return any(isinstance(c, dict) and c.get("target") in ("body", "request") for c in rule.get("match") or [])


def _target_text(req: VpRequest, target: str) -> Optional[str]:
    if target == "method":
        return req.method
    if target == "path":
        return req.path
    if target == "query":
        return req.query
    if target == "cookie":
        return req.cookie
    if target == "body":
        return req.body[:MAX_VP_TEXT]
    if target == "request":
        return f"{req.path}?{req.query}\n{req.cookie}\n{req.body[:MAX_VP_TEXT]}"
    if target.startswith("header:"):
        v = req.headers.get(target[7:].lower())
        if v is None:
            return None
        return ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
    return None


# Backreferences (numbered, \k<name> and Python's (?P=name)) and lookaround are refused.
_UNSAFE_PATTERN = re.compile(r"\\[1-9]|\\k<|\(\?<?[=!]|\(\?P=")
_regex_cache: Dict[str, Optional["re.Pattern[str]"]] = {}


def _compile(p: str) -> Optional["re.Pattern[str]"]:
    """Compiles a rule pattern; refuses backreferences, lookaround and overlong patterns."""
    if p not in _regex_cache:
        compiled = None
        if len(p) <= _MAX_PATTERN and not _UNSAFE_PATTERN.search(p):
            try:
                compiled = re.compile(p)
            except Exception:  # pylint: disable=broad-exception-caught
                compiled = None
        if len(_regex_cache) > 512:
            _regex_cache.clear()
        _regex_cache[p] = compiled
    return _regex_cache.get(p)


def clause_matches(req: VpRequest, c: Any) -> bool:
    if not isinstance(c, dict) or not isinstance(c.get("target"), str):
        return False
    text = _target_text(req, c["target"])
    op = c.get("op")
    if op == "present":
        return text is not None
    if text is None:
        return False
    values = [v for v in c.get("values") or [] if isinstance(v, str)] if isinstance(c.get("values"), list) else []
    if op == "equals":
        t = text.lower()
        return any(v.lower() == t for v in values)
    if op == "contains_any":
        if c.get("ignoreCase"):
            t = text.lower()
            return any(v != "" and v.lower() in t for v in values)
        return any(v != "" and v in text for v in values)
    if op == "regex" and isinstance(c.get("value"), str):
        compiled = _compile(c["value"])
        return bool(compiled.search(text[:MAX_VP_TEXT])) if compiled else False
    return False


def match_virtual_patches(
    req: VpRequest,
    rules: Sequence[Any],
    phase: str = "all",
    runtime: str = RUNTIME,
    version: Optional[str] = None,
) -> Optional[Finding]:
    """The first rule the request matches, as a finding. ``head`` judges only
    rules that do not read the body; ``body`` only rules that do; ``all`` both."""
    for r in rules:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str):
            continue
        match = r.get("match")
        if not isinstance(match, list) or not match:
            continue
        if phase != "all" and needs_body(r) != (phase == "body"):
            continue
        if not rule_applies(r, runtime, version):
            continue
        if all(clause_matches(req, c) for c in match):
            action = r.get("action") if r.get("action") in ("off", "monitor") else "block"
            cves = r.get("cves")
            cve = cves[0] if isinstance(cves, list) and cves and isinstance(cves[0], str) else None
            return Finding("virtual_patch", r["id"], cve=cve, action=action)
    return None
