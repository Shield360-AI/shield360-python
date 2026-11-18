"""Custom rules (README "Custom rules"): the organization's own rules, written
in the expression language of ``_rule_expr.py`` and delivered inside the
signed config (``customRules``). They are data: each expression is parsed and
type-checked when the config arrives and evaluated against the request (or a
built-in finding) as a value. An invalid rule is skipped with one warning and
never breaks the config; evaluation fails open.

This file turns rules and the request context into the language's terms; the
engine and capture decide what a match does. Mirrors the TypeScript SDK's
``custom-rules.ts``."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set

from shield360.rasp._context import RaspContext, route_of
from shield360.rasp._rule_expr import CompiledRuleExpr, RuleBudget, compile_rule_expr, evaluate_rule_expr
from shield360.rasp._types import Finding, RaspInput

logger = logging.getLogger("shield360.rasp")

MAX_CUSTOM_RULES = 64
MAX_RULE_APPS = 32
# Lower-case, so the event rule ``custom.<id>`` fits the platform's rule shape.
CUSTOM_RULE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
CUSTOM_RULE_PREFIX = "custom."
CUSTOM_RULE_ACTIONS = ("block", "monitor", "alert")
#: Wall-clock time custom rules may spend per request (README "Python SDK notes"): a
#: Python safeguard on top of the contract's step budget. 0 turns the cap off.
DEFAULT_RULES_TIME_BUDGET_MS = 25.0

_time_budget_s: Optional[float] = DEFAULT_RULES_TIME_BUDGET_MS / 1000
_warned_exhausted = [False]


def resolve_rules_time_budget_ms(option: Any = None, env: Optional[Mapping[str, str]] = None) -> float:
    """The time budget in ms: env ``SHIELD360_RULES_TIME_BUDGET_MS``, else the
    local option, else 25. A value that is not a number >= 0 is ignored."""
    env = os.environ if env is None else env
    for v in (env.get("SHIELD360_RULES_TIME_BUDGET_MS"), option):
        if isinstance(v, bool) or v is None:
            continue
        try:
            n = float(v)
        except (TypeError, ValueError):
            continue
        if n == n and 0 <= n < float("inf"):  # pylint: disable=comparison-with-itself
            return n
    return DEFAULT_RULES_TIME_BUDGET_MS


def set_rules_time_budget_ms(ms: float) -> None:
    """Sets the per-request time budget (0 = no time cap, the step budget only)."""
    global _time_budget_s  # pylint: disable=global-statement
    _time_budget_s = ms / 1000 if ms > 0 else None


def new_budget() -> RuleBudget:
    """A fresh per-request budget: the contract's steps and the time cap."""
    return RuleBudget(time_left=_time_budget_s)


def _warn_exhausted(budget: RuleBudget) -> None:
    """One log line per process when a request runs out of its custom-rule budget."""
    if _warned_exhausted[0]:
        return
    _warned_exhausted[0] = True
    what = "time budget" if budget.timed_out else "work budget"
    logger.warning(
        "Shield360 RASP: custom rules ran out of their %s on a request; the remaining rules were not evaluated for it "
        "(fail open). Further occurrences are not logged.",
        what,
    )


@dataclass
class CustomRule:
    id: str
    name: str
    action: str
    expr: CompiledRuleExpr
    apps: Optional[List[str]] = None


@dataclass
class SkippedRule:
    index: int
    reason: str
    id: Optional[str] = None


_warned: Set[str] = set()


def _default_warn(s: SkippedRule) -> None:
    which = f'"{s.id}"' if s.id else f"#{s.index + 1}"
    logger.warning("Shield360 RASP: custom rule %s was skipped (%s); the other rules apply.", which, s.reason)


def reset_custom_rule_warnings() -> None:
    """Tests only: lets the once-per-rule and once-per-process warnings fire again."""
    _warned.clear()
    _warned_exhausted[0] = False


def _valid_id(v: Any) -> bool:
    return isinstance(v, str) and CUSTOM_RULE_ID.fullmatch(v) is not None


def parse_custom_rules(  # pylint: disable=too-many-branches
    raw: Any, app: str, warn: Callable[[SkippedRule], None] = _default_warn
) -> List[CustomRule]:
    """The rules of a signed config that apply to this app: invalid rules are
    skipped (one warning per rule and reason, per process), disabled rules and
    rules scoped to other apps are left out silently. At most 64."""
    if not isinstance(raw, list):
        return []
    out: List[CustomRule] = []
    ids: Set[str] = set()

    def skip(s: SkippedRule, expression: Any = None) -> None:
        key = "\0".join((s.id if s.id is not None else str(s.index), s.reason, expression if isinstance(expression, str) else ""))
        if key in _warned:
            return
        if len(_warned) > 1024:
            _warned.clear()
        _warned.add(key)
        try:
            warn(s)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    for index, r in enumerate(raw):
        try:
            if not isinstance(r, dict):
                skip(SkippedRule(index, "not an object"))
                continue
            rid = r.get("id")
            if not _valid_id(rid):
                skip(SkippedRule(index, "invalid id"))
                continue
            if rid in ids:
                skip(SkippedRule(index, "duplicate id", rid))
                continue
            ids.add(rid)
            if not isinstance(r.get("enabled"), bool):
                skip(SkippedRule(index, "invalid enabled flag", rid))
                continue
            action = r.get("action")
            if not isinstance(action, str) or action not in CUSTOM_RULE_ACTIONS:
                skip(SkippedRule(index, "invalid action", rid))
                continue
            if "name" in r and not isinstance(r["name"], str):
                skip(SkippedRule(index, "invalid name", rid))
                continue
            apps = r.get("apps")
            if apps is not None and not (
                isinstance(apps, list) and len(apps) <= MAX_RULE_APPS and all(isinstance(a, str) for a in apps)
            ):
                skip(SkippedRule(index, "invalid apps", rid))
                continue
            compiled = compile_rule_expr(r.get("expression"))
            if not compiled.ok or compiled.expr is None:
                code = compiled.error.code if compiled.error else "syntax"
                skip(SkippedRule(index, f"expression: {code}", rid), r.get("expression"))
                continue
            if not r["enabled"]:
                continue
            scoped = list(apps) if isinstance(apps, list) and apps else None
            if scoped is not None and app not in scoped:
                continue
            if len(out) >= MAX_CUSTOM_RULES:
                skip(SkippedRule(index, "more than 64 rules", rid))
                continue
            name = r["name"] if isinstance(r.get("name"), str) else rid
            out.append(CustomRule(id=rid, name=name, action=action, expr=compiled.expr, apps=scoped))
        except Exception:  # pylint: disable=broad-exception-caught
            skip(SkippedRule(index, "unreadable"))
    return out


def action_mode(action: str) -> str:
    """The most a rule does: ``alert`` reports like ``monitor`` (the platform raises the alert)."""
    return "block" if action == "block" else "monitor"


def custom_finding(rule: CustomRule, inp: Optional[RaspInput] = None) -> Finding:
    """The finding a matched rule reports (attack type ``custom_rule``, rule ``custom.<id>``)."""
    return Finding("custom_rule", CUSTOM_RULE_PREFIX + rule.id, inp, action=action_mode(rule.action))


def _joined(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return str(v)


def request_subject(ctx: Optional[RaspContext], app: str, inputs: Optional[Sequence[RaspInput]] = None) -> Dict[str, Any]:
    """The request as the language sees it (README "Custom rules: fields")."""
    if ctx is None:
        return {"app": app, "inputs": []}
    items = list(inputs) if inputs is not None else ctx.inputs
    headers: Dict[str, str] = {}
    raw = ctx.vp.req.headers if ctx.vp is not None else None
    if isinstance(raw, dict):
        for k, v in raw.items():
            j = _joined(v)
            if j is not None:
                headers[str(k).lower()] = j
    query: Dict[str, str] = {}
    body: Dict[str, str] = {}
    for i in items:
        if i.source != "request":
            continue
        if i.key.startswith("query."):
            query.setdefault(i.key[6:], i.value)
        elif i.key.startswith("body."):
            body.setdefault(i.key[5:], i.value)
    path = ctx.path
    request = None
    if ctx.in_request:
        request = {
            "method": ctx.method.upper() if ctx.method else None,
            "path": path,
            "route": ctx.route if ctx.route is not None else (route_of(path) if path else None),
            "ip": ctx.ip,
            "headers": headers,
            "query": query,
            "body": body,
        }
    return {"app": app, "request": request, "inputs": list(items)}


@dataclass
class CustomRuleState:
    """Per-request evaluation state, kept on the context."""

    matched: Set[str] = field(default_factory=set)
    budget: RuleBudget = field(default_factory=new_budget)


def rule_state(ctx: RaspContext) -> CustomRuleState:
    if ctx.rules is None:
        ctx.rules = CustomRuleState()
    return ctx.rules


@dataclass
class RuleMatch:
    rule: CustomRule
    input: Optional[RaspInput] = None


def _as_input(v: Any) -> Optional[RaspInput]:
    return v if isinstance(v, RaspInput) else None


def match_request_rules(rules: Sequence[CustomRule], ctx: RaspContext, phase: str, subject: Dict[str, Any]) -> List[RuleMatch]:
    """The request rules to judge in a phase, matched in order. ``head``: every
    request rule that does not read the body. ``body``: rules that read the
    body, and rules reading ``input.*`` that did not match at ``head`` (the
    body added inputs). A rule matches at most once per request."""
    st = rule_state(ctx)
    out: List[RuleMatch] = []
    for rule in rules:
        e = rule.expr
        if st.budget.steps < 0:
            break
        if e.phase != "request" or rule.id in st.matched:
            continue
        if (e.uses_body if phase == "head" else not (e.uses_body or e.uses_input)):
            continue
        r = evaluate_rule_expr(e, subject, st.budget)
        if r.exhausted:
            _warn_exhausted(st.budget)
            break
        if not r.matched:
            continue
        st.matched.add(rule.id)
        out.append(RuleMatch(rule, _as_input(r.input)))
    return out


def match_finding_rules(rules: Sequence[CustomRule], subject: Dict[str, Any], budget: RuleBudget) -> List[RuleMatch]:
    """The finding rules a built-in finding matches, in order."""
    out: List[RuleMatch] = []
    for rule in rules:
        if budget.steps < 0:
            break
        if rule.expr.phase != "finding":
            continue
        r = evaluate_rule_expr(rule.expr, subject, budget)
        if r.exhausted:
            _warn_exhausted(budget)
            break
        if r.matched:
            out.append(RuleMatch(rule, _as_input(r.input)))
    return out
