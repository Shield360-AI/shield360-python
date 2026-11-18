"""Sink rules at work (README "Sink rules"): the rule set in force (the
built-in list, or the verified signed config's ``sinks``) points an existing
detector at a library function the SDK does not hook itself, through the
generic wrapper here. A rule carries no code: it names a module, a dotted
path to a function, an argument and one of the checks.

Rules apply to modules already imported and, through the post-import hook,
to modules imported later; nothing is imported for a rule. A new rule set
takes effect at once: a rule no longer listed stops checking (its wrapper
stays, passing through, while something wrapped on top of it). A function a
built-in hook already wraps is skipped (one check per call), and so is a
target on a built-in type, which cannot be changed.

For a method (a function on a class) ``arg`` counts from the first argument
after the instance, as ``this`` is not an argument in the TypeScript SDK.
``field`` reads a mapping key or an attribute.
"""

from __future__ import annotations

import inspect
import threading
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from shield360.rasp import _detect, _sinks
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._engine import allow_lists
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks.code import cap_xml
from shield360.rasp._hooks._wrap import Entry, restore, run_check, wrap_call
from shield360.rasp._sinks import SinkRule
from shield360.rasp._types import Finding

_TAG = "rasp.sinks"
_lock = threading.RLock()
_installed = False
# (id of the owner, attribute) -> the rule its wrapper checks now (absent = pass through).
_rules_of: Dict[Tuple[int, str], SinkRule] = {}
_entries: List[Entry] = []
# (id of the owner, attribute) -> the target's parameter names by position (after the instance), for keyword calls.
_params_of: Dict[Tuple[int, str], List[str]] = {}


def parameter_names(entry: Entry) -> List[str]:
    """The names that can pass each positional argument by keyword, the
    instance (or class) left out for a method. Stops at ``*args``."""
    raw = entry.original
    fn = raw.__func__ if isinstance(raw, (staticmethod, classmethod)) else raw
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (TypeError, ValueError):
        return []
    if entry.bound and params:
        params = params[1:]
    out: List[str] = []
    for p in params:
        if p.kind is p.POSITIONAL_ONLY:
            out.append("")  # cannot come by keyword
        elif p.kind is p.POSITIONAL_OR_KEYWORD:
            out.append(p.name)
        else:
            break
    return out


def value_of(rule: SinkRule, args: Sequence[Any], kwargs: Mapping[str, Any], names: Sequence[str] = ()) -> Any:
    """The value a rule checks, from the call's arguments: ``arg`` by position,
    or by the keyword that parameter has (``names``)."""
    if rule.arg < len(args):
        v = args[rule.arg]
    else:
        name = names[rule.arg] if rule.arg < len(names) else ""
        v = kwargs.get(name) if name else None
    if rule.check == "nosql":
        return v
    if isinstance(v, str):
        return v
    if rule.field and v is not None:
        f = v.get(rule.field) if isinstance(v, Mapping) else getattr(v, rule.field, None)
        if isinstance(f, str):
            return f
    return None


def detect(rule: SinkRule, value: Any) -> Optional[Finding]:
    ctx = current_context()
    if ctx is None:
        return None
    inputs = inputs_of(ctx)
    if rule.check == "nosql":
        # The operator check compares against the request's parsed trees, not the flat inputs.
        return _detect.detect_nosql(value, ctx.trees, inputs) if isinstance(value, (dict, list)) else None
    if not inputs:
        return None
    if not isinstance(value, str):
        return None
    if rule.check == "sql":
        return _detect.detect_sql(value, inputs, rule.dialect or "generic")
    if rule.check == "command":
        return _detect.detect_command(value, inputs)
    if rule.check == "path":
        return _detect.detect_path(value, rule.op or "read", inputs, allow_lists()["file_roots"], ctx.in_request)
    if rule.check == "ssrf":
        return _detect.detect_ssrf(value, inputs, [])
    if rule.check == "code":
        return _detect.detect_code(value, inputs)
    if rule.check == "deser":
        return _detect.detect_deserialization(str(rule.format), value, inputs)
    if rule.check == "xml":
        return cap_xml(_detect.detect_xml(value, inputs, rule.resolves_external), rule.resolves_external)
    return None


def _inspect(rule: SinkRule, args: Sequence[Any], kwargs: Dict[str, Any], names: Sequence[str] = ()) -> None:
    def run() -> Optional[Finding]:
        found = detect(rule, value_of(rule, args, kwargs, names))
        if found is not None:
            # The rule's action caps the decision (a cap the check set itself stays); the attack type's mode still applies.
            found.action = "monitor" if "monitor" in (found.action, rule.action) else rule.action
        return found

    run_check(f"rule:{rule.id}", run)


def resolve(module: Any, target: str) -> Optional[tuple]:
    """The owner and attribute name a rule's target names in a module."""
    segments = target.split(".")
    owner = module
    for s in segments[:-1]:
        owner = getattr(owner, s, None)
        if owner is None:
            return None
    return owner, segments[-1]


def apply_rule(rule: SinkRule, module: Any) -> None:
    """Points the rule at its target in ``module``; leaves the module alone when the target does not fit."""
    try:
        at = resolve(module, rule.target)
        if at is None:
            return
        key = (id(at[0]), at[1])

        def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
            current = _rules_of.get(key)
            if current is not None:
                _inspect(current, args, kwargs, _params_of.get(key, ()))

        with _lock:
            entry = wrap_call(at[0], at[1], before, tag=_TAG)
            if entry is None:
                return
            if entry not in _entries:
                _entries.append(entry)
            _params_of[key] = parameter_names(entry)
            _rules_of[key] = rule
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _release_all() -> None:
    with _lock:
        _rules_of.clear()
        for entry in reversed(_entries):
            restore(entry)
        _entries.clear()


def _apply(rules: List[SinkRule]) -> None:
    """Makes ``rules`` the rule set in force: targets still listed keep their
    wrapper, targets no longer listed stop checking at once. Never raises."""
    try:
        with _lock:
            previous = list(_entries)
            _rules_of.clear()
            _imports.forget(_TAG)
            by_module: Dict[str, List[SinkRule]] = {}
            for r in rules:
                by_module.setdefault(r.module, []).append(r)
            for name, group in by_module.items():

                def patch(module: Any, group: List[SinkRule] = group) -> None:
                    for r in group:
                        apply_rule(r, module)

                _imports.when_imported(name, _TAG, patch)
            for entry in previous:
                if (id(entry.owner), entry.key) not in _rules_of:
                    restore(entry)
                    _entries.remove(entry)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def install_sink_hooks() -> bool:
    """Applies the rule set in force now and every later one. Idempotent; never raises."""
    global _installed
    if _installed:
        return True
    _installed = True
    _sinks.set_listener(_apply)
    return True


def uninstall_sink_hooks() -> None:
    """Switches every rule off and puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed
    _installed = False
    _sinks.set_listener(None)
    _imports.forget(_TAG)
    _release_all()
