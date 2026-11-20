"""RASP engine: the effective mode of each attack type (local options, the
verified signed config, the kill switch), the decision for a finding, the
event, and the block error. Detectors (``_detect.py``) are pure; this file is
where a finding becomes an event or a block."""

from __future__ import annotations

import os
import re
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional

from shield360._masking import mask_target, mask_text  # noqa: F401 — mask_target is engine API
from shield360.rasp._context import current_context, event_route_of
from shield360.rasp._custom_rules import (
    CustomRule,
    custom_finding,
    new_budget,
    resolve_rules_time_budget_ms,
    set_rules_time_budget_ms,
    match_finding_rules,
    parse_custom_rules,
    request_subject,
    rule_state,
)
from shield360.rasp._deception import DECEPTION, DECEPTION_SINK, Deception, parse_deception
from shield360.rasp._iast import begin_iast, end_iast
from shield360.rasp._model_output import set_model_output_recording
from shield360.rasp._types import ATTACK_TYPES, MODES, Finding, RaspBlockedError
from shield360.rasp._vpatch import BUILT_IN_RULES
from shield360.rasp._edge_context import VERDICT_HEADER, edge_says_suspect, sign_verdict

_RANK = {"off": 0, "monitor": 1, "block": 2}


@dataclass
class RemoteConfig:
    """The parts of a verified signed config the engine uses (``_config_client.py`` verifies it)."""

    version: str
    exp: float
    kill_switch: bool = False
    snippets: bool = False
    mode: Optional[str] = None
    attacks: Dict[str, str] = field(default_factory=dict)
    # Each list is None when the config does not set it (the local list stays).
    allow: Optional[Dict[str, Optional[List[str]]]] = None
    rules: Optional[List[Dict[str, Any]]] = None
    # Sink rules as sent (``_sinks.py`` validates them); None = the built-in list.
    sinks: Optional[List[Any]] = None
    # Custom rules as sent (``_custom_rules.py`` validates them); None = none.
    custom_rules: Optional[List[Any]] = None
    # The ``deception`` block as sent (``_deception.py`` reads it); None = off.
    deception: Any = None
    # Events of the allow-list rules carry shield360.rasp.target (signed config only).
    report_targets: bool = False
    # SHIELD: protection triangle — keys for Edge's context header and the app's verdicts (_edge_context.py).
    edge_keys: List[Any] = field(default_factory=list)


def _empty_allow() -> Dict[str, List[str]]:
    return {"commands": [], "outbound_hosts": [], "file_roots": []}


@dataclass
class _State:
    enabled: bool = False
    # SHIELD360_RASP=off, read at configure time.
    env_off: bool = False
    runtime_disabled: bool = False
    # No pinned key while a remote config was expected: block is capped at monitor.
    monitor_only: bool = False
    mode: str = "monitor"
    attacks: Dict[str, str] = field(default_factory=dict)
    allow: Dict[str, List[str]] = field(default_factory=_empty_allow)
    remote: Optional[RemoteConfig] = None
    # The signed config's custom rules that apply to this app, compiled.
    custom_rules: List[CustomRule] = field(default_factory=list)
    # The signed config's decoys; None = deception off.
    deception: Optional[Deception] = None
    application_name: str = "default"
    sink: Any = None


_state = _State()
_lock = threading.Lock()


def as_mode(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v in MODES else None


def env_setting(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """``SHIELD360_RASP``: monitor, block or off (anything else is ignored)."""
    env = os.environ if env is None else env
    return as_mode((env.get("SHIELD360_RASP") or "").strip().lower())


def _clean_attacks(v: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(v, dict):
        return out
    for a in ATTACK_TYPES:
        m = as_mode(v.get(a))
        if m:
            out[a] = m
    # Deception is read on its own (deception_mode), never through mode_for's defaults.
    m = as_mode(v.get(DECEPTION))
    if m:
        out[DECEPTION] = m
    return out


def _strings(v: Any) -> Optional[List[str]]:
    if not isinstance(v, (list, tuple)):
        return None
    return [x for x in v if isinstance(x, str) and x != ""][:256]


def _allow_value(allow: Any, snake: str, camel: str) -> Any:
    if not isinstance(allow, dict):
        return None
    return allow.get(snake, allow.get(camel))


def configure_engine(
    enabled: bool,
    application_name: str,
    mode: Optional[str] = None,
    attacks: Optional[Dict[str, str]] = None,
    allow: Optional[Dict[str, Any]] = None,
    model_output: Optional[bool] = None,
    monitor_only: bool = False,
    env: Optional[Mapping[str, str]] = None,
    rules_time_budget_ms: Any = None,
) -> None:
    """Applies the local options. ``allow`` takes ``commands``,
    ``outbound_hosts`` and ``file_roots`` (the contract's camelCase names work too).
    ``rules_time_budget_ms`` caps the time custom rules spend per request (env
    ``SHIELD360_RULES_TIME_BUDGET_MS`` wins; default 25, 0 = no time cap)."""
    e = env_setting(env)
    set_rules_time_budget_ms(resolve_rules_time_budget_ms(rules_time_budget_ms, env))
    with _lock:
        _state.env_off = e == "off"
        _state.enabled = bool(enabled) and not _state.env_off
        _state.runtime_disabled = False
        _state.monitor_only = bool(monitor_only)
        _state.remote = None
        _state.custom_rules = []
        _state.deception = None
        _state.application_name = application_name or "default"
        _state.mode = as_mode(mode) or (e if e in ("block", "monitor") else "monitor")
        _state.attacks = _clean_attacks(attacks)
        _state.allow = {
            "commands": _strings(_allow_value(allow, "commands", "commands")) or [],
            "outbound_hosts": _strings(_allow_value(allow, "outbound_hosts", "outboundHosts")) or [],
            "file_roots": _strings(_allow_value(allow, "file_roots", "fileRoots")) or [],
        }
    set_model_output_recording(_state.enabled and model_output is not False)


def set_event_sink(sink: Any) -> None:
    """Where events go: an object with ``add(event, fold_key)`` (the reporter), or None."""
    _state.sink = sink


def set_monitor_only(on: bool) -> None:
    _state.monitor_only = bool(on)


def set_remote_config(c: Optional[RemoteConfig]) -> None:
    """Applies a verified signed config (None drops it: local options again)."""
    if c is None:
        _state.remote = None
        _state.custom_rules = []
        _state.deception = None
        return
    allow = None
    if isinstance(c.allow, dict):
        allow = {
            "commands": _strings(_allow_value(c.allow, "commands", "commands")),
            "outbound_hosts": _strings(_allow_value(c.allow, "outbound_hosts", "outboundHosts")),
            "file_roots": _strings(_allow_value(c.allow, "file_roots", "fileRoots")),
        }
    rules = None
    if isinstance(c.rules, list):
        rules = [r for r in c.rules if isinstance(r, dict) and isinstance(r.get("id"), str) and isinstance(r.get("match"), list)]
    _state.remote = RemoteConfig(
        version=c.version,
        exp=c.exp,
        kill_switch=c.kill_switch is True,
        snippets=c.snippets is True,
        report_targets=c.report_targets is True,
        mode=as_mode(c.mode),
        attacks=_clean_attacks(c.attacks),
        allow=allow,
        rules=rules,
        sinks=c.sinks if isinstance(c.sinks, list) else None,
        custom_rules=c.custom_rules if isinstance(c.custom_rules, list) else None,
        deception=c.deception,
        edge_keys=list(getattr(c, "edge_keys", None) or []),
    )
    _state.custom_rules = parse_custom_rules(c.custom_rules, _state.application_name)
    _state.deception = parse_deception(c.deception)


def custom_rules() -> List[CustomRule]:
    """The custom rules in force (README "Custom rules")."""
    return _state.custom_rules


def remote_config() -> Optional[RemoteConfig]:
    return _state.remote


def set_runtime_disabled(off: bool) -> None:
    """The runtime switch (third in the kill-switch order)."""
    _state.runtime_disabled = bool(off)


def is_active() -> bool:
    """Kill-switch order: env ``SHIELD360_RASP=off``, the signed ``killSwitch``, the runtime call."""
    r = _state.remote
    return _state.enabled and not _state.env_off and not (r is not None and r.kill_switch) and not _state.runtime_disabled


def is_enabled() -> bool:
    return _state.enabled


def current_application_name() -> str:
    return _state.application_name


def mode_for(attack: str) -> str:
    """The effective mode of an attack type: off when RASP is not active."""
    if not is_active():
        return "off"
    if _state.attacks.get(attack) == "off":
        return "off"
    r = _state.remote
    if r is not None:
        m = r.attacks.get(attack) or r.mode or "monitor"
    else:
        m = _state.attacks.get(attack) or _state.mode
    if m == "block" and (attack == "xss" or _state.monitor_only):
        m = "monitor"
    return m


def deception_config() -> Optional[Deception]:
    """The decoys in force while RASP is active, or None (README "Deception")."""
    return _state.deception if is_active() else None


def deception_mode(action: str) -> Optional[str]:
    """The effective mode of a deception finding ("Decision"): None when
    deception is off (RASP not active, or a local or signed ``off``);
    ``monitor`` caps it; ``block`` or unset leaves the block's ``action`` to
    decide; no pinned key caps block at monitor. Never the default mode."""
    if not is_active() or _state.attacks.get(DECEPTION) == "off":
        return None
    r = _state.remote
    signed = r.attacks.get(DECEPTION) if r is not None else None
    if signed == "off":
        return None
    mode = "block" if action == "block" else "monitor"
    if signed == "monitor" or _state.monitor_only:
        mode = "monitor"
    return mode


def allow_lists() -> Dict[str, List[str]]:
    """``commands``, ``outbound_hosts``, ``file_roots``: the signed config's lists where it sets them."""
    local = _state.allow
    r = _state.remote
    if r is None or r.allow is None:
        return local
    return {k: (r.allow.get(k) if r.allow.get(k) is not None else local[k]) for k in ("commands", "outbound_hosts", "file_roots")}


def virtual_patches() -> List[Dict[str, Any]]:
    r = _state.remote
    return r.rules if r is not None and isinstance(r.rules, list) else BUILT_IN_RULES


def mask_snippet(v: str) -> str:
    """A snippet: masked (sdk/rasp/README.md, Masking), at most 64 characters."""
    return mask_text(v, 64)


# The rules whose event carries the allow-list target (README "Allow-list targets").
TARGET_RULES = frozenset(("shell_spawn.shell", "outbound.not_allowed", "path.outside_root"))
SQL_DIALECTS_REPORTED = frozenset(("mysql", "postgres", "sqlite", "mssql", "oracle", "db2", "generic"))


# Event attributes must pass the platform's shape checks (lib/security/rasp/events.ts).
_KEY_CHARS = re.compile(r"[^A-Za-z0-9_.\-\[\]]")
_KEY_START = re.compile(r"^[^A-Za-z0-9_]")
_ROUTE_CHARS = re.compile(r"[^\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]")
_METHOD = re.compile(r"[A-Za-z]{3,10}")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.ASCII)


def _safe_key(k: str) -> str:
    return _KEY_START.sub("_", _KEY_CHARS.sub("_", k))[:128]


def _safe_route(r: str) -> str:
    s = _ROUTE_CHARS.sub("_", r)[:256]
    return s if s.startswith("/") else ""


def _safe_method(m: Optional[str]) -> str:
    return m.upper() if isinstance(m, str) and _METHOD.fullmatch(m) else ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def handle_finding(
    f: Finding,
    sink: str,
    framework: Optional[str] = None,
    route: Optional[str] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
) -> Optional[str]:
    """Applies a finding: reports it and, when the decision is ``blocked``,
    raises the block error. Returns the decision, or None when the attack type is off."""
    mode = mode_for(f.attack)
    # A rule's own action (virtual patches, sink rules) caps the mode.
    if f.action in _RANK and _RANK[f.action] < _RANK[mode]:
        mode = f.action
    if mode == "off":
        return None
    # SHIELD: protection triangle — a client Edge already marked is blocked for injection-class attacks this app only monitors.
    ctx = current_context()
    edge = getattr(ctx, "edge", None) if ctx else None
    tightened = mode == "monitor" and not f.action and f.attack in _TIGHTEN and edge_says_suspect(edge) and not _state.monitor_only
    if tightened:
        mode = "block"
    decision = "blocked" if mode == "block" and f.attack != "xss" else "monitored"
    event_id = _report(f, sink, decision, mode, framework, route, method, path)
    _send_verdict(f, decision)
    # Custom rules that look at built-in findings; the first blocking decision wins, the built-in one first.
    custom = None if f.attack == "custom_rule" else _run_finding_rules(f, sink, framework, route, method, path)
    if decision == "blocked":
        raise RaspBlockedError(f.attack, f.rule, event_id)
    if custom is not None:
        raise custom
    return decision


_TIGHTEN = {"sql_injection", "nosql_injection", "command_injection", "shell_spawn", "code_injection", "path_traversal", "ssrf", "deserialization", "xxe"}


def _send_verdict(f: Finding, decision: str) -> None:
    """SHIELD: protection triangle — tells Edge about a detection in a request that came through it (a signed response header)."""
    try:
        ctx = current_context()
        edge = getattr(ctx, "edge", None) if ctx else None
        keys = _state.remote.edge_keys if _state.remote else []
        if not edge or not keys or getattr(ctx, "verdict_sent", False):
            return
        if f.attack == "custom_rule" and decision != "blocked":
            return
        v = sign_verdict(keys, edge["rid"], "block" if decision == "blocked" else "flag", str(f.attack), "rasp", 3600 if decision == "blocked" else 900)
        if v:
            ctx.response_headers.append((VERDICT_HEADER, v))
            ctx.verdict_sent = True
    except Exception:  # pylint: disable=broad-except
        pass


def report_deception(
    rule: str, mode: str, framework: Optional[str], method: Optional[str], route: Optional[str], path: str
) -> RaspBlockedError:
    """Reports a deception finding in the given mode (``deception_mode``) and
    returns its block error, which the middleware raises or answers only when
    the mode is block. Never raises."""
    decision = "blocked" if mode == "block" else "monitored"
    event_id = _report(Finding(attack=DECEPTION, rule=rule), DECEPTION_SINK, decision, mode, framework, route, method, path)
    return RaspBlockedError(DECEPTION, rule, event_id)


def _report(
    f: Finding,
    sink: str,
    decision: str,
    mode: str,
    framework: Optional[str],
    route: Optional[str],
    method: Optional[str],
    path: Optional[str],
) -> str:
    """Hands the event to the sink (the reporter folds and rate-limits it). Returns its id. Never raises."""
    event_id = secrets.token_hex(16)
    try:
        ctx = current_context()
        p = path if path is not None else (ctx.path if ctx else None)
        r = route if route is not None else (ctx.route if ctx else None)
        safe_route = _safe_route(r if r else (event_route_of(p) if p else ""))
        remote = _state.remote
        attrs: Dict[str, str] = {
            "shield360.rasp.event_id": event_id,
            "shield360.rasp.app": _state.application_name,
            "shield360.rasp.attack": f.attack,
            "shield360.rasp.rule": f.rule,
            "shield360.rasp.decision": decision,
            "shield360.rasp.mode": mode,
            "shield360.rasp.sink": sink,
            "shield360.rasp.config_version": remote.version if remote is not None else "local",
            "shield360.rasp.language": "python",
        }

        def opt(k: str, v: Optional[str]) -> None:
            if v:
                attrs[k] = v

        opt("shield360.rasp.source", f.input.source if f.input else None)
        opt("shield360.rasp.input_key", _safe_key(f.input.key) if f.input else None)
        opt("shield360.rasp.route", safe_route)
        opt("shield360.rasp.method", _safe_method(method if method is not None else (ctx.method if ctx else None)))
        opt("shield360.rasp.framework", framework if framework is not None else (ctx.framework if ctx else None))
        # SHIELD: protection triangle — the Edge request this happened in (one correlated event in Shield360).
        edge = getattr(ctx, "edge", None) if ctx else None
        if edge:
            attrs["shield360.edge.request_id"] = edge["rid"]
        opt("shield360.rasp.cve", f.cve if isinstance(f.cve, str) and _CVE.fullmatch(f.cve) else None)
        if remote is not None and remote.snippets and f.input:
            attrs["shield360.rasp.snippet"] = mask_snippet(f.input.value)
        if remote is not None and remote.report_targets and f.rule in TARGET_RULES:
            opt("shield360.rasp.target", mask_target(f.target))
        if f.attack == "sql_injection" and f.dialect in SQL_DIALECTS_REPORTED:
            attrs["shield360.rasp.sql.dialect"] = f.dialect
        out = _state.sink
        if out is not None:
            out.add(
                {"name": "shield360.rasp.event", "time": _now_iso(), "attrs": attrs},
                "\0".join((f.attack, f.rule, sink, safe_route, decision)),
            )
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # reporting never breaks the call
    return event_id


def _run_finding_rules(
    f: Finding, sink: str, framework: Optional[str], route: Optional[str], method: Optional[str], path: Optional[str]
) -> Optional[RaspBlockedError]:
    """Reports each custom finding rule the finding matches; returns the block
    error of the first that blocks. Never raises."""
    try:
        rules = _state.custom_rules
        if not rules:
            return None
        ctx = current_context()
        subject = request_subject(ctx, _state.application_name)
        subject["sink"] = sink
        subject["attack"] = {"type": f.attack, "rule": f.rule}
        budget = rule_state(ctx).budget if ctx is not None else new_budget()
        for m in match_finding_rules(rules, subject, budget):
            try:
                handle_finding(
                    custom_finding(m.rule, m.input or f.input), sink, framework=framework, route=route, method=method, path=path
                )
            except RaspBlockedError as e:
                return e
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # fail open
    return None


def check(sink: str, run: Callable[[], Optional[Finding]], **extra: Any) -> Optional[str]:
    """Runs a check at a sink and applies what it finds. Fail open: any error
    other than the block error is swallowed. The entry point sink hooks use."""
    # Passive IAST (_iast.py): armed for sampled checks while it is on; reports only when no attack was found.
    iast = begin_iast() if is_active() else None
    try:
        f = run()
        if iast is not None:
            end_iast(iast, None if f else sink, extra)
        return handle_finding(f, sink, **extra) if f else None
    except RaspBlockedError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    finally:
        if iast is not None:
            end_iast(iast)
