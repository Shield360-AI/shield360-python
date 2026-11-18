"""Passive IAST (README "Passive IAST"): while RASP checks its sinks during
normal traffic, report the places where a request input reaches a sink
verbatim and unparameterized, even when the value is harmless and no attack
happened, so developers can fix "route X builds SQL from query.id" before
anyone attacks it.

Off by default; turned on by the signed config (``iast: "on"``), the local
option (``rasp={"iast": True}``) or ``SHIELD360_IAST=on``. Never blocks and
does not depend on the attack modes. It adds work only to sink checks that
already run with request input in scope, and only for sampled checks.

Each vulnerability has a fingerprint (route, sink, input key, rule) and is
reported at most once per process per hour, with how many times it was seen
since the last report. Events name locations, never values, and carry no
snippet: the code location (the app's own stack frame, captured once per
fingerprint) replaces it. Mirrors the TypeScript SDK's ``iast.ts``."""

from __future__ import annotations

import hashlib
import os
import random as _random
import re
import secrets
import sys
import sysconfig
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional

from shield360.rasp._context import current_context, event_route_of
from shield360.rasp._iast_rules import Vuln
from shield360.rasp._iast_scope import IastSlot, arm_iast_slot, close_iast_slot

RASP_VULNERABILITY = "shield360.rasp.vulnerability"
# A fingerprint is reported at most once per this period per process (seconds).
IAST_REPORT_EVERY_S = 60 * 60
# Fingerprints remembered per process; the oldest is forgotten past this.
IAST_MAX_FINGERPRINTS = 10_000
IAST_DEFAULT_RATE = 1.0
IAST_DEFAULT_RATE_PRODUCTION = 0.1

_PRODUCTION = re.compile(r"prod(uction)?", re.IGNORECASE)


@dataclass
class _Seen:
    last_sent: float
    pending: int
    location: str


@dataclass
class _State:  # pylint: disable=too-many-instance-attributes
    env: Optional[str] = None
    env_rate: Optional[float] = None
    local: Optional[bool] = None
    local_rate: Optional[float] = None
    remote: Optional[str] = None
    remote_rate: Optional[float] = None
    config_version: str = "local"
    production: bool = False
    app: str = "default"
    sink: Any = None
    seen: "OrderedDict[str, _Seen]" = field(default_factory=OrderedDict)
    now: Callable[[], float] = time.time
    random: Callable[[], float] = _random.random


_state = _State()
_lock = threading.Lock()


def _as_setting(v: Any) -> Optional[str]:
    if isinstance(v, bool):
        return "on" if v else "off"
    s = v.strip().lower() if isinstance(v, str) else ""
    return s if s in ("on", "off") else None


def _as_rate(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        if not v.strip():
            return None
        try:
            v = float(v)
        except ValueError:
            return None
    if isinstance(v, (int, float)) and v == v and 0 <= v <= 1:  # pylint: disable=comparison-with-itself
        return float(v)
    return None


def configure_iast(
    option: Any = None,
    application_name: str = "default",
    environment: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    now: Optional[Callable[[], float]] = None,
    random: Optional[Callable[[], float]] = None,
) -> None:
    """Reads the local option (``True`` / ``False``, or ``{"enabled", "sample_rate"}``)
    and the environment (``SHIELD360_IAST``, ``SHIELD360_IAST_SAMPLE_RATE``).
    Forgets what was seen. ``now`` (seconds) and ``random`` are for tests."""
    global _state  # pylint: disable=global-statement
    env = os.environ if env is None else env
    o = option
    local: Optional[bool] = None
    local_rate: Optional[float] = None
    if isinstance(o, bool):
        local = o
    elif isinstance(o, dict):
        local = o.get("enabled") is not False
        local_rate = _as_rate(o.get("sample_rate", o.get("sampleRate")))
    names = (env.get("NODE_ENV"), env.get("ENVIRONMENT"), environment)
    _state = _State(
        env=_as_setting(env.get("SHIELD360_IAST")),
        env_rate=_as_rate(env.get("SHIELD360_IAST_SAMPLE_RATE")),
        local=local,
        local_rate=local_rate,
        production=any(_PRODUCTION.fullmatch((v or "").strip()) for v in names),
        app=application_name or "default",
        now=now or time.time,
        random=random or _random.random,
    )


def set_iast_remote(c: Optional[Mapping[str, Any]]) -> None:
    """The verified signed config's ``iast``, ``iastSampleRate`` and ``version`` (None drops them)."""
    c = c or {}
    _state.remote = _as_setting(c.get("iast"))
    _state.remote_rate = _as_rate(c.get("iastSampleRate"))
    v = c.get("version")
    _state.config_version = v if isinstance(v, str) and v else "local"


def set_iast_sink(sink: Any) -> None:
    """Where reports go: the RASP reporter (``add(event, fold_key)`` returning False when it refuses)."""
    _state.sink = sink


def iast_enabled() -> bool:
    """Whether passive IAST is on. Order: ``SHIELD360_IAST=off`` wins; then the
    signed config's ``iast``; then the local option or ``SHIELD360_IAST=on``."""
    if _state.env == "off":
        return False
    if _state.remote:
        return _state.remote == "on"
    return _state.local is True or _state.env == "on"


def iast_sample_rate() -> float:
    """The share of checks that run the IAST rules: env, then the signed config,
    then the option, then 1.0 (0.1 in production)."""
    for r in (_state.env_rate, _state.remote_rate, _state.local_rate):
        if r is not None:
            return r
    return IAST_DEFAULT_RATE_PRODUCTION if _state.production else IAST_DEFAULT_RATE


def begin_iast() -> Optional[IastSlot]:
    """Arms the IAST slot for one check, or returns None: off, not sampled, or
    no request input in scope. ``_engine.check`` calls it only while RASP is active."""
    try:
        if not iast_enabled():
            return None
        ctx = current_context()
        if ctx is None or (not ctx.inputs and ctx.late is None):
            return None
        rate = iast_sample_rate()
        if rate <= 0 or (rate < 1 and _state.random() >= rate):
            return None
        return arm_iast_slot()
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def end_iast(slot: IastSlot, sink: Optional[str] = None, extra: Optional[Mapping[str, Any]] = None) -> None:
    """Disarms the slot. With a sink (the check found no attack), reports the
    vulnerability its detectors noted, if any. Never raises."""
    vuln = close_iast_slot(slot)
    if vuln is None or sink is None:
        return
    try:
        _report(vuln, sink, extra or {})
    except Exception:  # pylint: disable=broad-exception-caught
        pass  # reporting never breaks the call


# Event attributes must pass the platform's shape checks (lib/security/rasp/vulnerabilities.ts); same shapes as _engine.py.
_KEY_CHARS = re.compile(r"[^A-Za-z0-9_.\-\[\]]")
_KEY_START = re.compile(r"^[^A-Za-z0-9_]")
_ROUTE_CHARS = re.compile(r"[^\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]")
_METHOD = re.compile(r"[A-Za-z]{3,10}")
_SINK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:[.:/][A-Za-z0-9_]+)*", re.ASCII)


def _safe_key(k: str) -> str:
    return _KEY_START.sub("_", _KEY_CHARS.sub("_", k))[:128]


def _safe_route(r: str) -> str:
    s = _ROUTE_CHARS.sub("_", r)[:256]
    return s if s.startswith("/") else ""


def _safe_method(m: Any) -> str:
    return m.upper() if isinstance(m, str) and _METHOD.fullmatch(m) else ""


def vuln_fingerprint(route: str, sink: str, input_key: str, rule: str) -> str:
    """The fingerprint: SHA-256 of route, sink, input key and rule (NUL-separated), first 32 hex."""
    return hashlib.sha256("\0".join((route, sink, input_key, rule)).encode("utf-8")).hexdigest()[:32]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _report(v: Vuln, sink: str, extra: Mapping[str, Any]) -> None:  # pylint: disable=too-many-locals
    if not _SINK.fullmatch(sink) or len(sink) > 64:
        return
    ctx = current_context()
    path = extra.get("path") if extra.get("path") is not None else (ctx.path if ctx else None)
    template = extra.get("route") if extra.get("route") is not None else (ctx.route if ctx else None)
    route = _safe_route(template if template is not None else (iast_route_of(path) if path else ""))
    input_key = _safe_key(v.input.key)
    if not input_key:
        return
    fp = vuln_fingerprint(route, sink, input_key, v.rule)
    st = _state
    with _lock:
        now = st.now()
        seen = st.seen.get(fp)
        if seen is not None and now - seen.last_sent < IAST_REPORT_EVERY_S:
            seen.pending += 1
            return
        if seen is None:
            # First sight in this process: the one time the stack is read.
            seen = _Seen(last_sent=float("-inf"), pending=0, location=code_location())
            if len(st.seen) >= IAST_MAX_FINGERPRINTS:
                st.seen.popitem(last=False)
            st.seen[fp] = seen
        # Reserve the report: a concurrent sighting now counts toward the next one instead of sending its own.
        count = seen.pending + 1
        prev_sent = seen.last_sent
        seen.last_sent = now
        seen.pending = 0
    method = extra.get("method") if extra.get("method") is not None else (ctx.method if ctx else None)
    framework = extra.get("framework") if extra.get("framework") is not None else (ctx.framework if ctx else None)
    attrs: Dict[str, str] = {
        "shield360.rasp.kind": "vulnerability",
        "shield360.rasp.event_id": secrets.token_hex(16),
        "shield360.rasp.app": st.app,
        "shield360.rasp.rule": v.rule,
        "shield360.rasp.sink": sink,
        "shield360.rasp.source": "request",
        "shield360.rasp.input_key": input_key,
        "shield360.rasp.config_version": st.config_version,
        "shield360.rasp.language": "python",
        "shield360.rasp.vuln.fingerprint": fp,
        "shield360.rasp.vuln.position": v.position,
        "shield360.rasp.count": str(count),
    }

    def opt(k: str, value: Optional[str]) -> None:
        if value:
            attrs[k] = value

    opt("shield360.rasp.route", route)
    opt("shield360.rasp.method", _safe_method(method))
    opt("shield360.rasp.framework", framework if isinstance(framework, str) else None)
    opt("shield360.rasp.vuln.location", seen.location)
    out = st.sink
    accepted = False
    try:
        if out is not None:
            # No fold key: this module counts repeats itself, so the reporter must not keep a refused event to fold.
            accepted = out.add({"name": RASP_VULNERABILITY, "time": _iso(now), "attrs": attrs}, None) is not False
    finally:
        if not accepted:
            with _lock:
                # Refused (rate limit, full queue) or nowhere to send: keep the sightings and try again at the next one.
                seen.last_sent = prev_sent
                seen.pending += count


def iast_route_of(path: str) -> str:
    """The route of a finding whose framework gave no template: the event route
    (README "Event route"), shared with attack events."""
    return event_route_of(path)


# ---- code location --------------------------------------------------------------

# The SDK's own files: frames there are not the app's.
_SDK_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__))).replace("\\", "/")
_LOCATION_CHARS = re.compile(r"[^A-Za-z0-9_./@+~\-]")


def _runtime_roots() -> tuple:
    """The standard library's directories (real paths: a framework or Homebrew
    build reaches them through symlinks)."""
    paths = [os.path.dirname(os.__file__)]
    for key in ("stdlib", "platstdlib"):
        try:
            paths.append(sysconfig.get_paths().get(key) or "")
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    return tuple(sorted({os.path.realpath(p).replace("\\", "/") for p in paths if p}))


_RUNTIME_ROOTS = _runtime_roots()


def _under(f: str, root: str) -> bool:
    return f == root or f.startswith(root.rstrip("/") + "/")


def is_app_frame(file: str) -> bool:
    """Whether a stack frame's file is the app's own code: not a package
    (``site-packages`` / ``dist-packages``), not the standard library or a
    frozen or generated module, not the SDK."""
    if not file or file.startswith("<"):
        return False
    f = os.path.realpath(file).replace("\\", "/")
    if "/site-packages/" in f or "/dist-packages/" in f:
        return False
    if _under(f, _SDK_ROOT) or any(_under(f, r) for r in _RUNTIME_ROOTS):
        return False
    return f.startswith("/") or re.match(r"[A-Za-z]:/", f) is not None


def format_location(file: str, line: int, cwd: Optional[str] = None) -> str:
    """``path:line``: the path relative to the working directory (only the last
    three segments when outside it), ``/`` as the separator, other characters
    replaced by ``_``, at most 240 characters before the ``:line``."""
    base = cwd if cwd is not None else os.getcwd()
    try:
        rel = os.path.relpath(file, base)
    except ValueError:  # another drive (Windows)
        rel = ""
    rel = rel.replace("\\", "/")
    if rel and not rel.startswith("..") and not rel.startswith("/") and not re.match(r"[A-Za-z]:", rel):
        shown = rel
    else:
        shown = "/".join(re.split(r"[\\/]", file)[-3:])
    return f"{_LOCATION_CHARS.sub('_', shown)[:240]}:{line}"


def code_location(frame: Any = None) -> str:
    """The top stack frame in the app's own code (outside packages, the
    standard library and the SDK), as ``path:line``, or '' when there is none."""
    try:
        f = frame if frame is not None else sys._getframe(1)  # pylint: disable=protected-access
        depth = 0
        while f is not None and depth < 256:
            file = f.f_code.co_filename
            if is_app_frame(file):
                return format_location(os.path.abspath(file), f.f_lineno)
            f = f.f_back
            depth += 1
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return ""


def reset_iast() -> None:
    """Forgets every fingerprint seen and the configuration (tests, re-init)."""
    global _state  # pylint: disable=global-statement
    _state = _State()
