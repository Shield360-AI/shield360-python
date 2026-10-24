"""
Shield Protect -- the enforcement mode of this process.

    observe    every check runs and its finding is recorded (span event,
               decision report); nothing is refused. For seeing what enforced
               mode would stop before turning it on.
    warn       as observe, and the finding is logged as a warning.
    enforced   a finding refuses the call; a guard that raises refuses the
               call (fail closed, whatever ``guard_fail_open`` says); a
               provider named in ``required`` that could not be wrapped stops
               startup; a streamed completion that postflight guards cannot
               inspect is refused; input past the scan bound is refused rather
               than scanned in part.

The mode set in code is a floor: ``SHIELD360_PROTECT_MODE`` can raise it and
never lower it, so an environment variable in a shell or a container cannot
weaken what the application was deployed with. With no mode set anywhere,
guards behave as they always have (each guard's own action, ``guard_fail_open``
as given): that is ``legacy``, and nothing changes for an application that
never asked for Protect.

What this layer can and cannot claim: it runs inside the application's
process. Code that can disable the SDK, import a provider the SDK does not
wrap, or reach a network directly is not stopped by it. The mandatory boundary
is the Shield360 gateway; this layer is monitored or partially protected, and
its readiness report says so.

Must stay in sync with: sdk/typescript/src/protect/mode.ts
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Mapping, Optional

PROTECT_MODES = ("observe", "warn", "enforced")
_RANK = {"observe": 0, "warn": 1, "enforced": 2}

PROTECT_MODE_ENV = "SHIELD360_PROTECT_MODE"
PROTECT_REQUIRED_ENV = "SHIELD360_PROTECT_REQUIRED"


def is_protect_mode(value: object) -> bool:
    """Whether ``value`` names a mode."""
    return isinstance(value, str) and value in PROTECT_MODES


def strictest_mode(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """The stricter of two modes; ``None`` counts as nothing."""
    if not a:
        return b
    if not b:
        return a
    return a if _RANK[a] >= _RANK[b] else b


def resolve_protect_mode(from_code: Optional[str], env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The mode this process runs under: the code's, raised by the environment when it asks for more.

    An environment value that is not a mode is ignored, never a downgrade; a
    code value that is not a mode is refused.
    """
    if from_code is not None and not is_protect_mode(from_code):
        raise ValueError(f"protect mode must be one of {', '.join(PROTECT_MODES)}; got {from_code!r}")
    env = os.environ if env is None else env
    raw = (env.get(PROTECT_MODE_ENV) or "").strip().lower()
    from_env = raw if is_protect_mode(raw) else None
    return strictest_mode(from_code, from_env)


def resolve_required(from_code: Optional[List[str]], env: Optional[Mapping[str, str]] = None) -> List[str]:
    """Providers that must be wrapped: the code's list plus the environment's."""
    env = os.environ if env is None else env
    from_env = [s.strip() for s in (env.get(PROTECT_REQUIRED_ENV) or "").split(",") if s.strip()]
    seen: List[str] = []
    for name in list(from_code or []) + from_env:
        if name not in seen:
            seen.append(name)
    return seen


@dataclass
class ResolvedProtect:
    """What init() decided: the mode (None: legacy) and the required providers."""

    mode: Optional[str] = None
    required: List[str] = field(default_factory=list)


def resolve_protect(config: Optional[Mapping[str, object]], env: Optional[Mapping[str, str]] = None) -> ResolvedProtect:
    """``{"mode": ..., "required": [...]}`` from init(), merged with the environment."""
    config = config or {}
    mode = config.get("mode")
    required = config.get("required")
    return ResolvedProtect(
        mode=resolve_protect_mode(mode if isinstance(mode, str) else None, env),
        required=resolve_required(list(required) if isinstance(required, (list, tuple)) else None, env),
    )


def refuses(mode: Optional[str]) -> bool:
    """Whether a mode turns a finding into a refusal."""
    return mode == "enforced"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProtectError(Exception):
    """Base error for Shield Protect."""


class ProtectDeniedError(ProtectError):
    """A call refused for a reason that is not a guard finding: oversized input, uninspectable streaming, a failed check."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class ProtectReadinessError(ProtectError):
    """Enforced mode could not be set up: a required provider is not wrapped, or guards are missing. Raised from init()."""

    def __init__(self, missing: List[str], message: str):
        self.missing = list(missing)
        super().__init__(message)


# ---------------------------------------------------------------------------
# Readiness: what this process can honestly claim
# ---------------------------------------------------------------------------

_state = {"mode": None, "wrapped": [], "missing": []}


def set_protect_state(mode: Optional[str], wrapped: List[str], missing: List[str]) -> None:
    """Internal: what setup_auto_guards found."""
    _state["mode"] = mode
    _state["wrapped"] = list(wrapped)
    _state["missing"] = list(missing)


def current_protect_mode() -> Optional[str]:
    """Internal: the process's mode (None: legacy)."""
    return _state["mode"]


def reset_protect_state() -> None:
    """Internal, for tests."""
    set_protect_state(None, [], [])


def protect_readiness() -> dict:
    """What this process can claim. Never "enforced": that is the gateway's claim."""
    mode = _state["mode"] or "legacy"
    partial = mode == "enforced" and not _state["missing"] and bool(_state["wrapped"])
    return {
        "mode": mode,
        "wrapped": list(_state["wrapped"]),
        "missing": list(_state["missing"]),
        "level": "partially_protected" if partial else "monitored",
        "note": (
            "Supported provider calls in this process are refused before they leave when a guard finds a violation, "
            "and fail closed. Code in this process that bypasses the SDK is not covered; "
            "the mandatory boundary is the Shield360 gateway."
            if partial
            else "Findings are recorded; calls are not refused by this layer. The mandatory boundary is the Shield360 gateway."
        ),
    }
