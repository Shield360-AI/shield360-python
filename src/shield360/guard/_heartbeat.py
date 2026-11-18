"""
Guard heartbeat: tells Shield360 which guards this app runs, in which mode.

Guard reports (``_report.py``) carry only what a guard acted on, so an app
whose guards had nothing to stop looks the same as one with no guards. When
``shield360.init`` is given guards and a Shield360 URL and API key, the SDK
also sends a heartbeat once at start and then about every five minutes
(jittered): the app's service name, each guard kind's mode (off, warn or
block), whether prompt-injection checks are on, and the SDK's name and
version. Never any text, host or user. It goes through the same queue and
transport as guard reports and never raises.

Turn it off with ``guard_heartbeat=False`` in ``init``, or
``SHIELD360_GUARD_HEARTBEAT=false``.

Must stay in sync with: sdk/typescript/src/guard/heartbeat.ts
"""

from __future__ import annotations

import json
import os
import random
import re
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

HEARTBEAT_EVENT_NAME = "shield360.guard.heartbeat"
HEARTBEAT_INTERVAL_SECONDS = 5 * 60
HEARTBEAT_JITTER = 0.2
SDK_HEARTBEAT_NAME = "shield360-python"

_RANK = {"off": 0, "warn": 1, "block": 2}
_KIND = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def mode_of(action: Any) -> str:
    """deny and redact keep data from the model (block), warn warns, allow does nothing."""
    value = getattr(action, "value", action)
    if value in ("deny", "redact"):
        return "block"
    if value == "warn":
        return "warn"
    return "off"


def guard_modes(guards: Iterable[Any]) -> Dict[str, str]:
    """Each guard kind's mode, the strongest when one kind is configured twice."""
    modes: Dict[str, str] = {}
    for guard in guards or []:
        try:
            kind = str(getattr(guard, "name", "") or "").lower()
            if not _KIND.match(kind):
                continue
            mode = mode_of(guard.action)
            if kind not in modes or _RANK[mode] > _RANK[modes[kind]]:
                modes[kind] = mode
        except Exception:  # pylint: disable=broad-exception-caught
            continue
    return modes


def heartbeat_attrs(guards: Iterable[Any], app: str, sdk_version: str) -> Dict[str, str]:
    """The heartbeat's attributes."""
    modes = guard_modes(guards)
    injection = modes.get("prompt_injection", "off") != "off"
    return {
        "shield360.guard.app": app,
        "shield360.guard.modes": json.dumps(modes, separators=(",", ":")),
        "shield360.guard.injection": "true" if injection else "false",
        "shield360.sdk.name": SDK_HEARTBEAT_NAME,
        "shield360.sdk.version": sdk_version,
    }


def next_delay(rand: Callable[[], float] = random.random) -> float:
    """The interval give or take the jitter, in seconds."""
    return HEARTBEAT_INTERVAL_SECONDS * (1 + (rand() * 2 - 1) * HEARTBEAT_JITTER)


def heartbeat_enabled(option: Optional[bool], env: Optional[Mapping[str, str]] = None) -> bool:
    """On unless the option or the environment turns it off."""
    if option is False:
        return False
    value = ((env if env is not None else os.environ).get("SHIELD360_GUARD_HEARTBEAT") or "").strip().lower()
    return value not in ("false", "0", "no", "off")
