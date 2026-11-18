"""SHIELD: runtime SCA — the packages this process runs, reported to Shield360
so it can match them against vulnerability data server-side (Security → Code,
target type "runtime").

On by default whenever ``init`` has a Shield360 URL and API key, whether or not
runtime protection is on; ``init(runtime_packages=False)`` or
``SHIELD360_RUNTIME_PACKAGES=off`` turns it off. The report is the same
``shield360.rasp.component`` record runtime protection sends
(``rasp/_reporter.py`` ``collect_components``: the Python version, the
distributions of every module imported so far, then the other installed
distributions, read with ``importlib.metadata``), on the same route
(``POST /api/guard/events``, the app's API key). Names and versions only, never
a path; at most ``MAX_COMPONENTS``. Sent once shortly after start, so modules
imported lazily are in it, and then every day, from a daemon thread; a report
that cannot be delivered is dropped.

Must stay in step with sdk/typescript/src/runtime-packages.ts.
"""

from __future__ import annotations

import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional

from shield360.guard._report import post_guard_events
from shield360.rasp._reporter import MAX_COMPONENTS, RASP_COMPONENT, _safe_host, collect_components

START_DELAY_S = 15.0
EVERY_S = 24 * 60 * 60.0
_BATCH = 100
_OFF = re.compile(r"^(off|false|0|no)$", re.IGNORECASE)

_lock = threading.Lock()
_stop: Optional[threading.Event] = None


def runtime_packages_enabled(option: Optional[bool], env: Optional[Mapping[str, str]] = None) -> bool:
    """Whether the report runs: ``option=False`` or SHIELD360_RUNTIME_PACKAGES=off|false|0|no turns it off."""
    if option is False:
        return False
    env = os.environ if env is None else env
    return not _OFF.match(str(env.get("SHIELD360_RUNTIME_PACKAGES", "")).strip())


def runtime_packages_active() -> bool:
    """Whether the report is running (runtime protection then leaves its components report to it)."""
    return _stop is not None


def report_runtime_packages(
    url: Optional[str],
    api_key: Optional[str],
    application_name: str,
    environment: Optional[str] = None,
    sdk_version: Optional[str] = None,
    collect: Optional[Callable[[], List[Dict[str, str]]]] = None,
    urlopen: Any = None,
    retry_delay: float = 0.5,
) -> bool:
    """Sends one report now. Returns whether every batch was accepted; never raises."""
    if not url or not api_key:
        return False
    try:
        components = (collect or collect_components)()[:MAX_COMPONENTS]
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    time = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    events = [
        {
            "name": RASP_COMPONENT,
            "time": time,
            "attrs": {
                "shield360.rasp.app": application_name,
                "shield360.rasp.component.ecosystem": c["ecosystem"],
                "shield360.rasp.component.name": c["name"],
                "shield360.rasp.component.version": c["version"],
            },
        }
        for c in components
    ]
    resource: Dict[str, str] = {"service.name": application_name}
    host = _safe_host()
    if host:
        resource["host.name"] = host
    if environment:
        resource["deployment.environment"] = environment
    if sdk_version:
        resource["service.version"] = sdk_version
    endpoint = url.rstrip("/") + "/api/guard/events"
    for i in range(0, len(events), _BATCH):
        try:
            sent = post_guard_events(
                endpoint,
                api_key,
                {"resource": resource, "events": events[i : i + _BATCH]},
                label="runtime package report",
                retry_delay=retry_delay,
                urlopen=urlopen,
            )
        except Exception:  # pylint: disable=broad-exception-caught
            return False
        if not sent:
            return False
    return True


def start_runtime_packages(  # pylint: disable=too-many-arguments
    url: Optional[str],
    api_key: Optional[str],
    application_name: str,
    environment: Optional[str] = None,
    sdk_version: Optional[str] = None,
    option: Optional[bool] = None,
    env: Optional[Mapping[str, str]] = None,
    start_delay: float = START_DELAY_S,
    every: float = EVERY_S,
    collect: Optional[Callable[[], List[Dict[str, str]]]] = None,
    urlopen: Any = None,
) -> bool:
    """Starts the report: once after ``start_delay`` seconds, then every ``every``. Idempotent; a daemon thread."""
    global _stop  # pylint: disable=global-statement
    if not url or not api_key or not runtime_packages_enabled(option, env):
        return False
    with _lock:
        if _stop is not None:
            return False
        stop = threading.Event()
        _stop = stop

    def run() -> None:
        if stop.wait(start_delay):
            return
        while True:
            report_runtime_packages(url, api_key, application_name, environment, sdk_version, collect=collect, urlopen=urlopen)
            if stop.wait(every):
                return

    threading.Thread(target=run, name="shield360-runtime-packages", daemon=True).start()
    return True


def stop_runtime_packages() -> None:
    """Stops the report (tests, re-init)."""
    global _stop  # pylint: disable=global-statement
    with _lock:
        stop, _stop = _stop, None
    if stop is not None:
        stop.set()
