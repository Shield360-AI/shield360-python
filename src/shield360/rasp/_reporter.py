"""RASP event reporter (README "Events"). Batches ``shield360.rasp.event`` and
``shield360.rasp.component`` records to ``POST /api/guard/events`` through the
guard reporter's transport (``guard/_report.py`` ``post_guard_events``), off
the call path. At most 100 events a minute per process; repeats of the same
(attack, rule, sink, route, decision) within 10 s fold into one more event
carrying ``shield360.rasp.count``. Events name locations, never values."""

from __future__ import annotations

import platform
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .._trace_ids import trace_attrs, without_trace

RASP_EVENT = "shield360.rasp.event"
RASP_COMPONENT = "shield360.rasp.component"
PER_MINUTE = 100
FOLD_S = 10.0
_FLUSH_S = 2.0
_MAX_QUEUED = 1000
MAX_COMPONENTS = 500
_BATCH = 100


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class RaspReporter:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        url: str,
        api_key: str,
        application_name: str,
        environment: Optional[str] = None,
        sdk_version: Optional[str] = None,
        urlopen: Optional[Any] = None,
        now: Optional[Callable[[], float]] = None,
        retry_delay: float = 0.5,
    ):
        self._endpoint = url.rstrip("/") + "/api/guard/events"
        self._api_key = api_key
        self._application_name = application_name
        self._urlopen = urlopen
        self._retry_delay = retry_delay
        self._now = now or time.time
        self._queue: List[Dict[str, Any]] = []
        self._folds: Dict[str, Dict[str, Any]] = {}
        self._window_start = float("-inf")
        self._sent_in_window = 0
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.resource: Dict[str, str] = {"service.name": application_name}
        host = _safe_host()
        if host:
            self.resource["host.name"] = host
        if environment:
            self.resource["deployment.environment"] = environment
        if sdk_version:
            self.resource["service.version"] = sdk_version

    def start(self) -> None:
        if self._thread is not None:
            return

        def run() -> None:
            while not self._stop.wait(_FLUSH_S):
                self.flush()
            # Stopped: the last flush (open folds included) happens here, never on the caller's thread.
            self.flush(True)

        self._thread = threading.Thread(target=run, name="shield360-rasp-report", daemon=True)
        self._thread.start()

    def add(self, event: Dict[str, Any], fold_key: Optional[str]) -> bool:
        """Queues an event, folding repeats of the same key. Returns whether it
        was queued now. ``fold_key`` None queues without folding: the caller
        keeps its own count (passive IAST), so a refused event leaves nothing
        behind to be sent later."""
        # SHIELD: security event trace ids — read now, while the request's span is active.
        if event.get("name") == "shield360.rasp.event" and "shield360.rasp.trace_id" not in event.get("attrs", {}):
            ids = trace_attrs("shield360.rasp.")
            if ids:
                event = {**event, "attrs": {**event["attrs"], **ids}}
        with self._lock:
            now = self._now()
            self._close_folds(now)
            if fold_key is None:
                return self._enqueue(event, now)
            f = self._folds.get(fold_key)
            if f is not None and now < f["until"]:
                f["extra"] += 1
                return False
            self._folds[fold_key] = {"event": event, "extra": 0, "until": now + FOLD_S}
            return self._enqueue(event, now)

    def _enqueue(self, event: Dict[str, Any], now: float) -> bool:
        if now - self._window_start >= 60:
            self._window_start = now
            self._sent_in_window = 0
        if self._sent_in_window >= PER_MINUTE or len(self._queue) >= _MAX_QUEUED:
            return False
        self._sent_in_window += 1
        self._queue.append(event)
        return True

    def _close_folds(self, now: float) -> None:
        for k in list(self._folds):
            f = self._folds[k]
            if now < f["until"]:
                continue
            del self._folds[k]
            if f["extra"] > 0:
                at = now if now != float("inf") else self._now()
                ev = f["event"]
                attrs = {**without_trace(ev["attrs"], "shield360.rasp."), "shield360.rasp.count": str(f["extra"])}
                self._enqueue({**ev, "time": _iso(at), "attrs": attrs}, at)

    def pending(self) -> List[Dict[str, Any]]:
        """Queued events (tests)."""
        with self._lock:
            return list(self._queue)

    def flush(self, force: bool = False) -> None:
        """Sends what is queued; ``force`` also closes every open fold. Never raises."""
        from shield360.guard._report import post_guard_events

        try:
            with self._send_lock:
                with self._lock:
                    self._close_folds(float("inf") if force else self._now())
                while True:
                    with self._lock:
                        batch = self._queue[:_BATCH]
                        del self._queue[:_BATCH]
                    if not batch:
                        return
                    post_guard_events(
                        self._endpoint,
                        self._api_key,
                        {"resource": self.resource, "events": batch},
                        label="runtime protection event",
                        retry_delay=self._retry_delay,
                        urlopen=self._urlopen,
                    )
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def report_components(self, components: List[Dict[str, str]]) -> None:
        """Queues the components report: names and versions only, at most 500."""
        time_s = _iso(self._now())
        with self._lock:
            for c in components[:MAX_COMPONENTS]:
                if len(self._queue) >= _MAX_QUEUED:
                    break
                self._queue.append(
                    {
                        "name": RASP_COMPONENT,
                        "time": time_s,
                        "attrs": {
                            "shield360.rasp.app": self._application_name,
                            "shield360.rasp.component.ecosystem": c["ecosystem"],
                            "shield360.rasp.component.name": c["name"],
                            "shield360.rasp.component.version": c["version"],
                        },
                    }
                )

    def stop(self, wait: Optional[float] = None) -> None:
        """Stops the reporter. What is queued is sent by the reporter's own
        daemon thread, so stopping never waits on the network (``init_rasp``
        calls this). ``wait`` joins that thread for at most so many seconds."""
        self._stop.set()
        if self._thread is None:
            self._thread = threading.Thread(target=lambda: self.flush(True), name="shield360-rasp-report", daemon=True)
            self._thread.start()
        if wait is not None:
            self._thread.join(wait)


def _safe_host() -> str:
    try:
        return socket.gethostname()
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


_PACKAGE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._\-]{0,213}")
_VERSION = re.compile(r"v?[0-9A-Za-z][0-9A-Za-z.+_~\-]{0,63}")


def collect_components(modules: Optional[Dict[str, Any]] = None, distributions: Optional[List[Any]] = None) -> List[Dict[str, str]]:
    """The runtime, the distributions of every module imported so far, then
    the other installed distributions. Names and versions only; at most 500."""
    from importlib import metadata

    out: List[Dict[str, str]] = [{"ecosystem": "runtime", "name": "python", "version": platform.python_version()}]
    seen = set()

    def push(name: Any, version: Any) -> None:
        if not isinstance(name, str) or not isinstance(version, str):
            return
        if not _PACKAGE.fullmatch(name) or not _VERSION.fullmatch(version):
            return
        ident = f"{name.lower()}@{version}"
        if ident in seen or len(out) >= MAX_COMPONENTS:
            return
        seen.add(ident)
        out.append({"ecosystem": "pypi", "name": name, "version": version})

    dists = distributions
    if dists is None:
        try:
            dists = list(metadata.distributions())
        except Exception:  # pylint: disable=broad-exception-caught
            dists = []
    by_name: Dict[str, Any] = {}
    for d in dists:
        try:
            name = d.metadata["Name"]
        except Exception:  # pylint: disable=broad-exception-caught
            continue
        if isinstance(name, str):
            by_name.setdefault(name.lower(), d)
    loaded = sys.modules if modules is None else modules
    try:
        owners = metadata.packages_distributions()
    except Exception:  # pylint: disable=broad-exception-caught
        owners = {}
    for top in sorted({m.split(".")[0] for m in list(loaded)}):
        for dist_name in owners.get(top, []):
            d = by_name.get(dist_name.lower())
            if d is not None:
                push(d.metadata["Name"], d.version)
    for d in dists:
        try:
            push(d.metadata["Name"], d.version)
        except Exception:  # pylint: disable=broad-exception-caught
            continue
    return out
