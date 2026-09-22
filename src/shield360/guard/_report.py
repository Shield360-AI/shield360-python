"""
Reports guard decisions to Shield360 as compliance evidence.

When ``shield360.init`` is given a Shield360 URL and API key (or
``SHIELD360_URL`` / ``SHIELD360_API_KEY``), every guard decision other than
*allow* is sent to ``/api/guard/events``: which guard, what it did, the kind of
data found, in which app, on which host. Never the text that was checked.

With each report go the values found, masked, and fingerprinted with the
organisation's key (fetched from ``/api/guard/config``), so a reviewer can see
the same value recurring. The full value is never sent.

Delivery runs on a background thread, in batches, so a guard adds no network
time to the call it protects. A report that cannot be delivered is retried a
few times and then dropped; the decision itself has already been enforced.
Without a URL and key nothing is sent.
"""

from __future__ import annotations

import atexit
import getpass
import json
import logging
import queue
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

EVENT_NAME = "shield360.guard.decision"
_BATCH = 100
_FLUSH_SECONDS = 2.0
_MAX_QUEUED = 5000
_ATTEMPTS = 3


class _Reporter:
    def __init__(self, url: str, api_key: str, resource: Dict[str, Any], application_name: str):
        self.application_name = application_name
        self._endpoint = url.rstrip("/") + "/api/guard/events"
        self._api_key = api_key
        self._resource = resource
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=_MAX_QUEUED)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="shield360-guard-report", daemon=True)
        self._thread.start()

    def add(self, event: Dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.warning("Shield360 guard report queue is full; a report was dropped")

    def _drain(self) -> List[Dict[str, Any]]:
        batch: List[Dict[str, Any]] = []
        while len(batch) < _BATCH:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _post(self, batch: List[Dict[str, Any]]) -> None:
        body = json.dumps({"resource": self._resource, "events": batch}).encode()
        for attempt in range(_ATTEMPTS):
            req = urllib.request.Request(
                self._endpoint,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"},
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    if 200 <= resp.status < 300:
                        return
            except urllib.error.HTTPError as e:
                if e.code in (400, 401, 403, 413):
                    logger.warning("Shield360 rejected guard reports: HTTP %s", e.code)
                    return
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            time.sleep(0.5 * (attempt + 1))
        logger.warning("Could not deliver %d guard report(s) to Shield360", len(batch))

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(_FLUSH_SECONDS)
            self.flush()

    def flush(self) -> None:
        while True:
            batch = self._drain()
            if not batch:
                return
            self._post(batch)

    def close(self) -> None:
        self._stop.set()
        self.flush()


_reporter: Optional[_Reporter] = None
_lock = threading.Lock()


def configure(
    url: Optional[str],
    api_key: Optional[str],
    application_name: str,
    environment: str,
    sdk_version: str = "",
) -> bool:
    """Start reporting when both a URL and a key are given. Returns whether it did."""
    global _reporter  # pylint: disable=global-statement
    if not url or not api_key:
        return False
    try:
        user = getpass.getuser()
    except Exception:  # pylint: disable=broad-exception-caught
        user = ""
    resource = {
        "host.name": socket.gethostname(),
        "user.name": user,
        "deployment.environment": environment,
        "service.version": sdk_version,
    }
    with _lock:
        if _reporter is not None:
            _reporter.close()
        _reporter = _Reporter(url, api_key, {k: v for k, v in resource.items() if v}, application_name)
    # The organisation's fingerprint key: fetched now, briefly, so the first
    # guard decisions are fingerprinted too; retried in the background if the
    # platform does not answer in time.
    if not _fetch_key(url, api_key, timeout=2):
        threading.Thread(target=_retry_key, args=(url, api_key), name="shield360-guard-key", daemon=True).start()
    atexit.register(_reporter.close)
    return True


def report(
    guard_name: str,
    action: str,
    classification: str,
    phase: str,
    findings: Optional[List[Dict[str, str]]] = None,
) -> None:
    """Queue one decision. Allow decisions are not evidence of anything."""
    reporter = _reporter
    if reporter is None or action == "allow":
        return
    kinds = ",".join(k.strip() for k in (classification or "").split(",") if k.strip())
    findings = [f for f in (findings or []) if isinstance(f, dict)][:10]
    fingerprints = ",".join(f["fingerprint"] for f in findings if f.get("fingerprint"))
    reporter.add(
        {
            "name": EVENT_NAME,
            "time": datetime.now(timezone.utc).isoformat(),
            "attrs": {
                "shield360.guard.event_id": uuid.uuid4().hex,
                "shield360.guard.client": reporter.application_name,
                "shield360.guard.action": action,
                "shield360.guard.target": phase,
                "shield360.guard.kinds": kinds,
                "shield360.guard.name": guard_name,
                "shield360.guard.findings": json.dumps(findings) if findings else "",
                "shield360.guard.fingerprints": fingerprints,
            },
        }
    )


def _fetch_key(url: str, api_key: str, timeout: float = 10) -> bool:
    """Fetch and set the organisation's fingerprint key. Returns whether it did."""
    from shield360.guard import _findings

    req = urllib.request.Request(
        url.rstrip("/") + "/api/guard/config",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            key = json.loads(resp.read() or b"{}").get("fingerprintKey")
            if isinstance(key, str) and key:
                _findings.set_key(key)
                return True
    except Exception:  # pylint: disable=broad-exception-caught
        logger.debug("No fingerprint key from Shield360 yet; findings are masked only")
    return False


def _retry_key(url: str, api_key: str) -> None:
    for delay in (5, 30, 120, 600):
        time.sleep(delay)
        if _fetch_key(url, api_key):
            return


def flush() -> None:
    """Send everything queued now (tests, and short-lived scripts)."""
    reporter = _reporter
    if reporter is not None:
        reporter.flush()
