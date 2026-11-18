"""AI security events, sent to Shield360 (POST /api/ai-security/events) in
batches from a background thread, off the call path. Never the text that was
checked: the check, the kind, mode and action, the app, the end customer (ids
as given; the platform keeps user ids only as a keyed hash) and per finding a
kind, a masked token and a keyed fingerprint. Identical events inside a few
seconds are counted into one.

Must stay in sync with: sdk/typescript/src/ai-security/events.ts
"""

from __future__ import annotations

import json
import socket
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from shield360._customer import get_customer
from shield360._trace_ids import trace_attrs, without_trace

AI_SECURITY_EVENT = "shield360.ai_security.event"
_BATCH = 100
_FLUSH_SECONDS = 2.0
_MAX_QUEUED = 5000
_ATTEMPTS = 3
_DEDUPE_SECONDS = 5.0
_MAX_DETAIL = 1000


def _wire(app: str, event: Dict[str, Any], at: float) -> Dict[str, Any]:
    attrs: Dict[str, Any] = {
        "shield360.ai_security.event_id": uuid.uuid4().hex,
        "shield360.ai_security.app": app,
        "shield360.ai_security.check": event["check"],
        "shield360.ai_security.kind": event["kind"],
        "shield360.ai_security.mode": event["mode"],
        "shield360.ai_security.action": event["action"],
        "shield360.ai_security.count": event.get("count") or 1,
        # SHIELD: security event trace ids — the request this check ran in.
        **trace_attrs("shield360.ai_security."),
    }

    def put(k: str, v: Any) -> None:
        if v is None or v == "":
            return
        attrs[f"shield360.ai_security.{k}"] = v if isinstance(v, (int, float, bool)) else str(v)[:_MAX_DETAIL]

    put("source", event.get("source"))
    if isinstance(event.get("score"), (int, float)):
        put("score", round(event["score"], 3))
    put("rules", ",".join(event.get("rules") or []))
    put("categories", ",".join(event.get("categories") or []))
    put("rules_version", event.get("rules_version"))
    put("tool", event.get("tool"))
    put("server", event.get("server"))
    put("detail", event.get("detail"))
    findings = (event.get("findings") or [])[:10]
    if findings:
        put("findings", json.dumps(findings))
        put("fingerprints", ",".join(f["fingerprint"] for f in findings if f.get("fingerprint")))
    c = get_customer()
    if c:
        attrs["shield360.customer.tenant_id"] = c["tenant_id"]
        if c.get("user_id"):
            attrs["shield360.customer.user_id"] = c["user_id"]
    return {
        "name": AI_SECURITY_EVENT,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(at)) + f".{int(at * 1000) % 1000:03d}Z",
        "attrs": attrs,
    }


class MemorySink:
    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def add(self, event: Dict[str, Any]) -> None:
        if len(self.events) < 10_000:
            self.events.append(event)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class EventReporter:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        url: str,
        api_key: str,
        app: str,
        environment: str,
        post: Optional[Callable[[str, Dict[str, str], bytes], int]] = None,
        now: Callable[[], float] = time.time,
    ):
        self._endpoint = url.rstrip("/") + "/api/ai-security/events"
        self._api_key = api_key
        self._app = app
        self._environment = environment
        self._post_fn = post or _http_post
        self._now = now
        self._queue: List[Dict[str, Any]] = []
        self._recent: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="shield360-ai-security-events", daemon=True)
        self._thread.start()

    def add(self, event: Dict[str, Any]) -> None:
        try:
            c = get_customer() or {}
            key = "|".join(
                str(x)
                for x in (
                    event["check"],
                    event["kind"],
                    event["action"],
                    event.get("tool", ""),
                    event.get("server", ""),
                    c.get("tenant_id", ""),
                    c.get("user_id", ""),
                )
            )
            at = self._now()
            with self._lock:
                seen = self._recent.get(key)
                if seen and at - seen["at"] < _DEDUPE_SECONDS and seen["wire"] in self._queue:
                    seen["wire"]["attrs"]["shield360.ai_security.count"] += event.get("count") or 1
                    seen["wire"]["attrs"] = without_trace(seen["wire"]["attrs"], "shield360.ai_security.")
                    return
                if len(self._queue) >= _MAX_QUEUED:
                    return
                wire = _wire(self._app, event, at)
                self._queue.append(wire)
                self._recent[key] = {"wire": wire, "at": at}
                if len(self._recent) > 2000:
                    self._recent.clear()
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _run(self) -> None:
        while not self._stop.wait(_FLUSH_SECONDS):
            self.flush()

    def flush(self) -> None:
        while True:
            with self._lock:
                batch, self._queue = self._queue[:_BATCH], self._queue[_BATCH:]
            if not batch:
                return
            body = json.dumps(
                {
                    "resource": {
                        "host.name": socket.gethostname(),
                        "deployment.environment": self._environment,
                        "service.name": self._app,
                    },
                    "events": batch,
                }
            ).encode()
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self._api_key}"}
            for attempt in range(_ATTEMPTS):
                try:
                    status = self._post_fn(self._endpoint, headers, body)
                    if 200 <= status < 300 or status in (400, 401, 403, 413):
                        break
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
                time.sleep(0.3 * (attempt + 1))

    def close(self) -> None:
        self._stop.set()
        self.flush()


def _http_post(url: str, headers: Dict[str, str], body: bytes) -> int:
    import requests  # pylint: disable=import-outside-toplevel

    return requests.post(url, headers=headers, data=body, timeout=5).status_code
