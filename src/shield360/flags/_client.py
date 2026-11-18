"""Shield360 feature flags: fetch an environment's flags, evaluate them locally.

A background thread polls GET /api/flags/rules (every 30 seconds by default,
with jitter, sending the last ETag so an unchanged environment costs a 304)
and keeps the rules in memory; evaluation uses the same engine as the server
and the other SDKs (``_engine``). Nothing here raises into the app: until rules
arrive, for an unknown flag, or on any error, the caller's default is returned.

Each evaluation sets ``shield360.flag.<key>`` = the served variation's key on
the current span, so cost, latency and evals can be compared per variant.
"""

import logging
import os
import random
import threading
from typing import Any, Callable, Dict, List, Optional

from opentelemetry import trace

from shield360._config import Shield360Config
from shield360.flags import _engine

logger = logging.getLogger(__name__)

RULES_PATH = "/api/flags/rules"
SPAN_ATTRIBUTE_PREFIX = "shield360.flag."
DEFAULT_POLL_INTERVAL = 30.0
_MIN_POLL_INTERVAL = 5.0
_DEFAULT_TIMEOUT = 10.0


def _same_kind(value, default) -> bool:
    if default is None:
        return True
    if isinstance(default, bool) or isinstance(value, bool):
        return isinstance(default, bool) and isinstance(value, bool)
    if isinstance(default, (int, float)):
        return isinstance(value, (int, float))
    if isinstance(default, str):
        return isinstance(value, str)
    if isinstance(default, (dict, list)):
        return isinstance(value, (dict, list))
    return True


class FlagsClient:  # pylint: disable=too-many-instance-attributes
    """Polls one environment's flags and evaluates them locally. Thread-safe."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        application_name: Optional[str] = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
        timeout: float = _DEFAULT_TIMEOUT,
        record_on_span: bool = True,
        http_get: Optional[Callable[..., Any]] = None,
    ):
        self._url = url
        self._api_key = api_key
        self._application_name = application_name
        self._poll_interval = max(float(poll_interval), _MIN_POLL_INTERVAL)
        self._timeout = timeout
        self._record_on_span = record_on_span
        self._http_get = http_get
        self._flags: Dict[str, Dict[str, Any]] = {}
        self._segments: List[Dict[str, Any]] = []
        self._etag: Optional[str] = None
        self._ready = threading.Event()
        self._lock = threading.Lock()
        self._fetch_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._warned = False

    # ------------------------------------------------------------ settings

    def configure(self, **options) -> None:
        """Changes url, api_key, application_name, poll_interval, timeout or record_on_span."""
        for name, value in options.items():
            if name == "poll_interval":
                self._poll_interval = max(float(value), _MIN_POLL_INTERVAL)
            elif name in ("url", "api_key", "application_name", "timeout", "record_on_span", "http_get"):
                setattr(self, "_" + name, value)

    def _destination(self):
        url = self._url or getattr(Shield360Config, "shield360_url", None) or os.getenv("SHIELD360_URL") or ""
        api_key = self._api_key or getattr(Shield360Config, "shield360_api_key", None) or os.getenv("SHIELD360_API_KEY") or ""
        url, api_key = url.strip().rstrip("/"), api_key.strip()
        return (url, api_key) if url and api_key else None

    def _app(self) -> Optional[str]:
        return self._application_name or getattr(Shield360Config, "application_name", None)

    # ------------------------------------------------------------- polling

    def start(self) -> None:
        """Starts the polling thread (once). Called on first use."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, name="shield360-flags", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            # +/-10% jitter, so many processes started together do not poll together.
            delay = self._poll_interval * (0.9 + random.random() * 0.2)  # nosec B311 - jitter, not security
            if self._stop.wait(delay):
                return

    def close(self) -> None:
        """Stops polling. Rules already fetched keep being served."""
        self._stop.set()

    def is_ready(self) -> bool:
        return self._ready.is_set()

    def wait_until_ready(self, timeout: float = _DEFAULT_TIMEOUT) -> bool:
        """Blocks until rules have been fetched once, or ``timeout`` seconds pass."""
        self.start()
        return self._ready.wait(timeout)

    def _get(self, url: str, headers: Dict[str, str]):
        if self._http_get is not None:
            return self._http_get(url, headers=headers, timeout=self._timeout)
        import requests  # pylint: disable=import-outside-toplevel

        return requests.get(url, headers=headers, timeout=self._timeout)

    def refresh(self) -> bool:
        """Fetches the rules now. True when they are current; never raises."""
        with self._fetch_lock:
            try:
                return self._fetch()
            except Exception as error:  # pylint: disable=broad-exception-caught
                logger.debug("shield360 flags: rules fetch failed: %s", type(error).__name__)
                return False

    def _fetch(self) -> bool:
        dest = self._destination()
        if dest is None:
            if not self._warned:
                self._warned = True
                logger.warning(
                    "shield360 flags: no Shield360 URL and API key (SHIELD360_URL, SHIELD360_API_KEY); "
                    "every flag serves its default."
                )
            return False
        url, api_key = dest
        headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
        if self._etag:
            headers["If-None-Match"] = self._etag
        response = self._get(url + RULES_PATH, headers)
        if response.status_code == 304:
            self._ready.set()
            return True
        if not 200 <= response.status_code < 300:
            logger.debug("shield360 flags: rules fetch answered %s", response.status_code)
            return False
        body = response.json()
        if not isinstance(body, dict) or not isinstance(body.get("flags"), list):
            return False
        flags: Dict[str, Dict[str, Any]] = {}
        for raw in body["flags"]:
            # A flag that does not validate is left out: its callers get their default.
            if _engine.validate_flag(raw):
                continue
            flags[raw["key"]] = raw
        raw_segments = body.get("segments")
        segments = [s for s in (raw_segments if isinstance(raw_segments, list) else []) if not _engine.validate_segment(s)]
        with self._lock:
            self._flags = flags
            self._segments = segments
            self._etag = response.headers.get("ETag") or response.headers.get("etag")
        self._ready.set()
        return True

    # ---------------------------------------------------------- evaluation

    def get_flag_detail(self, key: str, context: Optional[Dict[str, Any]] = None, default: Any = None) -> Dict[str, Any]:
        """{value, variation, reason} for this context; the default when nothing is served. Never raises."""
        try:
            self.start()
            if not self._ready.is_set():
                return {"value": default, "variation": None, "reason": {"kind": "NOT_READY"}}
            with self._lock:
                flag = self._flags.get(key)
                segments = self._segments
            if flag is None or (flag.get("appName") and flag.get("appName") != self._app()):
                return {"value": default, "variation": None, "reason": {"kind": "FLAG_NOT_FOUND"}}
            result = _engine.evaluate(flag, context or {}, segments)
            if result["variation"] is None:
                return {"value": default, "variation": None, "reason": result["reason"]}
            if not _same_kind(result["value"], default):
                return {"value": default, "variation": None, "reason": {"kind": "WRONG_TYPE"}}
            if self._record_on_span:
                span = trace.get_current_span()
                if span is not None and span.is_recording():
                    span.set_attribute(SPAN_ATTRIBUTE_PREFIX + key, result["variation"])
            return result
        except Exception:  # pylint: disable=broad-exception-caught
            return {"value": default, "variation": None, "reason": {"kind": "ERROR"}}

    def get_flag(self, key: str, context: Optional[Dict[str, Any]] = None, default: Any = None) -> Any:
        """The flag's value for this context, or ``default``. Never raises."""
        return self.get_flag_detail(key, context, default)["value"]

    def is_enabled(self, key: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Whether a boolean flag is on for this context; False until rules arrive or on error."""
        return self.get_flag(key, context, False) is True

    # ------------------------------------------------------------ AI helpers

    def model(self, key: str, context: Optional[Dict[str, Any]] = None, default: str = "") -> str:
        """The provider/model id a model-switch flag (a string flag) serves; ``default`` otherwise."""
        value = self.get_flag(key, context, default)
        return value if isinstance(value, str) and value.strip() else default

    def kill_switch(self, key: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Whether a kill switch is engaged (True: stop the feature).

        A kill switch is a boolean flag serving True while the feature may run; switching it
        off (or serving False) engages it. Until rules arrive, or for an unknown flag, it is
        not engaged: the feature keeps running.
        """
        return self.get_flag(key, context, True) is False

    def prompt(
        self,
        key: str,
        context: Optional[Dict[str, Any]] = None,
        default: Optional[Dict[str, Any]] = None,
        variables: Optional[Dict[str, Any]] = None,
        should_compile: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """The Prompt Hub prompt a prompt-version flag serves, fetched with ``shield360.get_prompt``.

        Variations name prompts: ``{"name": "support-reply", "version": "1.2.0"}`` or
        ``"support-reply@1.2.0"``. Returns {name, version, variation, prompt, error}; never raises.
        """
        ref = prompt_ref_of(default) or {"name": "", "version": None}
        variation = None
        try:
            detail = self.get_flag_detail(key, context, None)
            served = prompt_ref_of(detail["value"]) if detail.get("variation") is not None else None
            if served:
                ref, variation = served, detail["variation"]
            if not ref["name"]:
                return {"name": "", "version": None, "variation": None, "prompt": None, "error": "no prompt"}
            # Lazy, and from the package: shield360 imports shield360.flags at start-up, and tests patch shield360.get_prompt.
            from shield360 import get_prompt  # pylint: disable=import-outside-toplevel,cyclic-import

            dest = self._destination()
            answer = get_prompt(
                url=dest[0] if dest else None,
                api_key=dest[1] if dest else None,
                name=ref["name"],
                version=ref["version"],
                should_compile=bool(variables) if should_compile is None else should_compile,
                variables=variables or {},
            )
            error = answer.get("err") if isinstance(answer, dict) else "no response"
            prompt = None if error else (answer.get("res") or answer.get("data"))
            return {
                "name": ref["name"],
                "version": ref["version"],
                "variation": variation,
                "prompt": prompt,
                "error": error or (None if prompt is not None else "empty response"),
            }
        except Exception as error:  # pylint: disable=broad-exception-caught
            return {
                "name": ref["name"],
                "version": ref["version"],
                "variation": variation,
                "prompt": None,
                "error": type(error).__name__,
            }


def prompt_ref_of(value) -> Optional[Dict[str, Any]]:
    """{name, version} from ``{"name", "version"?}`` or ``"name"`` / ``"name@version"``; None otherwise."""
    if isinstance(value, str):
        text = value.strip()
        at = text.rfind("@")
        if at == 0 or not text:
            return None
        if at > 0:
            return {"name": text[:at], "version": text[at + 1 :] or None}
        return {"name": text, "version": None}
    if isinstance(value, dict):
        name, version = value.get("name"), value.get("version")
        if not isinstance(name, str) or not name.strip() or (version is not None and not isinstance(version, str)):
            return None
        return {"name": name.strip(), "version": version or None}
    return None
