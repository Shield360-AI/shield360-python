"""
Application logs to Shield360, when asked for.

Shield360 ingests OTLP logs on the same per-API-key route as traces. The
handler here bridges the standard ``logging`` module to the SDK's own
LoggerProvider (``otel/events.py``), so records go to the same destination
with the same Authorization header as the spans, and the OpenTelemetry handler
stamps them with the trace and span ids of the span active when they are
written.

Nothing is sent unless it is turned on: ``shield360.init(capture_logs=True)``,
``SHIELD360_CAPTURE_LOGS=true``, or a call to ``shield360.capture_logs()``.

The handler never exports the SDK's own records (the ``shield360`` and
``opentelemetry`` loggers), nor anything logged while a record is being
exported (the exporter's HTTP client logs too), so it cannot feed itself.

Before a record leaves the process it is masked by the contract every SDK
shares (sdk/rasp/README.md, "Masking"): credential pairs, bearer credentials
and opaque tokens in the body and string attributes, and the whole value of an
attribute named like a credential (``password``, ``x-api-key``), lists and
maps item by item; readable identifiers such as class names and file paths
survive. ``code.*`` and ``exception.type`` are left as they are. The body and
the stack trace are cut to 16,384 characters, other strings to 4,096, after
masking. Each
handler sends at most ``DEFAULT_MAX_PER_SECOND`` records a second and drops
the rest, and the provider exports in batches from a bounded queue, so a log
storm cannot take down the application or the endpoint. Every SDK applies the
same rules.
"""

import logging
import threading
import time
import warnings
from typing import Any, Callable, Optional, Union

from opentelemetry import _logs
from opentelemetry.context import _SUPPRESS_INSTRUMENTATION_KEY, get_value
from opentelemetry.sdk._logs import LoggerProvider as SDKLoggerProvider
from opentelemetry.sdk._logs import LoggingHandler

from shield360._masking import mask_text
from shield360._masking import mask_value as _mask_value

_log = logging.getLogger(__name__)

DEFAULT_LEVEL = logging.INFO
_OWN_LOGGERS = ("shield360", "opentelemetry")
_LEVEL_ALIASES = {"WARN": "WARNING", "FATAL": "CRITICAL"}
_emitting = threading.local()
_SENT = "_shield360_sent"

DEFAULT_MAX_PER_SECOND = 500
MAX_BODY_LENGTH = 16384
MAX_ATTRIBUTE_LENGTH = 4096
_LONG_ATTRIBUTES = ("exception.stacktrace",)
_UNMASKED_ATTRIBUTES = ("exception.type",)

Level = Union[int, str, None]


def resolve_level(level: Level) -> int:
    """A ``logging`` level from a number or a name (``"info"``, ``"WARN"``); INFO otherwise."""
    if level is None or level == "":
        return DEFAULT_LEVEL
    if isinstance(level, int):
        return level
    name = str(level).strip().upper()
    value = logging.getLevelName(_LEVEL_ALIASES.get(name, name))
    if isinstance(value, int):
        return value
    _log.warning("Unknown log level %r; using INFO.", level)
    return DEFAULT_LEVEL


def _is_own(name: str) -> bool:
    return any(name == own or name.startswith(own + ".") for own in _OWN_LOGGERS)


def mask_value(key: str, value: Any) -> Any:
    """An attribute value as it may leave the process (sdk/rasp/README.md, Masking)."""
    if key.startswith("code.") or key in _UNMASKED_ATTRIBUTES:
        return value
    return _mask_value(key, value, MAX_BODY_LENGTH if key in _LONG_ATTRIBUTES else MAX_ATTRIBUTE_LENGTH)


class RateLimiter:
    """At most ``max_per_second`` calls allowed in each one-second window."""

    def __init__(self, max_per_second: int = DEFAULT_MAX_PER_SECOND, clock: Callable[[], float] = time.monotonic):
        self.max_per_second = max_per_second
        self._clock = clock
        self._window = None
        self._count = 0
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = self._clock()
            if self._window is None or now - self._window >= 1.0:
                self._window = now
                self._count = 0
            self._count += 1
            return self._count <= self.max_per_second


class Shield360LogHandler(LoggingHandler):
    """The OpenTelemetry ``LoggingHandler``, kept from exporting its own pipeline's records, masked and rate-limited."""

    def __init__(
        self,
        level: int,
        logger_provider: SDKLoggerProvider,
        max_per_second: int = DEFAULT_MAX_PER_SECOND,
    ):
        # The SDK marks its handler deprecated in favour of a separate
        # package; it is the same handler, and the SDK is what we depend on.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            super().__init__(level=level, logger_provider=logger_provider)
        self._limiter = RateLimiter(max_per_second)

    def _translate(self, record: logging.LogRecord):
        log_record = super()._translate(record)
        attributes = {
            key: mask_value(key, value)
            for key, value in (log_record.attributes or {}).items()
            if key != _SENT
        }
        log_record.attributes = attributes
        if isinstance(log_record.body, str):
            log_record.body = mask_text(log_record.body, MAX_BODY_LENGTH)
        elif log_record.body is not None:
            # Mappings, sequences and bytes: their text, so it can be masked too.
            log_record.body = mask_text(str(log_record.body), MAX_BODY_LENGTH)
        return log_record

    def emit(self, record: logging.LogRecord) -> None:
        if (
            _is_own(record.name)
            or get_value(_SUPPRESS_INSTRUMENTATION_KEY)
            or getattr(_emitting, "active", False)
            # Already sent by a handler on a logger below this one.
            or getattr(record, _SENT, False)
        ):
            return
        if not self._limiter.allow():
            return
        setattr(record, _SENT, True)
        _emitting.active = True
        try:
            super().emit(record)
        except Exception:  # pylint: disable=broad-exception-caught
            self.handleError(record)
        finally:
            _emitting.active = False


def capture_logs(
    logger: Union[logging.Logger, str, None] = None,
    level: Level = DEFAULT_LEVEL,
    logger_provider: Optional[SDKLoggerProvider] = None,
) -> Optional[Shield360LogHandler]:
    """Send ``logging`` records at ``level`` and above to Shield360.

    Attaches one handler to ``logger`` (a Logger or its name; the root logger
    by default). Calling it again for the same logger changes the level of the
    handler already there rather than adding a second one. Call it after
    ``shield360.init()``: the records go wherever init() sends traces.

    The logger's own level still applies; the root logger drops INFO records
    unless the application lowers it (``logging.basicConfig(level=logging.INFO)``).

    Returns the handler, or None when init() has not set up a LoggerProvider.
    """
    provider = logger_provider or _logs.get_logger_provider()
    if not isinstance(provider, SDKLoggerProvider):
        _log.warning(
            "shield360.capture_logs() needs shield360.init() first; application logs are not sent."
        )
        return None

    target = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
    minimum = resolve_level(level)

    for handler in target.handlers:
        if isinstance(handler, Shield360LogHandler):
            handler.setLevel(minimum)
            return handler

    handler = Shield360LogHandler(minimum, provider)
    target.addHandler(handler)
    return handler


def stop_capturing_logs(logger: Union[logging.Logger, str, None] = None) -> None:
    """Detach the handler ``capture_logs()`` added to ``logger`` (the root logger by default)."""
    target = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
    for handler in list(target.handlers):
        if isinstance(handler, Shield360LogHandler):
            target.removeHandler(handler)
