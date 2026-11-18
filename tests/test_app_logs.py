# pylint: disable=missing-function-docstring, redefined-outer-name, protected-access
"""
Application logs reach Shield360 only when asked for, through the SDK's own
LoggerProvider, linked to the span that was active when they were written, and
to the same ingest route and API key as traces. The TypeScript SDK carries the
same tests.
"""

import logging

import pytest
from opentelemetry.context import _SUPPRESS_INSTRUMENTATION_KEY, attach, detach, set_value
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor

try:
    from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter
except ImportError:  # older SDKs
    from opentelemetry.sdk._logs.export import InMemoryLogExporter as InMemoryLogRecordExporter
from opentelemetry.sdk.trace import TracerProvider

import shield360
import shield360.otel.events as events_module
from shield360.otel import app_logs
from shield360.otel.app_logs import Shield360LogHandler, capture_logs, stop_capturing_logs

URL = "https://app.shield360.ai"


@pytest.fixture
def memory():
    exporter = InMemoryLogRecordExporter()
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    return exporter, provider


@pytest.fixture
def app_logger():
    log = logging.getLogger("tests.app_logs.app")
    log.setLevel(logging.DEBUG)
    log.propagate = False
    yield log
    stop_capturing_logs(log)


def _records(exporter):
    return [getattr(item, "log_record", item) for item in exporter.get_finished_logs()]


def _handlers(log):
    return [h for h in log.handlers if isinstance(h, Shield360LogHandler)]


def test_sends_records_at_the_level_and_above(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, level="warning", logger_provider=provider)
    app_logger.debug("d")
    app_logger.info("i")
    app_logger.warning("w %s", "arg")
    app_logger.error("e")
    app_logger.critical("c")
    records = _records(exporter)
    assert [r.body for r in records] == ["w arg", "e", "c"]
    assert [r.severity_text for r in records] == ["WARN", "ERROR", "FATAL"]
    assert [r.severity_number.value for r in records] == [13, 17, 21]


def test_defaults_to_info(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    app_logger.debug("d")
    app_logger.info("i")
    assert [r.body for r in _records(exporter)] == ["i"]


def test_keeps_extra_attributes(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    app_logger.info("order placed", extra={"order_id": "o-1"})
    (record,) = _records(exporter)
    assert record.attributes["order_id"] == "o-1"


def test_attaching_twice_keeps_one_handler_and_takes_the_new_level(memory, app_logger):
    exporter, provider = memory
    first = capture_logs(app_logger, logger_provider=provider)
    second = capture_logs(app_logger, level=logging.ERROR, logger_provider=provider)
    assert first is second
    assert len(_handlers(app_logger)) == 1
    app_logger.warning("w")
    app_logger.error("e")
    assert [r.body for r in _records(exporter)] == ["e"]


def test_a_record_seen_by_two_handlers_is_sent_once(memory):
    exporter, provider = memory
    child = logging.getLogger("tests.app_logs.child")
    child.setLevel(logging.INFO)
    capture_logs(child, logger_provider=provider)
    capture_logs(logger_provider=provider)
    try:
        child.warning("once")
        assert [r.body for r in _records(exporter)] == ["once"]
    finally:
        stop_capturing_logs(child)
        stop_capturing_logs()


def test_never_exports_its_own_records(memory):
    exporter, provider = memory
    root = logging.getLogger()
    old_level = root.level
    root.setLevel(logging.DEBUG)
    capture_logs(logger_provider=provider)
    try:
        logging.getLogger("shield360.otel.tracing").warning("sdk")
        logging.getLogger("shield360").error("sdk root")
        logging.getLogger("opentelemetry.exporter.otlp").error("export failed")
        logging.getLogger("shield360_app").warning("not ours")
        assert [r.body for r in _records(exporter)] == ["not ours"]
    finally:
        stop_capturing_logs()
        root.setLevel(old_level)
    assert not _handlers(root)


def test_drops_records_written_while_exporting(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    token = attach(set_value(_SUPPRESS_INSTRUMENTATION_KEY, True))
    try:
        app_logger.warning("from the exporter's HTTP client")
    finally:
        detach(token)
    assert _records(exporter) == []


def test_a_record_logged_during_emit_does_not_loop(app_logger):
    """An exporter that logs (as urllib3 does) must not re-enter the handler."""

    class LoggingExporter(InMemoryLogRecordExporter):
        def export(self, batch):
            app_logger.warning("logged by the exporter")
            return super().export(batch)

    exporter = LoggingExporter()
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    capture_logs(app_logger, logger_provider=provider)
    app_logger.error("once")
    assert [r.body for r in _records(exporter)] == ["once"]


def test_links_a_record_to_the_active_span(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    tracer = TracerProvider().get_tracer("test")
    with tracer.start_as_current_span("work") as span:
        app_logger.info("inside")
        ctx = span.get_span_context()
    app_logger.info("outside")
    inside, outside = _records(exporter)
    assert inside.trace_id == ctx.trace_id
    assert inside.span_id == ctx.span_id
    assert not outside.trace_id


def test_needs_init_first(monkeypatch, app_logger):
    from opentelemetry._logs import NoOpLoggerProvider

    monkeypatch.setattr(app_logs._logs, "get_logger_provider", NoOpLoggerProvider)
    assert capture_logs(app_logger) is None
    assert not _handlers(app_logger)


@pytest.mark.parametrize(
    "given, expected",
    [
        (None, logging.INFO),
        ("", logging.INFO),
        ("debug", logging.DEBUG),
        ("WARN", logging.WARNING),
        ("fatal", logging.CRITICAL),
        (logging.ERROR, logging.ERROR),
        ("loud", logging.INFO),
    ],
)
def test_resolve_level(given, expected):
    assert app_logs.resolve_level(given) == expected


# --- init() --------------------------------------------------------------


@pytest.fixture
def init_spy(monkeypatch):
    """init() with its providers stubbed; records what it set up."""
    calls = {"events": None, "capture": []}

    def fake_setup_events(**kwargs):
        calls["events"] = kwargs
        return object()

    monkeypatch.setattr(shield360, "setup_events", fake_setup_events)
    monkeypatch.setattr(shield360, "setup_tracing", lambda **kwargs: object())
    monkeypatch.setattr(
        shield360._app_logs,
        "capture_logs",
        lambda **kwargs: calls["capture"].append(kwargs),
    )
    monkeypatch.setattr(shield360, "get_all_instrumentors", dict)
    for name in (
        "SHIELD360_CAPTURE_LOGS",
        "SHIELD360_LOG_LEVEL",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "SHIELD360_URL",
        "SHIELD360_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    shield360.Shield360Config.reset_to_defaults()
    return calls


def test_init_leaves_application_logs_off_by_default(init_spy):
    shield360.init(disable_metrics=True)
    assert init_spy["capture"] == []


def test_init_turns_them_on_with_the_parameter(init_spy):
    shield360.init(disable_metrics=True, capture_logs=True, log_level="warning")
    assert init_spy["capture"] == [{"level": "warning"}]


def test_init_turns_them_on_from_the_environment(init_spy, monkeypatch):
    monkeypatch.setenv("SHIELD360_CAPTURE_LOGS", "true")
    monkeypatch.setenv("SHIELD360_LOG_LEVEL", "ERROR")
    shield360.init(disable_metrics=True)
    assert init_spy["capture"] == [{"level": "ERROR"}]


def test_an_explicit_false_wins_over_the_environment(init_spy, monkeypatch):
    monkeypatch.setenv("SHIELD360_CAPTURE_LOGS", "true")
    shield360.init(disable_metrics=True, capture_logs=False)
    assert init_spy["capture"] == []


def test_init_hands_events_the_resolved_destination(init_spy):
    shield360.init(disable_metrics=True, shield360_url=URL, shield360_api_key="k-1")
    assert init_spy["events"]["otlp_endpoint"] == f"{URL}/api/ingest/otlp"
    assert init_spy["events"]["otlp_headers"] == {"Authorization": "Bearer k-1"}


# --- the logs exporter ---------------------------------------------------


def test_logs_go_to_the_ingest_route_with_the_key_as_bearer(monkeypatch):
    """With a Shield360 URL and API key, logs use <url>/api/ingest/otlp/v1/logs, as traces use /v1/traces."""
    from shield360._destination import resolve_destination

    for name in ("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_LOGS_EXPORTER"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    built = []
    real_exporter = events_module.OTLPLogExporter

    def recording_exporter(*args, **kwargs):
        exporter = real_exporter(*args, **kwargs)
        built.append(exporter)
        return exporter

    installed = []
    monkeypatch.setattr(events_module, "OTLPLogExporter", recording_exporter)
    monkeypatch.setattr(events_module, "EVENTS_SET", False)
    monkeypatch.setattr(events_module._logs, "get_logger_provider", lambda: None)
    monkeypatch.setattr(events_module._logs, "set_logger_provider", installed.append)
    monkeypatch.setattr(events_module._logs, "get_logger", lambda *a, **k: object())

    endpoint, headers = resolve_destination(None, None, URL + "/", "k-1", env={})
    assert events_module.setup_events(
        application_name="app",
        environment="test",
        event_logger=None,
        otlp_endpoint=endpoint,
        otlp_headers=headers,
        disable_batch=True,
    )
    assert len(built) == 1
    exporter = built[0]
    assert exporter._endpoint == f"{URL}/api/ingest/otlp/v1/logs"
    # Where the parsed headers live moved between SDK releases.
    sent = getattr(exporter, "_headers", None) or exporter._client._headers
    assert {k.lower(): v for k, v in sent.items()}["authorization"] == "Bearer k-1"
    assert len(installed) == 1


# --- masking, limits ------------------------------------------------------


def test_masks_credentials_and_long_tokens_in_the_body(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    app_logger.info("login password=hunter2 for %s", "ann")
    app_logger.info("key k3j4h5g6f7d8s9a0q1w2e3r4 used")
    first, second = _records(exporter)
    assert first.body == "login password=*** for ann"
    assert second.body == "key *** used"


def test_masks_string_attributes_but_not_code_location_or_exception_type(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    try:
        raise ValueError("token=abc123 rejected")
    except ValueError:
        app_logger.exception("failed", extra={"header": "Authorization: xyz", "count": 3})
    (record,) = _records(exporter)
    attrs = record.attributes
    assert attrs["header"] == "Authorization: ***"
    assert attrs["count"] == 3
    assert attrs["exception.type"] == "ValueError"
    assert attrs["exception.message"] == "token=*** rejected"
    assert "token=abc123" not in attrs["exception.stacktrace"]
    assert attrs["code.function.name"] == "test_masks_string_attributes_but_not_code_location_or_exception_type"
    assert attrs["code.file.path"].endswith("test_app_logs.py")


def test_never_exports_its_own_marker(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    app_logger.info("plain")
    (record,) = _records(exporter)
    assert app_logs._SENT not in record.attributes


def test_cuts_long_bodies_and_attributes(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    app_logger.info("a " * 20000, extra={"note": "b " * 5000})
    (record,) = _records(exporter)
    assert len(record.body) == app_logs.MAX_BODY_LENGTH
    assert len(record.attributes["note"]) == app_logs.MAX_ATTRIBUTE_LENGTH


def test_sends_at_most_the_rate_limit_a_second(memory, app_logger):
    exporter, provider = memory
    handler = capture_logs(app_logger, logger_provider=provider)
    now = [100.0]
    handler._limiter = app_logs.RateLimiter(3, clock=lambda: now[0])
    for i in range(5):
        app_logger.info("storm %d", i)
    now[0] += 1.0
    app_logger.info("next second")
    assert [r.body for r in _records(exporter)] == ["storm 0", "storm 1", "storm 2", "next second"]


def test_the_default_rate_limit_is_500_a_second():
    limiter = app_logs.RateLimiter(clock=lambda: 5.0)
    assert sum(limiter.allow() for _ in range(600)) == 500


def test_a_failing_exporter_never_reaches_the_application(app_logger):
    class FailingExporter(InMemoryLogRecordExporter):
        def export(self, batch):
            raise RuntimeError("endpoint down")

    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(FailingExporter()))
    capture_logs(app_logger, logger_provider=provider)
    app_logger.error("still fine")  # must not raise


def test_mask_snippet_follows_the_contract():
    from shield360.rasp._engine import mask_snippet

    assert mask_snippet("password=hunter2&x=1") == "password=***&x=1"
    assert mask_snippet("t k3j4h5g6f7d8s9a0q1w2e3r4") == "t ***"
    assert len(mask_snippet("a " * 100)) == 64


def test_masks_attributes_named_like_credentials_and_lists(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)
    app_logger.info("sign-in", extra={"password": "pw1", "x_api_key": "short", "tags": ["token=abc", "ok"], "user": "ann"})
    (record,) = _records(exporter)
    attrs = record.attributes
    assert attrs["password"] == "***"
    assert attrs["x_api_key"] == "***"
    assert list(attrs["tags"]) == ["token=***", "ok"]
    assert attrs["user"] == "ann"


def test_keeps_exception_class_names_readable(memory, app_logger):
    exporter, provider = memory
    capture_logs(app_logger, logger_provider=provider)

    class ArrayIndexOutOfBoundsError(Exception):
        pass

    try:
        raise ArrayIndexOutOfBoundsError("index 5 out of bounds")
    except ArrayIndexOutOfBoundsError:
        app_logger.exception("java.lang.ArrayIndexOutOfBoundsException seen")
    (record,) = _records(exporter)
    assert record.body == "java.lang.ArrayIndexOutOfBoundsException seen"
    assert "ArrayIndexOutOfBoundsError" in record.attributes["exception.stacktrace"]
    assert "test_app_logs.py" in record.attributes["exception.stacktrace"]
