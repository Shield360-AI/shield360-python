# pylint: disable=missing-function-docstring, redefined-outer-name
"""
Request correlation: Edge's request id and the trace id ride on every log
record written while a request is served, and on its server span. The
TypeScript SDK carries the same tests (otel/__tests__/edge-request.test.ts).
"""

import logging

import pytest
from opentelemetry.sdk._logs import LoggerProvider
from opentelemetry.sdk._logs.export import SimpleLogRecordProcessor

try:
    from opentelemetry.sdk._logs.export import InMemoryLogRecordExporter
except ImportError:  # older SDKs
    from opentelemetry.sdk._logs.export import InMemoryLogExporter as InMemoryLogRecordExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from shield360.otel import edge_request
from shield360.otel.app_logs import capture_logs, stop_capturing_logs
from shield360.otel.edge_request import EdgeRequestFilter, request_id_of, trace_id_of
from shield360.rasp._capture import capture_request
from shield360.rasp._context import reset_context, set_context

RID = "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6"
TRACE = "0af7651916cd43dd8448eb211c80319c"


@pytest.fixture
def logs():
    exporter = InMemoryLogRecordExporter()
    provider = LoggerProvider()
    provider.add_log_record_processor(SimpleLogRecordProcessor(exporter))
    log = logging.getLogger("tests.edge_request.app")
    log.setLevel(logging.INFO)
    capture_logs(log, logger_provider=provider)
    yield exporter, log
    stop_capturing_logs(log)
    edge_request.reset()


def _records(exporter):
    return [getattr(item, "log_record", item) for item in exporter.get_finished_logs()]


def test_accepts_only_id_shaped_values():
    assert request_id_of(RID) == RID
    assert request_id_of("short") is None
    assert request_id_of("has space in it") is None
    assert request_id_of("a" * 129) is None
    assert trace_id_of(f"00-{TRACE}-b7ad6b7169203331-01") == TRACE
    assert trace_id_of(f"00-{'0' * 32}-b7ad6b7169203331-01") is None


def test_log_record_carries_both_ids_without_tracing(logs):
    exporter, log = logs
    ctx = capture_request("test", "GET", "/a?q=1", {"x-request-id": RID, "traceparent": f"00-{TRACE}-b7ad6b7169203331-01"})
    token = set_context(ctx)
    try:
        log.info("served")
    finally:
        reset_context(token)
    log.info("boot")
    served, boot = _records(exporter)
    assert served.attributes["shield360.edge.request_id"] == RID
    assert served.attributes["shield360.edge.trace_id"] == TRACE
    assert "shield360.edge.request_id" not in boot.attributes


def test_ignores_a_request_id_that_is_not_id_shaped(logs):
    exporter, log = logs
    token = set_context(capture_request("test", "GET", "/", {"x-request-id": "<script>"}))
    try:
        log.info("served")
    finally:
        reset_context(token)
    assert "shield360.edge.request_id" not in _records(exporter)[0].attributes


def test_tags_the_server_span_and_child_span_logs(logs):
    exporter, log = logs
    spans = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(spans))
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("GET /a") as server:
        ctx = capture_request("test", "GET", "/a", {"x-request-id": RID})
        with tracer.start_as_current_span("db"):
            log.info("query")  # outside the RASP context: found by the trace
        token = set_context(ctx)
        reset_context(token)
        trace_id = server.get_span_context().trace_id
    finished = {s.name: s for s in spans.get_finished_spans()}
    assert finished["GET /a"].attributes["shield360.edge.request_id"] == RID
    (record,) = _records(exporter)
    assert record.attributes["shield360.edge.request_id"] == RID
    assert "shield360.edge.trace_id" not in record.attributes
    assert record.trace_id == trace_id


def test_filter_puts_ids_on_records_for_formatters():
    record = logging.LogRecord("app", logging.INFO, __file__, 1, "msg", None, None)
    token = set_context(capture_request("test", "GET", "/", {"x-request-id": RID}))
    try:
        assert EdgeRequestFilter().filter(record)
    finally:
        reset_context(token)
    assert record.shield360_request_id == RID
    outside = logging.LogRecord("app", logging.INFO, __file__, 1, "msg", None, None)
    EdgeRequestFilter().filter(outside)
    assert outside.shield360_request_id == ""
