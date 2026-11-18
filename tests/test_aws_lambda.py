# pylint: disable=missing-function-docstring, missing-class-docstring, too-few-public-methods, redefined-outer-name
"""
The Lambda wrapper: one faas span per invocation, flushed before the invocation
returns and never for longer than the budget. The TypeScript SDK carries the
same tests (src/lambda/__tests__/lambda.test.ts).
"""

import sys
import time

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from shield360 import aws_lambda

_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))


class Ctx:
    function_name = "checkout"
    function_version = "$LATEST"
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:checkout:prod"
    memory_limit_in_mb = "512"

    def __init__(self, request_id="req-1", remaining=30000):
        self.aws_request_id = request_id
        self._remaining = remaining

    def get_remaining_time_in_millis(self):
        return self._remaining


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    _EXPORTER.clear()
    aws_lambda.reset_for_testing()
    # The global provider can be set once per process and other test files may own it,
    # so the wrapper is pointed at this file's provider instead.
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: _PROVIDER)
    monkeypatch.setattr(trace, "get_tracer", lambda name, *a, **k: _PROVIDER.get_tracer(name))
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_LAMBDA_INITIALIZATION_TYPE", raising=False)
    monkeypatch.delenv("SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS", raising=False)
    yield


@pytest.mark.parametrize(
    "event, expected",
    [
        ({"httpMethod": "GET", "headers": {}, "requestContext": {}}, "http"),
        ({"requestContext": {"http": {"method": "POST"}}, "rawPath": "/x"}, "http"),
        ({"Records": [{"eventSource": "aws:sqs"}]}, "pubsub"),
        ({"Records": [{"EventSource": "aws:sns"}]}, "pubsub"),
        ({"Records": [{"eventSource": "aws:s3"}]}, "datasource"),
        ({"source": "aws.events", "detail-type": "Scheduled Event"}, "timer"),
        ({"hello": "world"}, "other"),
        (None, "other"),
    ],
)
def test_detect_trigger(event, expected):
    assert aws_lambda.detect_trigger(event) == expected


def test_faas_and_cloud_attributes():
    attrs = aws_lambda.invocation_attributes({"Records": [{"eventSource": "aws:sqs"}]}, Ctx(), True)
    assert attrs["faas.trigger"] == "pubsub"
    assert attrs["faas.coldstart"] is True
    assert attrs["faas.name"] == "checkout"
    assert attrs["faas.invocation_id"] == "req-1"
    assert attrs["faas.max_memory"] == 512 * 1024 * 1024
    assert attrs["cloud.provider"] == "aws"
    assert attrs["cloud.platform"] == "aws_lambda"
    assert attrs["cloud.region"] == "us-east-1"
    assert attrs["cloud.account.id"] == "123456789012"
    assert attrs["cloud.resource_id"] == "arn:aws:lambda:us-east-1:123456789012:function:checkout"


def test_traces_each_invocation_and_only_the_first_is_cold():
    wrapped = aws_lambda.wrap_handler(lambda event, context: {"doubled": event["n"] * 2}, auto_init=False)
    assert wrapped({"n": 2}, Ctx()) == {"doubled": 4}
    wrapped({"n": 3}, Ctx("req-2"))
    spans = _EXPORTER.get_finished_spans()
    assert len(spans) == 2
    assert spans[0].name == "checkout"
    assert spans[0].attributes["faas.coldstart"] is True
    assert spans[1].attributes["faas.coldstart"] is False
    assert spans[1].attributes["faas.invocation_id"] == "req-2"


def test_provisioned_concurrency_is_warm(monkeypatch):
    monkeypatch.setenv("AWS_LAMBDA_INITIALIZATION_TYPE", "provisioned-concurrency")
    aws_lambda.wrap_handler(lambda e, c: "ok", auto_init=False)({}, Ctx())
    assert _EXPORTER.get_finished_spans()[0].attributes["faas.coldstart"] is False


def test_decorator_with_options():
    @aws_lambda.wrap_handler(flush_timeout_ms=100, auto_init=False)
    def handler(event, context):
        return "ok"

    assert handler({}, Ctx()) == "ok"
    assert handler.__name__ == "handler"


def test_records_the_error_and_reraises():
    def boom(event, context):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        aws_lambda.wrap_handler(boom, auto_init=False)({}, Ctx())
    (span,) = _EXPORTER.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert any(e.name == "exception" for e in span.events)


def test_continues_an_incoming_trace_for_api_gateway_events():
    event = {
        "version": "2.0",
        "routeKey": "POST /orders",
        "rawPath": "/orders",
        "headers": {"traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
        "requestContext": {"http": {"method": "POST", "path": "/orders"}},
    }
    seen = {}

    def handler(_event, _context):
        seen["trace_id"] = trace.get_current_span().get_span_context().trace_id
        return {"statusCode": 503}

    aws_lambda.wrap_handler(handler, auto_init=False)(event, Ctx())
    (span,) = _EXPORTER.get_finished_spans()
    assert span.name == "POST /orders"
    assert span.kind == SpanKind.SERVER
    assert format(span.context.trace_id, "032x") == "0af7651916cd43dd8448eb211c80319c"
    assert seen["trace_id"] == span.context.trace_id
    assert span.attributes["http.response.status_code"] == 503
    assert span.status.status_code == StatusCode.ERROR


def test_flushes_before_returning(monkeypatch):
    calls = []
    monkeypatch.setattr(_PROVIDER, "force_flush", lambda timeout_millis=30000: calls.append(timeout_millis) or True)
    aws_lambda.wrap_handler(lambda e, c: "ok", auto_init=False, flush_timeout_ms=700)({}, Ctx())
    assert calls and calls[0] <= 700


def test_flush_gives_up_when_the_budget_is_spent(monkeypatch):
    def slow_flush(timeout_millis=30000):
        time.sleep(timeout_millis / 1000.0)
        return False

    monkeypatch.setattr(_PROVIDER, "force_flush", slow_flush)
    started = time.monotonic()
    assert aws_lambda.flush_telemetry(50) is False
    assert time.monotonic() - started < 1.0


def test_flush_budget_is_capped_by_the_deadline(monkeypatch):
    assert aws_lambda.flush_budget(Ctx(remaining=600), 2000) == 500
    assert aws_lambda.flush_budget(Ctx(remaining=50), 2000) == 0
    monkeypatch.setenv("SHIELD360_LAMBDA_FLUSH_TIMEOUT_MS", "750")
    assert aws_lambda.flush_budget(Ctx()) == 750


def test_rejects_a_non_function():
    with pytest.raises(TypeError):
        aws_lambda.wrap_handler(42)


def test_layer_handler_loads_and_wraps_the_function(tmp_path, monkeypatch):
    pkg = tmp_path / "svc"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "app.py").write_text("def handler(event, context):\n    return 'from-task-root'\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setenv("SHIELD360_LAMBDA_HANDLER", "svc/app.handler")
    monkeypatch.setattr(aws_lambda, "_state", {"cold": True, "initialized": True})
    try:
        assert aws_lambda.handler({}, Ctx()) == "from-task-root"
        assert _EXPORTER.get_finished_spans()[0].attributes["faas.name"] == "checkout"
    finally:
        sys.modules.pop("svc.app", None)
        sys.modules.pop("svc", None)


def test_layer_handler_explains_a_bad_setting(monkeypatch):
    monkeypatch.delenv("SHIELD360_LAMBDA_HANDLER", raising=False)
    with pytest.raises(RuntimeError, match="SHIELD360_LAMBDA_HANDLER"):
        aws_lambda.load_original_handler()
    with pytest.raises(RuntimeError, match="module.function"):
        aws_lambda.load_original_handler("app")
    with pytest.raises(RuntimeError, match="not a function"):
        aws_lambda.load_original_handler("os.sep")
