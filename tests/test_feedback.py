"""Hermetic tests for shield360.feedback: what is sent, and that it never raises."""

from unittest import mock

import pytest
from opentelemetry import trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

import shield360
from shield360 import _feedback as feedback_module
from shield360._config import Shield360Config

TRACE = "0af7651916cd43dd8448eb211c80319c"
SPAN = "b7ad6b7169203331"


@pytest.fixture(autouse=True)
def configured(monkeypatch):
    monkeypatch.delenv("SHIELD360_URL", raising=False)
    monkeypatch.delenv("SHIELD360_API_KEY", raising=False)
    monkeypatch.setattr(Shield360Config, "shield360_url", "https://shield360.example/", raising=False)
    monkeypatch.setattr(Shield360Config, "shield360_api_key", "key-1", raising=False)
    feedback_module.configure_feedback(app="checkout", release="2.0.0")
    yield
    feedback_module.configure_feedback()


def _ok(status=200):
    return mock.Mock(status_code=status)


def test_posts_the_rating_naming_app_and_release():
    with mock.patch("requests.post", return_value=_ok()) as post:
        assert shield360.feedback(
            -1, trace_id=TRACE.upper(), span_id=SPAN, comment="wrong", user_id="u-1", metadata={"plan": "pro"}
        )
    url = post.call_args.args[0]
    kwargs = post.call_args.kwargs
    assert url == "https://shield360.example/api/feedback"
    assert kwargs["headers"] == {"Authorization": "Bearer key-1"}
    assert kwargs["json"] == {
        "traceId": TRACE,
        "score": -1,
        "spanId": SPAN,
        "comment": "wrong",
        "userId": "u-1",
        "metadata": {"plan": "pro"},
        "app": "checkout",
        "release": "2.0.0",
    }


def test_defaults_to_the_active_trace():
    ctx = SpanContext(trace_id=int(TRACE, 16), span_id=int(SPAN, 16), is_remote=False, trace_flags=TraceFlags(1))
    # use_span is a context manager (OpenTelemetry's own contextmanager decorator), which pylint does not infer.
    with trace.use_span(NonRecordingSpan(ctx)):  # pylint: disable=not-context-manager
        assert shield360.get_current_trace_id() == TRACE
        assert shield360.get_current_span_id() == SPAN
        with mock.patch("requests.post", return_value=_ok()) as post:
            assert shield360.feedback(5)
    assert post.call_args.kwargs["json"]["traceId"] == TRACE
    assert shield360.get_current_trace_id() is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"score": 1},  # no trace
        {"score": 1, "trace_id": "nope"},
        {"score": 0, "trace_id": TRACE},
        {"score": True, "trace_id": TRACE},
        {"score": 3, "trace_id": TRACE, "scale": "thumbs"},
        {"score": 1, "trace_id": TRACE, "scale": "percent"},
        {"score": 1, "trace_id": TRACE, "span_id": "xyz"},
    ],
)
def test_bad_input_is_false_and_sends_nothing(kwargs):
    with mock.patch("requests.post") as post:
        assert shield360.feedback(**kwargs) is False
    post.assert_not_called()


def test_never_raises():
    with mock.patch("requests.post", side_effect=OSError("offline")):
        assert shield360.feedback(1, trace_id=TRACE) is False
    with mock.patch("requests.post", return_value=_ok(400)):
        assert shield360.feedback(1, trace_id=TRACE) is False


def test_no_key_is_false(monkeypatch):
    monkeypatch.setattr(Shield360Config, "shield360_api_key", None, raising=False)
    with mock.patch("requests.post") as post:
        assert shield360.feedback(1, trace_id=TRACE) is False
    post.assert_not_called()


def test_star_scale_is_sent_so_one_star_is_not_a_thumbs_up():
    with mock.patch("requests.post", return_value=_ok()) as post:
        assert shield360.feedback(1, trace_id=TRACE, scale="stars")
    assert post.call_args.kwargs["json"]["scale"] == "stars"
