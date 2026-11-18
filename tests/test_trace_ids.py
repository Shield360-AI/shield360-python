"""SHIELD: security event trace ids — RASP and AI security events carry the
request's W3C trace and span; a folded or merged repeat carries none."""

from opentelemetry import trace
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from shield360._trace_ids import trace_attrs, without_trace
from shield360.rasp._reporter import FOLD_S, RaspReporter

TRACE = 0x4BF92F3577B34DA6A3CE929D0E0E4736
SPAN = 0x00F067AA0BA902B7


def _span():
    return NonRecordingSpan(SpanContext(trace_id=TRACE, span_id=SPAN, is_remote=False, trace_flags=TraceFlags(1)))


def test_trace_attrs_in_and_out_of_a_span():
    assert not trace_attrs("p.")
    with trace.use_span(_span()):
        assert trace_attrs("p.") == {"p.trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "p.span_id": "00f067aa0ba902b7"}


def test_without_trace():
    assert without_trace({"a": 1, "p.trace_id": "x", "p.span_id": "y"}, "p.") == {"a": 1}


def _event(event_id="a" * 32):
    return {"name": "shield360.rasp.event", "time": "1970-01-01T00:00:00.000Z", "attrs": {"shield360.rasp.event_id": event_id}}


def test_reporter_attaches_the_trace_and_drops_it_on_a_folded_repeat():
    now = [1000.0]
    r = RaspReporter("https://example.test", "k", "shop", now=lambda: now[0])
    with trace.use_span(_span()):
        r.add(_event(), "k1")
        r.add(_event(), "k1")
    assert r.pending()[0]["attrs"]["shield360.rasp.trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    now[0] += FOLD_S + 1
    r.add(_event("b" * 32), "k2")
    fold = [e for e in r.pending() if "shield360.rasp.count" in e["attrs"]]
    assert fold and "shield360.rasp.trace_id" not in fold[0]["attrs"]
