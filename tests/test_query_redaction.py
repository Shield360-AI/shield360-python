"""Credential query values never reach a span.

Mirrors sdk/typescript/src/otel/__tests__/query-redaction.test.ts.
"""

import json

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from shield360.otel.query_redaction import (
    REDACTED,
    QueryRedactionSpanProcessor,
    is_credential_param,
    redact_query_string,
    redact_url,
)


@pytest.mark.parametrize(
    "name",
    ["key", "api_key", "apiKey", "X-Goog-Api-Key", "access_token", "id_token", "refresh_token", "token", "code",
     "client_secret", "password", "sig", "X-Amz-Signature", "X-Amz-Security-Token", "AWSAccessKeyId", "session_id", "jwt"],
)
def test_credential_names(name):
    assert is_credential_param(name)


@pytest.mark.parametrize("name", ["q", "page", "limit", "user", "model", "sort", "monkey", "keyword_count"])
def test_ordinary_names(name):
    assert not is_credential_param(name)


def test_redact_url_keeps_everything_else_byte_for_byte():
    assert (
        redact_url("https://api.example.com/v1/models?key=AIzaSyA-secret&alt=json")
        == f"https://api.example.com/v1/models?key={REDACTED}&alt=json"
    )
    assert redact_url("/reset?token=abc123&lang=en#x") == f"/reset?token={REDACTED}&lang=en#x"
    assert redact_url("/cb?code=4%2F0Ad&state=xyz") == f"/cb?code={REDACTED}&state=xyz"
    assert redact_url("https://user:hunter2@db.example.com/x") == f"https://{REDACTED}:{REDACTED}@db.example.com/x"
    assert redact_url("https://example.com/search?q=hello%20world&page=2") == "https://example.com/search?q=hello%20world&page=2"


def test_encoded_repeated_and_valueless_parameters():
    assert redact_query_string("?api%5Fkey=s1&api_key=s2&debug") == f"?api%5Fkey={REDACTED}&api_key={REDACTED}&debug"
    assert redact_query_string("a=1&b=2") == "a=1&b=2"
    assert redact_query_string("%E0%A4%A=1&token=x") == f"%E0%A4%A=1&token={REDACTED}"
    assert redact_query_string(None) is None


def test_idempotent():
    once = redact_url("https://u:p@h/x?token=a&q=1")
    assert redact_url(once) == once


def test_processor_rewrites_url_attributes_before_any_exporter():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(QueryRedactionSpanProcessor())
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    span = provider.get_tracer("t").start_span(
        "GET",
        attributes={
            "url.full": "https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyA-real-key",
            "url.query": "?access_token=ya29.a0AfH6&fields=id",
            "http.url": "http://svc/x?password=pw",
            "http.target": "/login?token=t0k3n",
            "url.path": "/v1beta/models",
        },
    )
    span.end()
    attrs = dict(exporter.get_finished_spans()[0].attributes)
    assert attrs["url.full"] == f"https://generativelanguage.googleapis.com/v1beta/models?key={REDACTED}"
    assert attrs["url.query"] == f"?access_token={REDACTED}&fields=id"
    assert attrs["http.url"] == f"http://svc/x?password={REDACTED}"
    assert attrs["http.target"] == f"/login?token={REDACTED}"
    assert attrs["url.path"] == "/v1beta/models"
    text = json.dumps(attrs)
    for leaked in ("AIzaSyA-real-key", "ya29", "t0k3n", "=pw"):
        assert leaked not in text
