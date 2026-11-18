"""Hermetic tests for cost per end customer: set_customer, customer(), the span processor."""

import asyncio
import math

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)

import shield360
from shield360._customer import (
    ATTR_CUSTOMER_TENANT_ID,
    ATTR_CUSTOMER_USER_ID,
    CustomerSpanProcessor,
    normalise_customer,
    normalise_customer_id,
)

TENANT = "shield360.customer.tenant_id"
USER = "shield360.customer.user_id"


@pytest.fixture(autouse=True)
def _clear_default():
    shield360.set_customer(None)
    yield
    shield360.set_customer(None)


@pytest.fixture(name="setup")
def fixture_setup():
    """A provider with the customer processor and an in-memory exporter."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(CustomerSpanProcessor())
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider.get_tracer("test"), exporter


def _last_attrs(exporter):
    return exporter.get_finished_spans()[-1].attributes


def test_attribute_keys():
    assert ATTR_CUSTOMER_TENANT_ID == TENANT
    assert ATTR_CUSTOMER_USER_ID == USER
    assert shield360.SemanticConvention.SHIELD360_CUSTOMER_TENANT_ID == TENANT
    assert shield360.SemanticConvention.SHIELD360_CUSTOMER_USER_ID == USER


def test_no_customer_by_default():
    assert shield360.get_customer() is None


def test_set_and_clear_default():
    shield360.set_customer(tenant_id="acme", user_id="u1")
    assert shield360.get_customer() == {"tenant_id": "acme", "user_id": "u1"}
    shield360.set_customer(None)
    assert shield360.get_customer() is None


def test_scoped_wins_nests_and_restores():
    shield360.set_customer(tenant_id="default-co")
    with shield360.customer(tenant_id="acme", user_id="u1"):
        assert shield360.get_customer() == {"tenant_id": "acme", "user_id": "u1"}
        with shield360.customer(tenant_id="globex"):
            assert shield360.get_customer() == {"tenant_id": "globex"}
        assert shield360.get_customer() == {"tenant_id": "acme", "user_id": "u1"}
    assert shield360.get_customer() == {"tenant_id": "default-co"}


def test_works_as_decorator():
    @shield360.customer(tenant_id="acme")
    def tagged():
        return shield360.get_customer()

    assert tagged() == {"tenant_id": "acme"}
    assert tagged() == {"tenant_id": "acme"}
    assert shield360.get_customer() is None


def test_none_or_invalid_scoped_customer_means_no_customer():
    shield360.set_customer(tenant_id="default-co")
    with shield360.customer(tenant_id=None):
        assert shield360.get_customer() is None
    with shield360.customer(tenant_id="   ", user_id="u1"):
        assert shield360.get_customer() is None


def test_asyncio_tasks_keep_their_own_customer():
    async def run(tenant):
        with shield360.customer(tenant_id=tenant):
            await asyncio.sleep(0.001)
            return shield360.get_customer()["tenant_id"]

    async def main():
        return await asyncio.gather(run("a"), run("b"), run("c"))

    assert asyncio.run(main()) == ["a", "b", "c"]
    assert shield360.get_customer() is None


def test_get_customer_returns_a_copy():
    shield360.set_customer(tenant_id="acme")
    shield360.get_customer()["tenant_id"] = "mutated"
    assert shield360.get_customer() == {"tenant_id": "acme"}


def test_trims_and_converts_numbers():
    assert normalise_customer_id("  acme ") == "acme"
    assert normalise_customer_id(42) == "42"
    assert normalise_customer_id("x" * 256) == "x" * 256


@pytest.mark.parametrize(
    "value",
    [
        "",
        "  \t ",
        "x" * 257,
        "ac\nme",
        "ac\x00me",
        "ac\x7fme",
        "ac\x85me",
        math.nan,
        math.inf,
        True,
        None,
        {"id": "acme"},
        b"acme",
    ],
)
def test_drops_invalid_ids(value):
    assert normalise_customer_id(value) is None


def test_user_without_tenant_is_dropped():
    assert normalise_customer(None, "u1") is None
    assert normalise_customer("", "u1") is None
    shield360.set_customer(tenant_id=None, user_id="u1")
    assert shield360.get_customer() is None


def test_invalid_user_keeps_tenant():
    assert normalise_customer("acme", "bad\nid") == {"tenant_id": "acme"}


def test_invalid_default_clears_previous():
    shield360.set_customer(tenant_id="acme")
    shield360.set_customer(tenant_id="")
    assert shield360.get_customer() is None


def test_processor_leaves_spans_alone_without_customer(setup):
    tracer, exporter = setup
    tracer.start_span("chat").end()
    attrs = _last_attrs(exporter)
    assert TENANT not in attrs
    assert USER not in attrs


def test_processor_stamps_default_on_every_span(setup):
    tracer, exporter = setup
    shield360.set_customer(tenant_id="acme", user_id="u1")
    tracer.start_span("GET /orders", attributes={"http.method": "GET"}).end()
    attrs = _last_attrs(exporter)
    assert attrs[TENANT] == "acme"
    assert attrs[USER] == "u1"


def test_processor_stamps_scoped_customer_in_asyncio(setup):
    tracer, exporter = setup
    shield360.set_customer(tenant_id="default-co")

    async def call():
        with shield360.customer(tenant_id="acme", user_id=7):
            await asyncio.sleep(0)
            tracer.start_span("chat").end()

    asyncio.run(call())
    attrs = _last_attrs(exporter)
    assert attrs[TENANT] == "acme"
    assert attrs[USER] == "7"

    tracer.start_span("chat").end()
    attrs = _last_attrs(exporter)
    assert attrs[TENANT] == "default-co"
    assert USER not in attrs


def test_processor_never_overwrites_caller_tenant(setup):
    tracer, exporter = setup
    shield360.set_customer(tenant_id="acme", user_id="u1")
    tracer.start_span("chat", attributes={TENANT: "given"}).end()
    attrs = _last_attrs(exporter)
    assert attrs[TENANT] == "given"
    assert USER not in attrs


def test_setup_tracing_registers_the_processor(monkeypatch):
    """setup_tracing adds CustomerSpanProcessor to a reused SDK provider."""
    # pylint: disable=import-outside-toplevel
    from opentelemetry import trace
    from shield360.otel import tracing

    provider = TracerProvider()
    added = []
    monkeypatch.setattr(provider, "add_span_processor", added.append)
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)
    monkeypatch.setattr(tracing, "TRACER_SET", False)
    tracing.setup_tracing(
        application_name="app",
        environment="test",
        tracer=None,
        otlp_endpoint=None,
        otlp_headers=None,
        disable_batch=True,
        capture_code_location=False,
    )
    assert any(isinstance(p, CustomerSpanProcessor) for p in added)
