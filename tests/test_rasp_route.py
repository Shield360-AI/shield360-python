"""Event route (sdk/rasp/README.md "Event route"): the shared conformance cases
(sdk/rasp/testdata/routes.json), and attack events built from a path when the
framework gives no route template.

Mirrors sdk/typescript/src/rasp/__tests__/route.test.ts.
"""

import pytest

from rasp_corpus import load_json
from shield360.rasp._context import event_route_of, new_context, reset_context, set_context
from shield360.rasp._engine import configure_engine, handle_finding, set_event_sink
from shield360.rasp._iast import iast_route_of
from shield360.rasp._types import Finding, RaspInput

CASES = load_json("testdata/routes.json")["cases"]
EVENTS = []
FINDING = Finding("sql_injection", "sqli.userinput", RaspInput("v", "query.id", "request"))


class _Sink:
    def add(self, event, fold_key):  # pylint: disable=unused-argument
        EVENTS.append(event)


@pytest.fixture(autouse=True)
def _engine():
    EVENTS.clear()
    configure_engine(enabled=True, application_name="orders-api", env={})
    set_event_sink(_Sink())
    yield
    set_event_sink(None)
    configure_engine(enabled=False, application_name="default", env={})


@pytest.mark.parametrize("case", CASES, ids=[c["path"] for c in CASES])
def test_event_route_conformance(case):
    assert event_route_of(case["path"]) == case["route"]
    assert iast_route_of(case["path"]) == case["route"]


def _route_of_event(**ctx):
    token = set_context(new_context(in_request=True, method="get", **ctx))
    try:
        handle_finding(FINDING, "psycopg.execute")
    finally:
        reset_context(token)
    return EVENTS[-1]["attrs"]["shield360.rasp.route"]


def test_attack_event_never_carries_a_secret_looking_path_segment():
    assert _route_of_event(path="/reset/Zx9TqLm2Rk7WpA4s/confirm") == "/reset/:id/confirm"


def test_attack_event_keeps_the_framework_route_template():
    assert _route_of_event(path="/reset/Zx9TqLm2Rk7WpA4s/confirm", route="/reset/:Token/confirm") == "/reset/:Token/confirm"


def test_attack_event_keeps_a_route_passed_by_the_hook():
    handle_finding(FINDING, "psycopg.execute", route="/Files/{fileName}", path="/Files/Secret")
    assert EVENTS[0]["attrs"]["shield360.rasp.route"] == "/Files/{fileName}"
