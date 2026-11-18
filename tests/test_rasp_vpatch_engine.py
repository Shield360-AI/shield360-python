"""Virtual patches: each built-in rule matches a request built from the shape
its own rule file documents (no new payloads), and stops matching when one
clause is missing. Then the engine: modes, caps, kill switches, events.

Mirrors sdk/typescript/src/rasp/__tests__/vpatch-engine.test.ts.
"""

import platform
import re
import time

import pytest

from rasp_corpus import request_for, rule_runtime
from shield360.rasp._context import new_context, reset_context, route_of, set_context
from shield360.rasp._engine import (
    RemoteConfig,
    check,
    configure_engine,
    handle_finding,
    is_active,
    mask_snippet,
    mode_for,
    set_event_sink,
    set_remote_config,
    set_runtime_disabled,
    virtual_patches,
)
from shield360.rasp._types import Finding, RaspBlockedError, RaspInput
from shield360.rasp._vpatch import BUILT_IN_RULES, VpRequest, clause_matches, match_virtual_patches, needs_body, rule_applies


def without(rule, i):
    """The same request without what one clause needs."""
    return request_for({**rule, "match": [c for k, c in enumerate(rule["match"]) if k != i]})


@pytest.mark.parametrize("rule", BUILT_IN_RULES, ids=[r["id"] for r in BUILT_IN_RULES])
def test_matches_its_documented_request_shape(rule):
    rt, version = rule_runtime(rule)
    f = match_virtual_patches(request_for(rule), [rule], "all", rt, version)
    assert f is not None and f.attack == "virtual_patch" and f.rule == rule["id"] and f.action == rule.get("action", "block")
    if rule.get("cves"):
        assert f.cve == rule["cves"][0]


@pytest.mark.parametrize("rule", BUILT_IN_RULES, ids=[r["id"] for r in BUILT_IN_RULES])
def test_needs_every_clause(rule):
    rt, version = rule_runtime(rule)
    for i, c in enumerate(rule["match"]):
        r = without(rule, i)
        # A clause on a target the remaining clauses also fill can still be met; only check clauses that are not.
        if clause_matches(r, c):
            continue
        assert match_virtual_patches(r, [rule], "all", rt, version) is None


def test_runtime_versions_half_open_ranges_other_runtimes_skip_node_rules():
    rule = next(r for r in BUILT_IN_RULES if (r.get("runtimeVersions") or {}).get("node"))
    lo, hi = rule["runtimeVersions"]["node"][0]
    assert rule_applies(rule, "node", lo)
    assert not rule_applies(rule, "node", hi)
    assert not rule_applies(rule, "python", lo)


def test_python_runtime_and_versions():
    py = platform.python_version()
    major_minor = ".".join(py.split(".")[:2])
    rule = {"id": "vp.py", "runtimes": ["python"], "runtimeVersions": {"python": [[f"{major_minor}.0", "99.0.0"]]}, "match": []}
    assert rule_applies(rule)
    assert not rule_applies({**rule, "runtimeVersions": {"python": [["1.0.0", "2.0.0"]]}})
    assert not rule_applies({**rule, "runtimes": ["node"]})
    # Node-only built-in rules never apply in Python.
    assert all(not rule_applies(r) for r in BUILT_IN_RULES if r.get("runtimes") == ["node"])
    # The example rule names no runtime, so it applies here.
    example = next(r for r in BUILT_IN_RULES if r.get("example"))
    assert match_virtual_patches(request_for(example), BUILT_IN_RULES).rule == example["id"]


def test_phases_head_rules_never_read_the_body_body_rules_wait_for_it():
    body_rule = next(r for r in BUILT_IN_RULES if needs_body(r))
    rt, version = rule_runtime(body_rule)
    r = request_for(body_rule)
    assert match_virtual_patches(r, [body_rule], "head", rt, version) is None
    assert match_virtual_patches(r, [body_rule], "body", rt, version).rule == body_rule["id"]


def test_refuses_patterns_with_backreferences_or_lookaround():
    r = VpRequest(method="GET", path="/aa")
    assert clause_matches(r, {"target": "path", "op": "regex", "value": "^/a+$"})
    assert not clause_matches(r, {"target": "path", "op": "regex", "value": "(a)\\1"})
    assert not clause_matches(r, {"target": "path", "op": "regex", "value": "a(?=a)"})
    assert not clause_matches(r, {"target": "path", "op": "regex", "value": "(?P<x>a)(?P=x)"})


# ---- engine ----

EVENTS = []


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)


FINDING = Finding("sql_injection", "sqli.userinput", RaspInput("v", "query.id", "request"))


def remote(**over):
    base = {"version": "v1", "exp": time.time() + 3600, "kill_switch": False, "snippets": False, "attacks": {}, "rules": None}
    base.update(over)
    return RemoteConfig(**base)


@pytest.fixture(autouse=True)
def _engine():
    EVENTS.clear()
    configure_engine(enabled=True, application_name="orders-api", env={})
    set_event_sink(_Sink())
    yield
    set_event_sink(None)
    configure_engine(enabled=False, application_name="default", env={})


def test_monitor_by_default_reports_never_raises():
    assert handle_finding(FINDING, "psycopg.execute") == "monitored"
    assert len(EVENTS) == 1
    a = EVENTS[0]["attrs"]
    assert re.fullmatch(r"[a-f0-9]{32}", a["shield360.rasp.event_id"])
    assert a["shield360.rasp.input_key"] == "query.id"
    assert a["shield360.rasp.config_version"] == "local"
    assert a["shield360.rasp.language"] == "python"
    assert '"v"' not in repr(EVENTS).replace("'", '"')


def test_block_mode_raises_the_typed_error_with_the_event_id():
    configure_engine(enabled=True, application_name="a", attacks={"sql_injection": "block"}, env={})
    with pytest.raises(RaspBlockedError) as err:
        handle_finding(FINDING, "psycopg.execute")
    assert err.value.event_id == EVENTS[0]["attrs"]["shield360.rasp.event_id"]
    assert err.value.status_code == 403
    assert err.value.attack == "sql_injection" and err.value.rule == "sqli.userinput"


def test_xss_never_blocks():
    configure_engine(enabled=True, application_name="a", mode="block", env={})
    assert mode_for("xss") == "monitor"
    assert handle_finding(Finding("xss", "xss.reflected"), "http.response") == "monitored"


def test_virtual_patch_capped_by_its_own_action_and_by_the_mode():
    configure_engine(enabled=True, application_name="a", attacks={"virtual_patch": "block"}, env={})
    assert handle_finding(Finding("virtual_patch", "vp.x", action="monitor"), "server.request") == "monitored"
    configure_engine(enabled=True, application_name="a", env={})
    assert handle_finding(Finding("virtual_patch", "vp.x", action="block"), "server.request") == "monitored"


def test_signed_config_overrides_local_modes_except_a_local_off():
    configure_engine(enabled=True, application_name="a", attacks={"sql_injection": "monitor", "ssrf": "off"}, env={})
    set_remote_config(remote(attacks={"sql_injection": "block", "ssrf": "block"}))
    assert mode_for("sql_injection") == "block"
    assert mode_for("ssrf") == "off"
    assert mode_for("xxe") == "monitor"


def test_monitor_only_caps_block():
    configure_engine(enabled=True, application_name="a", mode="block", monitor_only=True, env={})
    assert mode_for("sql_injection") == "monitor"


def test_kill_switch_order_env_off_signed_kill_switch_runtime_call():
    configure_engine(enabled=True, application_name="a", env={"SHIELD360_RASP": "off"})
    assert not is_active()
    configure_engine(enabled=True, application_name="a", env={})
    set_remote_config(remote(kill_switch=True))
    assert not is_active()
    assert mode_for("sql_injection") == "off"
    set_remote_config(remote())
    set_runtime_disabled(True)
    assert not is_active()
    set_runtime_disabled(False)
    assert is_active()


def test_env_block_sets_the_default_mode():
    configure_engine(enabled=True, application_name="a", env={"SHIELD360_RASP": "block"})
    assert mode_for("command_injection") == "block"


def test_signed_config_rules_replace_the_built_in_list_none_keeps_it():
    set_remote_config(remote(rules=[{"id": "vp.only", "match": [{"target": "method", "op": "equals", "values": ["GET"]}]}]))
    assert [r["id"] for r in virtual_patches()] == ["vp.only"]
    set_remote_config(remote(rules=None))
    assert virtual_patches() is BUILT_IN_RULES


def test_snippets_only_with_the_signed_flag_masked_and_at_most_64_characters():
    secret = "token=" + "s" * 30
    handle_finding(Finding("sql_injection", "sqli.userinput", RaspInput(secret, "body.t", "request")), "psycopg.execute")
    assert "shield360.rasp.snippet" not in EVENTS[0]["attrs"]
    set_remote_config(remote(snippets=True))
    handle_finding(Finding("sql_injection", "sqli.stacked", RaspInput(secret, "body.t", "request")), "psycopg.execute")
    assert EVENTS[1]["attrs"]["shield360.rasp.snippet"] == "token=***"
    assert len(mask_snippet("a" * 200)) <= 64


def test_events_carry_the_route_or_the_path_with_ids_replaced_and_shaped_keys():
    assert route_of("/api/orders/12345/items/3f2a9c1e-0b1d-4e6f-8a7b-9c0d1e2f3a4b") == "/api/orders/:id/items/:id"
    token = set_context(new_context(in_request=True, method="get", path="/api/orders/42", framework="flask"))
    try:
        handle_finding(Finding("sql_injection", "sqli.userinput", RaspInput("v", "query.a b", "request")), "psycopg.execute")
    finally:
        reset_context(token)
    a = EVENTS[0]["attrs"]
    assert a["shield360.rasp.route"] == "/api/orders/:id"
    assert a["shield360.rasp.method"] == "GET"
    assert a["shield360.rasp.framework"] == "flask"
    assert a["shield360.rasp.input_key"] == "query.a_b"


def test_check_fails_open_on_detector_errors_and_reraises_only_the_block_error():
    def boom():
        raise ValueError("detector bug")

    assert check("psycopg.execute", boom) is None
    configure_engine(enabled=True, application_name="a", mode="block", env={})
    with pytest.raises(RaspBlockedError):
        check("psycopg.execute", lambda: FINDING)


def test_inactive_findings_are_dropped():
    configure_engine(enabled=False, application_name="a", env={})
    assert handle_finding(FINDING, "psycopg.execute") is None
