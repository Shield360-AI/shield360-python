"""Sink rules at work: the generic wrapper points a detector at a library
function named by a rule, on modules already imported and imported later,
and a new rule set takes effect at once. The libraries are stand-in modules.

Mirrors the "a rule at work" part of sdk/typescript/src/rasp/__tests__/sinks-hook.test.ts.
"""

import pickle
import sys
import types

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError, _sinks, init_rasp, shutdown_rasp
from shield360.rasp._hooks.code import install_code_hooks, uninstall_code_hooks
from shield360.rasp._hooks.sinks import install_sink_hooks, uninstall_sink_hooks

INJECTION = "' OR '1'='1"
QUERY = f"SELECT * FROM products WHERE name = '{INJECTION}'"


def rule(**fields):
    base = {"id": "sink.fake.query", "module": "rasp_fake_driver", "target": "query", "check": "sql"}
    parsed = _sinks.parse_sink_rule(dict(base, **fields))
    assert parsed is not None
    return parsed


@pytest.fixture(name="driver")
def _driver(monkeypatch):
    module = types.ModuleType("rasp_fake_driver")

    class Connection:
        def run(self, statement):
            return statement

        @staticmethod
        def raw(sql):
            return sql

    module.query = lambda sql, params=None: sql
    module.Connection = Connection
    monkeypatch.setitem(sys.modules, "rasp_fake_driver", module)
    return module


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_sink_hooks()
    uninstall_code_hooks()
    _sinks.set_sink_rules(_sinks.BUILT_IN_SINKS)
    stop_engine()


def test_blocks_when_the_rule_and_the_attack_mode_both_say_block_with_the_rule_as_the_sink(driver):
    events = use_engine("block")
    _sinks.set_sink_rules([rule(action="block")])
    install_sink_hooks()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: driver.query(QUERY))
    assert events.sinks() == ["rule:sink.fake.query"]


def test_a_monitor_rule_only_reports_even_in_block_mode(driver):
    events = use_engine("block")
    _sinks.set_sink_rules([rule()])
    install_sink_hooks()
    assert in_request([INJECTION], lambda: driver.query(QUERY)) == QUERY
    assert events.attacks() == [("sql_injection", "sqli.userinput", "monitored")]


def test_methods_count_arguments_after_the_instance_and_read_fields(driver):
    events = use_engine("block")
    _sinks.set_sink_rules(
        [
            rule(id="sink.fake.run", target="Connection.run", field="text", action="block"),
            rule(id="sink.fake.raw", target="Connection.raw", action="block"),
        ]
    )
    install_sink_hooks()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: driver.Connection().run({"text": QUERY}))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: driver.Connection.raw(QUERY))
    assert in_request([INJECTION], lambda: driver.Connection().run({"text": "SELECT ?"})) == {"text": "SELECT ?"}
    assert events.sinks() == ["rule:sink.fake.run", "rule:sink.fake.raw"]


def test_runs_the_nosql_check_on_the_request_trees(driver):
    events = use_engine("block")
    _sinks.set_sink_rules([rule(check="nosql", action="block")])
    install_sink_hooks()
    attack = {"$gt": ""}
    with pytest.raises(RaspBlockedError):
        in_request([], lambda: driver.query({"password": attack}), trees=[{"password": attack}])
    assert events.attacks() == [("nosql_injection", "nosqli.operator", "blocked")]


def test_a_new_rule_set_switches_the_old_rules_off_at_once(driver):
    events = use_engine("block")
    original = driver.query
    _sinks.set_sink_rules([rule(action="block")])
    install_sink_hooks()
    assert driver.query is not original
    _sinks.set_sink_rules([])
    assert driver.query is original
    assert in_request([INJECTION], lambda: driver.query(QUERY)) == QUERY
    assert not events


def test_a_rule_applies_to_a_module_imported_later(tmp_path, monkeypatch):
    (tmp_path / "rasp_late_driver.py").write_text("def query(sql):\n    return sql\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    use_engine("block")
    _sinks.set_sink_rules([rule(module="rasp_late_driver", action="block")])
    install_sink_hooks()
    assert "rasp_late_driver" not in sys.modules
    import rasp_late_driver  # pylint: disable=import-outside-toplevel,import-error

    try:
        with pytest.raises(RaspBlockedError):
            in_request([INJECTION], lambda: rasp_late_driver.query(QUERY))
    finally:
        sys.modules.pop("rasp_late_driver", None)


def test_never_wraps_a_function_a_built_in_hook_already_checks():
    events = use_engine("block")
    install_code_hooks()
    hooked = pickle.loads
    _sinks.set_sink_rules([rule(id="sink.pickle", module="pickle", target="loads", check="deser", format="pickle", action="block")])
    install_sink_hooks()
    assert pickle.loads is hooked
    data = pickle.dumps(1)
    with pytest.raises(RaspBlockedError):
        in_request([data.decode("latin-1")], lambda: pickle.loads(data))
    assert events.sinks() == ["pickle.loads"]
    uninstall_sink_hooks()
    assert pickle.loads is hooked


def test_a_target_that_does_not_exist_leaves_the_module_alone(driver):
    before = dict(vars(driver))
    _sinks.set_sink_rules([rule(target="missing.query"), rule(id="sink.b", target="nothing")])
    install_sink_hooks()
    assert dict(vars(driver)) == before


def test_init_applies_the_built_in_rules_and_shutdown_removes_every_hook(driver):
    _sinks.set_sink_rules([])
    original = driver.query
    assert init_rasp({"mode": "block"}, env={}) is True
    try:
        # The built-in list is what init applies; a platform list replaces it.
        _sinks.set_sink_rules([rule(action="block")])
        assert driver.query is not original
    finally:
        shutdown_rasp()
    assert driver.query is original


def test_a_value_passed_by_keyword_is_checked_like_a_positional_one(driver):
    events = use_engine("block")
    _sinks.set_sink_rules(
        [
            rule(action="block"),
            rule(id="sink.fake.run", target="Connection.run", action="block"),
        ]
    )
    install_sink_hooks()
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: driver.query(sql=QUERY))
    with pytest.raises(RaspBlockedError):
        in_request([INJECTION], lambda: driver.Connection().run(statement=QUERY))
    assert events.sinks() == ["rule:sink.fake.query", "rule:sink.fake.run"]


def test_an_xml_rule_for_a_parser_that_never_fetches_stays_monitor(driver):
    events = use_engine("block", attacks={"xxe": "block"})
    _sinks.set_sink_rules([rule(check="xml", action="block")])
    install_sink_hooks()
    doc = '<!DOCTYPE r [<!ENTITY x SYSTEM "http://attacker.example/x">]><r>&x;</r>'
    assert in_request([doc], lambda: driver.query(doc)) == doc
    assert events.attacks() == [("xxe", "xxe.doctype", "monitored")]
