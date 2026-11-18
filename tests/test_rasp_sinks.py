"""Sink rule parsing: each field checked, invalid rules dropped one by one,
Python dotted modules accepted, ``runtimes`` must include python when given.

Mirrors the parseSinkRule part of sdk/typescript/src/rasp/__tests__/sinks-hook.test.ts.
"""

import pytest

from shield360.rasp._sinks import BUILT_IN_SINKS, parse_sink_rule, parse_sink_rules


def test_accepts_a_complete_rule_and_fills_defaults():
    r = parse_sink_rule({"id": "sink.x", "module": "@scope/pkg", "target": "default.query", "check": "sql"})
    assert r is not None and r.arg == 0 and r.action == "monitor"


def test_accepts_python_dotted_modules_and_python_runtimes():
    r = parse_sink_rule(
        {
            "id": "sink.py.loads",
            "module": "_pickle",
            "target": "loads",
            "check": "deser",
            "format": "pickle",
            "runtimes": ["python", "node"],
        }
    )
    assert r is not None and r.module == "_pickle" and r.format == "pickle"
    r = parse_sink_rule(
        {"id": "sink.y", "module": "yaml.constructor", "target": "Loader.construct", "check": "deser", "format": "yaml"}
    )
    assert r is not None
    r = parse_sink_rule(
        {"id": "sink.db", "module": "mydriver.cursor", "target": "Cursor.execute", "check": "sql", "arg": 1, "field": "sql",
         "dialect": "postgres", "action": "block", "resolvesExternal": True}
    )
    assert r is not None and r.arg == 1 and r.field == "sql" and r.dialect == "postgres" and r.action == "block"
    for dialect in ("oracle", "db2"):
        r = parse_sink_rule({"id": "sink.db", "module": "m", "target": "a", "check": "sql", "dialect": dialect})
        assert r is not None and r.dialect == dialect


@pytest.mark.parametrize(
    "raw",
    [
        {"module": "m", "target": "a", "check": "sql"},
        {"id": "sink.my-driver.query", "module": "m", "target": "a", "check": "sql"},
        {"id": "s" + "x" * 59, "module": "m", "target": "a", "check": "sql"},
        {"id": "x", "module": "m", "target": "a.__proto__.b", "check": "sql"},
        {"id": "x", "module": "m", "target": "constructor", "check": "sql"},
        {"id": "x", "module": "m", "target": "a.__globals__", "check": "sql"},
        {"id": "x", "module": "m", "target": "a.b.c.d.e", "check": "sql"},
        {"id": "x", "module": "m", "target": "a", "check": "eval-anything"},
        {"id": "x", "module": "m", "target": "a", "check": "deser"},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "action": "off"},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "runtimes": ["node"]},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "runtimes": "python"},
        {"id": "x", "module": "../m", "target": "a", "check": "sql"},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "field": "a.b"},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "arg": True},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "arg": 17},
        {"id": "x", "module": "m", "target": "a", "check": "sql", "dialect": "informix"},
        {"id": "x", "module": "m", "target": "a", "check": "path", "op": "chmod"},
    ],
    ids=[
        "no id",
        "an id with a hyphen",
        "an id too long for the event sink",
        "__proto__ in the path",
        "constructor in the path",
        "a dunder in the path",
        "too deep a path",
        "an unknown check",
        "deser without a format",
        "an action of off",
        "another runtime only",
        "runtimes not a list",
        "a module path with ..",
        "a field that is not a name",
        "a boolean arg",
        "an arg out of range",
        "an unknown dialect",
        "an unknown file op",
    ],
)
def test_drops(raw):
    assert parse_sink_rule(raw) is None


def test_keeps_the_valid_rules_of_a_list_at_most_64_first_id_wins():
    many = [{"id": f"r{i}", "module": "m", "target": "a", "check": "sql"} for i in range(70)]
    assert len(parse_sink_rules([{"bad": True}] + many)) == 64
    rules = parse_sink_rules(
        [{"id": "a", "module": "m", "target": "x", "check": "sql"}, {"id": "a", "module": "m", "target": "y", "check": "sql"}]
    )
    assert rules[0].target == "x" and len(rules) == 1
    assert not parse_sink_rules("nope")


def test_the_built_in_list_parses():
    assert isinstance(BUILT_IN_SINKS, list)
