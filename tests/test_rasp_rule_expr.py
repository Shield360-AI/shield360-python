"""Custom rule expressions (README "Custom rules"): the shared conformance
corpus (sdk/rasp/testdata/custom-rules.json), the limits, the safe regex
subset and its linear-time Pike VM, CIDR matching, and fail-open evaluation.

Mirrors sdk/typescript/src/rasp/__tests__/rule-expr.test.ts.
"""

import os
import time

import pytest

from rasp_corpus import RASP_DIR, load_json
from shield360.rasp import _rule_expr
from shield360.rasp._rule_expr import (
    RULE_EXPR_LIMITS,
    RuleBudget,
    compile_regex,
    compile_rule_expr,
    evaluate_rule_expr,
    parse_cidr,
    parse_ip_bytes,
)
from shield360.rasp._types import RaspInput

CORPUS = load_json("testdata/custom-rules.json")


def subject_of(s):
    return CORPUS["subjects"][s] if isinstance(s, str) else s


def compiled(src):
    r = compile_rule_expr(src)
    assert r.ok, f"{src}: {r.error}"
    return r.expr


def run(src, subject):
    return evaluate_rule_expr(compiled(src), subject).matched


def test_corpus_is_version_1_and_states_the_same_limits():
    assert CORPUS["version"] == 1
    assert CORPUS["limits"] == dict(RULE_EXPR_LIMITS)


@pytest.mark.parametrize("case", CORPUS["valid"], ids=[c["name"] for c in CORPUS["valid"]])
def test_valid(case):
    r = compile_rule_expr(case["expression"])
    assert ("ok" if r.ok else r.error.code) == "ok"
    if "phase" in case:
        assert r.expr.phase == case["phase"]
    if "usesInput" in case:
        assert r.expr.uses_input == case["usesInput"]
    if "usesBody" in case:
        assert r.expr.uses_body == case["usesBody"]
    for k in case["cases"]:
        assert (k["subject"], evaluate_rule_expr(r.expr, subject_of(k["subject"])).matched) == (k["subject"], k["expect"])


@pytest.mark.parametrize("case", CORPUS["invalid"], ids=[c["name"] for c in CORPUS["invalid"]])
def test_invalid(case):
    r = compile_rule_expr(case["expression"])
    assert ("ok" if r.ok else r.error.code) == case["error"]


def test_corpus_is_the_generator_output():
    with open(os.path.join(RASP_DIR, "scripts", "gen-custom-rules.mjs"), encoding="utf-8") as f:
        assert 'testdata", "custom-rules.json"' in f.read()
    assert len(CORPUS["valid"]) > 60
    assert len(CORPUS["invalid"]) > 60


# ---- compile ------------------------------------------------------------------


def test_refuses_anything_but_a_string():
    for v in (None, 1, {}, [], b"x"):
        r = compile_rule_expr(v)
        assert not r.ok and r.error.code == "empty"


def test_reports_where_a_syntax_error_is():
    r = compile_rule_expr('request.method == "GET" &&& true')
    assert not r.ok and r.error.code == "syntax" and r.error.pos > 20


def test_classifies_the_phase_from_the_fields_read():
    assert compiled('request.path == "/"').phase == "request"
    assert compiled('attack.type == "ssrf"').phase == "finding"
    e = compiled('sink.name == "fs.readFile" && input.key == "query.f"')
    assert (e.phase, e.uses_input, e.uses_body) == ("finding", True, False)
    assert compiled('request.body["a"] == "b"').uses_body
    assert compiled('request.headers["X-A"] == "1" && app.name == "a"').fields == ["app.name", "request.headers"]


def test_guards_parser_recursion_before_the_ast_is_built():
    # Far deeper than Python's recursion limit would allow, within the byte limit.
    assert compile_rule_expr("(" * 1000 + "true" + ")" * 1000).error.code == "depth"
    assert compile_rule_expr("!" * 2000 + "true").error.code == "depth"


def test_never_uses_the_backtracking_re_module_for_rule_patterns():
    with open(_rule_expr.__file__, encoding="utf-8") as f:
        src = f.read()
    assert "import re\n" not in src and "from re " not in src


# ---- evaluation ---------------------------------------------------------------

GET = CORPUS["subjects"]["get"]


def test_short_circuits_left_to_right():
    assert run('request.method == "GET" || request.path.matches("x")', GET)
    assert not run('request.method == "PUT" && request.path.matches("x")', GET)


def test_returns_the_input_that_matched():
    r = evaluate_rule_expr(compiled('input.key == "query.sort"'), GET)
    assert r.matched and r.input == {"value": "name desc", "key": "query.sort", "source": "request"}


def test_reads_sdk_inputs_too():
    inp = RaspInput("../x", "query.f")
    r = evaluate_rule_expr(compiled('input.value.contains("../")'), {"inputs": [inp]})
    assert r.matched and r.input is inp


def test_fails_open_on_a_malformed_subject():
    e = compiled('request.headers["a"] == "b" && input.value == "x"')
    for s in ({}, {"request": "nope"}, {"request": {"headers": "x"}}, {"inputs": "x"}, {"inputs": [None, 1]}, None, "x"):
        assert not evaluate_rule_expr(e, s).matched
    assert run('request.headers["a"] == null', {"request": {"headers": {"b": "inherited"}}})


def test_stops_at_the_budget_and_reports_no_match():
    e = compiled('input.value.matches("a{100}x")')
    big = {"app": "a", "inputs": [{"value": "a" * 4096, "key": f"query.k{i}", "source": "request"} for i in range(256)]}
    budget = RuleBudget(10_000)
    r = evaluate_rule_expr(e, big, budget)
    assert (r.matched, r.exhausted) == (False, True)
    assert budget.steps < 0


def test_matches_in_time_linear_in_the_subject():
    # The classic exponential case for backtracking engines, rewritten in the subset.
    t0 = time.monotonic()
    assert not run('app.name.matches("^(?:a|a)*b$")', {"app": "a" * 4000})
    assert not run('app.name.matches(".*.*.*.*.*.*x")', {"app": "a" * 4096})
    assert time.monotonic() - t0 < 5


def test_matches_reads_only_the_first_4096_code_points():
    assert not run('app.name.matches("b")', {"app": "a" * 4096 + "b"})
    assert run('app.name.matches("b")', {"app": "a" * 4095 + "b"})
    # Astral characters are one code point each, as in every SDK.
    assert run('app.name.matches("^.b$")', {"app": "\U0001f600b"})


# ---- regex subset -------------------------------------------------------------


@pytest.mark.parametrize("p", ["a", "^a$", "[a-z0-9_]+", "(?:x|y){1,3}", r"\d{3}-\d{4}", ".*", "a|", "(?:)", r"[\s\S]"])
def test_regex_accepts(p):
    assert compile_regex(p) is not None


@pytest.mark.parametrize(
    "p",
    [
        "(a+)+",
        "(a*)*",
        "(a|b+)*",
        "a{0,1000}",
        r"\1",
        "(?=x)",
        "(?!x)",
        "(?<=x)",
        "(?P<n>x)",
        r"\Z",
        r"\A",
        r"\cA",
        "a{1,2}{3}",
        r"[a-\d]",
        "x{",
        "\\",
    ],
)
def test_regex_refuses(p):
    assert compile_regex(p) is None


# ---- CIDR ---------------------------------------------------------------------


def test_parses_addresses_strictly():
    assert parse_ip_bytes("1.2.3.4") == [0] * 10 + [255, 255, 1, 2, 3, 4]
    assert parse_ip_bytes("::1") == [0] * 15 + [1]
    assert parse_ip_bytes("1:2:3:4:5:6:1.2.3.4") == [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4]
    for bad in ("1.2.3", "1.2.3.256", "01.2.3.4", ":1", "1:::2", "1:2:3:4:5:6:7:8:9", "12345::", "g::", "1.2.3.4::", "", "١.2.3.4"):
        assert parse_ip_bytes(bad) is None, bad


def test_keeps_ipv4_prefixes_in_ipv4_mapped_space():
    assert parse_cidr("10.0.0.0/8").prefix == 104
    assert parse_cidr("::/0").prefix == 0
    assert parse_cidr("1.2.3.4").prefix == 128


# ---- time budget (Python safeguard, README "Python SDK notes") ------------------


def test_the_time_budget_stops_string_work_outside_the_vm():
    # lowerAscii and comparisons never step the regex VM; only the clock can bound them.
    e = compiled(" || ".join(f'input.value.lowerAscii().lowerAscii() == "{i}"' for i in range(10)))
    big = {"inputs": [{"value": "A" * 4096, "key": f"query.k{i}", "source": "request"} for i in range(256)]}
    budget = RuleBudget(time_left=0.005)
    t0 = time.monotonic()
    r = evaluate_rule_expr(e, big, budget)
    assert (r.matched, r.exhausted) == (False, True)
    assert budget.timed_out and budget.steps < 0
    assert time.monotonic() - t0 < 0.5
    # Spent: the next evaluation charged to it stops at once.
    assert evaluate_rule_expr(compiled("true"), {}, budget).exhausted


def test_the_time_budget_also_bounds_the_vm():
    e = compiled('input.value.matches("a{100}x")')
    big = {"inputs": [{"value": "a" * 4096, "key": f"query.k{i}", "source": "request"} for i in range(256)]}
    budget = RuleBudget(time_left=0.005)
    t0 = time.monotonic()
    assert evaluate_rule_expr(e, big, budget).exhausted
    assert budget.timed_out and budget.steps < 0
    assert time.monotonic() - t0 < 0.5


def test_without_a_time_budget_only_steps_count():
    budget = RuleBudget()
    assert evaluate_rule_expr(compiled('app.name.lowerAscii() == "a"'), {"app": "A"}, budget).matched
    assert budget.time_left is None and not budget.timed_out
