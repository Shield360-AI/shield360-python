"""The shared RASP corpus (sdk/rasp/testdata): every benign case must fire
nothing (false-positive rate per section, must be 0), every entry of
attack-examples.json must be detected as it says, and the embedded data
files must stay byte-identical to the contract's copies."""

import os

import pytest

from rasp_corpus import RASP_DIR, SECTIONS, load_json, run_case
from shield360.rasp._lexers import sql_tokens
from shield360.rasp._sinks import BUILT_IN_SINKS

BENIGN = load_json("testdata/benign.json")
ATTACKS = load_json("testdata/attack-examples.json")
TEMPLATE_ATTACKS = load_json("testdata/template-attack-examples.json")
LEXER = load_json("testdata/sql-lexer.json")
_RATES = {}


@pytest.fixture(scope="module", autouse=True)
def _report_rates():
    yield
    # The report the contract asks each SDK for: false positives per section.
    print("\nRASP false-positive rates (Python):\n" + "\n".join(f"  {s}: {r}" for s, r in _RATES.items()))


def test_is_the_generated_corpus_version_1_with_every_section():
    assert BENIGN["version"] == 1
    for s in SECTIONS:
        assert isinstance(BENIGN[s], list) and BENIGN[s]


@pytest.mark.parametrize("section", SECTIONS)
def test_no_false_positives(section):
    cases = BENIGN[section]
    fired = [(c["name"], f) for c in cases for f in [run_case(section, c)] if f]
    _RATES[section] = f"{len(fired)}/{len(cases)} ({100 * len(fired) / len(cases):.2f}%)"
    assert [f"{name}: {f.rule}" for name, f in fired] == []


def test_attack_examples_is_the_reviewed_file():
    assert isinstance(ATTACKS["cases"], list)


@pytest.mark.parametrize("case", LEXER["cases"], ids=[c["name"] for c in LEXER["cases"]])
def test_sql_lexer_conformance(case):
    assert [[t.kind, t.text] for t in sql_tokens(case["query"], case["dialect"])] == case["tokens"]


ATTACK_CASES = ATTACKS["cases"] + TEMPLATE_ATTACKS["cases"]


@pytest.mark.parametrize("case", ATTACK_CASES, ids=[str(c.get("name") or c["check"]) for c in ATTACK_CASES])
def test_detects_attack_example(case):
    f = run_case(case["check"], case)
    assert f is not None and f.attack == case["expect"]["attack"]
    if case["expect"].get("rule"):
        assert f.rule == case["expect"]["rule"]


def _embedded(name):
    with open(os.path.join(os.path.dirname(__file__), "..", "src", "shield360", "rasp", "data", name), "rb") as f:
        return f.read()


def _contract(rel):
    with open(os.path.join(RASP_DIR, rel), "rb") as f:
        return f.read()


@pytest.mark.parametrize(
    "name,rel",
    [
        ("default-rules.json", "rules/default-rules.json"),
        ("default-sinks.json", "rules/default-sinks.json"),
        ("dnslog-domains.json", "testdata/dnslog-domains.json"),
    ],
)
def test_embedded_data_is_byte_identical(name, rel):
    assert _embedded(name) == _contract(rel)


def test_built_in_sinks_parse():
    assert isinstance(BUILT_IN_SINKS, list)
