# pylint: disable=missing-function-docstring
"""
The masking contract (sdk/rasp/README.md, "Masking"), held to the shared
cases in sdk/rasp/testdata/masking.json like every other SDK.
"""

import json
from pathlib import Path

import pytest

from shield360._masking import is_sensitive_key, mask_secrets, mask_text, mask_value
from shield360.rasp._engine import mask_snippet


def _cases():
    here = Path(__file__).resolve()
    for candidate in (
        here.parents[2] / "rasp" / "testdata" / "masking.json",
        here.parents[1] / "rasp" / "testdata" / "masking.json",
    ):
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8"))
    raise FileNotFoundError("sdk/rasp/testdata/masking.json")


CASES = _cases()


@pytest.mark.parametrize("case", CASES["text"], ids=lambda c: c["name"])
def test_text(case):
    assert mask_secrets(case["in"]) == case["out"]


@pytest.mark.parametrize("case", CASES["limited"], ids=lambda c: c["name"])
def test_limited(case):
    assert mask_text(case["in"], case["limit"]) == case["out"]


@pytest.mark.parametrize("case", CASES["keys"], ids=lambda c: c["key"])
def test_keys(case):
    assert is_sensitive_key(case["key"]) is case["sensitive"]


@pytest.mark.parametrize("case", CASES["values"], ids=lambda c: c["key"])
def test_values(case):
    assert mask_value(case["key"], case["value"], 4096) == case["out"]


@pytest.mark.parametrize("case", CASES["snippets"], ids=lambda c: c["in"][:20])
def test_snippets(case):
    assert mask_snippet(case["in"]) == case["out"]
