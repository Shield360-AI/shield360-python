"""The flag engine port answers every shared vector exactly as the TypeScript engine does."""

import json
import pathlib

import pytest

from shield360.flags import _engine


def _vectors():
    here = pathlib.Path(__file__).resolve()
    # Beside this SDK in the monorepo (sdk/flags-core), or inside the SDK's public mirror (flags-core/).
    candidates = [
        here.parents[2] / "flags-core" / "testdata" / "vectors.json",
        here.parents[1] / "flags-core" / "testdata" / "vectors.json",
    ]
    path = next((p for p in candidates if p.exists()), candidates[0])
    return json.loads(path.read_text(encoding="utf-8"))


VECTORS = _vectors()


@pytest.mark.parametrize("case", VECTORS["murmur3"], ids=lambda c: repr(c["input"]))
def test_murmur3(case):
    assert _engine.murmur3(case["input"]) == case["murmur3"]


@pytest.mark.parametrize("case", VECTORS["text"], ids=lambda c: repr(c["value"]))
def test_text_of(case):
    assert _engine.text_of(case["value"]) == case["text"]


@pytest.mark.parametrize("case", VECTORS["evaluations"], ids=lambda c: c["name"])
def test_evaluations(case):
    assert _engine.evaluate(case["flag"], case["context"], case.get("segments")) == case["expect"]


@pytest.mark.parametrize("case", VECTORS["segmentValidation"], ids=lambda c: c["name"])
def test_segment_validation(case):
    assert _engine.validate_segment(case["segment"]) == case["errors"]


@pytest.mark.parametrize("case", VECTORS["validation"], ids=lambda c: c["name"])
def test_validation(case):
    assert _engine.validate_flag(case["flag"]) == case["errors"]


def _flag(weights):
    return {
        "key": "dist",
        "type": "string",
        "variations": [{"key": k, "value": k} for k, _ in weights],
        "offVariation": weights[0][0],
        "on": True,
        "rules": [],
        "fallthrough": {"rollout": {"weights": [{"variation": k, "weight": w} for k, w in weights]}},
        "salt": "salt",
    }


def test_rollout_distribution_follows_weights():
    flag = _flag([("a", 10000), ("b", 30000), ("c", 60000)])
    counts = {"a": 0, "b": 0, "c": 0}
    for i in range(20000):
        counts[_engine.evaluate(flag, {"key": f"user-{i}"})["variation"]] += 1
    assert abs(counts["a"] / 20000 - 0.10) < 0.015
    assert abs(counts["b"] / 20000 - 0.30) < 0.015
    assert abs(counts["c"] / 20000 - 0.60) < 0.015


def test_bucketing_is_stable_and_never_raises():
    flag = _flag([("a", 50000), ("b", 50000)])
    first = [_engine.evaluate(flag, {"key": f"u{i}"})["variation"] for i in range(200)]
    again = [_engine.evaluate(flag, {"key": f"u{i}"})["variation"] for i in range(200)]
    assert first == again
    assert _engine.evaluate(None, None)["reason"]["kind"] == "ERROR"
    assert _engine.evaluate(flag, "not a dict")["reason"]["kind"] == "FALLTHROUGH"
