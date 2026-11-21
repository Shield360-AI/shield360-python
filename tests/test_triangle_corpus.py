"""SHIELD: protection triangle — the shared corpus sdk/rasp/testdata/triangle.json
(agent-guides/edge-deception-spec.md, "Protection triangle"), run from the
shared file. Every SDK's Edge-context code passes the same cases."""

import json
import pathlib

import pytest

from shield360.rasp._edge_context import ReplayCache, edge_says_suspect, parse_edge_keys, path_hash, sign_verdict, verify_edge_context

CORPUS = json.loads((pathlib.Path(__file__).resolve().parents[3] / "sdk/rasp/testdata/triangle.json").read_text(encoding="utf-8"))
KEYS = parse_edge_keys(CORPUS["edgeContext"])


@pytest.mark.parametrize("case", CORPUS["parseKeys"], ids=lambda c: c["name"])
def test_parse_keys(case):
    assert [kid for kid, _ in parse_edge_keys(case["config"])] == case["kids"]


def test_context_cases():
    caches = {}
    for case in CORPUS["context"]:
        cache = caches.setdefault(case["replayGroup"], ReplayCache()) if case["replayGroup"] else None
        got = verify_edge_context(KEYS, case["header"], case["method"], case["path"], case["requestId"], case["now"], cache)
        assert got == case["expect"], case["name"]


@pytest.mark.parametrize("case", CORPUS["verdict"], ids=lambda c: c["name"])
def test_verdict(case):
    assert sign_verdict(KEYS, case["rid"], case["act"], case["cat"], case["src"], case["ttl"], iat=case["iat"]) == case["expect"]


@pytest.mark.parametrize("case", CORPUS["suspect"])
def test_suspect(case):
    assert edge_says_suspect(case["context"]) is case["expect"]


@pytest.mark.parametrize("case", CORPUS["pathHash"], ids=lambda c: c["path"] or "empty")
def test_path_hash(case):
    assert path_hash(case["path"]) == case["hex"]
