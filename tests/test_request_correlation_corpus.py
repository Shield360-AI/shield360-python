"""Request correlation: the shared vectors (sdk/rasp/testdata/request-correlation.json)."""

import json
import os

import pytest

from shield360.otel.edge_request import request_id_of, trace_id_of

_CORPUS = json.load(open(os.path.join(os.path.dirname(__file__), "..", "..", "rasp", "testdata", "request-correlation.json"), encoding="utf-8"))


@pytest.mark.parametrize("case", _CORPUS["requestId"], ids=lambda c: c["name"])
def test_request_id(case):
    assert request_id_of(case["value"]) == case["expect"]


@pytest.mark.parametrize("case", _CORPUS["traceparent"], ids=lambda c: c["name"])
def test_traceparent(case):
    assert trace_id_of(case["value"]) == case["expect"]
