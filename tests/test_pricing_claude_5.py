# pylint: disable=missing-function-docstring, missing-class-docstring, too-few-public-methods
"""
The bundled price table knows the current Claude models.

``get_chat_model_cost`` returns 0 for a model it has no entry for, and 0 is
indistinguishable from "this call was free". When the table fell behind the
model line-up, every request to the newest — and dearest — models was reported
as costing nothing, which is the one direction a cost tracker must never be
wrong in. These pin the entries and the arithmetic against the published
per-million prices, and the TypeScript SDK carries the same test so the two
tables cannot drift apart unnoticed.
"""

import json
from pathlib import Path

import pytest

import shield360
from shield360.__helpers import get_chat_model_cost

MILLION = 1_000_000
PRICING = json.loads((Path(shield360.__file__).parent / "pricing.json").read_text())


def _per_million(model):
    return (
        get_chat_model_cost(model, PRICING, MILLION, 0),
        get_chat_model_cost(model, PRICING, 0, MILLION),
    )


@pytest.mark.parametrize(
    "model, input_price, output_price",
    [
        ("claude-opus-5", 5, 25),
        ("claude-opus-5-5", 4, 20),
        ("claude-opus-4-8", 5, 25),
        ("claude-sonnet-5", 2, 10),
        ("claude-sonnet-5-5", 2, 10),
        ("gpt-5.6-sol", 4, 20),
        ("gpt-5.6-terra", 2, 12),
        ("claude-fable-5", 10, 50),
        ("claude-fable-5-1", 10, 50),
        ("claude-haiku-4-5-20251001", 1, 5),
    ],
)
def test_per_million_prices(model, input_price, output_price):
    assert _per_million(model) == pytest.approx((input_price, output_price))


def test_cache_read_is_a_tenth_of_input_and_a_fortieth_on_fable_5_1():
    assert get_chat_model_cost("claude-opus-5", PRICING, 0, 0, MILLION) == pytest.approx(0.5)
    assert get_chat_model_cost("claude-fable-5-1", PRICING, 0, 0, MILLION) == pytest.approx(0.25)


def test_cache_write_is_one_and_a_quarter_times_input():
    assert get_chat_model_cost("claude-sonnet-5", PRICING, 0, 0, 0, MILLION) == pytest.approx(2.5)


def test_a_known_model_is_never_silently_free():
    assert get_chat_model_cost("claude-opus-5", PRICING, 1000, 1000) > 0
