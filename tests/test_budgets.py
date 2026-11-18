"""Budget check in the Python SDK: shield360.budgets.check() and the automatic pre-call check.

Hermetic: no network, a stand-in for requests.get and the clock.
"""

import asyncio
import sys
import types

import pytest

from shield360 import budgets
from shield360.budgets import BudgetClient, BudgetExceededError, setup_auto_budget_check


class Res:
    def __init__(self, status=200, body=None, raises=False):
        self.status_code = status
        self._body = body
        self._raises = raises

    def json(self):
        if self._raises:
            raise ValueError("not json")
        return self._body


def decision(**over):
    d = {
        "action": "allow",
        "code": "budget_ok",
        "reason": "",
        "limit": None,
        "failClosed": False,
        "ttlSeconds": 60,
        "headroomUsd": None,
    }
    d.update(over)
    return d


class Fake:
    def __init__(self, answer):
        self.answer = answer
        self.calls = []

    def __call__(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        a = self.answer() if callable(self.answer) else self.answer
        if isinstance(a, Exception):
            raise a
        return a


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def client(fake, clock=None, **over):
    kwargs = {"url": "https://shield.example/", "api_key": "k_test", "app": "checkout-api", "http_get": fake, "now": clock or Clock()}
    kwargs.update(over)
    return BudgetClient(**kwargs)


def test_asks_for_the_app_and_model_with_the_api_key():
    fake = Fake(Res(body=decision()))
    r = client(fake).check(model="gpt-4o", estimated_cost_usd=0.02)
    assert r.allowed and r.action == "allow" and not r.cached and not r.unavailable
    assert fake.calls[0]["url"] == "https://shield.example/api/budgets/decision?app=checkout-api&model=gpt-4o&cost=0.020000"
    assert fake.calls[0]["headers"]["Authorization"] == "Bearer k_test"


def test_reuses_a_decision_within_ttl_and_headroom_then_asks_again():
    clock = Clock()
    fake = Fake(lambda: Res(body=decision(headroomUsd=1)))
    c = client(fake, clock)
    c.check(estimated_cost_usd=0.4)
    assert c.check(estimated_cost_usd=0.4).cached
    assert len(fake.calls) == 1
    assert not c.check(estimated_cost_usd=0.4).cached
    assert len(fake.calls) == 2
    clock.t += 61
    c.check()
    assert len(fake.calls) == 3


def test_block_refuses_and_warn_allows_with_reason():
    limit = {"id": "b1", "name": "Checkout", "scope": "App: checkout-api"}
    blocked = client(Fake(Res(body=decision(action="block", code="budget_block", reason="Over budget.", limit=limit)))).check()
    assert not blocked.allowed and blocked.code == "budget_block" and blocked.reason == "Over budget."
    assert blocked.limit == limit
    warned = client(Fake(Res(body=decision(action="warn", code="budget_warn", reason="At 85%.")))).check()
    assert warned.allowed and warned.action == "warn"


def test_throttles_to_the_requests_a_minute():
    clock = Clock()
    c = client(Fake(lambda: Res(body=decision(action="throttle", throttle={"requestsPerMinute": 2}, ttlSeconds=600))), clock)
    assert c.check().allowed
    assert c.check().allowed
    assert not c.check().allowed
    clock.t += 61
    assert c.check().allowed


@pytest.mark.parametrize(
    "answer",
    [
        ConnectionError("down"),
        Res(status=503, body={"err": "x"}),
        Res(body="nonsense"),
        Res(body={"action": "explode"}),
        Res(raises=True),
    ],
)
def test_never_raises_and_fails_open_by_default(answer):
    r = client(Fake(answer)).check()
    assert r.allowed and r.unavailable and r.code == "budget_unavailable"


def test_without_url_or_key_nothing_is_asked(monkeypatch):
    monkeypatch.delenv("SHIELD360_URL", raising=False)
    monkeypatch.delenv("SHIELD360_API_KEY", raising=False)
    # An earlier init() in the session may have left these on the config.
    from shield360._config import Shield360Config

    monkeypatch.setattr(Shield360Config, "shield360_url", None, raising=False)
    monkeypatch.setattr(Shield360Config, "shield360_api_key", None, raising=False)
    fake = Fake(Res(body=decision()))
    r = BudgetClient(app="a", http_get=fake).check()
    assert r.unavailable and r.allowed
    assert not fake.calls


def test_fails_closed_when_asked_or_when_the_last_decision_said_so():
    def down():
        return Fake(ConnectionError("down"))

    assert not client(down(), fail_closed=True).check().allowed
    assert not client(down()).check(fail_closed=True).allowed
    assert client(down(), fail_closed=True).check(fail_closed=False).allowed

    clock = Clock()
    state = {"up": True}
    c = client(Fake(lambda: Res(body=decision(failClosed=True, ttlSeconds=1)) if state["up"] else ConnectionError("down")), clock)
    assert c.check().allowed
    state["up"] = False
    clock.t += 2
    assert not c.check().allowed


def test_backs_off_after_a_failed_read():
    clock = Clock()
    fake = Fake(ConnectionError("down"))
    c = client(fake, clock)
    c.check()
    c.check()
    assert len(fake.calls) == 1
    clock.t += 6
    c.check()
    assert len(fake.calls) == 2


def test_module_check_uses_the_configured_client():
    fake = Fake(Res(body=decision(action="block", code="budget_block")))
    budgets.configure(url="https://shield.example", api_key="k", app="svc", http_get=fake)
    try:
        assert not budgets.check(model="m").allowed
    finally:
        budgets.configure()


def test_the_automatic_check_refuses_a_blocked_call_and_lets_an_allowed_one_through(monkeypatch):
    module = types.ModuleType("fake_budget_provider")

    class Completions:
        def create(self, **kwargs):
            return f"ok {kwargs.get('model')}"

    class AsyncCompletions:
        async def create(self, **kwargs):
            return f"async ok {kwargs.get('model')}"

    module.Completions = Completions
    module.AsyncCompletions = AsyncCompletions
    monkeypatch.setitem(sys.modules, "fake_budget_provider", module)

    state = {"action": "allow"}
    clock = Clock()

    def answer():
        action = state["action"]
        reason = "Over budget." if action == "block" else ""
        return Res(body=decision(action=action, code=f"budget_{action}", reason=reason, ttlSeconds=1))

    fake = Fake(answer)
    c = client(fake, clock)
    wrapped = setup_auto_budget_check(
        c,
        methods=[
            ("fake_budget_provider", "Completions.create", None, None),
            ("fake_budget_provider", "AsyncCompletions.create", None, None),
        ],
    )
    assert wrapped == ["fake_budget_provider"]
    assert Completions().create(model="gpt-4o") == "ok gpt-4o"
    assert "model=gpt-4o" in fake.calls[0]["url"]
    assert asyncio.run(AsyncCompletions().create(model="gpt-4o")) == "async ok gpt-4o"

    state["action"] = "block"
    clock.t += 2
    with pytest.raises(BudgetExceededError) as err:
        Completions().create(model="gpt-4o")
    assert err.value.result.code == "budget_block"
    with pytest.raises(BudgetExceededError):
        asyncio.run(AsyncCompletions().create(model="gpt-4o"))
