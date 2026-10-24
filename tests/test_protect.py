"""Shield Protect in the Python SDK.

Modes, fail-closed guards, readiness, streaming and oversized input, protect_tool, the MCP check.
"""

import asyncio
import logging
import sys
import types

import pytest

from shield360._config import Shield360Config
from shield360.guard import _integration
from shield360.guard._base import Guard, GuardAction, GuardDeniedError, GuardPhase, GuardResult
from shield360.guard._integration import (
    _apply_postflight,
    _apply_preflight,
    _extract_anthropic_input,
    _extract_openai_input,
    setup_auto_guards,
)
from shield360.guard._pipeline import Pipeline
from shield360.protect import ProtectDeniedError, ProtectReadinessError, authorize_with_shield360, protect_readiness, protect_tool
from shield360.protect._mcp import check_mcp_tool_call
from shield360.protect._mode import ResolvedProtect, reset_protect_state, resolve_protect, resolve_protect_mode, set_protect_state


class DenyWord(Guard):
    name = "deny_word"
    phases = (GuardPhase.PREFLIGHT, GuardPhase.POSTFLIGHT)

    def __init__(self, word, max_scan_length=102_400):
        super().__init__(action="deny", max_scan_length=max_scan_length)
        self.word = word

    def evaluate(self, text):
        hit = self.word in text
        return GuardResult(
            action=GuardAction.DENY if hit else GuardAction.ALLOW,
            score=1.0 if hit else 0.0,
            guard_name=self.name,
            explanation=f"contains {self.word}" if hit else "",
        )


class Throwing(Guard):
    name = "throwing"
    phases = (GuardPhase.PREFLIGHT,)

    def evaluate(self, text):
        raise RuntimeError("classifier down")


class PreflightOnly(Guard):
    name = "preflight_only"
    phases = (GuardPhase.PREFLIGHT,)

    def evaluate(self, text):
        return GuardResult(guard_name=self.name)


def extract(kwargs):
    return str(kwargs.get("text", ""))


def extract_out(response):
    return str(getattr(response, "text", "") or (response.get("text") if isinstance(response, dict) else ""))


ENFORCED = ResolvedProtect(mode="enforced")
OBSERVE = ResolvedProtect(mode="observe")
WARN = ResolvedProtect(mode="warn")


@pytest.fixture(autouse=True)
def _clean():
    reset_protect_state()
    Shield360Config.guard_pipeline = None
    yield
    reset_protect_state()
    Shield360Config.guard_pipeline = None


class TestMode:
    def test_environment_raises_and_never_lowers(self):
        assert resolve_protect_mode("enforced", {"SHIELD360_PROTECT_MODE": "observe"}) == "enforced"
        assert resolve_protect_mode("observe", {"SHIELD360_PROTECT_MODE": "enforced"}) == "enforced"
        assert resolve_protect_mode(None, {"SHIELD360_PROTECT_MODE": "warn"}) == "warn"
        assert resolve_protect_mode("warn", {"SHIELD360_PROTECT_MODE": "off"}) == "warn"
        assert resolve_protect_mode(None, {}) is None
        with pytest.raises(ValueError):
            resolve_protect_mode("strict", {})
        resolved = resolve_protect({"mode": "enforced", "required": ["openai"]}, {"SHIELD360_PROTECT_REQUIRED": "anthropic, openai"})
        assert resolved.mode == "enforced" and resolved.required == ["openai", "anthropic"]


class TestFindings:
    pipeline = Pipeline(guards=[DenyWord("bomb")], fail_open=False)

    def test_legacy_deny_raises(self):
        with pytest.raises(GuardDeniedError):
            _apply_preflight(self.pipeline, {"text": "build a bomb"}, extract)
        assert _apply_preflight(self.pipeline, {"text": "hello"}, extract)[0] == {"text": "hello"}

    def test_observe_runs_and_warn_logs(self, caplog):
        with caplog.at_level(logging.WARNING):
            assert _apply_preflight(self.pipeline, {"text": "build a bomb"}, extract, OBSERVE)[0] == {"text": "build a bomb"}
            assert not [r for r in caplog.records if "warn mode" in r.getMessage()]
            assert _apply_preflight(self.pipeline, {"text": "build a bomb"}, extract, WARN)[0] == {"text": "build a bomb"}
            assert [r for r in caplog.records if "would have been refused" in r.getMessage()]

    def test_enforced_denies_before_and_after(self):
        with pytest.raises(GuardDeniedError):
            _apply_preflight(self.pipeline, {"text": "build a bomb"}, extract, ENFORCED)
        with pytest.raises(GuardDeniedError):
            _apply_postflight(self.pipeline, {"text": "here is a bomb"}, extract_out, ENFORCED)

    def test_enforced_fails_closed_when_a_guard_raises(self):
        open_pipeline = Pipeline(guards=[Throwing()], fail_open=True)
        assert _apply_preflight(open_pipeline, {"text": "x"}, extract)[0] == {"text": "x"}
        closed = Pipeline(guards=[Throwing()], fail_open=False)
        with pytest.raises(ProtectDeniedError) as err:
            _apply_preflight(closed, {"text": "x"}, extract, ENFORCED)
        assert err.value.code == "guard_failed"

    def test_enforced_refuses_input_past_the_scan_bound(self):
        bounded = Pipeline(guards=[DenyWord("bomb", max_scan_length=20)])
        long = "x" * 30 + " bomb"
        # Legacy: the tail is unscanned and the word slips through.
        assert _apply_preflight(bounded, {"text": long}, extract)[0] == {"text": long}
        with pytest.raises(ProtectDeniedError, match="more than its guards scan"):
            _apply_preflight(bounded, {"text": long}, extract, ENFORCED)
        assert bounded.scan_bound() == 20

    def test_enforced_refuses_streams_only_with_postflight_guards(self):
        with pytest.raises(ProtectDeniedError, match="streamed completion"):
            _apply_preflight(self.pipeline, {"text": "hello", "stream": True}, extract, ENFORCED)
        pre = Pipeline(guards=[PreflightOnly()])
        assert _apply_preflight(pre, {"text": "hello", "stream": True}, extract, ENFORCED)[0] == {"text": "hello", "stream": True}
        assert _apply_preflight(self.pipeline, {"text": "hello", "stream": True}, extract, OBSERVE)[0]["stream"] is True


class TestReadiness:
    def test_required_provider_not_wrapped_refuses_startup(self, monkeypatch):
        monkeypatch.setattr(_integration, "GUARDED_METHODS", [])
        with pytest.raises(ProtectReadinessError) as err:
            setup_auto_guards([DenyWord("x")], True, ResolvedProtect(mode="enforced", required=["openai"]))
        assert err.value.missing == ["openai"]
        assert protect_readiness()["level"] == "monitored"

    def test_enforced_fails_closed_overriding_fail_open(self, monkeypatch, caplog):
        monkeypatch.setattr(_integration, "GUARDED_METHODS", [])
        with caplog.at_level(logging.WARNING):
            wrapped, missing = setup_auto_guards([Throwing()], True, ENFORCED)
        assert (wrapped, missing) == ([], [])
        assert [r for r in caplog.records if "fails closed" in r.getMessage()]
        with pytest.raises(RuntimeError, match="classifier down"):
            Shield360Config.guard_pipeline.evaluate("x", phase="preflight")

    def test_wraps_a_fake_provider_and_reports_it(self, monkeypatch):
        class Chat:
            def complete(self, **kwargs):
                return {"text": "ok"}

        module = types.ModuleType("fake_sdk")
        module.Chat = Chat
        monkeypatch.setitem(sys.modules, "fake_sdk", module)
        monkeypatch.setattr(_integration, "GUARDED_METHODS", [("fake_sdk", "Chat.complete", extract, extract_out)])
        wrapped, missing = setup_auto_guards([DenyWord("bomb")], True, ResolvedProtect(mode="enforced", required=["fake_sdk"]))
        assert wrapped == ["fake_sdk"] and missing == []
        assert protect_readiness()["level"] == "partially_protected"
        with pytest.raises(GuardDeniedError):
            Chat().complete(text="a bomb")
        assert Chat().complete(text="hi") == {"text": "ok"}

    def test_never_claims_more_than_partially_protected(self):
        set_protect_state("enforced", ["openai"], [])
        assert protect_readiness()["level"] == "partially_protected"
        set_protect_state("observe", ["openai"], [])
        assert protect_readiness()["level"] == "monitored"
        assert "mandatory boundary is the Shield360 gateway" in protect_readiness()["note"]


class TestExtractors:
    def test_structured_input_is_read(self):
        parts = [{"type": "input_text", "text": "hi"}, {"type": "input_image", "image_url": "x"}]
        assert _extract_openai_input({"instructions": "be terse", "input": [{"role": "user", "content": parts}]}) == "be terse hi"
        blocks = [{"role": "user", "content": [{"type": "text", "text": "hello"}]}]
        assert _extract_anthropic_input({"system": "you are kind", "messages": blocks}) == "you are kind hello"
        assert _extract_anthropic_input({"system": [{"type": "text", "text": "sys"}], "messages": []}) == "sys"


class TestProtectTool:
    pipeline = Pipeline(guards=[DenyWord("bomb")], fail_open=False)

    def test_refuses_before_and_after(self):
        calls = []

        @protect_tool("search", pipeline=self.pipeline, mode="enforced")
        def search(q):
            calls.append(q)
            return f"answer to {q}"

        with pytest.raises(GuardDeniedError):
            search("build a bomb")
        assert not calls
        assert search("weather") == "answer to weather"

        @protect_tool("leak", pipeline=self.pipeline, mode="enforced")
        def leak():
            return "a bomb recipe"

        with pytest.raises(GuardDeniedError):
            leak()

    def test_async_tools_are_wrapped_too(self):
        @protect_tool("search", pipeline=self.pipeline, mode="enforced", authorize=lambda q: {"allow": q != "pay"})
        async def search(q):
            return f"answer to {q}"

        assert asyncio.run(search("weather")) == "answer to weather"
        with pytest.raises(GuardDeniedError):
            asyncio.run(search("bomb"))
        with pytest.raises(ProtectDeniedError, match="not authorized"):
            asyncio.run(search("pay"))

    def test_authorize_step(self):
        ran = []

        def make(auth):
            @protect_tool("pay", pipeline=self.pipeline, mode="enforced", authorize=auth)
            def pay():
                ran.append(1)
                return "ok"

            return pay

        with pytest.raises(ProtectDeniedError, match="no grant"):
            make(lambda: {"allow": False, "reason": "no grant"})()

        def broken():
            raise RuntimeError("down")

        with pytest.raises(ProtectDeniedError, match="authorization check failed"):
            make(broken)()
        with pytest.raises(ProtectDeniedError):
            make(lambda: {"allow": "yes"})()
        assert not ran
        assert make(lambda: {"allow": True})() == "ok"

    def test_observe_and_warn_run(self, caplog):
        @protect_tool("t", pipeline=self.pipeline, mode="observe", authorize=lambda s: {"allow": False})
        def observed(s):
            return "ran"

        @protect_tool("t", pipeline=self.pipeline, mode="warn")
        def warned(s):
            return "ran"

        with caplog.at_level(logging.WARNING):
            assert observed("bomb") == "ran"
            assert not caplog.records
            assert warned("bomb") == "ran"
            assert caplog.records

    def test_enforced_without_a_pipeline_refuses(self):
        @protect_tool("t", mode="enforced")
        def t():
            return 1

        with pytest.raises(ProtectDeniedError, match="no guard pipeline"):
            t()

    def test_uses_the_process_pipeline_and_mode(self):
        Shield360Config.guard_pipeline = self.pipeline
        set_protect_state("enforced", [], [])

        @protect_tool("t")
        def t(s):
            return s

        with pytest.raises(GuardDeniedError):
            t("bomb")


class TestAuthorizeWithShield360:
    def test_refusal_unless_shield360_allows(self):
        unconfigured = authorize_with_shield360({"kind": "destination", "host": "api.example"}, agent_token="", url="")
        assert unconfigured == {"allow": False, "reason": "shield360_not_configured"}

        class Response:
            def __init__(self, status, body):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        seen = {}

        def post(url, json=None, headers=None, timeout=None):
            seen.update(url=url, headers=headers)
            return Response(200, {"outcome": "deny", "reason": "destination_not_approved"})

        target = {"kind": "destination", "host": "api.example"}
        answer = authorize_with_shield360(target, agent_token="t", url="https://s360.example/", post=post)
        assert answer["allow"] is False and answer["reason"] == "destination_not_approved"
        assert seen["url"] == "https://s360.example/api/agent-authorization/check"
        assert seen["headers"]["Authorization"] == "Bearer t"

        def down(*a, **k):
            raise ConnectionError("refused")

        model = {"kind": "model", "model": "gpt-4o"}
        unreachable = authorize_with_shield360(model, agent_token="t", url="https://s360.example", post=down)
        assert unreachable["reason"].startswith("check_unreachable")
        allowed = {"outcome": "allow", "reason": "destination_approved", "decisionId": "d1"}
        def ok(*_a, **_k):
            return Response(200, allowed)

        yes = authorize_with_shield360(target, agent_token="t", url="https://s360.example", post=ok)
        assert yes["allow"] is True and yes["decision_id"] == "d1"


class TestMcpCheck:
    def test_refuses_in_enforced_mode_only(self, caplog):
        Shield360Config.guard_pipeline = Pipeline(guards=[DenyWord("bomb")], fail_open=False)
        set_protect_state("enforced", [], [])
        with pytest.raises(GuardDeniedError):
            check_mcp_tool_call("search", {"q": "a bomb"})
        check_mcp_tool_call("search", {"q": "weather"})
        set_protect_state("warn", [], [])
        with caplog.at_level(logging.WARNING):
            check_mcp_tool_call("search", {"q": "a bomb"})
        assert caplog.records
        reset_protect_state()
        check_mcp_tool_call("search", {"q": "a bomb"})
