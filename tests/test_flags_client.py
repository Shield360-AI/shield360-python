"""The flags client: defaults until rules arrive, ETag polling, never raising, span attributes."""

from unittest import mock

import shield360
from shield360.flags import FlagsClient

FLAG = {
    "key": "new-checkout",
    "type": "boolean",
    "variations": [{"key": "on", "value": True}, {"key": "off", "value": False}],
    "offVariation": "off",
    "on": True,
    "rules": [
        {"id": "pro", "conditions": [{"attribute": "plan", "operator": "equals", "values": ["pro"]}], "serve": {"variation": "on"}}
    ],
    "fallthrough": {"variation": "off"},
    "salt": "s1",
    "version": 3,
    "appName": None,
}
MODEL = {
    "key": "model-choice",
    "type": "string",
    "variations": [{"key": "a", "value": "gpt-4o-mini"}, {"key": "b", "value": "claude-haiku"}],
    "offVariation": "a",
    "on": True,
    "rules": [],
    "fallthrough": {"variation": "b"},
    "salt": "s2",
    "appName": "checkout-api",
}


class Reply:  # pylint: disable=too-few-public-methods
    def __init__(self, status, body=None, etag=None):
        self.status_code = status
        self._body = body
        self.headers = {"ETag": etag} if etag else {}

    def json(self):
        return self._body


class FakeHttp:
    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": dict(headers or {}), "timeout": timeout})
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply


def make(*replies, **options):
    http = FakeHttp(*replies)
    options.setdefault("application_name", "checkout-api")
    client = FlagsClient(url="https://s360.test/", api_key="k1", http_get=http, **options)
    # Tests drive fetches themselves; no polling thread.
    client.start = lambda: None
    return client, http


def test_defaults_until_rules_arrive_then_local_evaluation():
    client, http = make(Reply(200, {"version": "v1", "flags": [FLAG, MODEL]}, '"v1"'))
    assert client.is_enabled("new-checkout", {"plan": "pro"}) is False
    assert client.get_flag_detail("new-checkout", {}, False)["reason"]["kind"] == "NOT_READY"
    assert client.refresh() is True
    assert http.calls[0]["url"] == "https://s360.test/api/flags/rules"
    assert http.calls[0]["headers"] == {"Authorization": "Bearer k1", "Accept": "application/json"}
    assert client.is_enabled("new-checkout", {"key": "u1", "plan": "pro"}) is True
    assert client.is_enabled("new-checkout", {"key": "u1", "plan": "free"}) is False
    assert client.get_flag("model-choice", {"key": "u1"}, "gpt-4o-mini") == "claude-haiku"
    assert client.get_flag("missing", {}, "fallback") == "fallback"


def test_sends_the_etag_and_keeps_rules_on_304():
    client, http = make(Reply(200, {"flags": [FLAG]}, '"v1"'), Reply(304))
    client.refresh()
    assert client.refresh() is True
    assert http.calls[1]["headers"]["If-None-Match"] == '"v1"'
    assert client.is_enabled("new-checkout", {"plan": "pro"}) is True


def test_keeps_last_good_rules_and_never_raises():
    client, _ = make(Reply(200, {"flags": [FLAG]}), Reply(500), ConnectionError("offline"), Reply(200, "garbage"))
    client.refresh()
    assert client.refresh() is False
    assert client.refresh() is False
    assert client.refresh() is False
    assert client.is_enabled("new-checkout", {"plan": "pro"}) is True
    assert client.get_flag("new-checkout", "not a dict", True) in (True, False)


def test_leaves_out_invalid_flags_and_other_apps():
    broken = {**FLAG, "key": "broken", "offVariation": "nope"}
    client, _ = make(Reply(200, {"flags": [broken, MODEL]}), application_name="billing")
    client.refresh()
    assert client.get_flag_detail("broken", {}, True) == {"value": True, "variation": None, "reason": {"kind": "FLAG_NOT_FOUND"}}
    assert client.get_flag_detail("model-choice", {}, "x")["reason"]["kind"] == "FLAG_NOT_FOUND"


def test_wrong_type_returns_the_default():
    client, _ = make(Reply(200, {"flags": [MODEL]}))
    client.refresh()
    assert client.get_flag_detail("model-choice", {}, 7) == {"value": 7, "variation": None, "reason": {"kind": "WRONG_TYPE"}}


def test_stamps_the_variation_on_the_current_span():
    client, _ = make(Reply(200, {"flags": [FLAG]}))
    client.refresh()
    span = mock.Mock()
    span.is_recording.return_value = True
    with mock.patch("shield360.flags._client.trace.get_current_span", return_value=span):
        client.is_enabled("new-checkout", {"plan": "pro"})
        span.set_attribute.assert_called_once_with("shield360.flag.new-checkout", "on")
        span.set_attribute.reset_mock()
        client.is_enabled("missing", {})
        span.set_attribute.assert_not_called()


def test_no_destination_means_no_fetch(monkeypatch):
    monkeypatch.delenv("SHIELD360_URL", raising=False)
    monkeypatch.delenv("SHIELD360_API_KEY", raising=False)
    monkeypatch.setattr(shield360.Shield360Config, "shield360_url", None, raising=False)
    monkeypatch.setattr(shield360.Shield360Config, "shield360_api_key", None, raising=False)
    http = FakeHttp(Reply(200, {"flags": [FLAG]}))
    client = FlagsClient(http_get=http)
    assert client.refresh() is False
    assert not http.calls
    monkeypatch.setenv("SHIELD360_URL", "https://from-env.test")
    monkeypatch.setenv("SHIELD360_API_KEY", "env-key")
    assert client.refresh() is True
    assert http.calls[0]["url"] == "https://from-env.test/api/flags/rules"


def test_background_polling_thread_fetches_and_stops():
    http = FakeHttp(Reply(200, {"flags": [FLAG]}))
    client = FlagsClient(url="https://s360.test", api_key="k1", http_get=http)
    try:
        assert client.wait_until_ready(5) is True
        assert client.is_enabled("new-checkout", {"plan": "pro"}) is True
    finally:
        client.close()


def test_module_api():
    assert callable(shield360.flags.get_flag)
    assert callable(shield360.flags.is_enabled)
    assert isinstance(shield360.flags.client, FlagsClient)


SEGMENTED = {
    **MODEL,
    "key": "support-model",
    "appName": None,
    "variations": [{"key": "premium", "value": "openai/gpt-4o"}, {"key": "cheap", "value": "openai/gpt-4o-mini"}],
    "offVariation": "cheap",
    "rules": [
        {
            "id": "beta",
            "conditions": [{"attribute": "segment", "operator": "in_segment", "values": ["beta-users"]}],
            "serve": {"variation": "cheap"},
        }
    ],
    "fallthrough": {"variation": "premium"},
}
BETA = {"key": "beta-users", "conditions": [{"attribute": "groups", "operator": "in", "values": ["beta"]}]}
PROMPT = {
    "key": "support-prompt",
    "type": "json",
    "variations": [
        {"key": "v1", "value": {"name": "support-reply", "version": "1.0.0"}},
        {"key": "v2", "value": "support-reply@2.0.0"},
    ],
    "offVariation": "v1",
    "on": True,
    "rules": [],
    "fallthrough": {"variation": "v2"},
    "salt": "s3",
}


def test_segments_from_the_feed_and_the_model_helper():
    client, _ = make(Reply(200, {"version": "v1", "flags": [SEGMENTED], "segments": [BETA, {"key": "bad", "conditions": []}]}))
    assert client.model("support-model", {"key": "u1"}, "x/y") == "x/y"  # not ready
    client.refresh()
    assert client.model("support-model", {"key": "u1", "groups": ["beta"]}, "x/y") == "openai/gpt-4o-mini"
    assert client.model("support-model", {"key": "u1", "groups": ["staff"]}, "x/y") == "openai/gpt-4o"
    assert client.model("missing", {"key": "u1"}, "x/y") == "x/y"


def test_kill_switch_is_engaged_only_when_the_flag_says_so():
    killed = {**FLAG, "key": "killed", "on": False}
    live = {**FLAG, "key": "summaries", "rules": [], "fallthrough": {"variation": "on"}}
    client, _ = make(Reply(200, {"version": "v1", "flags": [live, killed]}))
    assert client.kill_switch("summaries") is False
    client.refresh()
    assert client.kill_switch("summaries", {"key": "u1"}) is False
    assert client.kill_switch("killed", {"key": "u1"}) is True
    assert client.kill_switch("unknown") is False


def test_prompt_helper_fetches_the_served_version_and_never_raises():
    client, _ = make(Reply(200, {"version": "v1", "flags": [PROMPT]}))
    client.refresh()
    with mock.patch("shield360.get_prompt", return_value={"err": None, "res": {"prompt": "Hello"}}) as get_prompt:
        served = client.prompt("support-prompt", {"key": "u1"}, {"name": "fallback"})
    assert served == {"name": "support-reply", "version": "2.0.0", "variation": "v2", "prompt": {"prompt": "Hello"}, "error": None}
    assert get_prompt.call_args.kwargs["url"] == "https://s360.test"
    assert get_prompt.call_args.kwargs["version"] == "2.0.0"
    with mock.patch("shield360.get_prompt", side_effect=RuntimeError("down")):
        failed = client.prompt("missing", {"key": "u1"}, {"name": "fallback", "version": "3"})
    assert failed["name"] == "fallback" and failed["variation"] is None and failed["prompt"] is None and failed["error"]


def test_prompt_refs():
    from shield360.flags import prompt_ref_of  # pylint: disable=import-outside-toplevel

    assert prompt_ref_of("a@1.2") == {"name": "a", "version": "1.2"}
    assert prompt_ref_of("a") == {"name": "a", "version": None}
    assert prompt_ref_of("@1") is None
    assert prompt_ref_of({"name": "a", "version": 2}) is None
