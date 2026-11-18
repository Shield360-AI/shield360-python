"""The OpenAI and Anthropic instrumentation hand what a model returned to RASP
as untrusted input (one call each, as the TypeScript SDK's recordModelResponse)."""

import json
import time

import pytest
from opentelemetry.sdk.trace import TracerProvider

from shield360._config import Shield360Config
from shield360.instrumentation.anthropic import utils as anthropic_utils
from shield360.instrumentation.openai import utils as openai_utils
from shield360.rasp._capture import capture_request
from shield360.rasp._context import current_context, inputs_of, reset_context, set_context
from shield360.rasp._engine import configure_engine


@pytest.fixture(autouse=True)
def _rasp_on():
    Shield360Config.reset_to_defaults()
    configure_engine(enabled=True, application_name="test", env={})
    token = set_context(capture_request("asgi", "POST", "/chat", {}))
    yield
    reset_context(token)
    configure_engine(enabled=False, application_name="default", env={})


def _model_inputs():
    return [(i.key, i.value) for i in inputs_of(current_context()) if i.source == "model_output"]


def _common(span):
    return {
        "pricing_info": {},
        "server_port": 443,
        "server_address": "example.com",
        "environment": "test",
        "application_name": "test",
        "metrics": None,
        "start_time": time.time(),
        "span": span,
        "capture_message_content": False,
        "disable_metrics": True,
        "version": "test",
    }


def _span():
    return TracerProvider().get_tracer("rasp-test").start_span("chat")


def test_openai_chat_completion_is_recorded():
    response = {
        "id": "c1",
        "model": "gpt-4o",
        "choices": [
            {
                "message": {
                    "content": "hello",
                    "tool_calls": [{"function": {"name": "run_sql", "arguments": json.dumps({"q": "select 1"})}}],
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    with _span() as span:
        openai_utils.process_chat_response(response, request_model="gpt-4o", model="gpt-4o", messages=[], **_common(span))
    assert _model_inputs() == [("model.completion", "hello"), ("model.tool.run_sql.q", "select 1")]


def test_openai_responses_output_is_recorded():
    response = {
        "id": "r1",
        "model": "gpt-4o",
        "status": "completed",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": "done"}]}],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    with _span() as span:
        openai_utils.process_response_response(response, request_model="gpt-4o", model="gpt-4o", input="hi", **_common(span))
    assert ("model.completion", "done") in _model_inputs()


def test_anthropic_message_is_recorded():
    response = {
        "id": "m1",
        "model": "claude-x",
        "role": "assistant",
        "stop_reason": "end_turn",
        "content": [
            {"type": "text", "text": "hi there"},
            {"type": "tool_use", "id": "t1", "name": "fetch", "input": {"url": "https://example.com"}},
        ],
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }
    with _span() as span:
        anthropic_utils.process_chat_response(
            response=response, request_model="claude-x", model="claude-x", messages=[], max_tokens=10, **_common(span)
        )
    assert _model_inputs() == [("model.completion", "hi there"), ("model.tool.fetch.url", "https://example.com")]
