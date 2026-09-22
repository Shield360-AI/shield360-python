"""
Auto-guard integration layer.

``setup_auto_guards`` wraps LLM provider methods a *second* time (after
the normal instrumentors) so that guards run on every call without any
changes to existing ``instrumentation/`` code.

Call chain after setup:

    User call
      -> Guard wrapper  (preflight → may deny/redact)
        -> Instrumentor wrapper  (OTel telemetry)
          -> Original SDK method  (actual API call)
        <- Instrumentor wrapper
      <- Guard wrapper  (postflight → may redact/warn)
    <- Returns to user

**Streaming limitation**: postflight guards require a complete response
object with ``choices[].message.content`` (or equivalent). Streaming
responses yield incremental chunks that extractors cannot fully
reassemble, so postflight guards are silently skipped for streamed
completions. Preflight guards always run.
"""

from __future__ import annotations

import importlib
import inspect
import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

from wrapt import wrap_function_wrapper

from shield360.guard._base import (
    Guard,
    GuardAction,
    GuardDeniedError,
    PipelineResult,
)
from shield360.guard._pipeline import Pipeline

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider-specific text extractors
# ---------------------------------------------------------------------------


def _extract_openai_input(kwargs: Dict[str, Any]) -> str:
    messages = kwargs.get("messages") or kwargs.get("input") or []
    if isinstance(messages, str):
        return messages
    parts: List[str] = []
    for m in messages:
        if isinstance(m, dict):
            content = m.get("content", "")
            if isinstance(content, str):
                parts.append(content)
        elif isinstance(m, str):
            parts.append(m)
    return " ".join(parts)


def _extract_openai_output(response: Any) -> str:
    try:
        choices = getattr(response, "choices", None)
        if choices:
            return " ".join(
                getattr(getattr(c, "message", None), "content", "") or ""
                for c in choices
            )
        output = getattr(response, "output", None)
        if output:
            parts: List[str] = []
            for item in output:
                msg = getattr(item, "content", None)
                if isinstance(msg, list):
                    for block in msg:
                        text = getattr(block, "text", None)
                        if text:
                            parts.append(text)
                elif isinstance(msg, str):
                    parts.append(msg)
            return " ".join(parts)
    except Exception:
        pass
    return ""


def _extract_anthropic_input(kwargs: Dict[str, Any]) -> str:
    messages = kwargs.get("messages", [])
    parts: List[str] = []
    for m in messages:
        if isinstance(m, dict):
            content = m.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
    return " ".join(parts)


def _extract_anthropic_output(response: Any) -> str:
    try:
        content = getattr(response, "content", [])
        parts: List[str] = []
        for block in content:
            text = getattr(block, "text", None)
            if text:
                parts.append(text)
        return " ".join(parts)
    except Exception:
        return ""


def _extract_generic_input(kwargs: Dict[str, Any]) -> str:
    for key in ("messages", "message", "prompt", "input", "text"):
        val = kwargs.get(key)
        if val is None:
            continue
        if isinstance(val, str):
            return val
        if isinstance(val, list):
            parts: List[str] = []
            for item in val:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(item.get("content", "") or "")
            return " ".join(parts)
    return ""


def _extract_generic_output(response: Any) -> str:
    try:
        choices = getattr(response, "choices", None)
        if choices:
            return " ".join(
                getattr(getattr(c, "message", None), "content", "") or ""
                for c in choices
            )
    except Exception:
        pass
    try:
        content = getattr(response, "content", None)
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: List[str] = []
            for block in content:
                text = getattr(block, "text", None)
                if text:
                    parts.append(text)
            if parts:
                return " ".join(parts)
    except Exception:
        pass
    try:
        text = getattr(response, "text", None)
        if text:
            return text
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Methods to guard:  (module, class.method, input_extractor, output_extractor)
# Only text-in / text-out methods; skip embeddings, images, audio, etc.
# ---------------------------------------------------------------------------

Extractor = Callable[..., str]

GUARDED_METHODS: List[Tuple[str, str, Extractor, Extractor]] = [
    # OpenAI
    (
        "openai.resources.chat.completions",
        "Completions.create",
        _extract_openai_input,
        _extract_openai_output,
    ),
    (
        "openai.resources.chat.completions",
        "AsyncCompletions.create",
        _extract_openai_input,
        _extract_openai_output,
    ),
    (
        "openai.resources.chat.completions",
        "Completions.parse",
        _extract_openai_input,
        _extract_openai_output,
    ),
    (
        "openai.resources.chat.completions",
        "AsyncCompletions.parse",
        _extract_openai_input,
        _extract_openai_output,
    ),
    (
        "openai.resources.responses.responses",
        "Responses.create",
        _extract_openai_input,
        _extract_openai_output,
    ),
    (
        "openai.resources.responses.responses",
        "AsyncResponses.create",
        _extract_openai_input,
        _extract_openai_output,
    ),
    # Anthropic
    (
        "anthropic.resources.messages",
        "Messages.create",
        _extract_anthropic_input,
        _extract_anthropic_output,
    ),
    (
        "anthropic.resources.messages",
        "AsyncMessages.create",
        _extract_anthropic_input,
        _extract_anthropic_output,
    ),
    # Groq
    (
        "groq.resources.chat.completions",
        "Completions.create",
        _extract_generic_input,
        _extract_generic_output,
    ),
    (
        "groq.resources.chat.completions",
        "AsyncCompletions.create",
        _extract_generic_input,
        _extract_generic_output,
    ),
    # Mistral
    (
        "mistralai.chat",
        "Chat.complete",
        _extract_generic_input,
        _extract_generic_output,
    ),
    (
        "mistralai.chat",
        "Chat.complete_async",
        _extract_generic_input,
        _extract_generic_output,
    ),
    (
        "mistralai.client.chat",
        "Chat.complete",
        _extract_generic_input,
        _extract_generic_output,
    ),
    (
        "mistralai.client.chat",
        "Chat.complete_async",
        _extract_generic_input,
        _extract_generic_output,
    ),
    # Cohere
    (
        "cohere.client_v2",
        "ClientV2.chat",
        _extract_generic_input,
        _extract_generic_output,
    ),
    (
        "cohere.client_v2",
        "AsyncClientV2.chat",
        _extract_generic_input,
        _extract_generic_output,
    ),
    # Together
    (
        "together.resources.chat.completions",
        "Completions.create",
        _extract_generic_input,
        _extract_generic_output,
    ),
    (
        "together.resources.chat.completions",
        "AsyncCompletions.create",
        _extract_generic_input,
        _extract_generic_output,
    ),
]


# ---------------------------------------------------------------------------
# Guard wrapper factories
# ---------------------------------------------------------------------------


def _redact_messages(pipeline: Pipeline, value: Any, phase: str) -> Any:
    """Redact a prompt or message list one message (and text block) at a time.

    The decision to redact is made on all the input together, but each message
    is rewritten on its own: writing the joined text into one message would
    copy the system prompt and earlier turns into it, and leave the originals
    -- secrets included -- untouched.
    """
    if isinstance(value, str):
        return pipeline.redact(value, phase)
    if not isinstance(value, list):
        return value
    out: List[Any] = []
    for m in value:
        if isinstance(m, str):
            m = pipeline.redact(m, phase)
        elif isinstance(m, dict):
            content = m.get("content")
            if isinstance(content, str):
                m = {**m, "content": pipeline.redact(content, phase)}
            elif isinstance(content, list):
                m = {
                    **m,
                    "content": [
                        {**b, "text": pipeline.redact(b["text"], phase)}
                        if isinstance(b, dict) and isinstance(b.get("text"), str)
                        else b
                        for b in content
                    ],
                }
        out.append(m)
    return out


def _apply_preflight(
    pipeline: Pipeline,
    kwargs: Dict[str, Any],
    extract_input: Extractor,
) -> Tuple[Dict[str, Any], Optional[PipelineResult]]:
    """Run preflight guards. Returns (possibly-modified kwargs, result_or_None)."""
    input_text = extract_input(kwargs)
    if not input_text:
        return kwargs, None

    result = pipeline.evaluate(input_text, phase="preflight")

    if result.action == GuardAction.DENY:
        raise GuardDeniedError(result)

    if result.action == GuardAction.REDACT and result.transformed_text is not None:
        for key in ("messages", "input", "prompt", "text"):
            if key in kwargs:
                kwargs = {**kwargs, key: _redact_messages(pipeline, kwargs[key], "preflight")}
                break

    return kwargs, result


def _redact_text_attr(pipeline: Pipeline, obj: Any, attr: str) -> None:
    text = getattr(obj, attr, None)
    if isinstance(text, str) and text:
        setattr(obj, attr, pipeline.redact(text, "postflight"))


def _apply_postflight(
    pipeline: Pipeline,
    response: Any,
    extract_output: Extractor,
) -> Any:
    """Run postflight guards on the response. Applies REDACT to response content.

    Each choice and text block is redacted on its own, so none is left holding
    the original text or another block's.
    """
    output_text = extract_output(response)
    if not output_text:
        return response

    result = pipeline.evaluate(output_text, phase="postflight")

    if result.action == GuardAction.DENY:
        raise GuardDeniedError(result)

    if result.action == GuardAction.REDACT and result.transformed_text is not None:
        try:
            choices = getattr(response, "choices", None)
            output = getattr(response, "output", None)
            content = getattr(response, "content", None)
            if choices:
                # OpenAI chat completions.
                for choice in choices:
                    msg = getattr(choice, "message", None)
                    if msg is not None:
                        _redact_text_attr(pipeline, msg, "content")
            elif isinstance(output, list) and output:
                # OpenAI Responses API: output items hold text blocks.
                for item in output:
                    blocks = getattr(item, "content", None)
                    if isinstance(blocks, list):
                        for block in blocks:
                            _redact_text_attr(pipeline, block, "text")
            elif isinstance(content, list) and content:
                # Anthropic messages.
                for block in content:
                    _redact_text_attr(pipeline, block, "text")
            else:
                _redact_text_attr(pipeline, response, "text")
        except Exception:
            logger.warning("Could not redact the response", exc_info=True)

    return response


def _is_async_method(module_path: str, class_method: str) -> bool:
    """Return True when the provider method has to be awaited.

    The name is not a reliable signal: Mistral spells its async chat method
    ``Chat.complete_async``, so a ``"Async" in class_method`` check installs the
    sync wrapper on a coroutine function and the postflight guards never run.
    Resolve the attribute instead, unwrapping the instrumentor wrapper that is
    already installed on it by the time guards are set up.
    """
    class_name, method_name = class_method.split(".", 1)
    module = importlib.import_module(module_path)
    method = getattr(getattr(module, class_name), method_name)
    return inspect.iscoroutinefunction(inspect.unwrap(method))


def _make_sync_guard_wrapper(
    pipeline: Pipeline,
    extract_input: Extractor,
    extract_output: Extractor,
):
    def _guard_wrapper(wrapped, instance, args, kwargs):
        kwargs, _ = _apply_preflight(pipeline, kwargs, extract_input)
        response = wrapped(*args, **kwargs)
        response = _apply_postflight(pipeline, response, extract_output)
        return response

    return _guard_wrapper


def _make_async_guard_wrapper(
    pipeline: Pipeline,
    extract_input: Extractor,
    extract_output: Extractor,
):
    async def _async_guard_wrapper(wrapped, instance, args, kwargs):
        kwargs, _ = _apply_preflight(pipeline, kwargs, extract_input)
        response = await wrapped(*args, **kwargs)
        response = _apply_postflight(pipeline, response, extract_output)
        return response

    return _async_guard_wrapper


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def setup_auto_guards(
    guards: List[Guard],
    fail_open: bool = True,
) -> None:
    """
    Wrap all known LLM provider methods with guard logic.

    Called from ``shield360.init()`` *after* all normal instrumentors have run.
    """
    pipeline = Pipeline(guards=guards, fail_open=fail_open)

    from shield360._config import Shield360Config

    Shield360Config.guard_pipeline = pipeline

    wrapped_count = 0
    for module_path, class_method, extract_in, extract_out in GUARDED_METHODS:
        try:
            if _is_async_method(module_path, class_method):
                wrapper = _make_async_guard_wrapper(pipeline, extract_in, extract_out)
            else:
                wrapper = _make_sync_guard_wrapper(pipeline, extract_in, extract_out)

            wrap_function_wrapper(module_path, class_method, wrapper)
            wrapped_count += 1
        except Exception:
            logger.debug(
                "Could not wrap %s.%s with guard — module likely not installed",
                module_path,
                class_method,
            )

    logger.info(
        "Auto-guards: wrapped %d/%d provider methods",
        wrapped_count,
        len(GUARDED_METHODS),
    )
