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
    GuardPhase,
    PipelineResult,
)
from shield360.guard._pipeline import Pipeline
from shield360.protect._mode import (
    ProtectDeniedError,
    ProtectReadinessError,
    ResolvedProtect,
    refuses,
    set_protect_state,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider-specific text extractors
# ---------------------------------------------------------------------------


def _content_text(content: Any) -> List[str]:
    """The text in a message's content: a string, or the text parts of a list of blocks."""
    if isinstance(content, str):
        return [content] if content else []
    if not isinstance(content, list):
        return []
    out: List[str] = []
    for block in content:
        if isinstance(block, str):
            out.append(block)
        elif isinstance(block, dict) and isinstance(block.get("text"), str):
            out.append(block["text"])
    return out


def _extract_openai_input(kwargs: Dict[str, Any]) -> str:
    messages = kwargs.get("messages") or kwargs.get("input") or []
    parts: List[str] = []
    # The Responses API's instructions are a system prompt: scanned like one.
    instructions = kwargs.get("instructions")
    if isinstance(instructions, str) and instructions:
        parts.append(instructions)
    if isinstance(messages, str):
        parts.append(messages)
    else:
        for m in messages:
            if isinstance(m, dict):
                parts.extend(_content_text(m.get("content", "")))
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
    # The system prompt is input too: a string, or text blocks.
    parts.extend(_content_text(kwargs.get("system")))
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


def _evaluate_under(
    pipeline: Pipeline,
    text: str,
    phase: str,
    protect: Optional[ResolvedProtect],
) -> PipelineResult:
    """Shield Protect: what a mode does with a pipeline result, and with a pipeline that failed.

    No mode (legacy): a DENY raises, as it always did. observe: recorded, the
    call goes on. warn: as observe, and logged. enforced: a DENY raises; a
    failed pipeline raises (fail closed), whatever ``fail_open`` says; text
    past the scan bound raises rather than being scanned in part.
    """
    mode = protect.mode if protect else None
    bound = pipeline.scan_bound()
    if refuses(mode) and 0 < bound < len(text):
        raise ProtectDeniedError(
            "oversized",
            f"Shield360 Protect refused the call: {len(text)} characters is more than its guards scan ({bound}); send less.",
        )
    try:
        result = pipeline.evaluate(text, phase=phase)
    except Exception as exc:
        if refuses(mode):
            raise ProtectDeniedError(
                "guard_failed",
                "Shield360 Protect refused the call: a guard failed and enforced mode does not run unchecked calls.",
            ) from exc
        raise
    if result.action == GuardAction.DENY:
        if mode is None or refuses(mode):
            raise GuardDeniedError(result)
        if mode == "warn":
            logger.warning("Shield360 Protect (warn mode): the call would have been refused at %s: %s", phase, result.explanation)
        return PipelineResult(action=GuardAction.WARN, results=result.results, transformed_text=result.transformed_text)
    return result


def _apply_preflight(
    pipeline: Pipeline,
    kwargs: Dict[str, Any],
    extract_input: Extractor,
    protect: Optional[ResolvedProtect] = None,
) -> Tuple[Dict[str, Any], Optional[PipelineResult]]:
    """Run preflight guards. Returns (possibly-modified kwargs, result_or_None)."""
    input_text = extract_input(kwargs)
    if not input_text:
        return kwargs, None

    # A streamed completion cannot be inspected after the fact. Enforced mode
    # with postflight guards refuses it rather than let the response through
    # unread; with preflight-only guards the stream is fine.
    enforced = protect is not None and refuses(protect.mode)
    if enforced and kwargs.get("stream") is True and pipeline.has_phase(GuardPhase.POSTFLIGHT.value):
        raise ProtectDeniedError(
            "streaming",
            "Shield360 Protect refused a streamed completion: postflight guards cannot inspect a stream. "
            "Call without stream, or configure preflight-only guards.",
        )

    result = _evaluate_under(pipeline, input_text, "preflight", protect)

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
    protect: Optional[ResolvedProtect] = None,
) -> Any:
    """Run postflight guards on the response. Applies REDACT to response content.

    Each choice and text block is redacted on its own, so none is left holding
    the original text or another block's.
    """
    output_text = extract_output(response)
    if not output_text:
        return response

    result = _evaluate_under(pipeline, output_text, "postflight", protect)

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
    protect: Optional[ResolvedProtect] = None,
):
    def _guard_wrapper(wrapped, instance, args, kwargs):
        kwargs, _ = _apply_preflight(pipeline, kwargs, extract_input, protect)
        response = wrapped(*args, **kwargs)
        response = _apply_postflight(pipeline, response, extract_output, protect)
        return response

    return _guard_wrapper


def _make_async_guard_wrapper(
    pipeline: Pipeline,
    extract_input: Extractor,
    extract_output: Extractor,
    protect: Optional[ResolvedProtect] = None,
):
    async def _async_guard_wrapper(wrapped, instance, args, kwargs):
        kwargs, _ = _apply_preflight(pipeline, kwargs, extract_input, protect)
        response = await wrapped(*args, **kwargs)
        response = _apply_postflight(pipeline, response, extract_output, protect)
        return response

    return _async_guard_wrapper


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def setup_auto_guards(
    guards: List[Guard],
    fail_open: bool = True,
    protect: Optional[ResolvedProtect] = None,
) -> Tuple[List[str], List[str]]:
    """
    Wrap all known LLM provider methods with guard logic.

    Called from ``shield360.init()`` *after* all normal instrumentors have run.
    Returns the top-level packages that were wrapped and the required ones
    that were not.

    Shield Protect: in enforced mode the pipeline fails closed (``fail_open``
    is overridden, with a warning when it was set), and a package named in
    ``protect.required`` that could not be wrapped raises
    ProtectReadinessError: protected startup fails rather than running
    unguarded. Only providers importable when init() runs are wrapped; name
    the ones that matter in ``required`` so a missing one is a failure, not a
    silent gap.
    """
    effective_fail_open = fail_open
    if protect is not None and refuses(protect.mode) and fail_open:
        logger.warning("Shield360 Protect: enforced mode fails closed; guard_fail_open is ignored.")
        effective_fail_open = False
    pipeline = Pipeline(guards=guards, fail_open=effective_fail_open)

    from shield360._config import Shield360Config

    Shield360Config.guard_pipeline = pipeline

    wrapped: List[str] = []
    for module_path, class_method, extract_in, extract_out in GUARDED_METHODS:
        try:
            if _is_async_method(module_path, class_method):
                wrapper = _make_async_guard_wrapper(pipeline, extract_in, extract_out, protect)
            else:
                wrapper = _make_sync_guard_wrapper(pipeline, extract_in, extract_out, protect)

            wrap_function_wrapper(module_path, class_method, wrapper)
            package = module_path.split(".", maxsplit=1)[0]
            if package not in wrapped:
                wrapped.append(package)
        except Exception:
            logger.debug(
                "Could not wrap %s.%s with guard — module likely not installed",
                module_path,
                class_method,
            )

    required = list(protect.required) if protect else []
    missing = [pkg for pkg in required if pkg not in wrapped]
    set_protect_state(protect.mode if protect else None, wrapped, missing)
    logger.info("Auto-guards: wrapped %d provider package(s): %s", len(wrapped), ", ".join(wrapped))
    if protect is not None and refuses(protect.mode) and missing:
        raise ProtectReadinessError(
            missing,
            f"Shield360 Protect: enforced mode requires guards on {', '.join(missing)}, "
            "which could not be wrapped (not installed, or not importable). Protected startup refused.",
        )
    return wrapped, missing
