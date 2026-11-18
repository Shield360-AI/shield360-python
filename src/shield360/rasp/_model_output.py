"""The hook point the SDK's LLM instrumentation calls with what a model
returned (README "Sources of untrusted input", ``source: "model_output"``).
No patching happens here: the instrumentation already sees the response and
hands it over. A no-op unless RASP is on with ``model_output``.

Inside a request the fragments join the request's inputs. Outside one, the
SDK starts a context for the rest of the current asyncio task (it ends with
the task). On a plain thread nothing is recorded outside a context, because a
context set there would reach the next job the thread runs: a worker that
acts on a model's answer wraps the job in ``run_in_rasp_scope(fn)``.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Optional

from shield360.rasp._context import RaspContext, current_context, new_context, set_context
from shield360.rasp._normalize import add_model_output, add_tool_arguments

_enabled = False
_TOOL_NAME = re.compile(r"[^A-Za-z0-9_\-]")


def set_model_output_recording(on: bool) -> None:
    """Set by the engine: whether model output is recorded at all."""
    global _enabled
    _enabled = bool(on)


def model_output_recording() -> bool:
    return _enabled


def _in_task() -> bool:
    try:
        return asyncio.current_task() is not None
    except RuntimeError:
        return False


def _scope() -> Optional[RaspContext]:
    """The context model output joins. Outside any context one is started
    only inside an asyncio task, whose context ends with the task; on a plain
    thread (a pooled worker) nothing is set, since it would outlive the job
    and reach the next one: such workers wrap the job in ``run_in_rasp_scope``."""
    ctx = current_context()
    if ctx is None and _in_task():
        ctx = new_context()
        set_context(ctx)
    return ctx


def record_model_output(text: Any, key: str = "model.completion") -> None:
    """Registers completion text a model returned as untrusted input. Never raises."""
    if not _enabled:
        return
    try:
        if not isinstance(text, str) or not text:
            return
        ctx = _scope()
        if ctx is not None:
            add_model_output(ctx.inputs, text, key)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def record_tool_arguments(args: Any, tool_name: Optional[str] = None) -> None:
    """Registers tool-call arguments (a JSON string or an object) as untrusted input. Never raises."""
    if not _enabled:
        return
    try:
        if args is None or args == "":
            return
        name = _TOOL_NAME.sub("_", tool_name)[:64] if isinstance(tool_name, str) else ""
        ctx = _scope()
        if ctx is not None:
            add_tool_arguments(ctx.inputs, args, f"model.tool.{name}" if name else "model.tool")
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _as_dict(value: Any) -> Any:
    if isinstance(value, dict) or value is None:
        return value
    for attr in ("model_dump", "to_dict", "dict"):
        fn = getattr(value, attr, None)
        if callable(fn):
            try:
                out = fn()
                if isinstance(out, dict):
                    return out
            except Exception:  # pylint: disable=broad-exception-caught
                continue
    return None


def _items(value: Any, limit: int) -> list:
    return list(value[:limit]) if isinstance(value, (list, tuple)) else []


def record_model_response(result: Any) -> None:
    """Records a provider response the instrumentation already holds: OpenAI
    chat completions (``choices[].message``), OpenAI Responses (``output[]``),
    Anthropic messages (``content[]``), as a dict or an SDK object. Text
    becomes completion fragments; tool-call arguments become
    ``model.tool.<name>`` inputs. Never raises."""
    if not _enabled or result is None:
        return
    try:
        r = _as_dict(result)
        if not isinstance(r, dict):
            return
        for c in _items(r.get("choices"), 8):
            m = c.get("message") if isinstance(c, dict) else None
            if not isinstance(m, dict):
                continue
            if isinstance(m.get("content"), str):
                record_model_output(m["content"])
            for t in _items(m.get("tool_calls"), 32):
                fn = t.get("function") if isinstance(t, dict) else None
                if isinstance(fn, dict):
                    record_tool_arguments(fn.get("arguments"), fn.get("name"))
        for item in _items(r.get("output"), 64):
            if not isinstance(item, dict):
                continue
            if item.get("type") == "function_call":
                record_tool_arguments(item.get("arguments"), item.get("name"))
            for part in _items(item.get("content"), 1 << 16):
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    record_model_output(part["text"])
        for block in _items(r.get("content"), 64):
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                record_model_output(block["text"])
            elif block.get("type") == "tool_use":
                record_tool_arguments(block.get("input"), block.get("name"))
    except Exception:  # pylint: disable=broad-exception-caught
        pass
