# pylint: disable=broad-exception-caught,too-many-branches,cyclic-import
"""Wires the AI security checks into the providers and frameworks the SDK
knows, apart from their instrumentations:

    OpenAI chat completions (sync and async), Anthropic messages
        before   limits; jailbreak check of the user turns; injection check
                 of tool results in the messages (stripped in enforce mode)
        after    output check (redacted in place), streamed answers through
                 the bounded stream scanner; tokens and cost counted
    LangChain    retrievers (BaseRetriever.invoke) and tools (BaseTool.invoke)
    LlamaIndex   retrievers (BaseRetriever.retrieve)
    MCP client   ClientSession.list_tools / call_tool

Every hook fails open. Each ``patch_*`` takes the class to patch, so apps
and tests can wire classes loaded another way.

Must stay in sync with: sdk/typescript/src/ai-security/hooks.ts
"""

from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Dict, List

from shield360 import ai_security as sec

_PATCHED = "__shield360_ai_security__"


def _wrap(owner: Any, name: str, make) -> bool:
    fn = getattr(owner, name, None)
    if fn is None or getattr(fn, _PATCHED, False):
        return False
    wrapped = make(fn)
    setattr(wrapped, _PATCHED, True)
    setattr(owner, name, wrapped)
    return True


def _pass(fn, fallback):
    try:
        return fn()
    except sec.AiSecurityBlockedError:
        raise
    except Exception:
        return fallback


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, str):
                out.append(b)
            elif isinstance(b, dict) and isinstance(b.get("text"), str):
                out.append(b["text"])
        return "\n".join(x for x in out if x)
    return ""


def prepare_request(kwargs: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Checks and, in enforce mode, rewrites a request. Returns {kwargs, system_prompt}."""
    sec.check_limits()
    out = dict(kwargs)
    system: List[str] = []
    user_turns: List[str] = []
    if provider == "anthropic":
        system.append(_text_of(kwargs.get("system")))
    if isinstance(kwargs.get("instructions"), str):
        system.append(kwargs["instructions"])
    messages = kwargs.get("messages")
    if isinstance(messages, list):
        new = []
        for m in messages:
            if not isinstance(m, dict):
                new.append(m)
                continue
            role = m.get("role")
            if role in ("system", "developer"):
                system.append(_text_of(m.get("content")))
            elif role == "tool":
                scan = sec.scan_context(_text_of(m.get("content")), source="tool_result", tool=m.get("name"))
                if scan["action"] == "stripped":
                    m = {**m, "content": scan["text"]}
            elif role == "user":
                content = m.get("content")
                if isinstance(content, list):
                    changed = False
                    blocks = []
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "tool_result":
                            scan = sec.scan_context(_text_of(b.get("content")), source="tool_result")
                            if scan["action"] == "stripped":
                                changed = True
                                b = {**b, "content": scan["text"]}
                        blocks.append(b)
                    text = "\n".join(
                        b if isinstance(b, str) else (b.get("text") or "")
                        for b in content
                        if not (isinstance(b, dict) and b.get("type") == "tool_result")
                    )
                    if text.strip():
                        user_turns.append(text)
                    if changed:
                        m = {**m, "content": blocks}
                else:
                    user_turns.append(_text_of(content))
            new.append(m)
        out["messages"] = new
    if user_turns:
        sec.check_prompt(user_turns)
    return {"kwargs": out, "system_prompt": "\n".join(s for s in system if s)}


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _set(obj: Any, key: str, value: Any) -> None:
    if isinstance(obj, dict):
        obj[key] = value
    else:
        setattr(obj, key, value)


def _output_target(response: Any):
    choices = _get(response, "choices")
    if isinstance(choices, list) and choices:
        msg = _get(choices[0], "message")
        if msg is not None and isinstance(_get(msg, "content"), str):
            return _get(msg, "content"), lambda t: _set(msg, "content", t)
        return None
    content = _get(response, "content")
    if isinstance(content, list):
        blocks = [b for b in content if isinstance(_get(b, "text"), str)]
        if blocks:

            def set_text(t):
                _set(blocks[0], "text", t)
                for b in blocks[1:]:
                    _set(b, "text", "")

            return "\n".join(_get(b, "text") for b in blocks), set_text
    return None


def _count_usage(kwargs: Dict[str, Any], response: Any) -> None:
    def run():
        usage = _get(response, "usage")
        if usage is None:
            sec.record_usage(requests=1)
            return
        inp = _get(usage, "prompt_tokens") or _get(usage, "input_tokens") or 0
        outp = _get(usage, "completion_tokens") or _get(usage, "output_tokens") or 0
        cost = 0.0
        try:
            from shield360.__helpers import get_chat_model_cost  # pylint: disable=import-outside-toplevel
            from shield360._config import Shield360Config  # pylint: disable=import-outside-toplevel

            cost = (
                get_chat_model_cost(
                    str(_get(response, "model") or kwargs.get("model") or ""),
                    getattr(Shield360Config, "pricing_info", {}) or {},
                    inp,
                    outp,
                )
                or 0.0
            )
        except Exception:
            cost = 0.0
        sec.record_usage(requests=1, tokens=int(inp) + int(outp), cost_usd=float(cost))

    _pass(run, None)


def finish_response(response: Any, prepared: Dict[str, Any]) -> Any:
    target = _pass(lambda: _output_target(response), None)
    if target and target[0]:
        res = sec.scan_output(target[0], system_prompt=prepared["system_prompt"])
        if res["action"] == "redacted":
            _pass(lambda: target[1](res["text"]), None)
    _count_usage(prepared["kwargs"], response)
    return response


def _delta_text(chunk: Any):
    choices = _get(chunk, "choices")
    if isinstance(choices, list) and choices:
        delta = _get(choices[0], "delta")
        if delta is not None and isinstance(_get(delta, "content"), str):
            return delta, "content", _get(choices[0], "finish_reason")
    if _get(chunk, "type") == "content_block_delta":
        delta = _get(chunk, "delta")
        if delta is not None and isinstance(_get(delta, "text"), str):
            return delta, "text", None
    return None, None, None


def wrap_stream(stream: Any, prepared: Dict[str, Any]):
    scanner = sec.stream_scanner(prepared["system_prompt"])

    def gen():
        for chunk in stream:
            delta, field, finish = _delta_text(chunk)
            if delta is not None:
                text = scanner.push(_get(delta, field))
                if finish:
                    text += scanner.end()
                _set(delta, field, text)
            elif _get(chunk, "type") in ("content_block_stop", "message_stop"):
                rest = scanner.end()
                if rest:
                    yield {
                        "type": "content_block_delta",
                        "index": _get(chunk, "index") or 0,
                        "delta": {"type": "text_delta", "text": rest},
                    }
            yield chunk
        rest = scanner.end()
        if rest:
            yield {"choices": [{"index": 0, "delta": {"content": rest}, "finish_reason": None}]}

    async def agen():
        async for chunk in stream:
            delta, field, finish = _delta_text(chunk)
            if delta is not None:
                text = scanner.push(_get(delta, field))
                if finish:
                    text += scanner.end()
                _set(delta, field, text)
            yield chunk
        rest = scanner.end()
        if rest:
            yield {"choices": [{"index": 0, "delta": {"content": rest}, "finish_reason": None}]}

    if hasattr(stream, "__aiter__"):
        return agen()
    if hasattr(stream, "__iter__"):
        return gen()
    return stream


def _provider_wrapper(provider: str):
    def make(original):
        if inspect.iscoroutinefunction(original):

            @functools.wraps(original)
            async def run_async(self, *args, **kwargs):
                prepared = _pass(lambda: prepare_request(kwargs, provider), {"kwargs": kwargs, "system_prompt": ""})
                response = await original(self, *args, **prepared["kwargs"])
                if prepared["kwargs"].get("stream") is True:
                    return _pass(lambda: wrap_stream(response, prepared), response)
                return _pass(lambda: finish_response(response, prepared), response)

            return run_async

        @functools.wraps(original)
        def run(self, *args, **kwargs):
            prepared = _pass(lambda: prepare_request(kwargs, provider), {"kwargs": kwargs, "system_prompt": ""})
            response = original(self, *args, **prepared["kwargs"])
            if prepared["kwargs"].get("stream") is True:
                return _pass(lambda: wrap_stream(response, prepared), response)
            return _pass(lambda: finish_response(response, prepared), response)

        return run

    return make


def patch_openai_completions(cls: Any) -> bool:
    return _wrap(cls, "create", _provider_wrapper("openai"))


def patch_anthropic_messages(cls: Any) -> bool:
    return _wrap(cls, "create", _provider_wrapper("anthropic"))


def patch_langchain_retriever(cls: Any) -> bool:
    def make(original):
        @functools.wraps(original)
        def invoke(self, query, *args, **kwargs):
            docs = original(self, query, *args, **kwargs)
            if not isinstance(docs, list):
                return docs

            def set_text(d, t):
                d.page_content = t
                return d

            res = sec.check_retrieval(
                docs,
                query=query if isinstance(query, str) else "",
                to_chunk=lambda d: {
                    "text": str(getattr(d, "page_content", "") or ""),
                    "id": getattr(d, "id", None),
                    "metadata": getattr(d, "metadata", None) or {},
                },
                set_text=set_text,
            )
            return res["chunks"]

        return invoke

    return _wrap(cls, "invoke", make)


def patch_langchain_tool(cls: Any) -> bool:
    def make(original):
        @functools.wraps(original)
        def invoke(self, tool_input, *args, **kwargs):
            name = str(getattr(self, "name", "tool"))
            d = _pass(lambda: sec.authorize_tool(name), {"runs": True})
            if not d["runs"]:
                return json.dumps({"error": "permission_denied", "tool": name, "message": sec.TOOL_DENIED_MESSAGE})
            result = original(self, tool_input, *args, **kwargs)
            if isinstance(result, str):
                scan = sec.scan_context(result, source="tool_result", tool=name)
                return scan["text"] if scan["action"] == "stripped" else result
            content = getattr(result, "content", None)
            if isinstance(content, str):
                scan = sec.scan_context(content, source="tool_result", tool=name)
                if scan["action"] == "stripped":
                    _pass(lambda: setattr(result, "content", scan["text"]), None)
            return result

        return invoke

    return _wrap(cls, "invoke", make)


def patch_llamaindex_retriever(cls: Any) -> bool:
    def make(original):
        @functools.wraps(original)
        def retrieve(self, query, *args, **kwargs):
            nodes = original(self, query, *args, **kwargs)
            if not isinstance(nodes, list):
                return nodes

            def node_of(n):
                return getattr(n, "node", n)

            def text_of(n):
                node = node_of(n)
                t = getattr(node, "text", None)
                if isinstance(t, str):
                    return t
                try:
                    return str(node.get_content())
                except Exception:
                    return ""

            def set_text(n, t):
                node = node_of(n)
                if isinstance(getattr(node, "text", None), str):
                    node.text = t
                return n

            q = query if isinstance(query, str) else str(getattr(query, "query_str", "") or "")
            res = sec.check_retrieval(
                nodes,
                query=q,
                to_chunk=lambda n: {
                    "text": text_of(n),
                    "id": getattr(node_of(n), "id_", None),
                    "metadata": getattr(node_of(n), "metadata", None) or {},
                },
                set_text=set_text,
            )
            return res["chunks"]

        return retrieve

    return _wrap(cls, "retrieve", make)


def _server_of(session: Any) -> Dict[str, Any]:
    info = getattr(session, "shield360_server_info", None) or getattr(session, "server_info", None)
    name = _get(info, "name") if info is not None else None
    version = _get(info, "version") if info is not None else None
    return {"name": str(name) if name else "unknown", "version": str(version) if version else None}


def patch_mcp_session(cls: Any) -> List[str]:
    done = []

    def make_list(original):
        @functools.wraps(original)
        async def list_tools(self, *args, **kwargs):
            result = await original(self, *args, **kwargs)
            tools = _get(result, "tools")
            if not isinstance(tools, list):
                return result
            views = [
                {"name": _get(t, "name"), "description": _get(t, "description"), "inputSchema": _get(t, "inputSchema")} for t in tools
            ]
            checked = sec.check_mcp_tools(_server_of(self), views)
            keep = {t["name"] for t in checked["tools"]}
            if len(keep) != len(tools):
                _set(result, "tools", [t for t in tools if _get(t, "name") in keep])
            return result

        return list_tools

    def make_call(original):
        @functools.wraps(original)
        async def call_tool(self, name, *args, **kwargs):
            server = _server_of(self)["name"]

            def refused(message):
                return {"isError": True, "content": [{"type": "text", "text": message}]}

            if _pass(lambda: sec.mcp_call_refused(server, name), False):
                return refused("This tool is not approved for use.")
            d = _pass(lambda: sec.authorize_tool(name), {"runs": True})
            if not d["runs"]:
                return refused(sec.TOOL_DENIED_MESSAGE)
            result = await original(self, name, *args, **kwargs)
            for block in _get(result, "content") or []:
                if _get(block, "type") == "text" and isinstance(_get(block, "text"), str):
                    scan = sec.scan_context(_get(block, "text"), source="tool_result", tool=name)
                    if scan["action"] == "stripped":
                        _pass(lambda b=block, s=scan: _set(b, "text", s["text"]), None)
            return result

        return call_tool

    if _wrap(cls, "list_tools", make_list):
        done.append("mcp.list_tools")
    if _wrap(cls, "call_tool", make_call):
        done.append("mcp.call_tool")
    return done


def setup() -> List[str]:
    done: List[str] = []
    targets = [
        (
            "openai.resources.chat.completions",
            ("Completions", "AsyncCompletions"),
            patch_openai_completions,
            "openai.chat.completions",
        ),
        ("anthropic.resources.messages", ("Messages", "AsyncMessages"), patch_anthropic_messages, "anthropic.messages"),
        ("langchain_core.retrievers", ("BaseRetriever",), patch_langchain_retriever, "langchain.retriever"),
        ("langchain_core.tools", ("BaseTool",), patch_langchain_tool, "langchain.tool"),
        ("llama_index.core.base.base_retriever", ("BaseRetriever",), patch_llamaindex_retriever, "llamaindex.retriever"),
    ]
    import importlib  # pylint: disable=import-outside-toplevel

    for module, classes, patch, label in targets:
        try:
            mod = importlib.import_module(module)
        except Exception:
            continue
        for cls_name in classes:
            cls = getattr(mod, cls_name, None)
            if cls is not None and _pass(lambda c=cls, f=patch: f(c), False):
                done.append(f"{label}.{cls_name}")
    try:
        mod = importlib.import_module("mcp.client.session")
        done += patch_mcp_session(mod.ClientSession)
    except Exception:
        pass
    return done
