# pylint: disable=global-statement,too-many-arguments,too-many-locals,broad-exception-caught,redefined-outer-name
"""Shield360 AI security pack: checks an app runs on its own AI traffic,
mapped to the OWASP Top 10 for LLM Applications (2025).

    scan_context()     LLM01 indirect prompt injection (tool results, chunks, pages, files)
    check_prompt()     LLM01 jailbreaks, single and multi-turn
    scan_output()      LLM02/05/07 PII, secrets, own kinds of data, cross-tenant data,
    stream_scanner()   exfiltration links, system prompt leaks and canaries
    define_tool /      LLM06 per end-user tool permissions
    @tool(...)
    check_limits() /   LLM10 per end-user and per-tenant request, token and cost limits
    record_usage()
    check_mcp_tools()  LLM03 MCP server and tool pinning, rug pulls, poisoning
    check_retrieval()  LLM08 RAG tenant isolation and hub chunks

Every check monitors by default, enforces only when its mode says so, and
fails open. ``setup_ai_security()`` wires the checks into installed providers
and frameworks (see ``_hooks``).

Must stay in sync with: sdk/typescript/src/ai-security/index.ts
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, List, Optional, Sequence

from shield360._customer import get_customer
from shield360.ai_security._context import (  # noqa: F401 — public re-exports
    current_tenant,
    end_user,
    foreign_identifiers,
    get_end_user,
    identifiers_in,
    remember_foreign_identifiers,
    set_end_user,
)
from shield360.ai_security._events import EventReporter, MemorySink
from shield360.ai_security._injection import INJECTION_RULES_VERSION, scan_for_injection  # noqa: F401
from shield360.ai_security._jailbreak import assess_turns
from shield360.ai_security._limits import LimitEngine, keys_for
from shield360.ai_security._mcp import check_server_tools, description_hash, schema_hash, scan_tool_description  # noqa: F401
from shield360.ai_security._output import OutputStreamScanner, scan_output as _scan_output_text
from shield360.ai_security._policy import DEFAULT_POLICY, merge_policy
from shield360.ai_security._rag import HubnessMonitor, chunk_id, tenant_verdicts

STRIPPED_NOTICE = "[Shield360 removed instructions from this content]"
WITHHELD_MESSAGE = "Shield360 withheld this response because it may expose information it should not."
TOOL_DENIED_MESSAGE = "This action is not permitted for the current user."


class AiSecurityBlockedError(Exception):
    """A check in enforce mode refused the call, the content or the answer."""

    def __init__(self, check: str, kind: str, message: str):
        super().__init__(message)
        self.check = check
        self.kind = kind


class _State:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    def __init__(
        self,
        policy: Any = None,
        sink: Any = None,
        app: str = "default",
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        record_allowed: bool = False,
    ):
        self.code = merge_policy(DEFAULT_POLICY, policy or {})
        self.policy = self.code
        self.sink = sink or MemorySink()
        self.app = app
        self.url = url
        self.api_key = api_key
        self.record_allowed = record_allowed
        self.hubs = HubnessMonitor()
        self.tool_rules: Dict[str, Dict] = {}
        self.observed: set = set()
        self.refused_tools: Dict[str, set] = {}
        self.config = None
        self.limits = LimitEngine(lambda: _state.policy["limits"], self._sync if url and api_key else None)

    def _sync(self, entries):
        try:
            import requests  # pylint: disable=import-outside-toplevel

            res = requests.post(
                f"{self.url.rstrip('/')}/api/ai-security/limits/sync",
                json={"app": self.app, "entries": entries},
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=5,
            )
            return res.json() if res.ok else None
        except Exception:
            return None


_state = _State()


def configure(
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    app: str = "default",
    environment: str = "default",
    policy: Any = None,
    config_public_key: Any = None,
    config_cache_file: Optional[str] = None,
    allow_unpinned_config: bool = False,
    remote_config: bool = True,
    record_allowed: bool = False,
    sink: Any = None,
) -> None:
    """Sets the pack up. Called by ``shield360.init(ai_security=...)``; callable on its own."""
    global _state
    _close()
    s = _State(policy, sink, app, url, api_key, record_allowed)
    if url and api_key and sink is None:
        s.sink = EventReporter(url, api_key, app, environment)
    _state = s
    s.limits.start()
    if url and api_key and remote_config:
        from shield360.ai_security._config import ConfigClient  # pylint: disable=import-outside-toplevel

        def on_policy(signed):
            if _state is s:
                s.policy = merge_policy(s.code, signed["policy"])

        s.config = ConfigClient(
            url,
            api_key,
            app,
            on_policy,
            public_key=config_public_key,
            cache_file=config_cache_file,
            allow_unpinned=allow_unpinned_config,
        )
        if s.config.usable:
            s.config.start()
        else:
            # No pinned key: the platform's policy is not applied; the policy from code runs. Reported once.
            s.sink.add(
                {
                    "check": "config",
                    "kind": "config_unpinned",
                    "mode": "monitor",
                    "action": "reported",
                    "detail": "no pinned config key; set config_public_key or SHIELD360_CONFIG_PUBLIC_KEY",
                }
            )
            import logging  # pylint: disable=import-outside-toplevel

            logging.getLogger(__name__).warning(
                "Shield360 AI security: no pinned config key (config_public_key or SHIELD360_CONFIG_PUBLIC_KEY); "
                "the platform policy is not applied, checks run in monitor mode with the policy from code."
            )


def _close() -> None:
    try:
        _state.sink.close()
        _state.limits.stop()
        if _state.config:
            _state.config.stop()
    except Exception:
        pass


def current_policy() -> Dict[str, Any]:
    return _state.policy


def apply_platform_policy(given: Any) -> None:
    _state.policy = merge_policy(_state.code, given)


def reset(policy: Any = None, record_allowed: bool = False) -> MemorySink:
    """Back to defaults with events in memory; for tests."""
    global _state
    _close()
    sink = MemorySink()
    _state = _State(policy, sink, record_allowed=record_allowed)
    return sink


def _emit(event: Dict[str, Any]) -> None:
    try:
        _state.sink.add(event)
    except Exception:
        pass


def _mode(m: str) -> str:
    return "enforce" if m == "enforce" else "monitor"


def _safely(fallback, fn):
    try:
        return fn()
    except AiSecurityBlockedError:
        raise
    except Exception:
        return fallback


# ---------------------------------------------------------------------------
# LLM01: indirect prompt injection.


def strip_spans(text: str, spans) -> str:
    if not spans:
        return text
    merged: List[List[int]] = []
    for a, b in sorted(spans):
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    out = text
    for a, b in reversed(merged):
        out = out[:a] + "[removed]" + out[b:]
    return f"{STRIPPED_NOTICE}\n{out}"


def scan_context(
    text: str, source: str = "context", tool: Optional[str] = None
) -> Dict[str, Any]:  # pylint: disable=redefined-outer-name
    """Checks untrusted content before it reaches the model. Enforce mode strips
    what matched (action strip) or raises AiSecurityBlockedError (action block)."""
    passed = {"text": text, "detected": False, "score": 0, "rules": [], "action": "none"}
    p = _state.policy["indirectInjection"]
    if p["mode"] == "off" or not isinstance(text, str) or not text:
        return passed
    res = _safely(None, lambda: scan_for_injection(text, source))
    if not res:
        return passed
    threshold = p["threshold"] if p["threshold"] is not None else res["threshold"]
    if not (res["matches"] and res["score"] >= threshold):
        return {**passed, "score": res["score"]}
    rules = [m["rule"] for m in res["matches"]]
    enforce = p["mode"] == "enforce"
    action = "reported" if not enforce else ("blocked" if p["action"] == "block" else "stripped")
    _emit(
        {
            "check": "indirect_injection",
            "kind": "injection",
            "mode": _mode(p["mode"]),
            "action": action,
            "source": source,
            "tool": tool,
            "score": res["score"],
            "rules": rules,
            "categories": res["categories"],
            "rules_version": INJECTION_RULES_VERSION,
            "findings": [
                {
                    "rule": m["rule"],
                    "category": m["category"],
                    "snippet": m["snippet"],
                    **({"fingerprint": m["fingerprint"]} if m.get("fingerprint") else {}),
                }
                for m in res["matches"][:10]
            ],
        }
    )
    if action == "blocked":
        raise AiSecurityBlockedError(
            "indirect_injection",
            "injection",
            "Shield360 blocked content that carries instructions for the model (possible prompt injection).",
        )
    out = strip_spans(text, [tuple(s) for m in res["matches"] for s in m["spans"]]) if action == "stripped" else text
    return {"text": out, "detected": True, "score": res["score"], "rules": rules, "action": action}


# ---------------------------------------------------------------------------
# Jailbreaks.


def check_prompt(turns) -> Dict[str, Any]:
    """Checks the user's turns (oldest first). Enforce mode raises on a jailbreak."""
    p = _state.policy["jailbreak"]
    none = {"detected": False, "how": "none", "score": 0, "rules": [], "categories": []}
    if p["mode"] == "off":
        return none
    lst = [turns] if isinstance(turns, str) else list(turns)
    v = _safely(none, lambda: assess_turns(lst if p["multiTurn"] else lst[-1:]))
    if not v["detected"]:
        return v
    enforce = p["mode"] == "enforce"
    _emit(
        {
            "check": "jailbreak",
            "kind": "jailbreak" if v["how"] == "single_turn" else f"jailbreak_{v['how']}",
            "mode": _mode(p["mode"]),
            "action": "blocked" if enforce else "reported",
            "source": "prompt",
            "score": v["score"],
            "rules": v["rules"],
            "categories": v["categories"],
            "rules_version": INJECTION_RULES_VERSION,
        }
    )
    if enforce:
        raise AiSecurityBlockedError(
            "jailbreak", v["how"], "Shield360 blocked this request: it reads like an attempt to get around the assistant's rules."
        )
    return v


# ---------------------------------------------------------------------------
# Output.


def _report_output(findings, mode: str, action: str) -> None:
    by_kind: Dict[str, List[Dict]] = {}
    for f in findings:
        by_kind.setdefault(f["kind"], []).append(f)
    for kind, lst in by_kind.items():
        _emit(
            {
                "check": "output",
                "kind": kind,
                "mode": mode,
                "action": action,
                "source": "output",
                "detail": f"shingles {lst[0]['label']}" if kind == "system_prompt_leak" else None,
                "findings": [
                    {"kind": f["label"], "masked": f["masked"], **({"fingerprint": f["fingerprint"]} if f.get("fingerprint") else {})}
                    for f in lst[:10]
                ],
                "count": len(lst),
            }
        )


def scan_output(text: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
    """Checks a model's answer before the app returns it. Enforce mode redacts or
    raises AiSecurityBlockedError (action block, and any prompt or canary leak)."""
    p = _state.policy["output"]
    passed = {"text": text, "findings": [], "action": "none"}
    if p["mode"] == "off" or not isinstance(text, str) or not text:
        return passed
    res = _safely(None, lambda: _scan_output_text(text, p, _state.policy["customDataKinds"], system_prompt, foreign_identifiers()))
    if not res or not res["findings"]:
        return passed
    enforce = p["mode"] == "enforce"
    block = enforce and (p["action"] == "block" or res["must_block"])
    action = "reported" if not enforce else ("blocked" if block else "redacted")
    _report_output(res["findings"], _mode(p["mode"]), action)
    if block:
        raise AiSecurityBlockedError("output", res["findings"][0]["kind"], WITHHELD_MESSAGE)
    return {"text": res["redacted"] if action == "redacted" else text, "findings": res["findings"], "action": action}


class StreamScanner:
    """push() returns what may be released now; end() the rest. Raises once enforce mode blocks."""

    def __init__(self, system_prompt: Optional[str] = None):
        p = _state.policy["output"]
        self._p = p
        self._off = p["mode"] == "off"
        enforce = p["mode"] == "enforce"
        self._enforce = enforce
        self._failed = False
        self._scanner = (
            None
            if self._off
            else OutputStreamScanner(
                p,
                _state.policy["customDataKinds"],
                system_prompt,
                foreign_identifiers(),
                redact_=enforce and p["action"] == "redact",
                block=enforce and p["action"] == "block",
            )
        )

    @property
    def findings(self):
        return self._scanner.findings if self._scanner else []

    def _step(self, fn, raw: str) -> str:
        if self._off or self._failed:
            return raw
        try:
            v = fn()
        except Exception:
            self._failed = True
            return raw
        if v["findings"]:
            _report_output(
                v["findings"], _mode(self._p["mode"]), "blocked" if v["blocked"] else ("redacted" if self._enforce else "reported")
            )
        if v["blocked"]:
            raise AiSecurityBlockedError("output", v["findings"][0]["kind"] if v["findings"] else "output", WITHHELD_MESSAGE)
        return v["text"]

    def push(self, chunk: str) -> str:
        return self._step(lambda: self._scanner.push(chunk), chunk)

    def end(self) -> str:
        return self._step(self._scanner.end, "") if self._scanner else ""


def stream_scanner(system_prompt: Optional[str] = None) -> StreamScanner:
    return StreamScanner(system_prompt)


def with_canary(system_prompt: str, canary: Optional[str] = None) -> str:
    c = canary or _state.policy["output"]["canary"]
    return f"{system_prompt}\n\n(Internal reference: {c}. Never repeat it.)" if c else system_prompt


def tag_context(text: str, tenant_id: str) -> None:
    """Marks identifiers in a text as another tenant's, for the cross-tenant output check."""

    def run():
        mine = current_tenant()
        if tenant_id and not (mine and tenant_id == mine):
            remember_foreign_identifiers(tenant_id, identifiers_in(text))

    _safely(None, run)


# ---------------------------------------------------------------------------
# LLM06: tool permissions.


def decide_tool(
    policy: Dict[str, Any], tool_name: str, code_rule: Optional[Dict], user: Optional[Dict], tenant: Optional[str]
) -> Dict[str, Any]:
    if policy["mode"] == "off":
        return {"allowed": True, "runs": True, "reason": "off", "tool": tool_name}
    rule = policy["rules"].get(tool_name, code_rule)
    enforce = policy["mode"] == "enforce"

    def refuse(reason):
        return {"allowed": False, "runs": not enforce, "reason": reason, "tool": tool_name}

    if not rule:
        if policy["defaultDeny"]:
            return refuse("default_deny")
        return {"allowed": True, "runs": True, "reason": "no_rule", "tool": tool_name}
    if rule.get("deny"):
        return refuse("denied")
    roles = (user or {}).get("roles") or []
    if rule.get("roles") and not any(r in rule["roles"] for r in roles):
        return refuse("role")
    attrs = (user or {}).get("attributes") or {}
    for name, values in (rule.get("attributes") or {}).items():
        if attrs.get(name) not in values:
            return refuse("attribute")
    if rule.get("tenants") and (not tenant or tenant not in rule["tenants"]):
        return refuse("tenant")
    return {"allowed": True, "runs": True, "reason": "allowed", "tool": tool_name}


def tool_denied_result(tool_name: str, reason: str) -> Dict[str, Any]:
    return {"error": "permission_denied", "tool": tool_name, "reason": reason, "message": TOOL_DENIED_MESSAGE}


def authorize_tool(name: str, code_rule: Optional[Dict] = None) -> Dict[str, Any]:
    p = _state.policy["toolPermissions"]
    d = _safely(
        {"allowed": True, "runs": True, "reason": "off", "tool": name},
        lambda: decide_tool(p, name, code_rule or _state.tool_rules.get(name), get_end_user(), current_tenant()),
    )
    if not d["allowed"]:
        _emit(
            {
                "check": "tool_permission",
                "kind": "tool_denied",
                "mode": _mode(p["mode"]),
                "action": "reported" if d["runs"] else "denied",
                "tool": name,
                "detail": d["reason"],
            }
        )
    elif _state.record_allowed and d["reason"] != "off":
        _emit(
            {
                "check": "tool_permission",
                "kind": "tool_allowed",
                "mode": _mode(p["mode"]),
                "action": "allowed",
                "tool": name,
                "detail": d["reason"],
            }
        )
    return d


def tool(name: Optional[str] = None, permissions: Optional[Dict] = None):
    """Decorator: authorize every call for the end user first. A refused call
    (enforce) returns a tool error the model can read instead of running.

        @shield360.ai_security.tool(permissions={"roles": ["support_lead"]})
        def refund_order(order_id: str): ...
    """

    def wrap(fn: Callable):
        tool_name = name or fn.__name__
        if permissions:
            _state.tool_rules[tool_name] = permissions
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def run_async(*args, **kwargs):
                d = authorize_tool(tool_name, permissions)
                if not d["runs"]:
                    return tool_denied_result(tool_name, d["reason"])
                return await fn(*args, **kwargs)

            run_async.shield360_tool = tool_name  # type: ignore[attr-defined]
            return run_async

        @functools.wraps(fn)
        def run(*args, **kwargs):
            d = authorize_tool(tool_name, permissions)
            if not d["runs"]:
                return tool_denied_result(tool_name, d["reason"])
            return fn(*args, **kwargs)

        run.shield360_tool = tool_name  # type: ignore[attr-defined]
        return run

    return wrap


def define_tool(name: str, execute: Callable, permissions: Optional[Dict] = None, description: Optional[str] = None):
    """The function form of ``@tool``."""
    wrapped = tool(name, permissions)(execute)
    wrapped.description = description  # type: ignore[attr-defined]
    return wrapped


# ---------------------------------------------------------------------------
# LLM10: limits.


def check_limits() -> Dict[str, Any]:
    p = _state.policy["limits"]
    if p["mode"] == "off":
        return {"allowed": True}
    c = get_customer() or {}
    v = _safely({"allowed": True}, lambda: _state.limits.check(keys_for(c.get("tenant_id"), c.get("user_id"))))
    if v["allowed"]:
        return v
    enforce = p["mode"] == "enforce"
    _emit(
        {
            "check": "limits",
            "kind": "rate_limited",
            "mode": _mode(p["mode"]),
            "action": "blocked" if enforce else "reported",
            "detail": f"{v['scope']}:{v['limit']} {round(v.get('used') or 0, 2)}/{v['max']}",
        }
    )
    if enforce:
        raise AiSecurityBlockedError("limits", v["limit"], "Usage limit reached for this account. Try again later.")
    return v


def record_usage(requests: float = 1, tokens: float = 0, cost_usd: float = 0) -> None:
    def run():
        c = get_customer() or {}
        _state.limits.record(
            keys_for(c.get("tenant_id"), c.get("user_id")), requests=requests, tokens=tokens, cost_micros=cost_usd * 1e6
        )

    _safely(None, run)


def sync_limits_now() -> None:
    _state.limits.sync_now()


# ---------------------------------------------------------------------------
# LLM03: MCP pinning.


def check_mcp_tools(server: Dict[str, Any], tools: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Checks a server's tools against the pins; returns the tools the model may see."""
    p = _state.policy["mcp"]
    tools = list(tools or [])
    if p["mode"] == "off":
        return {"tools": tools, "verdict": None}
    verdict = _safely(None, lambda: check_server_tools(p, server, tools))
    if not verdict:
        return {"tools": tools, "verdict": None}
    mode = _mode(p["mode"])
    enforce = p["mode"] == "enforce"
    name = server.get("name", "unknown")
    if not verdict["allowed"]:
        refused = any(t["refuse"] for t in verdict["tools"])
        _emit(
            {
                "check": "mcp",
                "kind": "mcp_unknown_server",
                "mode": mode,
                "action": "blocked" if refused else "reported",
                "server": name,
                "detail": f"{verdict.get('reason')}{' version ' + str(server['version']) if server.get('version') else ''}",
            }
        )
    for t in verdict["tools"]:
        action = "blocked" if t["refuse"] else "reported"
        if t["poisoning"]["detected"]:
            _emit(
                {
                    "check": "mcp",
                    "kind": "mcp_tool_poisoned",
                    "mode": mode,
                    "action": action,
                    "server": name,
                    "tool": t["tool"],
                    "score": t["poisoning"]["score"],
                    "rules": t["poisoning"]["rules"],
                    "source": "tool_description",
                }
            )
        if t["status"] == "changed":
            _emit(
                {
                    "check": "mcp",
                    "kind": "mcp_tool_changed",
                    "mode": mode,
                    "action": action,
                    "server": name,
                    "tool": t["tool"],
                    "detail": f"changed: {','.join(t.get('changed') or [])}; "
                    f"description {t['descriptionHash'][:12]} schema {t['schemaHash'][:12]}",
                }
            )
        elif t["status"] == "unknown" and verdict["allowed"]:
            _emit({"check": "mcp", "kind": "mcp_unknown_tool", "mode": mode, "action": action, "server": name, "tool": t["tool"]})
    _observe(server, tools, verdict)
    refused = {t["tool"] for t in verdict["tools"] if t["refuse"]}
    _state.refused_tools[name] = refused
    return {"tools": [t for t in tools if t.get("name") not in refused] if enforce else tools, "verdict": verdict}


def mcp_call_refused(server: str, tool_name: str) -> bool:
    return _state.policy["mcp"]["mode"] == "enforce" and tool_name in _state.refused_tools.get(server, set())


def _observe(server: Dict[str, Any], tools, verdict) -> None:
    if not _state.url or not _state.api_key:
        return
    fresh = []
    for t in verdict["tools"]:
        if t["status"] == "pinned" and verdict["allowed"]:
            continue
        key = (server.get("name"), t["tool"], t["descriptionHash"], t["schemaHash"])
        if key in _state.observed:
            continue
        _state.observed.add(key)
        fresh.append(t)
    if not fresh:
        return
    by_name = {t.get("name"): t for t in tools}
    body = {
        "app": _state.app,
        "server": {"name": server.get("name"), "version": server.get("version"), "publisher": server.get("publisher")},
        "tools": [
            {
                "name": t["tool"],
                "descriptionHash": t["descriptionHash"],
                "schemaHash": t["schemaHash"],
                "description": (by_name.get(t["tool"], {}).get("description") or "")[:4000],
                "poisoningScore": t["poisoning"]["score"],
                "poisoningRules": t["poisoning"]["rules"],
            }
            for t in fresh[:200]
        ],
    }
    s = _state

    def send():
        try:
            import requests  # pylint: disable=import-outside-toplevel

            requests.post(
                f"{s.url.rstrip('/')}/api/ai-security/mcp/observe",
                json=body,
                headers={"Authorization": f"Bearer {s.api_key}"},
                timeout=5,
            )
        except Exception:
            pass

    import threading  # pylint: disable=import-outside-toplevel

    threading.Thread(target=send, daemon=True).start()


# ---------------------------------------------------------------------------
# LLM08: RAG.


def check_retrieval(
    chunks: Sequence[Any],
    query: str = "",
    to_chunk: Optional[Callable[[Any], Dict]] = None,
    set_text: Optional[Callable[[Any, str], Any]] = None,
    tenant_of=None,
) -> Dict[str, Any]:
    """Checks retrieved chunks: tenant isolation (enforce drops or blocks), hub
    chunks (reported) and prompt injection in each chunk."""
    p = _state.policy["rag"]
    lst = list(chunks or [])
    result = {"chunks": lst, "foreign": 0, "hubs": 0, "injected": 0}
    if not lst:
        return result
    conv = to_chunk or (lambda c: c)
    views = _safely(None, lambda: [conv(c) for c in lst])
    if views is None:
        return result
    kept = lst
    if p["mode"] != "off":
        mode = _mode(p["mode"])
        enforce = p["mode"] == "enforce"
        verdicts = _safely([], lambda: tenant_verdicts(views, current_tenant(), p["tenantField"], tenant_of))
        foreign = [v for v in verdicts if v["foreign"]]
        result["foreign"] = len(foreign)
        if foreign:
            action = "reported" if not enforce else ("blocked" if p["action"] == "block" else "dropped")
            _emit(
                {
                    "check": "rag",
                    "kind": "rag_cross_tenant",
                    "mode": mode,
                    "action": action,
                    "source": "document",
                    "count": len(foreign),
                    "detail": f"{len(foreign)} of {len(views)} chunks",
                }
            )
            if action == "blocked":
                raise AiSecurityBlockedError(
                    "rag", "rag_cross_tenant", "Shield360 blocked a retrieval that returned another customer's data."
                )
            if action == "dropped":
                drop = {v["index"] for v in foreign}
                kept = [c for i, c in enumerate(lst) if i not in drop]
            else:
                for v in foreign:
                    remember_foreign_identifiers(v["tenant"], identifiers_in(views[v["index"]].get("text") or ""))
        if p["hubness"]:
            hubs = _safely([], lambda: _state.hubs.observe(query or "", [chunk_id(v) for v in views]))
            result["hubs"] = len(hubs)
            for h in hubs:
                _emit(
                    {
                        "check": "rag",
                        "kind": "rag_hub",
                        "mode": mode,
                        "action": "reported",
                        "source": "document",
                        "score": h["z"],
                        "detail": f"chunk {h['chunk']} in {round(h['rate'] * 100)}% of {h['retrievals']} retrievals "
                        f"across {h['groups']} unrelated query groups",
                    }
                )
    if _state.policy["indirectInjection"]["mode"] != "off":
        out = []
        for c in kept:
            scan = scan_context(conv(c).get("text") or "", source="document")
            if scan["detected"]:
                result["injected"] += 1
            out.append(set_text(c, scan["text"]) if scan["action"] == "stripped" and set_text else c)
        kept = out
    result["chunks"] = kept
    return result


def flush() -> None:
    _state.sink.flush()


def setup_ai_security() -> List[str]:
    """Wires the checks into installed providers and frameworks."""
    from shield360.ai_security._hooks import setup  # pylint: disable=import-outside-toplevel

    return setup()
