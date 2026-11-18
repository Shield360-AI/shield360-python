"""MCP and tool pinning (OWASP LLM03): allow-listed servers, tools pinned by
the SHA-256 of their description and canonical input schema, rug-pull and
unknown-tool detection, and a tool-poisoning scan of descriptions when first
seen and on change (the shared injection rules, tool_rules.json adapted from
Cisco AI Defense's mcp-scanner under Apache-2.0, and cross-tool shadowing).

Must stay in sync with: sdk/typescript/src/ai-security/mcp.ts
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence

from shield360.ai_security._injection import scan_for_injection, _round3
from shield360.ai_security._injection import translate as _translate

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "tool_rules.json"), "r", encoding="utf-8") as _f:
    _TOOL_RULES = json.load(_f)

TOOL_RULES_VERSION: str = _TOOL_RULES["version"]
_THRESHOLD: float = _TOOL_RULES["threshold"]
_RULES = [(r["id"], r["weight"], [re.compile(_translate(p), re.IGNORECASE) for p in r["patterns"]]) for r in _TOOL_RULES["rules"]]
_DIRECTIVE = re.compile(r"\b(?:always|must|instead|never|before|whenever|override|replace|redirect)\b")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    """JSON with keys sorted and the separators JavaScript's JSON.stringify uses."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value.is_integer():
            return str(int(value))
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(f"{json.dumps(str(k), ensure_ascii=False)}:{canonical_json(value[k])}" for k in sorted(value, key=str))
            + "}"
        )
    return "null"


def description_hash(description: Optional[str]) -> str:
    return sha256((description or "").strip())


def schema_hash(schema: Any) -> str:
    return sha256(canonical_json(schema))


def scan_tool_description(description: str, other_tools: Sequence[str] = ()) -> Dict[str, Any]:
    text = (description or "")[:20_000]
    if not text:
        return {"score": 0, "detected": False, "rules": []}
    inj = scan_for_injection(text, "tool_description")
    keep = 1 - inj["score"]
    rules = [m["rule"] for m in inj["matches"]]
    for rid, weight, patterns in _RULES:
        if any(p.search(text) for p in patterns):
            rules.append(rid)
            keep *= 1 - weight
    lower = text.lower()
    for name in other_tools:
        n = name.lower()
        if len(n) < 3:
            continue
        at = lower.find(n)
        if at < 0:
            continue
        if _DIRECTIVE.search(lower[max(0, at - 120) : at + len(n) + 120]):
            rules.append("tool.cross_tool_shadowing")
            keep *= 1 - 0.6
            break
    score = _round3(1 - keep)
    return {"score": score, "detected": score >= min(_THRESHOLD, inj["threshold"]), "rules": sorted(set(rules))}


def check_server_tools(policy: Dict[str, Any], server: Dict[str, Any], tools: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    enforce = policy["mode"] == "enforce"
    pin = next((s for s in policy["servers"] if s["name"] == server.get("name")), None)
    allowed, reason = True, None
    if pin is None:
        allowed, reason = False, "unknown"
    elif pin.get("publisher") and pin["publisher"] != server.get("publisher"):
        allowed, reason = False, "publisher"
    elif pin.get("version") and pin["version"] != server.get("version"):
        allowed, reason = False, "version"
    refuse_server = enforce and not allowed and (reason != "unknown" or policy["blockUnknown"])
    pins = {t["name"]: t for t in policy["tools"] if t["server"] == server.get("name")}
    names = [t.get("name", "") for t in tools]
    verdicts = []
    for tool in tools:
        dh = description_hash(tool.get("description"))
        sh = schema_hash(tool.get("inputSchema", tool.get("input_schema")))
        p = pins.get(tool.get("name"))
        changed: List[str] = []
        if p is None:
            status = "unknown"
        else:
            if p["descriptionHash"] != dh:
                changed.append("description")
            if p["schemaHash"] != sh:
                changed.append("schema")
            status = "changed" if changed else "pinned"
        poisoning = (
            {"score": 0, "detected": False, "rules": []}
            if status == "pinned"
            else scan_tool_description(tool.get("description") or "", [n for n in names if n != tool.get("name")])
        )
        refuse = refuse_server or (
            enforce and (poisoning["detected"] or status == "changed" or (status == "unknown" and policy["blockUnknown"]))
        )
        v = {
            "tool": tool.get("name"),
            "descriptionHash": dh,
            "schemaHash": sh,
            "status": status,
            "poisoning": poisoning,
            "refuse": refuse,
        }
        if changed:
            v["changed"] = changed
        verdicts.append(v)
    out = {"server": server.get("name"), "allowed": allowed, "tools": verdicts}
    if reason:
        out["reason"] = reason
    return out
