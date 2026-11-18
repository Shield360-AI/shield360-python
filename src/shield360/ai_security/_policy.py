# pylint: disable=too-many-branches,too-many-statements
"""The AI security policy: what each check does, for one app.

Every check is ``monitor`` by default: it reports and changes nothing.
``enforce`` is opt-in per check; ``off`` skips it. The policy comes from code
(``shield360.init(ai_security=...)``) and from the platform, which wins where
it sets a value. Keys are the platform's (camelCase), the same as the
TypeScript SDK's, so one JSON policy serves both.

Must stay in sync with: sdk/typescript/src/ai-security/policy.ts
"""

from __future__ import annotations

import copy
import math
import re
from typing import Any, Dict, List, Optional

CHECK_MODES = ("off", "monitor", "enforce")

DEFAULT_POLICY: Dict[str, Any] = {
    "version": 0,
    "indirectInjection": {"mode": "monitor", "action": "strip", "threshold": None},
    "jailbreak": {"mode": "monitor", "multiTurn": True},
    "output": {
        "mode": "monitor",
        "action": "redact",
        "pii": True,
        "secrets": True,
        "customKinds": True,
        "crossTenant": True,
        "exfilLinks": True,
        "systemPromptLeak": True,
        "allowedDomains": [],
        "canary": None,
    },
    "toolPermissions": {"mode": "monitor", "defaultDeny": False, "rules": {}},
    "limits": {"mode": "monitor", "perUser": {}, "perTenant": {}, "syncSeconds": 10},
    "mcp": {"mode": "monitor", "blockUnknown": False, "servers": [], "tools": []},
    "rag": {"mode": "monitor", "action": "drop", "tenantField": "tenant_id", "hubness": True},
    "customDataKinds": [],
}

_MAX_LIST = 500
_MAX_STR = 256
_HASH = re.compile(r"^[0-9a-f]{64}$")
_KIND_ID = re.compile(r"^[a-z0-9_]{1,32}$")


def _is_obj(v: Any) -> bool:
    return isinstance(v, dict)


def _mode(v: Any, d: str) -> str:
    return v if v in CHECK_MODES else d


def _bool(v: Any, d: bool) -> bool:
    return v if isinstance(v, bool) else d


def _str(v: Any) -> Optional[str]:
    if isinstance(v, str) and v.strip() and len(v) <= _MAX_STR:
        return v.strip()
    return None


def _str_list(v: Any) -> List[str]:
    if not isinstance(v, list):
        return []
    return [s for s in (_str(x) for x in v) if s][:_MAX_LIST]


def _one_of(v: Any, opts, d: str) -> str:
    return v if v in opts else d


def _limit_number(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return v if math.isfinite(v) and v > 0 else None


def _limit_window(v: Any, d: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(d)
    if not _is_obj(v):
        return out
    for key in ("requestsPerMinute", "tokensPerDay", "costPerDayUsd"):
        if key in v:
            out[key] = _limit_number(v[key])
    return out


def _tool_rule(v: Any) -> Optional[Dict[str, Any]]:
    if not _is_obj(v):
        return None
    rule: Dict[str, Any] = {}
    if v.get("deny") is True:
        rule["deny"] = True
    roles = _str_list(v.get("roles"))
    if roles:
        rule["roles"] = roles
    tenants = _str_list(v.get("tenants"))
    if tenants:
        rule["tenants"] = tenants
    attrs = v.get("attributes")
    if _is_obj(attrs):
        out = {}
        for k, values in list(attrs.items())[:50]:
            name = _str(k)
            vals = _str_list(values) if isinstance(values, list) else ([_str(values)] if _str(values) else [])
            if name and vals:
                out[name] = vals
        if out:
            rule["attributes"] = out
    return rule


def merge_policy(base: Dict[str, Any], given: Any) -> Dict[str, Any]:
    """Merges a partial policy over a base; anything malformed is ignored."""
    p = copy.deepcopy(base)
    if not _is_obj(given):
        return p
    ver = given.get("version")
    if isinstance(ver, int) and not isinstance(ver, bool) and ver >= 0:
        p["version"] = ver

    ii = given.get("indirectInjection")
    if _is_obj(ii):
        t = p["indirectInjection"]
        t["mode"] = _mode(ii.get("mode"), t["mode"])
        t["action"] = _one_of(ii.get("action"), ("strip", "block"), t["action"])
        if "threshold" in ii and ii["threshold"] is None:
            t["threshold"] = None
        elif isinstance(ii.get("threshold"), (int, float)) and 0 < ii["threshold"] <= 1:
            t["threshold"] = ii["threshold"]
    jb = given.get("jailbreak")
    if _is_obj(jb):
        p["jailbreak"]["mode"] = _mode(jb.get("mode"), p["jailbreak"]["mode"])
        p["jailbreak"]["multiTurn"] = _bool(jb.get("multiTurn"), p["jailbreak"]["multiTurn"])
    out = given.get("output")
    if _is_obj(out):
        o = p["output"]
        o["mode"] = _mode(out.get("mode"), o["mode"])
        o["action"] = _one_of(out.get("action"), ("redact", "block"), o["action"])
        for k in ("pii", "secrets", "customKinds", "crossTenant", "exfilLinks", "systemPromptLeak"):
            o[k] = _bool(out.get(k), o[k])
        if isinstance(out.get("allowedDomains"), list):
            o["allowedDomains"] = [d.lower() for d in _str_list(out["allowedDomains"])]
        if "canary" in out and out["canary"] is None:
            o["canary"] = None
        elif _str(out.get("canary")) and len(out["canary"].strip()) >= 8:
            o["canary"] = out["canary"].strip()
    tp = given.get("toolPermissions")
    if _is_obj(tp):
        t = p["toolPermissions"]
        t["mode"] = _mode(tp.get("mode"), t["mode"])
        t["defaultDeny"] = _bool(tp.get("defaultDeny"), t["defaultDeny"])
        if _is_obj(tp.get("rules")):
            for name, raw in list(tp["rules"].items())[:_MAX_LIST]:
                rule = _tool_rule(raw)
                if _str(name) and rule is not None:
                    t["rules"][name] = rule
    lim = given.get("limits")
    if _is_obj(lim):
        t = p["limits"]
        t["mode"] = _mode(lim.get("mode"), t["mode"])
        t["perUser"] = _limit_window(lim.get("perUser"), t["perUser"])
        t["perTenant"] = _limit_window(lim.get("perTenant"), t["perTenant"])
        s = lim.get("syncSeconds")
        if isinstance(s, (int, float)) and not isinstance(s, bool) and 2 <= s <= 300:
            t["syncSeconds"] = int(round(s))
    mcp = given.get("mcp")
    if _is_obj(mcp):
        t = p["mcp"]
        t["mode"] = _mode(mcp.get("mode"), t["mode"])
        t["blockUnknown"] = _bool(mcp.get("blockUnknown"), t["blockUnknown"])
        if isinstance(mcp.get("servers"), list):
            servers = []
            for s in [x for x in mcp["servers"] if _is_obj(x)][:_MAX_LIST]:
                name = _str(s.get("name"))
                if not name:
                    continue
                pin = {"name": name}
                if _str(s.get("publisher")):
                    pin["publisher"] = _str(s["publisher"])
                if _str(s.get("version")):
                    pin["version"] = _str(s["version"])
                servers.append(pin)
            t["servers"] = servers
        if isinstance(mcp.get("tools"), list):
            tools = []
            for x in [x for x in mcp["tools"] if _is_obj(x)][: _MAX_LIST * 4]:
                server, name = _str(x.get("server")), _str(x.get("name"))
                dh, sh = str(x.get("descriptionHash") or ""), str(x.get("schemaHash") or "")
                if server and name and _HASH.match(dh) and _HASH.match(sh):
                    tools.append({"server": server, "name": name, "descriptionHash": dh, "schemaHash": sh})
            t["tools"] = tools
    rag = given.get("rag")
    if _is_obj(rag):
        t = p["rag"]
        t["mode"] = _mode(rag.get("mode"), t["mode"])
        t["action"] = _one_of(rag.get("action"), ("drop", "block"), t["action"])
        t["tenantField"] = _str(rag.get("tenantField")) or t["tenantField"]
        t["hubness"] = _bool(rag.get("hubness"), t["hubness"])
    if isinstance(given.get("customDataKinds"), list):
        kinds = []
        for k in [x for x in given["customDataKinds"] if _is_obj(x)][:50]:
            kid = _str(k.get("id"))
            m = k.get("match")
            if not kid or not _KIND_ID.match(kid) or not _is_obj(m):
                continue
            name = _str(k.get("name")) or kid
            if m.get("type") == "keywords" and _str_list(m.get("keywords")):
                kinds.append({"id": kid, "name": name, "match": {"type": "keywords", "keywords": _str_list(m["keywords"])}})
            elif m.get("type") == "masks" and _str_list(m.get("masks")):
                kinds.append({"id": kid, "name": name, "match": {"type": "masks", "masks": _str_list(m["masks"])[:20]}})
        p["customDataKinds"] = kinds
    return p
