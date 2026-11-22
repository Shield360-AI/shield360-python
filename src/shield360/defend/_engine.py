"""Defend's policy reader and decision, the same contract as the TypeScript SDK
(sdk/typescript/src/defend/policy.ts and engine.ts; docs/latest/shield360/defend.mdx).

Pure apart from the two in-memory tables it is handed (rate buckets, marked
clients). No network, no file system.
"""

import math
import re
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

from shield360.rasp._rule_expr import in_cidr, parse_cidr

DEFEND_JWS_TYPE = "shield360-defend+jws"
DEFEND_POLICY_PATH = "/api/defend/policy"
DECISIONS = ("allow", "deny", "challenge", "require_sign_in")
CLIENT_TYPES = ("human", "verified_agent", "unverified_automation", "suspected_ai_agent", "ai_attack_agent", "scanner")
# scanner and ai_attack_agent are subtypes of unverified_automation (sdk/rasp/README.md "AI attack agents").
_AUTOMATION_SUBTYPES = frozenset(("scanner", "ai_attack_agent"))


def client_type_matches(rule_types: Any, client_type: Any) -> bool:
    """Whether a rule's client types cover a classified client: a rule naming
    ``unverified_automation`` also matches its subtypes ``scanner`` and
    ``ai_attack_agent``; a rule naming a subtype matches only it."""
    if not client_type:
        return False
    return client_type in rule_types or (client_type in _AUTOMATION_SUBTYPES and "unverified_automation" in rule_types)
LIST_TTL_S = 60
MAX_BUCKETS = 10_000
MAX_CONTENT_CHARS = 20_000

LIMITS = {
    "rules": 200,
    "list": 2000,
    "cidrs": 50,
    "paths": 10,
    "path": 256,
    "methods": 10,
    "countries": 50,
    "asns": 50,
    "attacks": 16,
}
_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
_METHOD = re.compile(r"^[A-Z]{3,10}$")
_COUNTRY = re.compile(r"^[A-Z]{2}$")
_ATTACK = re.compile(r"^[a-z_]{1,32}$")
_ACTIONS = ("block", "challenge", "allow", "monitor")


def _strings(v: Any, cap: int, ok) -> Optional[List[str]]:
    if v is None:
        return []
    if not isinstance(v, list):
        return None
    out: List[str] = []
    for x in v[:cap]:
        if not isinstance(x, str) or not ok(x):
            return None
        if x not in out:
            out.append(x)
    return out


def _is_cidr(s: str) -> bool:
    return len(s) <= 64 and parse_cidr(s) is not None


def _is_path(s: str) -> bool:
    return len(s) <= LIMITS["path"] and s.startswith("/") and not re.search(r"[\s?#\"'\\]", s)


def parse_rule(v: Any) -> Optional[Dict[str, Any]]:
    """One rule, or None when any condition cannot be read (never widened)."""
    if not isinstance(v, dict):
        return None
    if not isinstance(v.get("id"), str) or not _RULE_ID.match(v["id"]) or v.get("action") not in _ACTIONS:
        return None
    cidrs = _strings(v.get("cidrs"), LIMITS["cidrs"], _is_cidr)
    countries = _strings(v.get("countries"), LIMITS["countries"], lambda s: bool(_COUNTRY.match(s)))
    paths = _strings(v.get("paths"), LIMITS["paths"], _is_path)
    methods = _strings(v.get("methods"), LIMITS["methods"], lambda s: bool(_METHOD.match(s)))
    attacks = _strings(v.get("attacks"), LIMITS["attacks"], lambda s: bool(_ATTACK.match(s)))
    client_types = _strings(v.get("clientTypes"), len(CLIENT_TYPES), lambda s: s in CLIENT_TYPES)
    if None in (cidrs, countries, paths, methods, attacks, client_types):
        return None
    asns: List[int] = []
    if v.get("asns") is not None:
        a = v["asns"]
        if not isinstance(a, list) or not all(isinstance(x, int) and not isinstance(x, bool) and 0 < x <= 4294967295 for x in a):
            return None
        asns = a[: LIMITS["asns"]]
    if "except" in v and not isinstance(v["except"], bool):
        return None
    rule: Dict[str, Any] = {"id": v["id"], "action": v["action"]}
    if cidrs:
        rule["cidrs"] = cidrs
    if countries:
        rule["countries"] = countries
    if asns:
        rule["asns"] = asns
    if v.get("except") is True:
        if not countries and not asns:
            return None
        rule["except"] = True
    if paths:
        rule["paths"] = [p[:-1] if len(p) > 1 and p.endswith("/") else p for p in paths]
    if methods:
        rule["methods"] = methods
    if attacks:
        rule["attacks"] = attacks
    if client_types:
        rule["clientTypes"] = client_types
    if "rate" in v:
        r = v["rate"]
        if not isinstance(r, dict):
            return None
        rps, burst = r.get("rps"), r.get("burst", 0)
        if not isinstance(rps, (int, float)) or isinstance(rps, bool) or not math.isfinite(rps) or rps <= 0 or rps > 100_000:
            return None
        if not isinstance(burst, int) or isinstance(burst, bool) or burst < 0 or burst > 1_000_000:
            return None
        rule["rate"] = {"rps": rps, "burst": burst}
    return rule


def _list(v: Any) -> List[str]:
    out: List[str] = []
    for x in v if isinstance(v, list) else []:
        if len(out) >= LIMITS["list"]:
            break
        if isinstance(x, str) and _is_cidr(x) and x not in out:
            out.append(x)
    return out


def parse_defend_policy(claims: Any) -> Optional[Dict[str, Any]]:
    """The policy from verified claims; None when they hold no usable policy."""
    if (
        not isinstance(claims, dict)
        or not isinstance(claims.get("version"), str)
        or not isinstance(claims.get("exp"), (int, float))
    ):
        return None
    rules: List[Dict[str, Any]] = []
    ids = set()
    for r in claims.get("rules")[: LIMITS["rules"]] if isinstance(claims.get("rules"), list) else []:
        rule = parse_rule(r)
        if rule and rule["id"] not in ids:
            ids.add(rule["id"])
            rules.append(rule)
    t = claims.get("traps") if isinstance(claims.get("traps"), dict) else {}
    ttl = t.get("ttlSeconds")
    lv = claims.get("listsVersion")
    return {
        "version": claims["version"],
        "exp": claims["exp"],
        "listsVersion": lv[:64] if isinstance(lv, str) else "",
        "killSwitch": claims.get("killSwitch") is True,
        "rules": rules,
        "deny": _list(claims.get("deny")),
        "challenge": _list(claims.get("challenge")),
        "allow": _list(claims.get("allow")),
        "traps": {
            # Absent: block. No person or verified agent ever reaches a trap.
            "action": t.get("action") if t.get("action") in ("monitor", "challenge") else "block",
            "ttlSeconds": (
                min(int(ttl), 86_400)
                if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and math.isfinite(ttl) and ttl >= 1
                else 900
            ),
        },
    }


class RateTable:
    """Token buckets per rule and client address, at most MAX_BUCKETS (the oldest dropped first)."""

    def __init__(self, cap: int = MAX_BUCKETS):
        self._cap = cap
        self._b: "OrderedDict[str, List[float]]" = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str, rps: float, burst: int, now_ms: float) -> bool:
        size = max(1, burst or math.ceil(rps))
        with self._lock:
            b = self._b.get(key)
            if b is None:
                if len(self._b) >= self._cap:
                    self._b.popitem(last=False)
                b = [float(size), now_ms]
                self._b[key] = b
            else:
                b[0] = min(size, b[0] + (now_ms - b[1]) / 1000 * rps)
                b[1] = now_ms
            if b[0] >= 1:
                b[0] -= 1
                return True
            return False

    def __len__(self) -> int:
        return len(self._b)


def path_under(path: str, prefix: str) -> bool:
    if prefix in ("/", path):
        return True
    return path.startswith(prefix if prefix.endswith("/") else prefix + "/")


def check_content(content: Optional[List[str]], sensitive: str) -> Dict[str, bool]:
    """Prompt injection and sensitive data in the text the caller passed. Never raises."""
    out = {"promptInjection": False, "sensitiveData": False}
    if not content:
        return out
    left = MAX_CONTENT_CHARS
    for raw in content:
        if left <= 0:
            break
        text = raw[:left]
        left -= len(text)
        try:
            from shield360.ai_security._injection import scan_for_injection  # pylint: disable=import-outside-toplevel

            if not out["promptInjection"] and scan_for_injection(text, "prompt").get("detected"):
                out["promptInjection"] = True
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        try:
            if sensitive != "off" and not out["sensitiveData"]:
                from shield360.ai_security._output import scan_output  # pylint: disable=import-outside-toplevel
                from shield360.ai_security._policy import DEFAULT_POLICY  # pylint: disable=import-outside-toplevel

                r = scan_output(text, DEFAULT_POLICY["output"])
                if any(f.get("kind") in ("pii", "secret") for f in r.get("findings", [])):
                    out["sensitiveData"] = True
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    return out


_RANK = {"allow": 0, "require_sign_in": 1, "challenge": 2, "deny": 3}
_nets_cache: Dict[int, Dict[str, Any]] = {}


def _nets(lst: List[str]) -> list:
    return [n for n in (parse_cidr(c) for c in lst) if n is not None]


def _compiled(p: Dict[str, Any]) -> Dict[str, Any]:
    key = id(p)
    c = _nets_cache.get(key)
    if c is None or c["policy"] is not p:
        if len(_nets_cache) > 16:
            _nets_cache.clear()
        c = {
            "policy": p,
            "deny": _nets(p["deny"]),
            "challenge": _nets(p["challenge"]),
            "allow": _nets(p["allow"]),
            "rules": {r["id"]: _nets(r["cidrs"]) for r in p["rules"] if r.get("cidrs")},
        }
        _nets_cache[key] = c
    return c


def _in_any(ip: Optional[str], nets: list) -> bool:
    return bool(ip) and any(in_cidr(ip, n) for n in nets)


def _geo_matches(rule: Dict[str, Any], f: Dict[str, Any]) -> bool:
    if "countries" not in rule and "asns" not in rule:
        return True
    if not f.get("country") and f.get("asn") is None:
        return False
    inside = (bool(f.get("country")) and f["country"] in rule.get("countries", [])) or (
        f.get("asn") is not None and f["asn"] in rule.get("asns", [])
    )
    return (not inside) if rule.get("except") else inside


def _matches(rule: Dict[str, Any], inp: Dict[str, Any], nets: Optional[list]) -> bool:
    f = inp["facts"]
    if "cidrs" in rule and not _in_any(f.get("ip"), nets or []):
        return False
    if not _geo_matches(rule, f):
        return False
    if "paths" in rule and not any(path_under(f["path"], p) for p in rule["paths"]):
        return False
    if "methods" in rule and f["method"] not in rule["methods"]:
        return False
    if "clientTypes" in rule:
        c = inp.get("classification")
        if not c or not client_type_matches(rule["clientTypes"], c.get("clientType")):
            return False
    if "attacks" in rule:
        if not ("prompt_injection" in rule["attacks"] and inp["content"]["promptInjection"]):
            return False
    return True


def rate_rules_for(inp: Dict[str, Any]) -> List[Dict[str, Any]]:
    c = _compiled(inp["policy"])
    return [r for r in inp["policy"]["rules"] if "rate" in r and _matches(r, inp, c["rules"].get(r["id"]))]


def _finish(r: Dict[str, Any], mode: str) -> Dict[str, Any]:
    if mode == "monitor" and r["decision"] != "allow":
        return {**r, "decision": "allow", "wouldBe": r["decision"]}
    return r


def fail_result(fail_mode: str, reason: str, mode: str) -> Dict[str, Any]:
    return _finish({"decision": "deny" if fail_mode == "closed" else "allow", "reasons": [reason], "ruleIds": [], "ttl": 0}, mode)


def decide(inp: Dict[str, Any]) -> Dict[str, Any]:
    """The decision for one request (the contract's order). Never raises: an error is the fail mode."""
    try:
        return _decide(inp)
    except Exception:  # pylint: disable=broad-exception-caught
        return fail_result(inp.get("failMode", "open"), "error", inp.get("mode", "enforce"))


def _decide(inp: Dict[str, Any]) -> Dict[str, Any]:  # pylint: disable=too-many-return-statements,too-many-branches
    policy, f, mode = inp.get("policy"), inp["facts"], inp.get("mode", "enforce")
    if not policy:
        return fail_result(inp.get("failMode", "open"), "policy_unavailable", mode)
    if policy["killSwitch"]:
        return {"decision": "allow", "reasons": ["kill_switch"], "ruleIds": [], "ttl": 0}
    c = _compiled(policy)
    reasons: List[str] = []
    rule_ids: List[str] = []
    agent = inp.get("agent") or None
    cls = inp.get("classification") or None
    trap = bool(inp.get("trapHit"))
    verified = bool(agent and agent.get("verified"))
    client_type = "verified_agent" if verified else "suspected_ai_agent" if trap else (cls or {}).get("clientType")

    def out(decision: str, ttl: int) -> Dict[str, Any]:
        r = {"decision": decision, "reasons": reasons, "ruleIds": rule_ids, "ttl": ttl}
        if client_type:
            r["clientType"] = client_type
        return _finish(r, mode)

    trusted = _in_any(f.get("ip"), c["allow"])
    exempt = trusted or verified
    if cls and cls.get("reasons") and not verified and not trap:
        reasons.extend(f"client:{x}" for x in cls["reasons"][:8])
    if not trusted and _in_any(f.get("ip"), c["deny"]):
        reasons.append("deny_list")
        return out("deny", LIST_TTL_S)
    if agent and agent.get("blocked"):
        reasons.append("agent_policy")
        if agent.get("reason"):
            reasons.append(f"agent:{agent['reason']}")
        return out("deny", 0)
    if verified:
        reasons.append("agent_verified")
    elif agent and agent.get("reason"):
        reasons.append(f"agent:{agent['reason']}")
    if trap and not exempt:
        reasons.append("trap_hit")
        action = policy["traps"]["action"]
        if action != "monitor":
            return out("deny" if action == "block" else "challenge", policy["traps"]["ttlSeconds"])
    if not exempt and _in_any(f.get("ip"), c["challenge"]):
        reasons.append("challenge_list")
        return out("challenge", LIST_TTL_S)
    if inp["content"]["promptInjection"]:
        reasons.append("prompt_injection")
    decision, ttl = "allow", 0
    for rule in policy["rules"]:
        if not _matches(rule, inp, c["rules"].get(rule["id"])):
            continue
        if "rate" in rule:
            if not f.get("ip"):
                continue
            shared = (inp.get("sharedOver") or {}).get(rule["id"])
            over = (
                shared
                if shared is not None
                else not inp["rates"].take(f"{rule['id']}|{f['ip']}", rule["rate"]["rps"], rule["rate"]["burst"], inp["nowMs"])
            )
            if not over:
                continue
            reasons.append("rate_limit")
            ttl = max(1, math.ceil(1 / rule["rate"]["rps"]))
        rule_ids.append(rule["id"])
        if rule["action"] == "allow":
            reasons.append("rule:allow")
            return out("allow", 0)
        if rule["action"] == "monitor" or exempt:
            reasons.append(f"rule:{rule['action']}:exempt" if exempt and rule["action"] != "monitor" else "rule:monitor")
            continue
        reasons.append(f"rule:{rule['action']}")
        decision = "deny" if rule["action"] == "block" else "challenge"
        break
    if inp["content"]["sensitiveData"]:
        reasons.append("sensitive_data")
        if inp.get("sensitiveData") == "block" and not exempt and _RANK["deny"] > _RANK[decision]:
            decision = "deny"
    return out(decision, 0 if decision == "allow" else ttl)
