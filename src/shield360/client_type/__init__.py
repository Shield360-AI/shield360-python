"""
shield360.client_type: who is calling — a person, a verified agent, unverified automation or a
suspected AI agent — with the reasons. The same signatures and order as the TypeScript SDK
(sdk/typescript/src/client-type); deterministic, no model, no network. Defend uses it by default.

    from shield360.client_type import classify_client
    classify_client({"user-agent": "curl/8.4"})  # {"clientType": "unverified_automation", ...}
"""

import json
import os
import re
import threading
from collections import OrderedDict
from typing import Any, Dict, Mapping, Optional

__all__ = ["classify_client", "CLIENT_TYPES", "BREADTH_AGENT", "SIGNATURES_VERSION", "BreadthCounter"]

CLIENT_TYPES = ("human", "verified_agent", "unverified_automation", "suspected_ai_agent")
BREADTH_AGENT = 30

with open(os.path.join(os.path.dirname(__file__), "signatures.json"), "rb") as _f:
    _S = json.loads(_f.read().decode("utf-8"))
SIGNATURES_VERSION: str = _S["version"]
_CHROME = re.compile(r"chrome/\d")


def _find(ua: str, group: str) -> Optional[Dict[str, str]]:
    return next((s for s in _S[group] if s["match"] in ua), None)


def _out(client_type: str, reasons: list, confidence: str) -> Dict[str, Any]:
    return {"clientType": client_type, "reasons": reasons, "confidence": confidence}


def classify_client(
    headers: Mapping[str, str], signals: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:  # pylint: disable=too-many-return-statements,too-many-branches
    """The client type of a request (lower-case header names) and the reasons. Never a header value in a reason."""
    sig = signals or {}
    edge = sig.get("edge") or {}
    ua = (headers.get("user-agent") or "").lower()[:512]
    if sig.get("verifiedAgent"):
        return _out("verified_agent", ["agent_verified"], "high")
    if edge.get("ct") in ("verified_agent", "verified_crawler"):
        return _out("verified_agent", [f"edge:{edge['ct']}"], "high")
    if sig.get("trapHit"):
        return _out("suspected_ai_agent", ["trap_hit"], "high")
    if (edge.get("trap") or 0) >= 2:
        return _out("suspected_ai_agent", [f"edge:trap_level_{edge['trap']}"], "high")
    reasons = []
    if edge.get("ct") == "suspected_agent":
        reasons.append("edge:suspected_agent")
    agent = _find(ua, "aiAgents")
    if agent:
        reasons.append(f"ua_ai_agent:{agent['id']}")
    framework = _find(ua, "agentFrameworks")
    if framework:
        reasons.append(f"ua_agent_framework:{framework['id']}")
    if reasons:
        return _out("suspected_ai_agent", reasons, "high" if edge.get("ct") == "suspected_agent" else "medium")
    crawler, automation, headless = _find(ua, "aiCrawlers"), _find(ua, "automation"), _find(ua, "headless")
    if crawler:
        reasons.append(f"ua_ai_crawler:{crawler['id']}")
    if automation:
        reasons.append(f"ua_automation:{automation['id']}")
    if headless:
        reasons.append(f"headless:{headless['id']}")
    if not ua:
        reasons.append("no_user_agent")
    if (
        _CHROME.search(ua)
        and not headless
        and not headers.get("sec-ch-ua")
        and not headers.get("sec-fetch-mode")
        and not headers.get("accept-language")
    ):
        reasons.append("browser_headers_missing")
    if edge.get("ct") == "automation":
        reasons.append("edge:automation")
    if reasons:
        if (sig.get("breadth") or 0) >= BREADTH_AGENT:
            return _out("suspected_ai_agent", reasons + ["breadth"], "medium")
        return _out("unverified_automation", reasons, "high" if crawler or automation or headless else "medium")
    if edge.get("fl") or (edge.get("risk") or 0) >= 70:
        return _out("unverified_automation", ["edge:flagged" if edge.get("fl") else "edge:risk"], "medium")
    return _out("human", [], "low")


class BreadthCounter:
    """Distinct paths per client over a sliding minute, bounded (at most ``cap`` clients, 64 paths each)."""

    def __init__(self, window_s: float = 60.0, cap: int = 10_000):
        self._window, self._cap = window_s, cap
        self._clients: "OrderedDict[str, list]" = OrderedDict()
        self._lock = threading.Lock()

    def see(self, client: str, path: str, now_s: float) -> int:
        """Records the path and returns the distinct paths in the current window."""
        with self._lock:
            c = self._clients.get(client)
            if c is None or now_s - c[0] > self._window:
                if c is None and len(self._clients) >= self._cap:
                    self._clients.popitem(last=False)
                c = [now_s, set()]
                self._clients.pop(client, None)
                self._clients[client] = c
            if len(c[1]) < 64:
                c[1].add("/".join(path.split("/")[:4]))
            return len(c[1])
