"""Jailbreak detection on what end users send: each user turn with the shared
injection rules, and the conversation for multi-turn escalation
(accumulation, split, continuation; see the TypeScript module for the
reasoning, after the idea of Cisco AI Defense's project-quarry, Apache-2.0).

Must stay in sync with: sdk/typescript/src/ai-security/jailbreak.ts
"""

from __future__ import annotations

import re
from typing import Dict, List, Sequence

from shield360.ai_security._injection import INJECTION_THRESHOLD, scan_for_injection, _round3

MAX_TURNS = 8
JOINED = 3

_ESCALATING = {"roleplay", "jailbreak", "override"}
_SETUP = {"roleplay", "jailbreak"}
_FRAME = re.compile(r"\b(?:story|role-?play|pretend|character|fiction(?:al)?|persona|game|scenario)\b", re.IGNORECASE)
_LAWLESS = re.compile(
    r"\b(?:unfiltered|uncensored|unrestricted|amoral|evil|no\s+(?:rules|limits|restrictions|filters|ethics|morals)"
    r"|without\s+(?:any\s+)?(?:rules|limits|restrictions|filters))\b",
    re.IGNORECASE,
)
_CONTINUE = re.compile(
    r"\b(?:continue|keep\s+going|go\s+on|stay\s+in\s+character"
    r"|now\s+(?:do|say|write|tell|explain)\s+(?:it|that|this)\s+(?:for\s+real|without)"
    r"|drop\s+the\s+(?:act|pretence|pretense|disclaimer)|(?:same|that)\s+but\s+(?:real|for\s+real|detailed|step\s+by\s+step)"
    r"|what\s+would\s+(?:he|she|they|it|the\s+character)\s+say\s+next)\b",
    re.IGNORECASE,
)


def assess_turns(turns: Sequence[str]) -> Dict:
    recent = [t for t in turns if isinstance(t, str) and t.strip()][-MAX_TURNS:]
    none = {"detected": False, "how": "none", "score": 0, "rules": [], "categories": []}
    if not recent:
        return none
    scans = [scan_for_injection(t, "prompt") for t in recent]
    last = scans[-1]
    if last["detected"]:
        return {
            "detected": True,
            "how": "single_turn",
            "score": last["score"],
            "rules": [m["rule"] for m in last["matches"]],
            "categories": last["categories"],
        }
    hits = [s for s in scans if s["matches"]]
    rules: List[str] = sorted({m["rule"] for s in hits for m in s["matches"]})
    categories: List[str] = sorted({c for s in hits for c in s["categories"]})
    if len(hits) >= 2:
        keep = 1.0
        for s in hits:
            keep *= 1 - s["score"]
        combined = _round3(1 - keep)
        if combined >= INJECTION_THRESHOLD and any(c in _ESCALATING for c in categories):
            return {"detected": True, "how": "accumulation", "score": combined, "rules": rules, "categories": categories}
    if len(recent) >= 2:
        joined = scan_for_injection(" ".join(recent[-JOINED:]), "prompt")
        if joined["detected"]:
            return {
                "detected": True,
                "how": "split",
                "score": joined["score"],
                "rules": [m["rule"] for m in joined["matches"]],
                "categories": joined["categories"],
            }
    setup_at = next(
        (
            i
            for i, s in enumerate(scans)
            if any(c in _SETUP for c in s["categories"]) or (_FRAME.search(recent[i]) and _LAWLESS.search(recent[i]))
        ),
        -1,
    )
    if 0 <= setup_at < len(recent) - 1 and _CONTINUE.search(recent[-1]):
        score = max(INJECTION_THRESHOLD, scans[setup_at]["score"])
        return {"detected": True, "how": "continuation", "score": score, "rules": rules, "categories": categories or ["roleplay"]}
    return none
