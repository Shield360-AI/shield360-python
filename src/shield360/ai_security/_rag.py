"""RAG retrieval checks (OWASP LLM08): tenant isolation of retrieved chunks,
and hub chunks that answer many unrelated queries (a streaming version of
Cisco AI Defense's adversarial-hubness-detector scoring, Apache-2.0: robust
median/MAD z-scores of hub rates and spread across query groups).

Must stay in sync with: sdk/typescript/src/ai-security/rag.ts
"""

from __future__ import annotations

import hashlib
import math
import re
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Sequence


def chunk_tenant(chunk: Dict[str, Any], field: str, tenant_of: Optional[Callable[[Dict[str, Any]], Any]] = None) -> Optional[str]:
    try:
        if tenant_of:
            raw = tenant_of(chunk)
        else:
            raw: Any = chunk.get("metadata")
            for part in field.split("."):
                raw = raw.get(part) if isinstance(raw, dict) else None
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        if isinstance(raw, (int, float)) and not isinstance(raw, bool) and math.isfinite(raw):
            return str(raw)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return None


def tenant_verdicts(chunks: Sequence[Dict[str, Any]], tenant: Optional[str], field: str, tenant_of=None) -> List[Dict[str, Any]]:
    out = []
    for i, c in enumerate(chunks):
        t = chunk_tenant(c, field, tenant_of)
        out.append({"index": i, "tenant": t, "foreign": bool(tenant and t and t != tenant)})
    return out


def chunk_id(c: Dict[str, Any]) -> str:
    if isinstance(c.get("id"), str) and c["id"]:
        return c["id"]
    meta = c.get("metadata") or {}
    if isinstance(meta.get("id"), str) and meta["id"]:
        return meta["id"]
    return hashlib.sha256((c.get("text") or "").encode("utf-8")).hexdigest()[:16]


_STOP = set(
    (
        "a an and are as at be by for from how i in is it of on or that the this to was what when where which who why "
        "with you your me my do does can"
    ).split()
)
_TERM = re.compile(r"[^\W_]{3,}", re.UNICODE)


def _terms(query: str) -> set:
    return set([w for w in _TERM.findall(query.lower()) if w not in _STOP][:32])


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    both = len(a & b)
    return both / (len(a) + len(b) - both)


def _quantile(values: List[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    pos = (len(s) - 1) * q
    lo, hi = math.floor(pos), math.ceil(pos)
    return s[lo] + (s[hi] - s[lo]) * (pos - lo)


class HubnessMonitor:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        window: int = 500,
        min_retrievals: int = 50,
        min_z: float = 5,
        min_rate: float = 0.1,
        min_groups: int = 5,
        now: Callable[[], float] = time.time,
    ):
        self._o = {"window": window, "min_retrievals": min_retrievals, "min_z": min_z, "min_rate": min_rate, "min_groups": min_groups}
        self._now = now
        self._ring: deque = deque()
        self._counts: Dict[str, int] = {}
        self._groups_of: Dict[str, Dict[int, int]] = {}
        self._groups: List[set] = []
        self._flagged: Dict[str, float] = {}

    def _group_of(self, query: str) -> int:
        terms = _terms(query)
        best, best_score = -1, 0.3
        for i, g in enumerate(self._groups):
            s = _jaccard(terms, g)
            if s >= best_score:
                best, best_score = i, s
        if best >= 0:
            return best
        if len(self._groups) < 500:
            self._groups.append(terms)
        return len(self._groups) - 1

    def observe(self, query: str, chunk_ids: Sequence[str]) -> List[Dict[str, Any]]:
        ids = list(dict.fromkeys(chunk_ids))[:100]
        group = self._group_of(query or "")
        self._ring.append((group, ids))
        for cid in ids:
            self._counts[cid] = self._counts.get(cid, 0) + 1
            g = self._groups_of.setdefault(cid, {})
            g[group] = g.get(group, 0) + 1
        if len(self._ring) > self._o["window"]:
            old_group, old_ids = self._ring.popleft()
            for cid in old_ids:
                n = self._counts.get(cid, 1) - 1
                if n <= 0:
                    self._counts.pop(cid, None)
                    self._groups_of.pop(cid, None)
                else:
                    self._counts[cid] = n
                    g = self._groups_of.get(cid)
                    if g is not None:
                        k = g.get(old_group, 1) - 1
                        if k <= 0:
                            g.pop(old_group, None)
                        else:
                            g[old_group] = k
        if len(self._ring) < self._o["min_retrievals"]:
            return []
        total = len(self._ring)
        rates = [c / total for c in self._counts.values()]
        median = _quantile(rates, 0.5)
        mad = _quantile([abs(r - median) for r in rates], 0.5)
        scale = 1.4826 * mad + 1 / total
        out = []
        now = self._now()
        for cid in ids:
            rate = self._counts.get(cid, 0) / total
            z = (rate - median) / scale
            groups = len(self._groups_of.get(cid) or {})
            if rate < self._o["min_rate"] or z < self._o["min_z"] or groups < self._o["min_groups"]:
                continue
            last = self._flagged.get(cid)
            if last is not None and now - last < 3600:
                continue
            self._flagged[cid] = now
            out.append({"chunk": cid, "rate": round(rate, 3), "z": round(z, 1), "groups": groups, "retrievals": total})
        return out
