"""SHIELD: the protection triangle (agent-guides/edge-deception-spec.md,
"Protection triangle"). Shield360 Edge in front of the app sends a signed,
short-lived ``X-Shield360-Edge-Context`` header; the app's RASP verifies it
and may tighten on it. A detection in a request that came through Edge is
answered with a signed ``X-Shield360-Verdict`` response header so Edge blocks
the client on its next request. Both are
``v1.<kid>.<base64url payload>.<base64url HMAC-SHA-256>`` with the
environment's key from the signed config (``edgeContext``). A header that
does not verify is ignored. Never raises."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple

CONTEXT_HEADER = "x-shield360-edge-context"
VERDICT_HEADER = "X-Shield360-Verdict"
# Edge's own request id, which Edge always sends upstream; the signed context's
# rid must equal it (a context lifted onto another request is refused).
REQUEST_ID_HEADER = "x-request-id"

_CONTEXT_TTL = 30
_SKEW = 5
_MAX_HEADER = 4096
_KID = re.compile(r"^[0-9a-f]{8}$")
_RID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
_CAT = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_KEY = re.compile(r"^[A-Za-z0-9_-]{43}$")
_CLIENTS = {"human", "verified_crawler", "verified_agent", "automation", "suspected_agent", "unknown"}
_CONTEXT_KEYS = {"rid", "iat", "exp", "m", "ph", "ct", "risk", "waf", "trap", "fl", "tp", "rt"}
# A red team run id (rt): Edge verified the request's X-Shield360-Red-Team header.
_RUN = re.compile(r"[a-z0-9]{8,40}")
_VERDICT_KEYS = {"rid", "iat", "act", "cat", "src", "ttl"}

EdgeKey = Tuple[str, bytes]


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def parse_edge_keys(raw: Any) -> List[EdgeKey]:
    """The signed config's ``edgeContext``: {"keys": [{"kid", "key"}]}, at most two."""
    keys = raw.get("keys") if isinstance(raw, dict) else None
    if not isinstance(keys, list):
        return []
    out: List[EdgeKey] = []
    for k in keys[:2]:
        if not isinstance(k, dict) or not isinstance(k.get("kid"), str) or not isinstance(k.get("key"), str):
            return []
        if not _KID.match(k["kid"]) or not _KEY.match(k["key"]):
            return []
        secret = _b64d(k["key"])
        if len(secret) != 32:
            return []
        out.append((k["kid"], secret))
    return out


def path_hash(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8")).digest()[:8].hex()


def _mac(secret: bytes, label: str, payload: str) -> bytes:
    return hmac.new(secret, label.encode() + payload.encode(), hashlib.sha256).digest()


def _open(keys: List[EdgeKey], label: str, value: str, allowed: set) -> Optional[Dict[str, Any]]:
    if not value or len(value) > _MAX_HEADER:
        return None
    parts = value.split(".")
    if len(parts) != 4 or parts[0] != "v1" or not _KID.match(parts[1]):
        return None
    secret = next((s for kid, s in keys if kid == parts[1]), None)
    if secret is None:
        return None
    try:
        sig = _b64d(parts[3])
        if not hmac.compare_digest(sig, _mac(secret, label, parts[2])):
            return None
        obj = json.loads(_b64d(parts[2]).decode("utf-8"))
    except Exception:  # pylint: disable=broad-except
        return None
    if not isinstance(obj, dict) or any(k not in allowed for k in obj):
        return None
    return obj


class ReplayCache:
    """Remembers ids until they expire; bounded."""

    def __init__(self, max_entries: int = 10000) -> None:
        self._seen: Dict[str, float] = {}
        self._max = max_entries
        self._lock = threading.Lock()

    def first(self, key: str, exp: float, now: float) -> bool:
        with self._lock:
            t = self._seen.get(key)
            if t is not None and t > now:
                return False
            if len(self._seen) >= self._max:
                for k in [k for k, v in self._seen.items() if v <= now]:
                    del self._seen[k]
                while len(self._seen) >= self._max:
                    del self._seen[next(iter(self._seen))]
            self._seen[key] = exp
            return True


_replay = ReplayCache()


def verify_edge_context(
    keys: List[EdgeKey],
    value: Any,
    method: str,
    path: str,
    request_id: Optional[str] = None,
    now: Optional[float] = None,
    cache: Optional[ReplayCache] = _replay,
) -> Optional[Dict[str, Any]]:
    """The verified context for this request, or None."""
    try:
        if not isinstance(value, str) or not keys:
            return None
        c = _open(keys, "s360-ctx|v1|", value, _CONTEXT_KEYS)
        if c is None:
            return None
        n = int(time.time() if now is None else now)
        if not isinstance(c.get("rid"), str) or not _RID.match(c["rid"]) or c.get("ct") not in _CLIENTS:
            return None
        iat, exp = c.get("iat"), c.get("exp")
        if not isinstance(iat, int) or not isinstance(exp, int) or iat > n + _SKEW or exp < n - _SKEW or exp - iat > _CONTEXT_TTL:
            return None
        # Bound to this request: method, path and Edge's X-Request-Id, which must be present.
        if c.get("m") != method or c.get("ph") != path_hash(path) or not isinstance(request_id, str) or request_id != c["rid"]:
            return None
        risk, trap = c.get("risk"), c.get("trap")
        if not isinstance(risk, int) or not 0 <= risk <= 100 or not isinstance(trap, int) or not 0 <= trap <= 4:
            return None
        waf = c.get("waf")
        if waf is not None and (
            not isinstance(waf, list) or len(waf) > 16 or not all(isinstance(w, str) and _CAT.match(w) for w in waf)
        ):
            return None
        rt = c.get("rt")
        if rt is not None and (not isinstance(rt, str) or not _RUN.fullmatch(rt)):
            return None
        if cache is not None and not cache.first("c:" + c["rid"], exp + _SKEW, n):
            return None
        c["fl"] = c.get("fl") is True
        return c
    except Exception:  # pylint: disable=broad-except
        return None


def sign_verdict(
    keys: List[EdgeKey], rid: str, act: str, cat: str, src: str = "rasp", ttl: int = 3600, iat: Optional[int] = None
) -> Optional[str]:
    """A signed verdict for Edge with the current key, or None."""
    try:
        if not keys or not _RID.match(rid) or not _CAT.match(cat):
            return None
        if act not in ("block", "flag") or src not in ("rasp", "sdk", "defend") or not 0 <= ttl <= 86400:
            return None
        kid, secret = keys[0]
        body = {"rid": rid, "iat": int(time.time()) if iat is None else iat, "act": act, "cat": cat, "src": src, "ttl": ttl}
        payload = _b64e(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        return f"v1.{kid}.{payload}.{_b64e(_mac(secret, 's360-verdict|v1|', payload))}"
    except Exception:  # pylint: disable=broad-except
        return None


def edge_red_team(c: Optional[Mapping[str, Any]]) -> Optional[str]:
    """The red team run Edge verified for this request (rt), or None."""
    rt = c.get("rt") if c else None
    return rt if isinstance(rt, str) else None


def edge_says_suspect(c: Optional[Mapping[str, Any]]) -> bool:
    """Edge already marked this client: injection-class attacks tighten from monitor to block."""
    return (
        bool(c)
        and c.get("ct") not in ("verified_crawler", "verified_agent")
        and (c.get("fl") is True or c.get("trap", 0) >= 2 or c.get("risk", 0) >= 70)
    )
