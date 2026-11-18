"""Deception (README "Deception"): decoy paths from the signed config's
``deception`` block, the matcher, and the table of suspicious client
addresses. Pure parts only; the engine decides the mode and reports, the
middleware answers the request."""

from __future__ import annotations

import bisect
import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

DECEPTION = "deception"
DECEPTION_SINK = "http.deception"
RULE_HIT = "deception.hit"
RULE_SUSPICIOUS = "deception.suspicious"

MAX_PATHS = 64
MAX_PATH_LEN = 256
DEFAULT_TTL_S = 900
MAX_TTL_S = 86400
MAX_SUSPICIOUS = 10_000

_HEX = frozenset(b"0123456789abcdefABCDEF")


@dataclass(frozen=True)
class Deception:
    """A usable ``deception`` block: at least one decoy path."""

    paths: Tuple[str, ...]
    action: str = "monitor"
    ttl_seconds: int = DEFAULT_TTL_S


def parse_deception(v: Any) -> Optional[Deception]:
    """Reads the signed config's ``deception`` block ("Config"). None when it
    is not an object or names no usable path: deception is off."""
    if not isinstance(v, dict) or not isinstance(v.get("paths"), list):
        return None
    paths = []
    for p in v["paths"]:
        if not isinstance(p, str) or len(p) > MAX_PATH_LEN or not p.startswith("/"):
            continue
        if p.endswith("/"):
            p = p[:-1]
        if p in ("", "/"):
            continue
        paths.append(p)
        if len(paths) == MAX_PATHS:
            break
    if not paths:
        return None
    ttl = v.get("ttlSeconds")
    if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and math.isfinite(ttl) and ttl >= 1:
        ttl_s = min(int(math.floor(ttl)), MAX_TTL_S)
    else:
        ttl_s = DEFAULT_TTL_S
    return Deception(paths=tuple(paths), action="block" if v.get("action") == "block" else "monitor", ttl_seconds=ttl_s)


def decode_target(target: bytes) -> Optional[bytes]:
    """The path of a raw request target (before the first ``?``),
    percent-decoded once ("Matching"). None when an escape is invalid: such a
    path hits nothing."""
    path = target.split(b"?", 1)[0]
    if b"%" not in path:
        return path
    out = bytearray()
    i, n = 0, len(path)
    while i < n:
        c = path[i]
        if c == 0x25:
            h = path[i + 1 : i + 3]
            if len(h) < 2 or h[0] not in _HEX or h[1] not in _HEX:
                return None
            out.append(int(h, 16))
            i += 3
        else:
            out.append(c)
            i += 1
    return bytes(out)


def match_decoy(path: Optional[bytes], decoys: Sequence[str]) -> Optional[str]:
    """The first decoy the decoded path equals or is under (decoy + ``/``),
    compared byte for byte with the decoy's UTF-8, case-sensitively."""
    if path is None:
        return None
    for d in decoys:
        b = d.encode("utf-8")
        if path == b or path.startswith(b + b"/"):
            return d
    return None


class SuspiciousTable:
    """Client addresses that hit a decoy, in memory for this process only, at
    most ``cap`` of them, kept in expiry order, the soonest first
    ("Suspicious addresses"): a full table drops expired marks first, then
    the mark closest to expiring, never a live mark while an expired one
    remains (a lower TTL makes newer marks expire before older ones)."""

    def __init__(self, cap: int = MAX_SUSPICIOUS, clock: Optional[Callable[[], float]] = None):
        self._cap = max(1, int(cap))
        self._clock = clock or time.monotonic
        # (until, seq, ip) sorted; seq keeps equal expiries in marking order.
        self._order: List[Tuple[float, int, str]] = []
        self._marks: Dict[str, Tuple[float, int, str]] = {}
        self._seq = 0
        self._lock = threading.Lock()

    def _remove(self, entry: Tuple[float, int, str]) -> None:
        del self._marks[entry[2]]
        del self._order[bisect.bisect_left(self._order, entry)]

    def mark(self, ip: Optional[str], ttl_seconds: float) -> None:
        """Marks an address for ``ttl_seconds``; marking it again restarts the time."""
        if not isinstance(ip, str) or not ip:
            return
        with self._lock:
            now = self._clock()
            old = self._marks.get(ip)
            if old is not None:
                self._remove(old)
            elif len(self._marks) >= self._cap:
                while self._order and self._order[0][0] <= now:
                    self._remove(self._order[0])
                if len(self._marks) >= self._cap:
                    self._remove(self._order[0])
            self._seq += 1
            entry = (now + ttl_seconds, self._seq, ip)
            # With one TTL this lands at the end; it only moves in after a TTL change.
            self._order.insert(bisect.bisect_right(self._order, entry), entry)
            self._marks[ip] = entry

    def is_suspicious(self, ip: Optional[str]) -> bool:
        """Whether an address is marked; an expired mark is dropped."""
        if not isinstance(ip, str) or not ip:
            return False
        with self._lock:
            entry = self._marks.get(ip)
            if entry is None:
                return False
            if entry[0] <= self._clock():
                self._remove(entry)
                return False
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._marks)

    def addresses(self) -> Tuple[str, ...]:
        """The marked addresses, soonest to expire first (tests)."""
        with self._lock:
            return tuple(e[2] for e in self._order)


_table = SuspiciousTable()


def suspicious_table() -> SuspiciousTable:
    return _table


def set_suspicious_table(t: Optional[SuspiciousTable] = None) -> SuspiciousTable:
    """Replaces the process's table (tests); None starts an empty default one."""
    global _table
    _table = t if t is not None else SuspiciousTable()
    return _table
