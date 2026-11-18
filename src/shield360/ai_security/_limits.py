"""Per end-user and per-tenant rate and token limits (OWASP LLM10).

Local approximate limits with periodic sync: each process counts locally and,
every ``limits.syncSeconds`` in a background thread, sends what it counted
since the last sync to the platform, which answers with the totals across
every process. A check is a dictionary lookup; the platform is never called
on the request path and an outage never fails a call. N processes can
overshoot a limit by at most what they serve in one sync interval. See the
TypeScript module for the full reasoning.

Must stay in sync with: sdk/typescript/src/ai-security/limits.ts
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional

_MAX_KEYS = 50_000


def _zero() -> Dict[str, float]:
    return {"requests": 0, "tokens": 0, "costMicros": 0}


def _key_of(k: Dict[str, Any]) -> str:
    return f"{k['scope']}\x00{k['tenantId']}\x00{k.get('userId') or ''}"


def keys_for(tenant_id: Optional[str], user_id: Optional[str]) -> List[Dict[str, Any]]:
    if not tenant_id:
        return []
    keys: List[Dict[str, Any]] = [{"scope": "tenant", "tenantId": tenant_id}]
    if user_id:
        keys.append({"scope": "user", "tenantId": tenant_id, "userId": user_id})
    return keys


class LimitEngine:
    def __init__(
        self,
        policy: Callable[[], Dict[str, Any]],
        sync: Optional[Callable[[List[Dict[str, Any]]], Optional[Dict[str, Any]]]],
        now: Callable[[], float] = time.time,
    ):
        self._policy = policy
        self._sync = sync
        self._now = now
        self._counters: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._syncing = False
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread or not self._sync:
            return

        def run():
            while not self._stop.wait(max(2, self._policy()["syncSeconds"])):
                self.sync_now()

        self._thread = threading.Thread(target=run, name="shield360-ai-security-limits", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _windows(self):
        t = self._now()
        return int(t // 60), int(t // 86400)

    def _counter(self, key: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        kid = _key_of(key)
        minute, day = self._windows()
        c = self._counters.get(kid)
        if c is None:
            if len(self._counters) >= _MAX_KEYS:
                for k in [k for k, v in self._counters.items() if v["day"] != day]:
                    del self._counters[k]
            if len(self._counters) >= _MAX_KEYS:
                return None
            c = {"key": key, "minute": minute, "day": day, "shared": _zero(), "local": _zero(), "inflight": _zero()}
            self._counters[kid] = c
        if c["day"] != day:
            c.update(day=day, minute=minute, shared=_zero(), local=_zero())
        elif c["minute"] != minute:
            c["minute"] = minute
            c["shared"]["requests"] = 0
            c["local"]["requests"] = 0
        return c

    def check(self, keys: List[Dict[str, Any]]) -> Dict[str, Any]:
        p = self._policy()
        if p["mode"] == "off":
            return {"allowed": True}
        with self._lock:
            for key in keys:
                lim = p["perUser"] if key["scope"] == "user" else p["perTenant"]
                c = self._counter(key)
                if c is None:
                    continue

                def used(u, c=c):
                    return c["shared"][u] + c["local"][u] + c["inflight"][u]

                if lim.get("requestsPerMinute") and used("requests") + 1 > lim["requestsPerMinute"]:
                    return {
                        "allowed": False,
                        "limit": "requests_per_minute",
                        "scope": key["scope"],
                        "used": used("requests"),
                        "max": lim["requestsPerMinute"],
                    }
                if lim.get("tokensPerDay") and used("tokens") >= lim["tokensPerDay"]:
                    return {
                        "allowed": False,
                        "limit": "tokens_per_day",
                        "scope": key["scope"],
                        "used": used("tokens"),
                        "max": lim["tokensPerDay"],
                    }
                if lim.get("costPerDayUsd") and used("costMicros") >= lim["costPerDayUsd"] * 1e6:
                    return {
                        "allowed": False,
                        "limit": "cost_per_day",
                        "scope": key["scope"],
                        "used": used("costMicros") / 1e6,
                        "max": lim["costPerDayUsd"],
                    }
        return {"allowed": True}

    def record(self, keys: List[Dict[str, Any]], requests: float = 0, tokens: float = 0, cost_micros: float = 0) -> None:
        if self._policy()["mode"] == "off":
            return
        with self._lock:
            for key in keys:
                c = self._counter(key)
                if c is None:
                    continue
                c["local"]["requests"] += max(0, requests)
                c["local"]["tokens"] += max(0, round(tokens))
                c["local"]["costMicros"] += max(0, round(cost_micros))

    def sync_now(self) -> None:
        if not self._sync or self._syncing:
            return
        self._syncing = True
        batch: List[Dict[str, Any]] = []
        try:
            with self._lock:
                for c in list(self._counters.values()):
                    self._counter(c["key"])
                    if any(c["local"].values()) or c["shared"]["requests"] or c["shared"]["tokens"]:
                        c["inflight"] = c["local"]
                        c["local"] = _zero()
                        batch.append(c)
            if not batch:
                return
            answer = self._sync([{**c["key"], "minute": c["minute"], "day": c["day"], **c["inflight"]} for c in batch[:5000]])
            if not answer:
                raise RuntimeError("no answer")
            by_key = {_key_of(c["key"]): c for c in batch}
            with self._lock:
                for e in answer.get("entries") or []:
                    c = by_key.get(_key_of({"scope": e.get("scope"), "tenantId": e.get("tenantId"), "userId": e.get("userId")}))
                    if c is None:
                        continue
                    if e.get("day") == c["day"]:
                        c["shared"]["tokens"] = max(0, float(e.get("tokens") or 0))
                        c["shared"]["costMicros"] = max(0, float(e.get("costMicros") or 0))
                    if e.get("minute") == c["minute"]:
                        c["shared"]["requests"] = max(0, float(e.get("requests") or 0))
                for c in batch:
                    c["inflight"] = _zero()
        except Exception:  # pylint: disable=broad-exception-caught
            with self._lock:
                for c in batch:
                    for k in ("requests", "tokens", "costMicros"):
                        c["local"][k] += c["inflight"][k]
                    c["inflight"] = _zero()
        finally:
            self._syncing = False

    def usage(self, key: Dict[str, Any]) -> Dict[str, float]:
        with self._lock:
            c = self._counter(key)
            if c is None:
                return _zero()
            return {k: c["shared"][k] + c["local"][k] + c["inflight"][k] for k in ("requests", "tokens", "costMicros")}
