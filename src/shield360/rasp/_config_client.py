"""Signed RASP config client (README "The signed config").

``GET /api/rasp/config?app=`` returns ``{"config": <compact JWS>, "keys": [...]}``.
The JWS is trusted only when it verifies against a key the app pinned
(``config_public_key`` / ``SHIELD360_CONFIG_PUBLIC_KEY``: a JWK, a JWKS for
rotation, or the bare base64url Ed25519 ``x``). The ``keys`` in the response
are never trusted on their own: they came over the same channel as the
config. Only with trust on first use (development: ``allow_unpinned_config``
or ``SHIELD360_CONFIG_TOFU=dev``, never in production) is the first ``kid``
seen pinned; a config signed by another kid after that is rejected. A pinned
key that does not verify never falls back to trust on first use.

ETag polling every 60 s +/- 10 s, 5 minutes after a failure; the last
verified config is kept in memory and in a cache file that is re-verified
when loaded. Polling runs on a daemon thread; nothing here raises or blocks
start-up. Ed25519 verification is the SDK's own (``cryptography`` when
installed, else the pure-Python RFC 8032 verifier), so no new dependency.
"""

from __future__ import annotations

import base64
import json
import os
import random
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

JWS_TYPE = "shield360-rasp+jws"
SKEW_S = 60
POLL_S = 60.0
JITTER_S = 10.0
BACKOFF_S = 300.0
_FETCH_TIMEOUT_S = 10.0
_MAX_TOKEN = 256 * 1024

# Captured at import, before any later file-system hook, so the cache never trips RASP itself.
_open = open
_makedirs = os.makedirs
_replace = os.replace
_getpid = os.getpid
_os_open = os.open

_B64URL = re.compile(r"[A-Za-z0-9_\-]+")


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass(frozen=True)
class PinnedKey:
    x: str
    raw: bytes
    kid: Optional[str] = None


def _from_jwk(jwk: Any) -> Optional[PinnedKey]:
    try:
        if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            return None
        x = jwk.get("x")
        if not isinstance(x, str) or not _B64URL.fullmatch(x):
            return None
        raw = _b64url(x)
        if len(raw) != 32:
            return None
        kid = jwk.get("kid")
        return PinnedKey(x=x, raw=raw, kid=kid if isinstance(kid, str) and kid else None)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def parse_public_keys(value: Any) -> List[PinnedKey]:
    """Parses a pinned key: a JWK, a JWKS, or the bare base64url Ed25519 ``x``
    (objects or JSON text). Unusable entries are left out; [] when none is usable."""
    if value is None or value == "":
        return []
    v = value
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("{") or s.startswith("["):
            try:
                v = json.loads(s)
            except Exception:  # pylint: disable=broad-exception-caught
                return []
        else:
            k = _from_jwk({"kty": "OKP", "crv": "Ed25519", "x": s})
            return [k] if k else []
    if isinstance(v, list):
        items = v
    elif isinstance(v, dict) and isinstance(v.get("keys"), list):
        items = v["keys"]
    else:
        items = [v]
    return [k for k in (_from_jwk(i) for i in items[:16]) if k is not None]


def _header(token: str) -> Optional[Dict[str, Any]]:
    try:
        h = json.loads(_b64url(token.split(".")[0]).decode("utf-8"))
        return h if isinstance(h, dict) else None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def jws_kid(token: Any) -> Optional[str]:
    """The ``kid`` in a JWS header, or None."""
    h = _header(token) if isinstance(token, str) else None
    return h["kid"] if h and isinstance(h.get("kid"), str) else None


def _verify(raw: bytes, msg: bytes, sig: bytes) -> bool:
    from shield360.ai_security._config import ed25519_verify

    return ed25519_verify(raw, msg, sig)


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_rollback(nxt: Dict[str, Any], current: Optional[Dict[str, Any]]) -> bool:
    """Whether ``nxt`` was signed before the config in force (beyond SKEW_S of clock skew)."""
    if not current or not isinstance(current.get("iat"), (int, float)):
        return False
    iat = nxt.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        return True
    return iat + SKEW_S < current["iat"]


def verify_config_jws(token: Any, keys: List[PinnedKey], app: str, now_s: Optional[float] = None) -> Dict[str, Any]:
    """Verifies a compact JWS against the given keys only: ``alg`` EdDSA,
    ``typ`` shield360-rasp+jws, an Ed25519 signature by the pinned key whose
    kid matches the header (any pinned key when the header names none
    listed), ``v`` 1, ``app`` equal to ours, ``exp`` in the future (60 s
    skew). Returns ``{"ok": True, "claims", "kid"}`` or ``{"ok": False, "reason"}``."""
    try:
        now = time.time() if now_s is None else now_s
        if not isinstance(token, str) or len(token) > _MAX_TOKEN:
            return {"ok": False, "reason": "malformed"}
        parts = token.split(".")
        if len(parts) != 3 or not all(_B64URL.fullmatch(p) for p in parts):
            return {"ok": False, "reason": "malformed"}
        h = _header(token)
        if h is None:
            return {"ok": False, "reason": "malformed"}
        if h.get("alg") != "EdDSA":
            return {"ok": False, "reason": "alg"}
        if h.get("typ") != JWS_TYPE:
            return {"ok": False, "reason": "typ"}
        kid = h.get("kid") if isinstance(h.get("kid"), str) else None
        candidates = [k for k in keys if kid and k.kid == kid] or list(keys)
        if not candidates:
            return {"ok": False, "reason": "no_key"}
        signed = f"{parts[0]}.{parts[1]}".encode()
        sig = _b64url(parts[2])
        if not any(_verify(k.raw, signed, sig) for k in candidates):
            return {"ok": False, "reason": "signature"}
        claims = json.loads(_b64url(parts[1]).decode("utf-8"))
        if not isinstance(claims, dict) or not _is_number(claims.get("v")) or claims.get("v") != 1:
            return {"ok": False, "reason": "version"}
        if claims.get("app") != app:
            return {"ok": False, "reason": "app"}
        if not _is_number(claims.get("exp")) or claims["exp"] + SKEW_S <= now:
            return {"ok": False, "reason": "expired"}
        if not isinstance(claims.get("version"), str) or not claims["version"]:
            return {"ok": False, "reason": "version"}
        return {"ok": True, "claims": claims, "kid": kid}
    except Exception:  # pylint: disable=broad-exception-caught
        return {"ok": False, "reason": "malformed"}


# (status, headers with lower-case names, body) for one GET.
FetchResult = Tuple[int, Dict[str, str], bytes]


def _http_get(url: str, headers: Dict[str, str], timeout: float) -> FetchResult:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(_MAX_TOKEN * 2)
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, b""


_SAFE_APP = re.compile(r"[^A-Za-z0-9._\-]")


class RaspConfigClient:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        url: str,
        api_key: str,
        app: str,
        pinned: List[PinnedKey],
        cache_dir: str,
        on_config: Callable[[Optional[Dict[str, Any]]], None],
        allow_unpinned: bool = False,
        on_warning: Optional[Callable[[str], None]] = None,
        fetch: Optional[Callable[[str, Dict[str, str], float], FetchResult]] = None,
        now: Optional[Callable[[], float]] = None,
        rand: Optional[Callable[[], float]] = None,
    ):
        self._base = url.rstrip("/")
        self._api_key = api_key
        self._app = app
        self._pinned = list(pinned)
        # Development only (the caller already refused it in production): pin the first kid the server sends.
        self._allow_unpinned = bool(allow_unpinned)
        self._cache_dir = cache_dir
        self._on_config = on_config
        self._on_warning = on_warning
        self._fetch = fetch or _http_get
        self._now = now or time.time
        self._rand = rand or random.random
        self._etag: Optional[str] = None
        # Keys pinned on first use (allow_unpinned only).
        self._tofu: List[PinnedKey] = []
        self._warned: Set[str] = set()
        self._stop = threading.Event()
        self._apply_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.current: Optional[Dict[str, Any]] = None

    def _trusted(self) -> List[PinnedKey]:
        """The keys a config must verify against right now."""
        if self._pinned:
            return self._pinned
        return self._tofu if self._allow_unpinned else []

    def cache_file(self) -> str:
        name = _SAFE_APP.sub("_", self._app)[:128] or "default"
        return os.path.join(self._cache_dir, f"{name}.json")

    def _warn(self, reason: str) -> None:
        if reason in self._warned:
            return
        self._warned.add(reason)
        try:
            if self._on_warning:
                self._on_warning(reason)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _apply(self, claims: Optional[Dict[str, Any]], token: Optional[str] = None) -> bool:
        """Applies (and with ``token`` caches) a config, unless the client was
        stopped: a fetch still in flight when the SDK is re-initialized must
        never apply the previous app's config. ``stop()`` takes the same lock,
        so once it returns nothing more is applied."""
        with self._apply_lock:
            if self._stop.is_set():
                return False
            self.current = claims
            try:
                self._on_config(claims)
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # fail open
            if token is not None:
                self._save_cache(token)
            return True

    def load_cache(self) -> bool:
        """Loads the cached config and re-verifies it. Pinned keys are never read from the cache."""
        try:
            with _open(self.cache_file(), "r", encoding="utf-8") as f:
                saved = json.load(f)
            if not isinstance(saved, dict):
                return False
            if not self._pinned and self._allow_unpinned and not self._tofu:
                self._tofu = parse_public_keys({"keys": saved.get("tofu") or []})
            r = verify_config_jws(saved.get("config"), self._trusted(), self._app, self._now())
            if not r["ok"]:
                return False
            return self._apply(r["claims"])
        except Exception:  # pylint: disable=broad-exception-caught
            return False

    def _save_cache(self, config: str) -> None:
        try:
            _makedirs(self._cache_dir, mode=0o700, exist_ok=True)
            body: Dict[str, Any] = {"config": config}
            if not self._pinned and self._tofu:
                body["tofu"] = [
                    {"kty": "OKP", "crv": "Ed25519", "x": k.x, **({"kid": k.kid} if k.kid else {})} for k in self._tofu
                ]
            target = self.cache_file()
            tmp = f"{target}.{_getpid()}.tmp"
            fd = _os_open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with _open(fd, "w", encoding="utf-8") as f:
                json.dump(body, f)
            _replace(tmp, target)
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # the cache is best effort

    def _expire(self) -> None:
        """Drops the config in force once it has expired (the platform could not be reached for its whole lifetime)."""
        cur = self.current
        if cur is not None and _is_number(cur.get("exp")) and cur["exp"] + SKEW_S <= self._now():
            self._etag = None
            self._apply(None)

    def poll(self) -> str:
        """One poll: ``updated``, ``unchanged``, ``rejected`` or ``failed``. Never raises."""
        result = self._fetch_once()
        self._expire()
        return result

    def _fetch_once(self) -> str:
        try:
            if not self._pinned and not self._allow_unpinned:
                self._warn("unpinned")
                return "rejected"
            headers = {"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"}
            if self._etag and self.current is not None:
                headers["If-None-Match"] = self._etag
            url = f"{self._base}/api/rasp/config?app={urllib.parse.quote(self._app, safe='')}"
            status, resp_headers, raw = self._fetch(url, headers, _FETCH_TIMEOUT_S)
            if status == 304:
                return "unchanged"
            if not 200 <= status < 300:
                return "failed"
            body = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
            if not isinstance(body, dict):
                body = {}
            token = body.get("config") if isinstance(body.get("config"), str) else ""
            if not self._pinned and self._allow_unpinned and not self._tofu:
                # Trust on first use (development only): pin the key the response names.
                kid = jws_kid(token)
                offered = parse_public_keys({"keys": body.get("keys") if isinstance(body.get("keys"), list) else []})
                first = next((k for k in offered if k.kid == kid), None) or (offered[0] if len(offered) == 1 else None)
                if first is not None:
                    self._tofu = [first]
                    self._warn("trust_on_first_use")
            r = verify_config_jws(token, self._trusted(), self._app, self._now())
            if not r["ok"]:
                self._warn(r["reason"])
                return "rejected"
            # A validly signed config older than the one in force is a replay
            # (re-served from the path, kill switch and all): refused.
            if is_rollback(r["claims"], self.current):
                self._warn("rollback")
                return "rejected"
            if not self._apply(r["claims"], token):
                return "rejected"
            self._etag = resp_headers.get("etag") or None
            return "updated"
        except Exception:  # pylint: disable=broad-exception-caught
            return "failed"

    def next_delay(self, result: str) -> float:
        """Seconds before the next poll after a result."""
        if result in ("failed", "rejected"):
            return BACKOFF_S
        return POLL_S + round((self._rand() * 2 - 1) * JITTER_S, 3)

    def start(self) -> None:
        """Loads the cache (a local file, verified in milliseconds), then polls on a daemon thread, off the start-up path."""
        if self._thread is not None:
            return
        self.load_cache()

        def run() -> None:
            while not self._stop.is_set():
                r = self.poll()
                if self._stop.wait(self.next_delay(r)):
                    return

        self._thread = threading.Thread(target=run, name="shield360-rasp-config", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        # Under the apply lock: an apply in progress finishes first, none starts after.
        with self._apply_lock:
            self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()
