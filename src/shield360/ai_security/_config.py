"""The app's AI security policy from the platform, signed.

GET /api/ai-security/config?app=<name> answers a compact JWS (EdDSA,
Ed25519, typ ``shield360-ai-security+jws``) with claims ``{app, policy, ver,
iat, exp}`` and the signing key's public JWK. The SDK verifies it and refuses
another app's or an expired policy.

Pinning is required: the token must verify under a pinned key,
``config_public_key`` (a JWK, a PEM or a JWKS ``{"keys": [...]}`` listing the
old and new key during a rotation) or env ``SHIELD360_CONFIG_PUBLIC_KEY``.
The key sent beside the token is never trusted on its own. Without a pin the
platform's policy is not applied (the policy from code runs, monitoring by
default) and that is reported once. Trust on first use exists only behind
``allow_unpinned_config=True``, for development. A verified answer can be
cached to a file and is re-verified under the pinned keys; a cached answer
never pins a key. Refreshed in a background thread every 60 s, never on the
request path; when nothing valid can be read the policy from code applies.

Ed25519 verification uses the ``cryptography`` package when it is installed
and otherwise a small pure-Python implementation of RFC 8032 section 5.1.7
(after the RFC's reference code, section 6), so the SDK needs no new
dependency. Only verification, only public data: no secret ever touches it.

Must stay in sync with: sdk/typescript/src/ai-security/config.ts
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

CONFIG_JWS_TYPE = "shield360-ai-security+jws"
_MAX_JWS = 256 * 1024


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032).

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)  # pylint: disable=arguments-out-of-order
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q):
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _verify_pure(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64:
        return False
    a = _decompress(public)
    r = _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # pylint: disable=import-outside-toplevel

        try:
            Ed25519PublicKey.from_public_bytes(public).verify(sig, msg)
            return True
        except Exception:  # pylint: disable=broad-exception-caught
            return False
    except ImportError:
        return _verify_pure(public, msg, sig)


def public_key_from(value: Any) -> Optional[bytes]:
    """The raw 32-byte Ed25519 key from a JWK dict (or its JSON); None otherwise."""
    try:
        if isinstance(value, str):
            value = json.loads(value)
        if isinstance(value, dict) and value.get("kty") == "OKP" and value.get("crv") == "Ed25519" and isinstance(value.get("x"), str):
            raw = _b64d(value["x"])
            return raw if len(raw) == 32 else None
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return None


_SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")


def _pem_key(text: str) -> Optional[bytes]:
    if "BEGIN PUBLIC KEY" not in text:
        return None
    body = "".join(line for line in text.strip().splitlines() if not line.startswith("-----"))
    try:
        der = base64.b64decode(body)
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return der[12:] if len(der) == 44 and der.startswith(_SPKI_ED25519) else None


def pinned_keys_from(value: Any) -> List[Tuple[Optional[str], bytes]]:
    """(kid, raw key) for each key a value pins: a JWK, a PEM, a JWKS, or the JSON text of one."""
    v = value
    if isinstance(v, str):
        t = v.strip()
        if not t:
            return []
        if "BEGIN PUBLIC KEY" in t:
            k = _pem_key(t)
            return [(None, k)] if k else []
        try:
            v = json.loads(t)
        except Exception:  # pylint: disable=broad-exception-caught
            return []
    if isinstance(v, dict) and isinstance(v.get("keys"), list):
        items = v["keys"]
    elif isinstance(v, list):
        items = v
    else:
        items = [v]
    out: List[Tuple[Optional[str], bytes]] = []
    for item in items[:20]:
        k = public_key_from(item)
        if k is None:
            continue
        kid = item.get("kid") if isinstance(item, dict) and isinstance(item.get("kid"), str) else None
        out.append((kid, k))
    return out


def _kid_of(token: Any) -> Optional[str]:
    try:
        header = json.loads(_b64d(token.split(".")[0]))
        return header.get("kid") if isinstance(header, dict) else None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def verify_policy(token: Any, key: bytes, app: str, now: float) -> Optional[Dict[str, Any]]:
    if not isinstance(token, str) or len(token) > _MAX_JWS:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64d(parts[0]))
        claims = json.loads(_b64d(parts[1]))
        sig = _b64d(parts[2])
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    if (
        not isinstance(header, dict)
        or header.get("alg") != "EdDSA"
        or header.get("typ") != CONFIG_JWS_TYPE
        or not isinstance(header.get("kid"), str)
    ):
        return None
    if not ed25519_verify(key, f"{parts[0]}.{parts[1]}".encode(), sig):
        return None
    if not isinstance(claims, dict) or claims.get("app") != app:
        return None
    for k in ("exp", "iat", "ver"):
        if not isinstance(claims.get(k), (int, float)) or isinstance(claims.get(k), bool):
            return None
    if claims["exp"] < now:
        return None
    return {
        "app": app,
        "policy": claims.get("policy"),
        "ver": claims["ver"],
        "iat": claims["iat"],
        "exp": claims["exp"],
        "kid": header["kid"],
    }


class ConfigClient:  # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        url: str,
        api_key: str,
        app: str,
        on_policy: Callable[[Dict[str, Any]], None],
        public_key: Any = None,
        cache_file: Optional[str] = None,
        allow_unpinned: bool = False,
        refresh_seconds: float = 60,
        timeout: float = 3,
        get: Optional[Callable[[str, Dict[str, str], float], Any]] = None,
        now: Callable[[], float] = time.time,
    ):
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._app = app
        self._on_policy = on_policy
        pin = public_key if public_key is not None else os.environ.get("SHIELD360_CONFIG_PUBLIC_KEY", "")
        self._keys = pinned_keys_from(pin)
        self._tofu = not self._keys and allow_unpinned is True
        self._cache_file = cache_file
        self._refresh = max(10, refresh_seconds)
        self._timeout = timeout
        self._get = get or _http_get
        self._now = now
        self._last_ver = -1
        self._stop = threading.Event()

    @property
    def usable(self) -> bool:
        """Whether anything can be verified: a pinned key, or trust on first use allowed."""
        return bool(self._keys) or self._tofu

    def start(self) -> None:
        if not self.usable:
            return
        self._read_cache()

        def run():
            self.refresh()
            while not self._stop.wait(self._refresh):
                self.refresh()

        threading.Thread(target=run, name="shield360-ai-security-config", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def _accept(self, answer: Any, pin: bool = True) -> bool:
        if not isinstance(answer, dict):
            return False
        candidates = self._keys
        if not candidates:
            if not self._tofu:
                return False
            candidates = pinned_keys_from(answer.get("publicKey"))[:1]
            if not candidates:
                return False
        kid = _kid_of(answer.get("jws")) if isinstance(answer.get("jws"), str) else None
        ordered = [c for c in candidates if c[0] and c[0] == kid] + [c for c in candidates if not c[0] or c[0] != kid]
        signed = None
        used = None
        for c in ordered:
            signed = verify_policy(answer.get("jws"), c[1], self._app, self._now())
            if signed is not None:
                used = c
                break
        if signed is None:
            return False
        if pin and not self._keys:
            self._keys = [used]
        if signed["ver"] != self._last_ver:
            self._last_ver = signed["ver"]
            self._on_policy(signed)
        return True

    def refresh(self) -> bool:
        if not self.usable:
            return False
        try:
            answer = self._get(
                f"{self._url}/api/ai-security/config?app={_quote(self._app)}",
                {"Authorization": f"Bearer {self._api_key}"},
                self._timeout,
            )
            if answer is None or not self._accept(answer):
                return False
            self._write_cache(answer)
            return True
        except Exception:  # pylint: disable=broad-exception-caught
            return False

    def _read_cache(self) -> None:
        if not self._cache_file:
            return
        try:
            with open(self._cache_file, "r", encoding="utf-8") as f:
                self._accept(json.load(f), pin=False)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _write_cache(self, answer: Dict[str, Any]) -> None:
        if not self._cache_file:
            return
        try:
            fd = os.open(self._cache_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"jws": answer.get("jws"), "publicKey": answer.get("publicKey")}, f)
        except Exception:  # pylint: disable=broad-exception-caught
            pass


def _quote(s: str) -> str:
    from urllib.parse import quote  # pylint: disable=import-outside-toplevel

    return quote(s, safe="")


def _http_get(url: str, headers: Dict[str, str], timeout: float) -> Any:
    import requests  # pylint: disable=import-outside-toplevel

    res = requests.get(url, headers=headers, timeout=timeout)
    return res.json() if res.ok else None
