"""
Reading an agent passport: the compact JWS, its claims, the issuer's keys and the
audience. Nothing here raises on hostile input.

Must stay in sync with: sdk/typescript/src/agents/passport.ts
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import math
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from shield360.agents._types import PASSPORT_TYP

logger = logging.getLogger(__name__)

MAX_TOKEN_LENGTH = 8192
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_SCOPE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_HOST = re.compile(r"^[a-z0-9.-]+(:\d{1,5})?$")
_MAX_SCOPES = 32
_HOUR = 3600.0
_MISS_REFETCH = 60.0
FETCH_TIMEOUT = 5.0

# (method, url, headers, body, timeout) -> (status, body bytes); raises on network failure.
HttpTransport = Callable[[str, str, Dict[str, str], Optional[bytes], float], Tuple[int, bytes]]


def urllib_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes], timeout: float) -> Tuple[int, bytes]:
    """The default transport: urllib, with HTTP errors returned rather than raised."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - https issuer/console URLs
            return resp.status, resp.read(1_000_000)
    except urllib.error.HTTPError as err:
        try:
            return err.code, err.read(1_000_000)
        except Exception:
            return err.code, b""


def fetch_json(http: HttpTransport, method: str, url: str, headers: Dict[str, str], body: Any = None) -> Optional[Tuple[int, Any]]:
    """Calls ``http`` and decodes JSON; None on any failure."""
    data = json.dumps(body).encode() if body is not None else None
    hdrs = {"Accept": "application/json", **headers}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    try:
        status, raw = http(method, url, hdrs, data, FETCH_TIMEOUT)
    except Exception:
        return None
    try:
        decoded = json.loads(raw.decode("utf-8")) if raw else None
    except Exception:
        decoded = None
    return status, decoded


def _b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _json_part(part: str) -> Any:
    try:
        return json.loads(_b64decode(part).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


def _text(v: Any, max_len: int = 1024) -> bool:
    return isinstance(v, str) and 0 < len(v) <= max_len


def _opt_text(v: Any, max_len: int = 1024) -> bool:
    return v is None or (isinstance(v, str) and len(v) <= max_len)


def _number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


@dataclass
class ParsedPassport:
    kid: str
    claims: Dict[str, Any]
    signing_input: bytes
    signature: bytes


def parse_passport(token: Any) -> Tuple[Optional[ParsedPassport], Optional[str]]:
    """Step 1: three base64url parts, typ and alg, claims of the right shape. Returns (passport, reason)."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
        return None, "malformed"
    parts = token.split(".")
    if len(parts) != 3 or not all(_B64URL.match(p) for p in parts):
        return None, "malformed"
    header = _json_part(parts[0])
    if not isinstance(header, dict):
        return None, "malformed"
    typ = header.get("typ")
    if not isinstance(typ, str) or typ.lower() != PASSPORT_TYP:
        return None, "malformed"
    if "crit" in header:
        return None, "malformed"
    if header.get("alg") != "EdDSA":
        return None, "unsupported_alg"
    if not _text(header.get("kid"), 256):
        return None, "malformed"

    c = _json_part(parts[1])
    if not isinstance(c, dict):
        return None, "malformed"
    agent, operator, act, decision = c.get("agent"), c.get("operator"), c.get("act"), c.get("decision")
    ok = (
        _text(c.get("iss"), 512)
        and _text(c.get("sub"), 512)
        and _text(c.get("aud"), 512)
        and _text(c.get("jti"), 256)
        and _number(c.get("iat"))
        and _number(c.get("exp"))
        and isinstance(agent, dict)
        and _text(agent.get("id"), 256)
        and _text(agent.get("name"), 512)
        and _opt_text(agent.get("purpose"), 2048)
        and isinstance(operator, dict)
        and _text(operator.get("id"), 256)
        and _text(operator.get("name"), 512)
        and _opt_text(operator.get("domain"), 256)
        and (act is None or (isinstance(act, dict) and _text(act.get("sub"), 256) and _opt_text(act.get("domain"), 256)))
        and (c.get("scope") is None or isinstance(c.get("scope"), str))
        and (decision is None or isinstance(decision, dict))
    )
    if not ok:
        return None, "malformed"
    try:
        signature = _b64decode(parts[2])
    except (ValueError, binascii.Error):
        return None, "malformed"
    if len(signature) != 64:
        return None, "malformed"
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    return ParsedPassport(kid=header["kid"], claims=c, signing_input=signing_input, signature=signature), None


def scopes_of(scope: Any) -> List[str]:
    """The scopes a passport presents: well-formed ones only, at most 32."""
    if not isinstance(scope, str):
        return []
    out: List[str] = []
    for s in scope.split():
        if _SCOPE.match(s) and s not in out:
            out.append(s)
        if len(out) >= _MAX_SCOPES:
            break
    return out


def normalise_issuer(iss: str) -> str:
    return iss.rstrip("/")


def parse_audience(value: Any, strict: bool) -> Optional[Tuple[str, Optional[str]]]:
    """(host, origin or None) an audience names. ``strict`` refuses origins that are not https (passport audiences)."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if not v:
        return None
    if "://" in v:
        try:
            u = urllib.parse.urlsplit(v)
            port = u.port
        except ValueError:
            return None
        if u.scheme != "https" and (strict or u.scheme != "http"):
            return None
        if u.username or u.password or not u.hostname:
            return None
        if u.path not in ("", "/") or u.query or u.fragment:
            return None
        default_port = 443 if u.scheme == "https" else 80
        host = u.hostname if port in (None, default_port) else f"{u.hostname}:{port}"
        return host, f"{u.scheme}://{host}"
    return (v.rstrip("."), None) if _HOST.match(v) else None


def audience_matches(aud: str, audiences: List[str]) -> bool:
    """Step 5: the passport's aud names one of the receiver's audiences.

    Hosts compare case-insensitively; a bare host on either side matches an
    origin with that host; two origins must be identical.
    """
    a = parse_audience(aud, True)
    if not a:
        return False
    for value in audiences:
        b = parse_audience(value, False)
        if not b:
            continue
        if a[1] and b[1]:
            if a[1] == b[1]:
                return True
        elif a[0] == b[0]:
            return True
    return False


def _load_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "shield360.agents needs the 'cryptography' package to verify agent passports: pip install 'shield360[agents]'"
        ) from exc
    return Ed25519PublicKey, InvalidSignature


def require_crypto() -> None:
    _load_crypto()


def key_from_jwk(jwk: Any) -> Optional[Tuple[str, Any]]:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        return None
    if not _text(jwk.get("x"), 128) or not _text(jwk.get("kid"), 256) or "d" in jwk:
        return None
    Ed25519PublicKey, _ = _load_crypto()
    try:
        raw = _b64decode(jwk["x"])
        if len(raw) != 32:
            return None
        return jwk["kid"], Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def verify_signature(p: ParsedPassport, key: Any) -> bool:
    _, InvalidSignature = _load_crypto()
    try:
        key.verify(p.signature, p.signing_input)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


class KeyCache:
    """Issuers' public keys: cached an hour; an unknown kid (or a stale set) refetches at most once a minute per issuer."""

    def __init__(self, http: HttpTransport, clock: Callable[[], float]):
        self._http = http
        self._clock = clock
        self._lock = threading.Lock()
        self._issuers: Dict[str, Dict[str, Any]] = {}

    def get(self, issuer: str, kid: str) -> Optional[Any]:
        with self._lock:
            entry = self._issuers.setdefault(issuer, {"keys": {}, "fetched_at": -math.inf, "last_attempt": -math.inf})
            now = self._clock()
            known = entry["keys"].get(kid)
            if known is not None and now - entry["fetched_at"] < _HOUR:
                return known
            if now - entry["last_attempt"] < _MISS_REFETCH:
                return known
            entry["last_attempt"] = now
        got = fetch_json(self._http, "GET", f"{issuer}/api/agent-passports/keys?kid={urllib.parse.quote(kid, safe='')}", {})
        if got and got[0] == 200 and isinstance(got[1], dict) and isinstance(got[1].get("keys"), list):
            loaded = [k for k in (key_from_jwk(j) for j in got[1]["keys"][:50]) if k]
            with self._lock:
                for k_id, k in loaded:
                    entry["keys"][k_id] = k
                entry["fetched_at"] = self._clock()
        with self._lock:
            return entry["keys"].get(kid, known)
