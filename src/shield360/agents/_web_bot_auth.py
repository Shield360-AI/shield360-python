"""
Web Bot Auth: agents that sign their requests with HTTP Message Signatures
(RFC 9421) and publish their public keys in a key directory, as specified by the
IETF webbotauth working group (draft-ietf-webbotauth-httpsig-protocol) and
verified by Cloudflare for its signed agents.

A signature proves which signer sent the request: the host named by its
Signature-Agent header, which publishes the key. It does not say for whom the
agent acts; that is what a Shield360 passport adds.

Both Signature-Agent forms are read: the dictionary the current draft requires
(``sig1="https://signer.example"``, covered as ``"signature-agent";key="sig1"``)
and the bare string Cloudflare still sends (``"https://signer.example"``,
covered as ``"signature-agent"``). Only Ed25519 keys are accepted, as
Cloudflare does.

Must stay in sync with: sdk/typescript/src/agents/web-bot-auth.ts
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

from shield360.agents._passport import FETCH_TIMEOUT, HttpTransport, audience_matches
from shield360.agents._structured import (
    InnerList,
    Item,
    Member,
    StructuredError,
    Token,
    parse_dictionary,
    parse_item_field,
    serialize_inner_list,
    serialize_member,
)

WEB_BOT_AUTH_TAG = "web-bot-auth"
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"

#: The longest a signature may be valid (expires - created): the draft's recommended day.
MAX_SIGNATURE_SECONDS = 24 * 60 * 60

_MAX_HEADER_CHARS = 4096
_MAX_COMPONENTS = 16
_MAX_LABELS = 3
_MAX_DIRECTORY_BYTES = 64 * 1024
_MAX_DIRECTORY_KEYS = 50
_MAX_DIRECTORIES = 1000
_HOUR = 3600.0
_MISS_REFETCH = 60.0
#: Directory fetches a verifier starts in a minute: callers choose the URLs, so they must not drive unbounded outbound traffic.
_FETCHES_PER_MINUTE = 30

_DERIVED = {"@authority", "@method", "@path", "@query", "@target-uri", "@scheme"}
_FIELD_NAME = re.compile(r"^[a-z0-9!#$%&'*+\-.^_`|~]+$")
_KEY_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_AUTHORITY = re.compile(r"^[a-z0-9.\-\[\]:]{1,260}$")
_PRIVATE_HOST = re.compile(r"^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.home\.arpa)$")

UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class Signer:
    agent: str  # the Signature-Agent URL
    host: str  # its host, lower case
    key_id: str  # the key's JWK thumbprint
    expires: int  # epoch seconds


@dataclass(frozen=True)
class WebBotAuthResult:
    status: str  # "absent" | "invalid" | "verified"
    reason: Optional[str] = None
    host: Optional[str] = None
    signer: Optional[Signer] = None


_ABSENT = WebBotAuthResult("absent")


def _invalid(reason: str, host: Optional[str] = None) -> WebBotAuthResult:
    return WebBotAuthResult("invalid", reason=reason, host=host)


# ---------------------------------------------------------------- reading a request


@dataclass
class SignedRequest:
    """The parts of a request a signature can cover."""

    header: Callable[[str], Optional[str]]
    scheme: str = "https"
    method: Optional[str] = None
    authority: Optional[str] = None  # host[:port], lower case, default port removed
    path: Optional[str] = None
    query: Optional[str] = None  # without the "?"; None when the request had no query


def _text(v: Any) -> Optional[str]:
    if isinstance(v, bytes):
        return v.decode("latin-1")
    return v if isinstance(v, str) else None


def _join(values: List[Any]) -> Optional[str]:
    found = []
    for v in values:
        if isinstance(v, (list, tuple)):
            found.extend(t.strip() for t in (_text(x) for x in v) if t is not None)
        else:
            t = _text(v)
            if t is not None:
                found.append(t.strip())
    return ", ".join(found) if found else None


def _is_environ(source: Any) -> bool:
    return isinstance(source, Mapping) and ("REQUEST_METHOD" in source or "wsgi.version" in source)


def _header_getter(source: Any) -> Callable[[str], Optional[str]]:
    if _is_environ(source):

        def from_environ(name: str) -> Optional[str]:
            key = name.upper().replace("-", "_")
            key = key if key in ("CONTENT_TYPE", "CONTENT_LENGTH") else "HTTP_" + key
            return _join([source[key]]) if key in source else None

        return from_environ
    if source is not None and not isinstance(source, (dict, list, tuple, str, bytes)) and hasattr(source, "headers"):
        return _header_getter(source.headers)
    if isinstance(source, Mapping):

        def from_mapping(name: str) -> Optional[str]:
            getlist = getattr(source, "getlist", None) or getattr(source, "get_all", None)
            if callable(getlist):
                try:
                    vals = getlist(name)
                    if vals:
                        return _join(list(vals))
                except Exception:
                    pass
            want = name.lower()
            return _join([v for k, v in source.items() if (_text(k) or "").lower() == want])

        return from_mapping
    if isinstance(source, (list, tuple)):

        def from_pairs(name: str) -> Optional[str]:
            want = name.lower()
            pairs = [p for p in source if isinstance(p, (list, tuple)) and len(p) == 2]
            return _join([p[1] for p in pairs if (_text(p[0]) or "").lower() == want])

        return from_pairs
    return lambda _name: None


def _authority(host: Optional[str], scheme: str) -> Optional[str]:
    if not host:
        return None
    h = host.strip().lower()
    if not _AUTHORITY.match(h):
        return None
    if (scheme == "https" and h.endswith(":443")) or (scheme == "http" and h.endswith(":80")):
        return h.rsplit(":", 1)[0]
    return h


def signed_request(
    source: Any, route: Optional[str] = None, method: Optional[str] = None, query: Any = None, scheme: Optional[str] = None
) -> SignedRequest:
    """What a check can see of the request.

    A WSGI environ or a request object (Starlette/FastAPI, Flask/Werkzeug, Django) gives the method,
    path, query and scheme itself; for bare headers (or an ASGI header list) they come from the
    arguments. The scheme is https unless the request says otherwise.
    """
    header = _header_getter(source)
    host = header("host")
    path = route.split("?", 1)[0].split("#", 1)[0] if isinstance(route, str) else None
    q = _text(query)
    q = q if q else None
    s = (scheme or "https").lower()
    m = method
    try:
        if _is_environ(source):
            s = str(source.get("wsgi.url_scheme") or s).lower()
            m = source.get("REQUEST_METHOD") or m
            path = (source.get("SCRIPT_NAME") or "") + (source.get("PATH_INFO") or "") or path
            q = source.get("QUERY_STRING") or None
            if not host and source.get("SERVER_NAME"):
                host = f"{source['SERVER_NAME']}:{source.get('SERVER_PORT', '')}".rstrip(":")
        elif source is not None and not isinstance(source, (dict, list, tuple, str, bytes)) and hasattr(source, "headers"):
            m = getattr(source, "method", None) or m
            url = getattr(source, "url", None)
            if url is not None and not isinstance(url, str) and hasattr(url, "path"):
                # Starlette/FastAPI: request.url is a URL object.
                path, q, s = url.path, (getattr(url, "query", "") or None), str(getattr(url, "scheme", s) or s)
                host = host or getattr(url, "netloc", None)
            else:
                path = getattr(source, "path", None) or path
                qs = getattr(source, "query_string", None)
                meta = getattr(source, "META", None)
                if qs is not None:
                    q = _text(qs) or None
                elif isinstance(meta, Mapping):
                    q = meta.get("QUERY_STRING") or None
                sch = getattr(source, "scheme", None)
                s = str(sch).lower() if isinstance(sch, str) and sch else s
    except Exception:
        pass
    return SignedRequest(
        header=header,
        scheme=s,
        method=m.upper() if isinstance(m, str) else None,
        authority=_authority(host, s),
        path=path,
        query=q,
    )


# ---------------------------------------------------------------- the key directory


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def jwk_thumbprint(kty: str, crv: str, x: str) -> str:
    """A JWK's SHA-256 thumbprint (RFC 7638; RFC 8037 for OKP), base64url."""
    canonical = '{"crv":' + json.dumps(crv) + ',"kty":' + json.dumps(kty) + ',"x":' + json.dumps(x) + "}"
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


@dataclass
class _DirectoryKey:
    key: Any
    nbf: Optional[float] = None
    exp: Optional[float] = None

    def valid_at(self, t: float, skew: float) -> bool:
        """Whether the directory's nbf/exp allow the key at ``t``."""
        return (self.nbf is None or self.nbf <= t + skew) and (self.exp is None or self.exp > t - skew)


def _seconds(v: Any) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def directory_keys(body: Any) -> Dict[str, _DirectoryKey]:
    """The keys of a JWKS: Ed25519 public keys, by thumbprint. A private key is never accepted."""
    from shield360.agents._passport import _load_crypto  # pylint: disable=import-outside-toplevel

    Ed25519PublicKey, _ = _load_crypto()
    keys: Dict[str, _DirectoryKey] = {}
    if not isinstance(body, dict) or not isinstance(body.get("keys"), list):
        return keys
    for jwk in body["keys"][:_MAX_DIRECTORY_KEYS]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" in jwk:
            continue
        x = jwk.get("x")
        if not isinstance(x, str) or len(x) > 128:
            continue
        try:
            raw = _b64url_decode(x)
            if len(raw) != 32:
                continue
            key = Ed25519PublicKey.from_public_bytes(raw)
        except Exception:
            continue
        keys[jwk_thumbprint("OKP", "Ed25519", x)] = _DirectoryKey(key, _seconds(jwk.get("nbf")), _seconds(jwk.get("exp")))
    return keys


def directory_url(agent: str) -> Optional[Tuple[str, str]]:
    """(directory URL, host) for a Signature-Agent, or None when it is not an https URL on a public host
    name: never an IP address or a private name, since the caller chooses it and the receiver fetches it."""
    try:
        u = urllib.parse.urlsplit(agent)
        port = u.port
    except ValueError:
        return None
    host = (u.hostname or "").lower()
    if u.scheme != "https" or u.username or u.password or u.fragment:
        return None
    if port is not None or not host:
        return None
    if "." not in host or host.startswith("[") or ":" in host or re.fullmatch(r"[0-9.]+", host) or _PRIVATE_HOST.match(host):
        return None
    origin = f"https://{host}"
    if u.path in ("", "/") and not u.query:
        return origin + DIRECTORY_PATH, host
    return urllib.parse.urlunsplit(("https", host, u.path, u.query, "")), host


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102 - refuse every redirect
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def directory_transport(method: str, url: str, headers: Dict[str, str], body: Optional[bytes], timeout: float) -> Tuple[int, bytes]:
    """The default directory transport: urllib that never follows a redirect, reading at most 64 KB + 1."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # nosec B310 - https only, checked by directory_url
            return resp.status, resp.read(_MAX_DIRECTORY_BYTES + 1)
    except urllib.error.HTTPError as err:
        return err.code, b""


@dataclass
class _Directory:
    keys: Dict[str, _DirectoryKey] = field(default_factory=dict)
    fetched_at: float = float("-inf")
    last_attempt: float = float("-inf")
    reachable: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


class DirectoryCache:
    """Signers' key directories: cached an hour; an unknown key refetches at most once a minute per
    directory; at most 1000 directories are kept, and at most 30 fetches start in any minute (beyond
    that a directory reads as unreachable, so the call is treated as unsigned)."""

    def __init__(self, http: HttpTransport, clock: Callable[[], float]):
        self._http = http
        self._clock = clock
        self._dirs: "OrderedDict[str, _Directory]" = OrderedDict()
        self._starts: List[float] = []
        self._lock = threading.Lock()

    def _budget(self, now: float) -> bool:
        with self._lock:
            while self._starts and now - self._starts[0] >= _MISS_REFETCH:
                self._starts.pop(0)
            if len(self._starts) >= _FETCHES_PER_MINUTE:
                return False
            self._starts.append(now)
            return True

    def _entry(self, url: str) -> _Directory:
        with self._lock:
            entry = self._dirs.get(url)
            if entry is None:
                if len(self._dirs) >= _MAX_DIRECTORIES:
                    self._dirs.popitem(last=False)
                entry = self._dirs[url] = _Directory()
            return entry

    @staticmethod
    def _answer(entry: _Directory, key_id: str, known: Optional[_DirectoryKey]) -> Union[_DirectoryKey, str, None]:
        got = entry.keys.get(key_id) or known
        if got is not None:
            return got
        return None if entry.reachable else UNREACHABLE

    def get(self, url: str, key_id: str) -> Union[_DirectoryKey, str, None]:
        """The key; None when the directory does not list it; "unreachable" when it has never answered."""
        entry = self._entry(url)
        known = entry.keys.get(key_id)
        if known is not None and self._clock() - entry.fetched_at < _HOUR:
            return known
        with entry.lock:
            now = self._clock()
            # Another thread may have fetched it while this one waited.
            fresh = entry.keys.get(key_id)
            if fresh is not None and now - entry.fetched_at < _HOUR:
                return fresh
            if now - entry.last_attempt < _MISS_REFETCH or not self._budget(now):
                return self._answer(entry, key_id, known)
            entry.last_attempt = now
            body = self._fetch(url)
            if body is not None:
                entry.keys = directory_keys(body)
                entry.reachable = True
                entry.fetched_at = self._clock()
            return self._answer(entry, key_id, known)

    def _fetch(self, url: str) -> Any:
        try:
            status, raw = self._http("GET", url, {"Accept": f"{DIRECTORY_MEDIA_TYPE}, application/json"}, None, FETCH_TIMEOUT)
        except Exception:
            return None
        if status != 200 or not raw or len(raw) > _MAX_DIRECTORY_BYTES:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None


# ---------------------------------------------------------------- the signature base (RFC 9421 section 2.5)


class _Unsupported(Exception):
    pass


def _component_value(req: SignedRequest, c: Item) -> str:
    if not isinstance(c.value, str):
        raise StructuredError("component")
    name = c.value
    if name.startswith("@"):
        if name not in _DERIVED or c.params:
            raise _Unsupported(name)
        if name == "@authority":
            v = req.authority
        elif name == "@method":
            v = req.method
        elif name == "@scheme":
            v = req.scheme
        elif name == "@path":
            v = (req.path or "/") if req.path is not None else None
        elif name == "@query":
            v = "?" + (req.query or "")
        else:  # @target-uri
            v = (
                f"{req.scheme}://{req.authority}{req.path}" + (f"?{req.query}" if req.query is not None else "")
                if req.authority and req.path is not None
                else None
            )
        if v is None:
            raise StructuredError(name)
        return v
    if not _FIELD_NAME.match(name):
        raise StructuredError(name)
    if any(p != "key" for p in c.params):
        raise _Unsupported(name)
    raw = req.header(name)
    if raw is None:
        raise StructuredError(name)
    key = c.params.get("key")
    if key is None:
        return raw
    if not isinstance(key, str):
        raise StructuredError(name)
    member = parse_dictionary(raw).get(key)
    if member is None:
        raise StructuredError(name)
    return serialize_member(member)


def signature_base(req: SignedRequest, lst: InnerList) -> str:
    """The signature base for a label's covered components and parameters."""
    lines = [f"{serialize_member(c)}: {_component_value(req, c)}" for c in lst.items]
    lines.append(f'"@signature-params": {serialize_inner_list(lst)}')
    return "\n".join(lines)


# ---------------------------------------------------------------- verifying


def _covers(lst: InnerList, name: str) -> Optional[Item]:
    return next((c for c in lst.items if c.value == name), None)


def _signature_agent(req: SignedRequest, component: Item) -> Optional[str]:
    raw = req.header("signature-agent")
    if not raw:
        return None
    key = component.params.get("key")
    member: Optional[Member] = parse_dictionary(raw).get(key) if isinstance(key, str) else parse_item_field(raw)
    if not isinstance(member, Item) or not isinstance(member.value, str):
        return None
    # An earlier draft (and Cloudflare's library) marks a key directory with type=directory; no other type is read.
    for k, v in member.params.items():
        if k != "type" or v != Token("directory"):
            return None
    return member.value


def _int(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


class WebBotAuthVerifier:
    def __init__(self, audiences: List[str], directories: DirectoryCache, replay: Any, skew: float, clock: Callable[[], float]):
        self._audiences = audiences
        self._directories = directories
        self._replay = replay
        self._skew = skew
        self._clock = clock

    def _label(self, req: SignedRequest, lst: InnerList, signature: Optional[Member]) -> WebBotAuthResult:
        from shield360.agents._passport import _load_crypto  # pylint: disable=import-outside-toplevel

        _, InvalidSignature = _load_crypto()
        p = lst.params
        created, expires = _int(p.get("created")), _int(p.get("expires"))
        key_id, alg, nonce = p.get("keyid"), p.get("alg"), p.get("nonce")
        if created is None or expires is None or not isinstance(key_id, str) or not _KEY_ID.match(key_id):
            return _invalid("malformed")
        if alg is not None and alg != "ed25519":
            return _invalid("unsupported_alg")
        if nonce is not None and (not isinstance(nonce, str) or not nonce or len(nonce) > 256):
            return _invalid("malformed")
        if not isinstance(signature, Item) or not isinstance(signature.value, bytes):
            return _invalid("malformed")
        if len(lst.items) > _MAX_COMPONENTS or any(not isinstance(c.value, str) for c in lst.items):
            return _invalid("malformed")

        agent_component = _covers(lst, "signature-agent")
        if agent_component is None or (_covers(lst, "@authority") is None and _covers(lst, "@target-uri") is None):
            return _invalid("malformed")
        agent = _signature_agent(req, agent_component)
        if not agent:
            return _invalid("malformed")
        found_dir = directory_url(agent)
        if found_dir is None:
            return _invalid("untrusted_signature_agent")
        url, host = found_dir

        t = self._clock()
        if expires <= created:
            return _invalid("malformed", host)
        if created > t + self._skew:
            return _invalid("not_yet_valid", host)
        if expires <= t - self._skew:
            return _invalid("expired", host)
        if expires - created > MAX_SIGNATURE_SECONDS:
            return _invalid("lifetime_too_long", host)

        # The signature must be for this receiver: a signature for another site is not replayable here.
        if not req.authority or not audience_matches(f"https://{req.authority}", self._audiences):
            return _invalid("wrong_audience", host)

        try:
            base = signature_base(req, lst)
        except _Unsupported:
            return _invalid("unsupported_component", host)
        except Exception:
            return _invalid("malformed", host)

        found = self._directories.get(url, key_id)
        if found == UNREACHABLE:
            return _invalid("directory_unreachable", host)
        if not isinstance(found, _DirectoryKey) or not found.valid_at(t, self._skew):
            return _invalid("unknown_key", host)
        try:
            found.key.verify(signature.value, base.encode("utf-8"))
        except InvalidSignature:
            return _invalid("bad_signature", host)
        except Exception:
            return _invalid("bad_signature", host)

        # Each signature is accepted once: by its nonce when it has one, otherwise by the signature itself.
        marker = f"n:{nonce}" if isinstance(nonce, str) else "s:" + base64.urlsafe_b64encode(signature.value).rstrip(b"=").decode()
        try:
            if self._replay.seen(f"wba:{key_id}:{marker}", float(expires) + self._skew):
                return _invalid("replayed", host)
        except Exception:
            return _invalid("replay_check_failed", host)
        return WebBotAuthResult("verified", host=host, signer=Signer(agent=agent, host=host, key_id=key_id, expires=expires))

    def verify(self, req: SignedRequest) -> WebBotAuthResult:
        """'absent' when the request carries no Signature-Input member tagged web-bot-auth; otherwise the
        first label that verifies, or the first label's failure. Never raises."""
        raw = req.header("signature-input")
        if not raw:
            return _ABSENT
        claimed = WEB_BOT_AUTH_TAG in raw
        if len(raw) > _MAX_HEADER_CHARS:
            return _invalid("malformed") if claimed else _ABSENT
        try:
            inputs = parse_dictionary(raw)
        except StructuredError:
            return _invalid("malformed") if claimed else _ABSENT
        labels = [(k, m) for k, m in inputs.items() if isinstance(m, InnerList) and m.params.get("tag") == WEB_BOT_AUTH_TAG]
        if not labels:
            return _ABSENT
        sig_raw = req.header("signature")
        signatures: Dict[str, Member] = {}
        try:
            if sig_raw and len(sig_raw) <= _MAX_HEADER_CHARS:
                signatures = parse_dictionary(sig_raw)
        except StructuredError:
            return _invalid("malformed")
        first: Optional[WebBotAuthResult] = None
        for label, lst in labels[:_MAX_LABELS]:
            try:
                result = self._label(req, lst, signatures.get(label))
            except Exception:
                result = _invalid("malformed")
            if result.status == "verified":
                return result
            first = first or result
        return first or _ABSENT
