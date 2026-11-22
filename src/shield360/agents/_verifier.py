"""
The agent passport verifier: reads the Shield360-Agent header, verifies the
passport offline (optionally online too), applies the receiver's policy and
reports the result. A passport proves who the agent is, who runs it and for whom
it acts; it never grants access by itself.

Verification order and reason codes are the contract in the agent passports
spec, shared with the TypeScript verifier and the issuer's verify route.

Must stay in sync with: sdk/typescript/src/agents/verifier.ts
"""

from __future__ import annotations

import atexit
import logging
import math
import os
import queue
import re
import threading
import time
import urllib.parse
from collections import OrderedDict
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from shield360.agents._passport import (
    HttpTransport,
    KeyCache,
    ParsedPassport,
    audience_matches,
    fetch_json,
    normalise_issuer,
    parse_passport,
    require_crypto,
    scopes_of,
    urllib_transport,
    verify_signature,
)
from shield360.agents._types import (
    AGENT_HEADER,
    DEFAULT_BASE_URL,
    DEFAULT_ISSUERS,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_LIFETIME_SECONDS,
    AgentCheck,
    AgentIdentity,
    AgentMandate,
    AgentOnBehalfOf,
    AgentOwner,
    AgentOperator,
    AgentPolicy,
    ReplayStore,
    SignatureInfo,
    assurance_of,
    assurance_rank,
)

from shield360.agents._web_bot_auth import DirectoryCache, WebBotAuthVerifier, directory_transport, signed_request

logger = logging.getLogger(__name__)

_HEADER_LC = AGENT_HEADER.lower()
_ENVIRON_KEY = "HTTP_" + AGENT_HEADER.upper().replace("-", "_")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_POLICY_CACHE = 60.0
REPORT_BATCH = 100
_FLUSH_SECONDS = 3.0
_MAX_QUEUED = 5000
_ATTEMPTS = 3


# ---------------------------------------------------------------- input


def _from_values(values: List[Any]) -> Tuple[Optional[str], bool]:
    found = []
    for v in values:
        if isinstance(v, bytes):
            v = v.decode("latin-1")
        if isinstance(v, (list, tuple)):
            found.extend(x for x in v if isinstance(x, str) and x.strip())
        elif isinstance(v, str) and v.strip():
            found.append(v)
    if len(found) > 1:
        return None, True
    return (found[0].strip() if found else None), False


def read_passport(source: Any) -> Tuple[Optional[str], bool]:
    """Finds the passport in a token, header mapping, WSGI environ, ASGI header list or request object.

    Returns (token, multiple): multiple is True when more than one passport was sent.
    """
    try:
        if source is None:
            return None, False
        if isinstance(source, (str, bytes)):
            return _from_values([source])
        # Request objects (Starlette's is itself a Mapping over the ASGI scope) carry .headers.
        if not isinstance(source, (dict, list, tuple)) and hasattr(source, "headers"):
            return read_passport(source.headers)
        if isinstance(source, Mapping):
            if _ENVIRON_KEY in source:
                return _from_values([source[_ENVIRON_KEY]])
            getlist = getattr(source, "getlist", None) or getattr(source, "get_all", None)
            if callable(getlist):
                try:
                    vals = getlist(AGENT_HEADER)
                    if vals:
                        return _from_values(list(vals))
                except Exception:
                    pass
            return _from_values([v for k, v in source.items() if isinstance(k, (str, bytes)) and _lower(k) == _HEADER_LC])
        if isinstance(source, (list, tuple)):
            vals = [pair[1] for pair in source if isinstance(pair, (list, tuple)) and len(pair) == 2 and _lower(pair[0]) == _HEADER_LC]
            return _from_values(vals)
    except Exception:
        return None, False
    return None, False


def _short_text(v: Any, max_len: int) -> bool:
    return isinstance(v, str) and 0 < len(v) <= max_len


def _lower(k: Any) -> str:
    if isinstance(k, bytes):
        return k.decode("latin-1").lower()
    return k.lower() if isinstance(k, str) else ""


# ---------------------------------------------------------------- replay


class MemoryReplayStore:
    """The default replay store: passport ids in memory until they expire, with a size cap. One per process."""

    def __init__(self, max_entries: int = 100_000, clock=time.time):
        self._max = max(1, max_entries)
        self._clock = clock
        self._entries: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def seen(self, jti: str, expires_at: float) -> bool:
        with self._lock:
            now = self._clock()
            until = self._entries.get(jti)
            if until is not None and until > now:
                return True
            self._entries.pop(jti, None)
            if len(self._entries) >= self._max:
                self._evict(now)
            self._entries[jti] = expires_at
            return False

    def __len__(self) -> int:
        return len(self._entries)

    def _evict(self, now: float) -> None:
        for k in [k for k, until in self._entries.items() if until <= now]:
            del self._entries[k]
        while len(self._entries) >= self._max:
            self._entries.popitem(last=False)


# ---------------------------------------------------------------- policy


def _base_url(conn: Mapping[str, Any]) -> str:
    return str(conn.get("base_url") or conn.get("baseUrl") or os.environ.get("SHIELD360_URL") or DEFAULT_BASE_URL).rstrip("/")


def _api_key(conn: Optional[Mapping[str, Any]]) -> Optional[str]:
    if not conn:
        return None
    key = conn.get("api_key") or conn.get("apiKey")
    return key if isinstance(key, str) and key else None


class _PolicySource:
    """Defaults < console policy (cached 60 s) < local policy. A failed fetch keeps the last good console policy."""

    def __init__(self, local: Any, source: Optional[Mapping[str, Any]], http: HttpTransport, clock):
        self._local = AgentPolicy.sanitise(local)
        self._source = source if _api_key(source) else None
        self._http = http
        self._clock = clock
        self._remote: Optional[Dict[str, Any]] = None
        self._fetched_at = -math.inf
        self._lock = threading.Lock()
        self._refreshing: Optional[threading.Thread] = None

    def current(self) -> AgentPolicy:
        if self._source is not None and self._clock() - self._fetched_at >= _POLICY_CACHE:
            if self._remote is None:
                with self._lock:
                    if self._remote is None and self._clock() - self._fetched_at >= _POLICY_CACHE:
                        self._refresh()
            else:
                self._refresh_in_background()
        fields = {**(self._remote or {}), **self._local}
        return replace(AgentPolicy(), **fields)

    def _refresh_in_background(self) -> None:
        with self._lock:
            if self._refreshing is not None and self._refreshing.is_alive():
                return
            self._refreshing = threading.Thread(target=self._refresh, name="shield360-agents-policy", daemon=True)
            self._refreshing.start()

    def wait(self, timeout: float = 5.0) -> None:
        t = self._refreshing
        if t is not None:
            t.join(timeout)

    def _refresh(self) -> None:
        src = self._source or {}
        url = f"{_base_url(src)}/api/inbound-agents/policy"
        got = fetch_json(self._http, "GET", url, {"Authorization": f"Bearer {_api_key(src)}"})
        self._fetched_at = self._clock()
        if not got or got[0] != 200 or not isinstance(got[1], dict):
            logger.warning(
                "Shield360 agents: could not load the inbound agents policy%s; using the last known policy",
                f" (HTTP {got[0]})" if got else "",
            )
            return
        body = got[1]
        self._remote = AgentPolicy.sanitise(body["policy"] if isinstance(body.get("policy"), dict) else body)


# ---------------------------------------------------------------- reports


class _Reporter:
    """Batches results to POST /api/inbound-agents/decisions on a background thread. Never the passport."""

    def __init__(self, conn: Mapping[str, Any], http: HttpTransport, retry_delay: float = 0.5):
        self._endpoint = f"{_base_url(conn)}/api/inbound-agents/decisions"
        self._api_key = _api_key(conn)
        self._http = http
        self._retry_delay = retry_delay
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=_MAX_QUEUED)
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._send_lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="shield360-agents-report", daemon=True)
        self._thread.start()
        atexit.register(self.close)

    def add(self, decision: Dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(decision)
        except queue.Full:
            logger.warning("Shield360 agents: the decision report queue is full; a report was dropped")
            return
        if self._queue.qsize() >= REPORT_BATCH:
            self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(_FLUSH_SECONDS)
            self._wake.clear()
            self.flush()

    def flush(self) -> None:
        with self._send_lock:
            while True:
                batch: List[Dict[str, Any]] = []
                while len(batch) < REPORT_BATCH:
                    try:
                        batch.append(self._queue.get_nowait())
                    except queue.Empty:
                        break
                if not batch:
                    return
                self._post(batch)

    def _post(self, batch: List[Dict[str, Any]]) -> None:
        for attempt in range(_ATTEMPTS):
            got = fetch_json(self._http, "POST", self._endpoint, {"Authorization": f"Bearer {self._api_key}"}, {"decisions": batch})
            if got is not None:
                status = got[0]
                if 200 <= status < 300:
                    return
                if status in (400, 401, 403, 404, 413):
                    logger.warning("Shield360 agents: the inbound decision log refused %d report(s): HTTP %d", len(batch), status)
                    return
            if attempt < _ATTEMPTS - 1:
                time.sleep(self._retry_delay * (attempt + 1))
        logger.warning("Shield360 agents: could not deliver %d decision report(s); dropped", len(batch))

    def close(self) -> None:
        self._stop.set()
        self._wake.set()
        try:
            self.flush()
        except Exception:
            pass


# ---------------------------------------------------------------- verifier


class AgentVerifier:
    """Verifies agent passports for one receiver.

    Args:
        audience: the receiver: a host name (``api.example.com``) or an https origin, or several.
        issuers: trusted issuers' base URLs; default ``["https://app.shield360.ai"]``.
        policy: local policy (dict with snake_case or camelCase keys, or AgentPolicy), merged over the
            defaults and over the console policy.
        policy_from: ``{"api_key": ..., "base_url"?: ...}``: follow the console policy (cached 60 s).
        report: ``{"api_key": ..., "base_url"?: ...}``: send results to the inbound decision log
            (batched on a background thread, never blocks the call).
        replay: where passport ids are remembered; default in memory, per process.
        clock_skew_seconds: allowed clock difference with the issuer; default 60, at most 300.
        online_failure: what an unreachable issuer on an online check means: "allow" (default) or "deny".
        web_bot_auth: check Web Bot Auth signatures (RFC 9421, as Cloudflare's signed agents send them)
            on calls without a passport; default True. The signer's key directory is fetched from the
            https URL its Signature-Agent header names (public host names only, no redirects, cached an hour).
        http: transport ``(method, url, headers, body, timeout) -> (status, body)``; default urllib.
        clock: seconds since the epoch; for tests.
    """

    def __init__(
        self,
        audience: Union[str, Sequence[str]],
        issuers: Optional[Iterable[str]] = None,
        policy: Any = None,
        policy_from: Optional[Mapping[str, Any]] = None,
        report: Optional[Mapping[str, Any]] = None,
        replay: Optional[ReplayStore] = None,
        clock_skew_seconds: float = 60,
        online_failure: str = "allow",
        http: Optional[HttpTransport] = None,
        clock=None,
        web_bot_auth: bool = True,
    ):
        require_crypto()
        auds = [audience] if isinstance(audience, str) else list(audience or [])
        self._audiences = [a for a in auds if isinstance(a, str) and a.strip()]
        if not self._audiences:
            raise ValueError("AgentVerifier: an audience (the receiver host or origin) is required")
        self._issuers = {normalise_issuer(i) for i in (list(issuers) if issuers else list(DEFAULT_ISSUERS))}
        # Bounded: a skew of hours would stretch every passport's five-minute life and the replay window with it.
        try:
            asked = float(clock_skew_seconds)
        except (TypeError, ValueError):
            asked = 60.0
        self._skew = min(float(MAX_CLOCK_SKEW_SECONDS), max(0.0, asked)) if math.isfinite(asked) else 60.0
        self._clock = clock or time.time
        self._http = http or urllib_transport
        self._keys = KeyCache(self._http, self._clock)
        self._replay: ReplayStore = replay if replay is not None else MemoryReplayStore(clock=self._clock)
        # Anyone can mint Web Bot Auth signatures (any host with a key directory): in the default in-memory
        # store they get their own, so a flood of them never pushes out (and re-opens) remembered passport ids.
        self._signature_replay: ReplayStore = replay if replay is not None else MemoryReplayStore(clock=self._clock)
        self._policies = _PolicySource(policy, policy_from, self._http, self._clock)
        self._reporter = _Reporter(report, self._http) if _api_key(report) else None
        self._online_failure = online_failure
        # A transport given for tests is used for directories too; the default one never follows a redirect.
        self._web_bot_auth = (
            WebBotAuthVerifier(
                self._audiences,
                DirectoryCache(http or directory_transport, self._clock),
                self._signature_replay,
                self._skew,
                self._clock,
            )
            if web_bot_auth
            else None
        )

    # -- public

    def policy(self) -> AgentPolicy:
        """The policy in force now (defaults, console, local)."""
        return self._policies.current()

    def check(
        self,
        headers_or_token: Any = None,
        online: bool = False,
        route: Optional[str] = None,
        method: Optional[str] = None,
        *,
        query: Any = None,
        scheme: Optional[str] = None,
    ) -> AgentCheck:
        """Checks the passport, or the Web Bot Auth signature, a request carries. Never raises.

        ``query`` and ``scheme`` matter only for a signature that covers them when ``headers_or_token``
        is bare headers; a WSGI environ or a request object carries them itself.
        """
        try:
            result = self._evaluate(headers_or_token, online, route, method, query, scheme)
        except Exception:
            # Unreachable by design; a verifier bug must still deny, never raise.
            try:
                enforce = self._policies.current().mode == "enforce"
            except Exception:
                enforce = False
            result = AgentCheck(status="invalid", decision="deny", blocked=enforce, reason="malformed")
        self._report(result, route, method)
        return result

    def flush(self) -> None:
        """Sends queued reports now."""
        if self._reporter is not None:
            self._reporter.flush()

    def close(self) -> None:
        """Stops the reporter and sends what is queued."""
        if self._reporter is not None:
            self._reporter.close()

    def asgi(self, app):
        """Wraps an ASGI app (see AgentVerifierASGIMiddleware)."""
        from shield360.agents._middleware import AgentVerifierASGIMiddleware

        return AgentVerifierASGIMiddleware(app, self)

    def wsgi(self, app):
        """Wraps a WSGI app (see AgentVerifierWSGIMiddleware)."""
        from shield360.agents._middleware import AgentVerifierWSGIMiddleware

        return AgentVerifierWSGIMiddleware(app, self)

    # -- steps

    def _online(self, p: ParsedPassport, token: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """(reachable, invalid reason, lowered assurance, note): invalid reason None means still valid."""
        got = fetch_json(
            self._http,
            "POST",
            f"{normalise_issuer(p.claims['iss'])}/api/agent-passports/verify",
            {},
            {"passport": token, "audience": p.claims["aud"]},
        )
        if not got or got[0] != 200 or not isinstance(got[1], dict) or not isinstance(got[1].get("valid"), bool):
            return False, None, None, None
        reason = got[1].get("reason")
        reason = reason if isinstance(reason, str) and _REASON.match(reason) else None
        if not got[1]["valid"]:
            return True, reason or "revoked", None, None
        # Still valid, but the issuer may lower the on-behalf-of assurance (e.g. reason "mandate_revoked").
        lowered = got[1].get("assurance")
        return True, None, (assurance_of(lowered) if lowered is not None else None), reason

    def _verify(
        self, token: str, want_online: bool
    ) -> Tuple[Optional[ParsedPassport], Optional[str], Optional[ParsedPassport], Optional[str], Optional[str]]:
        """Steps 1-7. Returns (ok_passport, note, failed_passport, reason, lowered assurance)."""
        p, reason = parse_passport(token)
        if p is None:
            return None, None, None, reason, None
        c = p.claims
        iss = normalise_issuer(c["iss"])
        if iss not in self._issuers:
            return None, None, None, "untrusted_issuer", None
        key = self._keys.get(iss, p.kid)
        if key is None:
            return None, None, None, "unknown_key", None
        if not verify_signature(p, key):
            return None, None, None, "bad_signature", None
        now = self._clock()
        if not c["exp"] > now - self._skew:
            return None, None, p, "expired", None
        if not c["iat"] <= now + self._skew:
            return None, None, p, "not_yet_valid", None
        if c["exp"] - c["iat"] > MAX_LIFETIME_SECONDS:
            return None, None, p, "lifetime_too_long", None
        if not audience_matches(c["aud"], self._audiences):
            return None, None, p, "wrong_audience", None
        try:
            if self._replay.seen(c["jti"], float(c["exp"]) + self._skew):
                return None, None, p, "replayed", None
        except Exception:
            return None, None, p, "replay_check_failed", None
        if want_online:
            reachable, why, lowered, note = self._online(p, token)
            if not reachable:
                if self._online_failure == "deny":
                    return None, None, p, "issuer_unreachable", None
                return p, "issuer_unreachable", None, None, None
            if why:
                return None, None, p, why, None
            return p, note, None, None, lowered
        return p, None, None, None, None

    @staticmethod
    def _on_behalf_of(act: Any, lowered: Optional[str]) -> Optional[AgentOnBehalfOf]:
        if not isinstance(act, dict):
            return None
        claimed = assurance_of(act.get("assurance"))
        # The issuer can only lower the assurance online, never raise it.
        downgraded = lowered is not None and assurance_rank(lowered) < assurance_rank(claimed)
        m = act.get("mandate")
        mandate = None
        if not downgraded and isinstance(m, dict) and _short_text(m.get("id"), 256) and _short_text(m.get("expiresAt"), 64):
            mandate = AgentMandate(id=m["id"], expires_at=m["expiresAt"])
        return AgentOnBehalfOf(
            id=act["sub"], domain=act.get("domain") or None, assurance=lowered if downgraded else claimed, mandate=mandate
        )

    @staticmethod
    def _agent(a: Dict[str, Any]) -> AgentIdentity:
        def opt(key: str) -> Optional[str]:
            v = a.get(key)
            return v if _short_text(v, 128) else None

        owner = a.get("owner")
        return AgentIdentity(
            id=a["id"],
            name=a["name"],
            purpose=a.get("purpose") or None,
            status=a.get("status") if a.get("status") in ("enrolled", "not_enrolled") else None,
            environment=opt("environment"),
            risk=opt("risk"),
            owner=AgentOwner(domain=owner.get("domain") if _short_text(owner.get("domain"), 256) else None)
            if isinstance(owner, dict)
            else None,
            reviewed_at=opt("reviewedAt"),
            enrolled_at=opt("enrolledAt"),
        )

    @staticmethod
    def _identity(p: Optional[ParsedPassport], lowered: Optional[str] = None) -> Dict[str, Any]:
        if p is None:
            return {}
        c = p.claims
        a, o, act = c["agent"], c["operator"], c.get("act")
        try:
            expires = datetime.fromtimestamp(c["exp"], tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            expires = None
        return {
            "agent": AgentVerifier._agent(a),
            "operator": AgentOperator(id=o["id"], name=o["name"], domain=o.get("domain") or None),
            "on_behalf_of": AgentVerifier._on_behalf_of(act, lowered),
            "scopes": scopes_of(c.get("scope")),
            "issuer": normalise_issuer(c["iss"]),
            "passport_id": c["jti"],
            "expires_at": expires,
        }

    @staticmethod
    def _operator_allowed(policy: AgentPolicy, operator: Dict[str, Any]) -> bool:
        if not policy.operators:
            return True
        op_id = operator["id"].lower()
        domain = (operator.get("domain") or "").lower()
        return any(o.lower() == op_id or (domain and o.lower() == domain) for o in policy.operators)

    def _denial(self, policy: AgentPolicy, operator: Dict[str, Any], acts_for_person: bool, assurance: Optional[str]) -> Optional[str]:
        """The receiver policy's verdict on a verified caller: the reason it is denied, if it is."""
        if not self._operator_allowed(policy, operator):
            return "operator_not_allowed"
        if policy.require_on_behalf_of and not acts_for_person:
            return "on_behalf_of_required"
        need = assurance_rank(policy.min_assurance)
        if need and assurance_rank(assurance) < need:
            return "assurance_too_low"
        return None

    def _evaluate_signed(self, source: Any, policy: AgentPolicy, finish, absent, route, method, query, scheme) -> AgentCheck:
        """A call without a passport, checked for a Web Bot Auth signature. The signer's host stands for
        both the agent and its operator, so the operators list allows or denies signers too. A signature
        names no person, so a policy that wants one denies it. A signer whose key directory cannot be
        reached is treated as no signature: its outage never denies a call allowed without one."""
        assert self._web_bot_auth is not None
        r = self._web_bot_auth.verify(signed_request(source, route, method, query, scheme))
        if r.status == "absent":
            return absent("absent")
        if r.status == "invalid":
            if r.reason == "directory_unreachable":
                return absent("directory_unreachable")
            who = {"operator": AgentOperator(id=r.host, name=r.host, domain=r.host)} if r.host else {}
            return finish(status="invalid", decision="deny", reason=r.reason, via="web-bot-auth", **who)
        s = r.signer
        assert s is not None
        parts = urllib.parse.urlsplit(s.agent)
        expires = datetime.fromtimestamp(s.expires, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        base = {
            "status": "verified",
            "via": "web-bot-auth",
            "agent": AgentIdentity(id=s.host, name=s.host),
            "operator": AgentOperator(id=s.host, name=s.host, domain=s.host),
            "issuer": f"{parts.scheme}://{parts.netloc}",
            "signature": SignatureInfo(agent=s.agent, key_id=s.key_id),
            "expires_at": expires,
        }
        denied = self._denial(policy, {"id": s.host, "domain": s.host}, False, None)
        return finish(decision="deny" if denied else "allow", reason=denied, **base)

    def _evaluate(self, source: Any, online: bool, route=None, method=None, query=None, scheme=None) -> AgentCheck:
        policy = self._policies.current()

        def finish(**kw) -> AgentCheck:
            kw.setdefault("scopes", [])
            return AgentCheck(blocked=kw["decision"] == "deny" and policy.mode == "enforce", **kw)

        def absent(reason: str) -> AgentCheck:
            return finish(status="absent", decision="deny" if policy.require_agent else "allow", reason=reason)

        token, multiple = read_passport(source)
        if multiple:
            return finish(status="invalid", decision="deny", reason="malformed", via="passport")
        if not token:
            if self._web_bot_auth is not None and source is not None and not isinstance(source, (str, bytes)):
                return self._evaluate_signed(source, policy, finish, absent, route, method, query, scheme)
            return absent("absent")

        ok, note, failed, reason, lowered = self._verify(token, bool(online or policy.online))
        if ok is None:
            return finish(status="invalid", decision="deny", reason=reason, via="passport", **self._identity(failed))
        ident = self._identity(ok, lowered)
        obo = ident.get("on_behalf_of")
        denied = self._denial(policy, ok.claims["operator"], isinstance(ok.claims.get("act"), dict), obo.assurance if obo else None)
        if denied:
            return finish(status="verified", decision="deny", reason=denied, via="passport", **ident)
        return finish(status="verified", decision="allow", reason=note, via="passport", **ident)

    def _report(self, result: AgentCheck, route: Optional[str], method: Optional[str]) -> None:
        if self._reporter is None:
            return
        # Calls without a passport are only worth a log line when the policy denied them.
        if result.status == "absent" and result.decision == "allow":
            return
        try:
            entry = result.to_dict()
            at = datetime.fromtimestamp(self._clock(), tz=timezone.utc)
            entry["at"] = at.isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if route:
                entry["route"] = str(route).split("?", 1)[0][:512]
            if method:
                entry["method"] = str(method)[:16].upper()
            entry["receiver"] = self._audiences[0]
            self._reporter.add(entry)
        except Exception:
            pass
