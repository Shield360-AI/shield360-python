"""
shield360.defend: decide in the app whether a request may go on.

    from shield360.defend import create_defend

    shield = create_defend(app="checkout", url=URL, api_key=KEY)   # SHIELD360_CONFIG_PUBLIC_KEY pins the policy key
    app.wsgi_app = shield.wsgi(app.wsgi_app)                         # Flask / any WSGI app
    app.add_middleware(shield.asgi_middleware())                     # FastAPI / Starlette (ASGI)
    result = shield.defend(request)                                  # by hand: a dict, environ, scope or request

The decision is local, from a signed policy fetched and cached the way the RASP
config is (same key pinning, same refresh), with a decisions feed checked every
5 seconds so a block made anywhere reaches this process quickly. No network
call on the request path unless ``shared_rate_limits`` is on. Fail open by
default. The same contract as the TypeScript SDK: docs/latest/shield360/defend.mdx.
"""

import json
import os
import re
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Mapping, Optional

from shield360.defend._engine import (
    CLIENT_TYPES,
    DECISIONS,
    DEFEND_JWS_TYPE,
    DEFEND_POLICY_PATH,
    RateTable,
    check_content,
    decide,
    fail_result,
    parse_defend_policy,
    path_under,
    rate_rules_for,
)
from shield360.client_type import BreadthCounter, classify_client
from shield360.rasp._config_client import RaspConfigClient, parse_public_keys
from shield360.rasp._edge_context import CONTEXT_HEADER, REQUEST_ID_HEADER, parse_edge_keys, verify_edge_context
from shield360.rasp._deception import SuspiciousTable
from shield360.rasp._rule_expr import parse_ip_bytes

__all__ = [
    "create_defend",
    "Defend",
    "decide",
    "parse_defend_policy",
    "facts_of",
    "path_of",
    "RateTable",
    "CLIENT_TYPES",
    "DECISIONS",
    "DEFEND_JWS_TYPE",
    "DEFEND_POLICY_PATH",
    "DEFEND_DECISIONS_PATH",
    "DEFEND_REPORT_PATH",
    "path_under",
]

DEFEND_DECISIONS_PATH = "/api/defend/decisions"
DEFEND_DECIDE_PATH = "/api/defend/decide"
DEFEND_REPORT_PATH = "/api/defend/report"
DECISIONS_EVERY_S = 5.0
BLOCK_BODY = b'{"error":"Forbidden"}'
MAX_CONTENT_ITEMS = 16
MAX_CONTENT_ITEM = 8192
_PRODUCTION = re.compile(r"^prod(uction)?$", re.I)
_CODE = re.compile(r"^[a-z0-9_.-]{1,48}$")
_REPORT_PER_MINUTE = 300
_FOLD_S = 10.0


def _sdk_version() -> str:
    try:
        from importlib.metadata import version  # pylint: disable=import-outside-toplevel

        return version("shield360")[:32]
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


def env_mode(env: Mapping[str, str]) -> Optional[str]:
    """SHIELD360_DEFEND: off, monitor or enforce; anything else: the option decides."""
    v = (env.get("SHIELD360_DEFEND") or "").strip().lower()
    return v if v in ("off", "monitor", "enforce") else None


def _tofu_allowed(option: Optional[bool], env: Mapping[str, str]) -> bool:
    asked = option is True or (env.get("SHIELD360_CONFIG_TOFU") or "").strip().lower() == "dev"
    return asked and not any(_PRODUCTION.match((env.get(k) or "").strip()) for k in ("NODE_ENV", "ENVIRONMENT"))


def path_of(target: str) -> str:
    """The path before any ``?``, percent-decoded once."""
    p = target or "/"
    if re.match(r"^[a-z][a-z0-9+.-]*://", p, re.I):
        p = urllib.parse.urlsplit(p).path or "/"
    p = re.split(r"[?#]", p, maxsplit=1)[0]
    if not p.startswith("/"):
        p = "/" + p
    try:
        return urllib.parse.unquote(p, errors="strict")
    except Exception:  # pylint: disable=broad-exception-caught
        return p


def _usable_ip(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = v.strip()
    if s.startswith("[") and "]" in s:
        s = s[1 : s.index("]")]
    if s.startswith("::ffff:") and "." in s:
        s = s[7:]
    return s if parse_ip_bytes(s) else None


def _forwarded_ip(header: Optional[str], hops: int) -> Optional[str]:
    if not header or hops < 1:
        return None
    parts = [p.strip() for p in header.split(",") if p.strip()]
    return _usable_ip(parts[-hops]) if len(parts) >= hops else None


def facts_of(
    req: Any,
    ip: Optional[str] = None,
    country: Optional[str] = None,
    asn: Any = None,
    content: Any = None,
    trust_proxy: int = 0,
    geo_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """The facts of a WSGI environ, an ASGI scope, a framework request or a plain dict
    ({"method", "path"/"url", "headers", "ip"}). Never raises."""
    headers: Dict[str, str] = {}
    method, target, own_ip = "GET", "/", None
    try:
        if isinstance(req, dict) and "REQUEST_METHOD" in req:  # WSGI environ
            method = req.get("REQUEST_METHOD") or "GET"
            target = (req.get("PATH_INFO") or "/") if not req.get("RAW_URI") else req["RAW_URI"]
            for k, v in req.items():
                if k.startswith("HTTP_") and isinstance(v, str):
                    headers[k[5:].replace("_", "-").lower()] = v[:4096]
            own_ip = req.get("REMOTE_ADDR")
        elif isinstance(req, dict) and req.get("type") in ("http", "websocket"):  # ASGI scope
            method = req.get("method") or "GET"
            raw = req.get("raw_path")
            target = raw.decode("latin-1") if isinstance(raw, (bytes, bytearray)) else (req.get("path") or "/")
            for k, v in req.get("headers") or []:
                headers[k.decode("latin-1").lower()] = v.decode("latin-1")[:4096]
            client = req.get("client")
            own_ip = client[0] if client else None
        elif isinstance(req, dict):
            method = req.get("method") or "GET"
            target = req.get("path") or req.get("url") or "/"
            headers = {str(k).lower(): str(v)[:4096] for k, v in (req.get("headers") or {}).items()}
            own_ip = req.get("ip")
        else:  # Starlette / Django / Flask request objects
            method = getattr(req, "method", "GET") or "GET"
            url = getattr(req, "url", None)
            target = getattr(url, "path", None) or getattr(req, "path", None) or (url if isinstance(url, str) else "/")
            h = getattr(req, "headers", None) or {}
            headers = {str(k).lower(): str(v)[:4096] for k, v in dict(h).items()}
            client = getattr(req, "client", None)
            own_ip = (
                getattr(client, "host", None)
                or getattr(req, "remote_addr", None)
                or (getattr(req, "META", {}) or {}).get("REMOTE_ADDR")
            )
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    raw = (
        re.split(
            r"[?#]",
            urllib.parse.urlsplit(str(target)).path if re.match(r"^[a-z][a-z0-9+.-]*://", str(target), re.I) else str(target),
            maxsplit=1,
        )[0]
        or "/"
    )
    facts: Dict[str, Any] = {"method": str(method).upper()[:16], "path": path_of(str(target)), "rawPath": raw, "headers": headers}
    address = _usable_ip(ip) or _forwarded_ip(headers.get("x-forwarded-for"), trust_proxy) or _usable_ip(own_ip)
    if address:
        facts["ip"] = address
    g = geo_headers or {}
    c = country if country is not None else (headers.get(g["country"].lower()) if g.get("country") else None)
    if isinstance(c, str) and re.match(r"^[A-Za-z]{2}$", c.strip()):
        facts["country"] = c.strip().upper()
    a = asn if asn is not None else (headers.get(g["asn"].lower()) if g.get("asn") else None)
    try:
        n = int(str(a).upper().removeprefix("AS")) if a is not None else None
        if n is not None and 0 < n <= 4294967295:
            facts["asn"] = n
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    items = content if isinstance(content, list) else ([content] if content is not None else [])
    kept = [c[:MAX_CONTENT_ITEM] for c in items if isinstance(c, str) and c][:MAX_CONTENT_ITEMS]
    if kept:
        facts["content"] = kept
    return facts


def _post(url: str, api_key: str, body: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310: the configured Shield360 URL
        raw = resp.read(65536)
        return json.loads(raw.decode()) if raw else {}


class _Reporter:
    """Batches events to POST /api/defend/report every 5 s; at most 300 a minute, repeats folded."""

    def __init__(self, url: str, api_key: str, app: str, post: Callable[..., Any], clock: Callable[[], float]):
        self._url = url.rstrip("/") + DEFEND_REPORT_PATH
        self._key, self._app, self._post, self._clock = api_key, app, post, clock
        self._queue: List[Dict[str, Any]] = []
        self._folds: Dict[str, Any] = {}
        self._window = (0.0, 0)
        self._lock = threading.Lock()
        self.dropped = 0

    def add(self, e: Dict[str, Any]) -> None:
        try:
            now = self._clock()
            key = "|".join(
                [
                    e["kind"],
                    e.get("decision", ""),
                    str(e.get("monitored", False)),
                    e.get("ip", ""),
                    e.get("path", ""),
                    e.get("method", ""),
                    ",".join(e["reasons"]),
                    ",".join(e["ruleIds"]),
                ]
            )
            with self._lock:
                fold = self._folds.get(key)
                if fold and fold[1] > now:
                    fold[0]["count"] += 1
                    return
                start, sent = self._window
                if now - start >= 60:
                    start, sent = now, 0
                if sent >= _REPORT_PER_MINUTE or len(self._queue) >= 1000:
                    self.dropped += 1
                    return
                self._window = (start, sent + 1)
                ev = {
                    **e,
                    "reasons": e["reasons"][:16],
                    "ruleIds": e["ruleIds"][:16],
                    "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                    "count": 1,
                }
                self._queue.append(ev)
                if len(self._folds) > 5000:
                    self._folds.clear()
                self._folds[key] = (ev, now + _FOLD_S)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def flush(self) -> None:
        while True:
            with self._lock:
                batch, self._queue = self._queue[:100], self._queue[100:]
            if not batch:
                return
            try:
                self._post(
                    self._url, self._key, {"app": self._app, "sdk": "python", "sdkVersion": _sdk_version(), "events": batch}, 10.0
                )
            except Exception:  # pylint: disable=broad-exception-caught
                self.dropped += len(batch)


class Defend:  # pylint: disable=too-many-instance-attributes
    """A Defend instance for one app. Use ``create_defend``."""

    def __init__(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        app: str,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        config_public_key: Any = None,
        allow_unpinned_config: bool = False,
        mode: str = "enforce",
        fail_mode: str = "open",
        trust_proxy: int = 0,
        geo_headers: Optional[Dict[str, str]] = None,
        agents: Any = None,
        classify: Any = None,
        sensitive_data: str = "monitor",
        report: bool = True,
        shared_rate_limits: bool = False,
        cache_dir: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
        fetch: Any = None,
        post: Optional[Callable[..., Any]] = None,
        clock: Optional[Callable[[], float]] = None,
        background: bool = True,
    ):
        if not isinstance(app, str) or not app.strip():
            raise ValueError("create_defend: app (the app name in Shield360) is required")
        self.app = app.strip()
        self._env = env if env is not None else os.environ
        self._clock = clock or time.time
        self._mode = mode if mode in ("enforce", "monitor") else "enforce"
        self._fail = "closed" if fail_mode == "closed" else "open"
        self._facts_opts = {"trust_proxy": trust_proxy, "geo_headers": geo_headers}
        self._agents, self._classify, self._sensitive = agents, classify, sensitive_data
        self._shared = shared_rate_limits
        self._url, self._key = url, api_key
        self._post = post or _post
        self._rates = RateTable()
        self._breadth = BreadthCounter()
        self._marks = SuspiciousTable(10_000, clock=self._clock)
        self._policy: Optional[Dict[str, Any]] = None
        self._stop = threading.Event()
        self._client: Optional[RaspConfigClient] = None
        remote = bool(url and api_key)
        pinned = parse_public_keys(
            config_public_key if config_public_key is not None else self._env.get("SHIELD360_CONFIG_PUBLIC_KEY")
        )
        tofu = not pinned and _tofu_allowed(allow_unpinned_config, self._env)
        self._reporter = _Reporter(url, api_key, self.app, self._post, self._clock) if remote and report else None  # type: ignore[arg-type]
        if remote and (pinned or tofu):
            self._client = RaspConfigClient(
                url=url,  # type: ignore[arg-type]
                api_key=api_key,  # type: ignore[arg-type]
                app=self.app,
                pinned=pinned,
                allow_unpinned=tofu,
                cache_dir=cache_dir or os.path.join(tempfile.gettempdir(), "shield360-defend"),
                on_config=self._on_config,
                on_warning=lambda r: None,
                fetch=fetch,
                now=self._clock,
                path=DEFEND_POLICY_PATH,
                jws_type=DEFEND_JWS_TYPE,
            )
            self._client.load_cache()
            self._client.poll()
            if background:
                self._client.start()
                threading.Thread(target=self._feed_loop, name="shield360-defend-feed", daemon=True).start()
        if self._reporter and background:
            threading.Thread(target=self._report_loop, name="shield360-defend-report", daemon=True).start()
        self._fetch = fetch
        self._feed_etag: Optional[str] = None

    def _on_config(self, claims: Optional[Dict[str, Any]]) -> None:
        policy = parse_defend_policy(claims) if claims else None
        if policy is not None:
            policy["edgeKeys"] = parse_edge_keys(claims.get("edgeContext"))  # type: ignore[union-attr]
        self._policy = policy

    def policy(self) -> Optional[Dict[str, Any]]:
        return self._policy

    def check_feed(self) -> None:
        """One check of the decisions feed: the policy is read again when its lists changed. Never raises."""
        if not self._client or not self._policy:
            return
        try:
            from shield360.rasp._config_client import _http_get  # pylint: disable=import-outside-toplevel

            headers = {"Authorization": f"Bearer {self._key}", "Accept": "application/json"}
            if self._feed_etag:
                headers["If-None-Match"] = self._feed_etag
            url = f"{str(self._url).rstrip('/')}{DEFEND_DECISIONS_PATH}?app={urllib.parse.quote(self.app, safe='')}"
            status, resp_headers, raw = (self._fetch or _http_get)(url, headers, 3.0)
            if status != 200:
                return
            self._feed_etag = resp_headers.get("etag") or None
            body = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
            if (
                isinstance(body, dict)
                and isinstance(body.get("version"), str)
                and body["version"] != self._policy.get("listsVersion")
            ):
                self._client.poll()
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _feed_loop(self) -> None:
        while not self._stop.wait(DECISIONS_EVERY_S):
            self.check_feed()

    def _report_loop(self) -> None:
        while not self._stop.wait(5.0):
            if self._reporter:
                self._reporter.flush()

    def _current_mode(self) -> str:
        return env_mode(self._env) or self._mode

    def _shared_over(self, base: Dict[str, Any]) -> Optional[Dict[str, bool]]:
        if not self._shared or not self._url or not base["facts"].get("ip"):
            return None
        ids = [r["id"] for r in rate_rules_for(base)]
        if not ids:
            return None
        try:
            body = self._post(
                f"{self._url.rstrip('/')}{DEFEND_DECIDE_PATH}",
                self._key,
                {"app": self.app, "ip": base["facts"]["ip"], "ruleIds": ids},
                0.15,
            )
            over = body.get("over") if isinstance(body, dict) else None
            return {k: v for k, v in over.items() if k in ids and isinstance(v, bool)} if isinstance(over, dict) else None
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def _report(self, result: Dict[str, Any], facts: Dict[str, Any]) -> None:
        if not self._reporter:
            return
        decision = result.get("wouldBe") or result["decision"]
        if decision == "allow" and "trap_hit" not in result["reasons"] and "rule:monitor" not in result["reasons"]:
            return
        e: Dict[str, Any] = {
            "kind": "decision",
            "decision": decision,
            "path": facts["path"][:256],
            "method": facts["method"],
            "reasons": result["reasons"],
            "ruleIds": result["ruleIds"],
        }
        if result.get("wouldBe"):
            e["monitored"] = True
        if result.get("clientType"):
            e["clientType"] = result["clientType"]
        if facts.get("ip"):
            e["ip"] = facts["ip"]
        self._reporter.add(e)

    def defend(
        self, request: Any, content: Any = None, ip: Optional[str] = None, country: Optional[str] = None, asn: Any = None
    ) -> Dict[str, Any]:
        """The decision for a request: {decision, reasons, ruleIds, ttl, wouldBe?, clientType?}. Never raises."""
        mode = self._current_mode()
        if mode == "off":
            return {"decision": "allow", "reasons": ["off"], "ruleIds": [], "ttl": 0}
        facts: Dict[str, Any] = {"method": "GET", "path": "/", "headers": {}}
        try:
            facts = facts_of(request, ip=ip, country=country, asn=asn, content=content, **self._facts_opts)  # type: ignore[arg-type]
            policy = self._policy if self._policy and self._policy["exp"] + 60 > self._clock() else None
            agent = None
            h = facts["headers"]
            if self._agents is not None and (h.get("shield360-agent") or (h.get("signature") and h.get("signature-input"))):
                try:
                    check = self._agents.check(h)
                    status = getattr(check, "status", None) or (check.get("status") if isinstance(check, dict) else None)
                    blocked = getattr(check, "blocked", None) if not isinstance(check, dict) else check.get("blocked")
                    reason = getattr(check, "reason", None) if not isinstance(check, dict) else check.get("reason")
                    agent = {
                        "verified": status == "verified",
                        "blocked": blocked is True,
                        "reason": None if status == "verified" else reason,
                    }
                except Exception:  # pylint: disable=broad-exception-caught
                    agent = None
            # Protection triangle: what Edge in front says about this client, verified (never trusted unverified).
            keys = (policy or {}).get("edgeKeys") or []
            ctx_value = facts["headers"].get(CONTEXT_HEADER)
            if ctx_value and keys:
                edge = verify_edge_context(
                    keys,
                    ctx_value,
                    facts["method"],
                    facts.get("rawPath") or facts["path"],
                    facts["headers"].get(REQUEST_ID_HEADER) or None,
                    self._clock(),
                )
                if edge:
                    facts["edge"] = {"ct": edge["ct"], "trap": edge["trap"], "fl": edge["fl"], "risk": edge["risk"]}
            edge_verified = (facts.get("edge") or {}).get("ct") in ("verified_agent", "verified_crawler")
            trap = bool(facts.get("ip")) and self._marks.is_suspicious(facts["ip"])
            # A client Edge's honeypots caught following a trail (level 2+) is a trap hit here too.
            trap = trap or ((facts.get("edge") or {}).get("trap", 0) >= 2)
            if not trap and facts.get("ip"):
                try:
                    from shield360.rasp._deception import suspicious_table  # pylint: disable=import-outside-toplevel

                    trap = suspicious_table().is_suspicious(facts["ip"])
                except Exception:  # pylint: disable=broad-exception-caught
                    trap = False
            trap = trap and not edge_verified
            classification = None
            if self._classify is not False and not (agent and agent["verified"]) and not trap:
                try:
                    if self._classify:
                        classification = self._classify(facts, {"verifiedAgent": False, "trapHit": False})
                    else:
                        breadth = self._breadth.see(facts["ip"], facts["path"], self._clock()) if facts.get("ip") else None
                        classification = classify_client(facts["headers"], {"edge": facts.get("edge"), "breadth": breadth})
                except Exception:  # pylint: disable=broad-exception-caught
                    classification = None
            base = {
                "policy": policy,
                "facts": facts,
                "mode": mode,
                "failMode": self._fail,
                "agent": agent,
                "trapHit": trap,
                "classification": classification,
                "content": check_content(facts.get("content"), self._sensitive),
                "sensitiveData": self._sensitive,
            }
            shared = self._shared_over(base) if policy else None
            result = decide({**base, "rates": self._rates, "nowMs": self._clock() * 1000, "sharedOver": shared})
        except Exception:  # pylint: disable=broad-exception-caught
            result = fail_result(self._fail, "error", mode)
        self._report(result, facts)
        return result

    def trap_hit(self, request: Any, trap: str, ip: Optional[str] = None) -> None:
        """The app saw a trap hit: the client is marked suspected for the policy's trap TTL (the next request is
        decided by the trap action at once) and the hit is reported so every instance and Edge follow within seconds."""
        try:
            facts = facts_of(request, ip=ip, **self._facts_opts)  # type: ignore[arg-type]
            ttl = self._policy["traps"]["ttlSeconds"] if self._policy else 900
            if facts.get("ip"):
                self._marks.mark(facts["ip"], ttl)
            if self._reporter:
                e = {
                    "kind": "trap_hit",
                    "path": facts["path"][:256],
                    "method": facts["method"],
                    "clientType": "suspected_ai_agent",
                    "reasons": [f"trap:{trap if _CODE.match(trap or '') else 'trap'}"],
                    "ruleIds": [],
                }
                if facts.get("ip"):
                    e["ip"] = facts["ip"]
                self._reporter.add(e)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def failed_login(self, request: Any, ip: Optional[str] = None) -> None:
        """The app saw a failed sign-in: reported, never the user name or password."""
        try:
            facts = facts_of(request, ip=ip, **self._facts_opts)  # type: ignore[arg-type]
            if self._reporter:
                e = {
                    "kind": "failed_login",
                    "path": facts["path"][:256],
                    "method": facts["method"],
                    "reasons": ["failed_login"],
                    "ruleIds": [],
                }
                if facts.get("ip"):
                    e["ip"] = facts["ip"]
                self._reporter.add(e)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def flush(self) -> None:
        if self._reporter:
            self._reporter.flush()

    def close(self) -> None:
        self._stop.set()
        if self._client:
            self._client.stop()
        self.flush()

    def wsgi(self, app: Callable) -> Callable:
        """WSGI middleware: answers 403 (deny, challenge) or 401 (require sign-in) before the app runs."""

        def middleware(environ, start_response):
            result = self.defend(environ)
            environ["shield360.defend"] = result
            if result["decision"] == "allow":
                return app(environ, start_response)
            status = "401 Unauthorized" if result["decision"] == "require_sign_in" else "403 Forbidden"
            start_response(
                status,
                [("Content-Type", "application/json"), ("Shield360-Defend", result["decision"]), ("Cache-Control", "no-store")],
            )
            return [BLOCK_BODY]

        return middleware

    def asgi_middleware(self):
        """An ASGI middleware class for app.add_middleware(...) (FastAPI, Starlette)."""
        defend = self

        class DefendASGIMiddleware:
            def __init__(self, app):
                self.app = app

            async def __call__(self, scope, receive, send):
                if scope.get("type") != "http":
                    return await self.app(scope, receive, send)
                result = defend.defend(scope)
                scope.setdefault("state", {})
                scope["state"]["shield360_defend"] = result
                if result["decision"] == "allow":
                    return await self.app(scope, receive, send)
                status = 401 if result["decision"] == "require_sign_in" else 403
                await send(
                    {
                        "type": "http.response.start",
                        "status": status,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"shield360-defend", result["decision"].encode()),
                            (b"cache-control", b"no-store"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": BLOCK_BODY})
                return None

        return DefendASGIMiddleware


def create_defend(app: str, **options: Any) -> Defend:
    """A Defend instance for one app (see the module docstring)."""
    return Defend(app, **options)
