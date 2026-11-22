"""AI attack agents (sdk/rasp/README.md "AI attack agents"): the shared
conformance vectors (testdata/ai-attack-agents.json), the tracker's bounds,
and the WSGI/ASGI middleware: deter answer, verdict for Edge, events,
tripwire page."""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import time

import pytest

from shield360.client_type import classify_client
from shield360.defend._engine import client_type_matches
from shield360.rasp import _engine
from shield360.rasp._attack_agents import (
    DEFAULT_ATTACK_AGENTS,
    AttackAgentTracker,
    attack_fingerprint,
    client_key,
    find_callback_domain,
    parse_attack_agents,
    set_attack_agent_tracker,
    tripwire_page,
    user_key,
)
from shield360.rasp._agents import identify_rasp_user
from shield360.rasp._deception import set_suspicious_table
from shield360.rasp._edge_context import path_hash
from shield360.rasp._middleware import RaspASGIMiddleware, RaspWSGIMiddleware
from shield360.rasp import _to_remote

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "rasp", "testdata")
with open(os.path.join(_ROOT, "ai-attack-agents.json"), encoding="utf-8") as _f:
    V = json.load(_f)


@pytest.mark.parametrize("case", V["config"], ids=[c["name"] for c in V["config"]])
def test_config(case):
    assert parse_attack_agents(case["value"]).as_contract() == case["expect"]


@pytest.mark.parametrize("case", V["clientKey"], ids=[c["ip"] or "empty" for c in V["clientKey"]])
def test_client_key(case):
    assert client_key(case["ip"]) == case["key"]


@pytest.mark.parametrize("case", V["userKey"])
def test_user_key(case):
    assert user_key(case["user"]) == case["key"]


@pytest.mark.parametrize("case", V["fingerprint"], ids=[c["name"] for c in V["fingerprint"]])
def test_fingerprint(case):
    assert attack_fingerprint(case["headers"]) == case["expect"]


@pytest.mark.parametrize("case", V["oast"], ids=[c["value"] for c in V["oast"]])
def test_oast(case):
    assert find_callback_domain(case["value"]) == case["expect"]


@pytest.mark.parametrize("seq", V["sequences"], ids=[s["name"] for s in V["sequences"]])
def test_sequence(seq):
    cfg = parse_attack_agents({**DEFAULT_ATTACK_AGENTS.as_contract(), **(seq.get("config") or {})})
    t = AttackAgentTracker()
    for i, st in enumerate(seq["steps"]):
        now = float(st["at"])
        headers = st.get("headers", V["defaultHeaders"])
        # A client Edge verified and the red team Edge named (rt) are both left alone.
        verified = st.get("verified", False) or st.get("redTeam", False)
        if st.get("decoy"):
            deter = False
            mark = t.after(st["ip"], st.get("user"), st["path"], headers, st["status"], cfg, now, decoy=True, verified=verified)
        else:
            made, marked, tripwire = t.before(
                st["ip"], st.get("user"), st["path"], headers, st.get("inputs", []), cfg, now, verified
            )
            deter = marked is not None
            mark = made
            if not deter and not tripwire:
                mark = (
                    t.after(
                        st["ip"],
                        st.get("user"),
                        st["path"],
                        headers,
                        st["status"],
                        cfg,
                        now,
                        route=st.get("route"),
                        finding=st.get("finding", False),
                        verified=verified,
                    )
                    or mark
                )
        assert {"step": i, "deter": deter, "mark": mark} == {"step": i, **st["expect"]}


@pytest.mark.parametrize("case", V["clientTypeRules"])
def test_defend_client_type_rules(case):
    assert client_type_matches(case["rule"], case["clientType"]) is case["match"]


def test_attack_sequences_mark_benign_never():
    assert {s["kind"] for s in V["sequences"]} == {"attack", "benign"}
    for s in V["sequences"]:
        assert (s["name"], any(st["expect"]["mark"] for st in s["steps"])) == (s["name"], s["kind"] == "attack")


def test_bounds_and_expiry():
    cfg = DEFAULT_ATTACK_AGENTS
    t = AttackAgentTracker(50, 20)
    for i in range(500):
        t.after(f"10.0.{i >> 8}.{i & 255}", None, f"/x{i}", {}, 404, cfg, 1000.0)
        t.before(f"10.1.{i >> 8}.{i & 255}", None, "/", {"user-agent": "sqlmap/1"}, (), cfg, 1000.0)
    keys, marks = t.sizes
    assert keys <= 50 and marks <= 20
    t = AttackAgentTracker()
    assert t.before("192.0.2.1", None, "/", {"user-agent": "nikto/2.5"}, (), cfg, 0.0)[1] == {
        "kind": "scanner",
        "reason": "fingerprint",
    }
    assert t.before("192.0.2.1", None, "/", V["defaultHeaders"], (), cfg, 1799.0)[1] is not None
    assert t.before("192.0.2.1", None, "/", V["defaultHeaders"], (), cfg, 1800.0)[1] is None


def test_cost_per_request():
    cfg = DEFAULT_ATTACK_AGENTS
    t = AttackAgentTracker()
    n = 20_000
    started = time.perf_counter()
    for i in range(n):
        ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        t.before(ip, None, f"/api/items/{i}", V["defaultHeaders"], ("hello world", "a@b.example"), cfg, float(i))
        t.after(ip, None, f"/api/items/{i}", V["defaultHeaders"], 200, cfg, float(i), route="/api/items/:id")
    per_us = (time.perf_counter() - started) / n * 1e6
    assert per_us < 500  # generous for slow CI; locally tens of microseconds


def test_tripwire_page_hidden():
    page = tripwire_page("/_debug/console/abc")
    assert '<div hidden aria-hidden="true">' in page and "<!-- " in page
    assert page.count("/_debug/console/abc") == 2


def test_client_type_kinds():
    assert classify_client({"user-agent": "", "x-artex-replay-nonce": "1"}) == {
        "clientType": "ai_attack_agent",
        "reasons": ["attack_agent_header:artex-replay"],
        "confidence": "high",
    }
    assert classify_client({"user-agent": "sqlmap/1.8"}) == {
        "clientType": "scanner",
        "reasons": ["ua_attack_tool:sqlmap"],
        "confidence": "high",
    }
    assert classify_client({"user-agent": "sqlmap/1.8"}, {"verifiedAgent": True})["clientType"] == "verified_agent"
    assert classify_client({"user-agent": "Mozilla/5.0"}, {"attackMark": "ai_attack_agent"})["clientType"] == "ai_attack_agent"
    assert classify_client({"user-agent": "python-httpx/0.27"})["clientType"] == "unverified_automation"


# ---- middleware ---------------------------------------------------------------

KEY = b"0123456789abcdef0123456789abcdef"
EDGE = {"keys": [{"kid": "0a1b2c3d", "key": base64.urlsafe_b64encode(KEY).decode().rstrip("=")}]}


class Sink:
    def __init__(self):
        self.events = []

    def add(self, event, _fold):
        self.events.append(event)

    def rules(self):
        return [e["attrs"]["shield360.rasp.rule"] for e in self.events]


@pytest.fixture(name="sink")
def _sink_fixture():
    s = Sink()
    yield s
    _engine.set_event_sink(None)
    _engine.set_remote_config(None)
    _engine.configure_engine(enabled=False, application_name="default", env={})
    set_attack_agent_tracker()


def setup(sink, attack_agents, mode="block", **extra):
    _engine.configure_engine(enabled=True, application_name="orders-api", env={})
    _engine.set_event_sink(sink)
    claims = {
        "v": 1,
        "app": "orders-api",
        "exp": 4_000_000_000,
        "version": "v-agents",
        "attacks": {"ai_attack_agent": mode},
        "attackAgents": attack_agents,
        "edgeContext": EDGE,
    }
    claims.update(extra)
    _engine.set_remote_config(_to_remote(claims))
    set_attack_agent_tracker()
    set_suspicious_table()


def app(environ, start_response):
    identify_rasp_user(environ.get("HTTP_X_TEST_USER") or "")
    if environ.get("PATH_INFO", "").startswith("/missing"):
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"nope"]
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def call(mw, path, headers=None, ip="198.51.100.7"):
    environ = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": path.split("?")[0],
        "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "",
        "REMOTE_ADDR": ip,
        "wsgi.input": None,
    }
    for k, v in (headers or {}).items():
        environ["HTTP_" + k.upper().replace("-", "_")] = v
    got = {}

    def start(status, hdrs, *_):
        got["status"] = int(status.split()[0])
        got["headers"] = {k.lower(): v for k, v in hdrs}

    body = b"".join(mw(environ, start))
    return got["status"], got["headers"], body


def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_verdict(value, rid):
    v, kid, payload, sig = value.split(".")
    want = hmac.new(KEY, b"s360-verdict|v1|" + payload.encode(), hashlib.sha256).digest()
    assert v == "v1" and kid == "0a1b2c3d" and hmac.compare_digest(_b64d(sig), want)
    out = json.loads(_b64d(payload))
    assert out["rid"] == rid
    return out


def edge_context(method, path, rid, ct="human", **extra):
    now = int(time.time())
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "rid": rid,
                    "iat": now,
                    "exp": now + 30,
                    "m": method,
                    "ph": path_hash(path),
                    "ct": ct,
                    "risk": 0,
                    "trap": 0,
                    "fl": False,
                    **extra,
                }
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    sig = (
        base64.urlsafe_b64encode(hmac.new(KEY, b"s360-ctx|v1|" + payload.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    )
    return f"v1.0a1b2c3d.{payload}.{sig}"


UA = {"user-agent": "Mozilla/5.0"}


def test_wsgi_deters_a_tool_with_429(sink):
    setup(sink, {"retryAfterSeconds": 120})
    mw = RaspWSGIMiddleware(app)
    status, headers, body = call(mw, "/api/items?id=1", {"user-agent": "sqlmap/1.8.2#stable"})
    assert status == 429 and headers["retry-after"] == "120"
    assert json.loads(body) == {"error": "Too Many Requests"}
    a = sink.events[0]["attrs"]
    assert a["shield360.rasp.attack"] == "ai_attack_agent" and a["shield360.rasp.rule"] == "attack_agent.fingerprint"
    assert a["shield360.rasp.client_kind"] == "scanner" and a["shield360.rasp.reason"] == "fingerprint"
    assert a["shield360.rasp.decision"] == "blocked" and a["shield360.rasp.sink"] == "http.attack_agent"
    assert call(mw, "/", UA)[0] == 429
    assert sink.rules()[1] == "attack_agent.marked"


def test_wsgi_monitor_only_reports(sink):
    setup(sink, {}, mode="monitor")
    status, _, _ = call(RaspWSGIMiddleware(app), "/x?u=http%3A%2F%2Fabc.oast.fun%2F", UA)
    assert status == 200
    assert sink.events[0]["attrs"]["shield360.rasp.rule"] == "attack_agent.oast"
    assert sink.events[0]["attrs"]["shield360.rasp.decision"] == "monitored"


def test_wsgi_behavior_then_deter(sink):
    setup(sink, {"threshold": 5})
    mw = RaspWSGIMiddleware(app)
    for i in range(5):
        assert call(mw, f"/missing/{i}", UA)[0] == 404
    assert sink.rules() == ["attack_agent.behavior"]
    assert call(mw, "/", UA)[0] == 429


def test_wsgi_verdict_for_edge(sink):
    setup(sink, {})
    rid = "req_attackagent01"
    status, headers, _ = call(
        RaspWSGIMiddleware(app),
        "/api/x",
        {"user-agent": "nuclei/3.3", "x-request-id": rid, "x-shield360-edge-context": edge_context("GET", "/api/x", rid)},
    )
    assert status == 429
    v = verify_verdict(headers["x-shield360-verdict"], rid)
    assert v and v["act"] == "block" and v["cat"] == "scanner" and v["ttl"] == 1800


def test_wsgi_verified_client_left_alone(sink):
    setup(sink, {})
    rid = "req_verifiedcrawl1"
    status, _, _ = call(
        RaspWSGIMiddleware(app),
        "/api/x",
        {
            "user-agent": "nuclei/3.3",
            "x-request-id": rid,
            "x-shield360-edge-context": edge_context("GET", "/api/x", rid, "verified_crawler"),
        },
    )
    assert status == 200 and not sink.events


def test_wsgi_red_team_left_alone(sink):
    """The authorized red team (Edge verified its header and named the run in
    the context, rt) is never marked or deterred, even from a marked address;
    normal RASP detection still runs. Without the context it is deterred."""
    setup(sink, {"tripwire": True})
    mw = RaspWSGIMiddleware(app)
    assert call(mw, "/", {"user-agent": "nuclei/3.3"})[0] == 429  # the address is marked now
    sink.events.clear()
    for path in ("/api/x", "/_debug/console/abc"):
        rid = "req_redteam_" + str(len(path))
        status, headers, _ = call(
            mw,
            path,
            {
                "user-agent": "nuclei/3.3",
                "x-request-id": rid,
                "x-shield360-edge-context": edge_context("GET", path, rid, "automation", rt="crun12345678"),
            },
        )
        assert status != 429 and "x-shield360-verdict" not in headers
    assert not [e for e in sink.events if e["attrs"]["shield360.rasp.attack"] == "ai_attack_agent"]
    rid = "req_notredteam1"
    plain = {
        "user-agent": "Mozilla/5.0",
        "x-request-id": rid,
        "x-shield360-edge-context": edge_context("GET", "/api/x", rid, "automation"),
    }
    assert call(mw, "/api/x", plain)[0] == 429


def test_wsgi_off(sink):
    setup(sink, {}, attacks={"ai_attack_agent": "off"})
    assert call(RaspWSGIMiddleware(app), "/", {"user-agent": "sqlmap/1"})[0] == 200
    assert not sink.events


def test_wsgi_tripwire_page_and_hit(sink):
    setup(sink, {"tripwire": True}, mode="monitor", deception={"paths": ["/wp-admin"], "action": "monitor", "ttlSeconds": 60})
    mw = RaspWSGIMiddleware(app)
    status, headers, body = call(mw, "/wp-admin", UA)
    assert status == 404 and headers["content-type"].startswith("text/html")
    url = re.search(r"(/_debug/console/[A-Za-z0-9_-]{16})", body.decode()).group(1)
    assert call(mw, url, UA)[0] == 404
    hit = [e["attrs"] for e in sink.events if e["attrs"]["shield360.rasp.rule"] == "attack_agent.tripwire"]
    assert hit and hit[0]["shield360.rasp.client_kind"] == "ai_attack_agent"


def test_wsgi_decoy_plain_without_tripwire(sink):
    setup(sink, {}, mode="monitor", deception={"paths": ["/wp-admin"], "action": "monitor", "ttlSeconds": 60})
    assert call(RaspWSGIMiddleware(app), "/wp-admin", UA)[2] == b"Not Found"


def test_wsgi_user_across_addresses(sink):
    setup(sink, {"threshold": 6})
    t = set_attack_agent_tracker()

    def forbidden(environ, start_response):
        identify_rasp_user("mallory")
        start_response("403 Forbidden", [])
        return [b""]

    mw = RaspWSGIMiddleware(forbidden)
    for i in range(3):
        call(mw, "/admin", UA, ip=f"192.0.2.{i + 1}")
    assert t.mark_of(["u:mallory"], time.time()) == {"kind": "ai_attack_agent", "reason": "behavior"}


def test_asgi_deter_and_behavior(sink):
    setup(sink, {"threshold": 5})

    async def inner(scope, receive, send):
        status = 404 if scope["path"].startswith("/missing") else 200
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = RaspASGIMiddleware(inner)

    async def run(path, headers):
        sent = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            sent.append(m)

        scope = {
            "type": "http",
            "method": "GET",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
            "client": ("198.51.100.9", 1),
        }
        await mw(scope, receive, send)
        return sent[0]["status"], dict(sent[0]["headers"])

    async def main():
        for i in range(5):
            assert (await run(f"/missing/{i}", UA))[0] == 404
        status, headers = await run("/", UA)
        assert status == 429 and headers[b"retry-after"] == b"300"
        assert (await run("/", {"user-agent": "", "x-artex-replay-nonce": "n"}))[0] == 429

    asyncio.run(main())
    assert sink.rules()[0] == "attack_agent.behavior"
