"""Agent passport verifier: the contract's steps and reason codes, the receiver policy,
the console policy, reports, the ASGI/WSGI middleware and the inputs a passport is read from.
Keys are generated here; the network is a fake transport."""
# pylint: disable=redefined-outer-name

import asyncio
import base64
import json
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shield360.agents import (
    AGENT_HEADER,
    AgentPolicy,
    AgentVerifier,
    AgentVerifierASGIMiddleware,
    AgentVerifierWSGIMiddleware,
    MemoryReplayStore,
    check,
)
from shield360.agents._passport import audience_matches, parse_passport

ISS = "https://app.shield360.ai"
T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64j(v) -> str:
    return b64(json.dumps(v).encode())


class Key:
    def __init__(self, kid="k1"):
        self.kid = kid
        self.private = Ed25519PrivateKey.generate()
        raw = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64(raw), "kid": kid, "alg": "EdDSA", "use": "sig"}


_MISSING = object()


def claims(**over):
    iat = int(T0)
    c = {
        "iss": ISS,
        "sub": "agent:a1",
        "aud": "api.servflo.ai",
        "iat": iat,
        "exp": iat + 120,
        "jti": str(uuid.uuid4()),
        "agent": {"id": "a1", "name": "Dispatch bot", "purpose": "Schedules jobs"},
        "operator": {"id": "org_1", "name": "Acme", "domain": "acme.com"},
        "scope": "jobs.read invoices.write",
        "decision": {"id": "d1", "policyVersion": "pv1"},
    }
    for k, v in over.items():
        if v is _MISSING:
            c.pop(k, None)
        else:
            c[k] = v
    return c


def passport(key, header=None, **over):
    h = b64j({"alg": "EdDSA", "typ": "shield360-agent+jwt", "kid": key.kid, **(header or {})})
    p = b64j(claims(**over))
    sig = key.private.sign(f"{h}.{p}".encode())
    return f"{h}.{p}.{b64(sig)}"


class Net:
    def __init__(self, keys):
        self.keys = keys
        self.calls = []
        self.verify = None  # callable(body) -> (status, bytes)
        self.policy = None  # callable() -> (status, bytes)
        self.decisions = []
        self.decision_status = 200

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body))
        path = url.split("?")[0]
        if path.endswith("/api/agent-passports/keys"):
            return 200, json.dumps({"keys": [k.jwk for k in self.keys]}).encode()
        if path.endswith("/api/agent-passports/verify"):
            if self.verify is None:
                raise OSError("down")
            return self.verify(json.loads(body))  # pylint: disable=not-callable
        if path.endswith("/api/inbound-agents/policy"):
            if self.policy is None:
                raise OSError("down")
            return self.policy()  # pylint: disable=not-callable
        if path.endswith("/api/inbound-agents/decisions"):
            self.decisions.append(json.loads(body)["decisions"])
            return self.decision_status, b"{}"
        raise AssertionError(url)

    def count(self, part):
        return len([c for c in self.calls if part in c[1]])


def ok(body, status=200):
    return status, json.dumps(body).encode()


@pytest.fixture
def env():
    state = {"now": T0}
    key = Key()
    net = Net([key])

    def make(**kw):
        kw.setdefault("audience", "api.servflo.ai")
        return AgentVerifier(http=net, clock=lambda: state["now"], **kw)

    return state, key, net, make


def test_valid_passport_carries_identity(env):
    _, key, net, make = env
    token = passport(key, act={"sub": "pairwiseId0123456789ab", "domain": "acme.com"})
    r = make().check(token)
    assert r.status == "verified" and r.decision == "allow" and not r.blocked and r.reason is None
    assert r.agent.name == "Dispatch bot" and r.agent.purpose == "Schedules jobs"
    assert r.operator.domain == "acme.com"
    assert r.on_behalf_of.id == "pairwiseId0123456789ab"
    assert r.scopes == ["jobs.read", "invoices.write"]
    assert r.expires_at == "2026-10-28T12:02:00.000Z"
    d = r.to_dict()
    assert d["onBehalfOf"] == {"id": "pairwiseId0123456789ab", "domain": "acme.com", "assurance": "named"}
    assert d["passportId"] == r.passport_id
    assert token not in json.dumps(d)
    assert net.calls[0][1] == f"{ISS}/api/agent-passports/keys?kid=k1"


def test_issuer_shapes(env):
    _, key, net, make = env
    r = make().check(passport(key, scope=_MISSING, decision=_MISSING, act={"sub": "p1", "domain": None}))
    assert r.status == "verified" and r.scopes == [] and r.on_behalf_of.domain is None
    assert r.to_dict()["onBehalfOf"] == {"id": "p1", "domain": None, "assurance": "named"}
    original = net.__call__
    v = make()
    v._keys._http = lambda m, u, h, b, t: (404, b'{"err": "unknown kid", "keys": []}') if "/keys" in u else original(m, u, h, b, t)
    assert v.check(passport(key)).reason == "unknown_key"


def test_online_429_is_unreachable(env):
    _, key, net, make = env
    net.verify = lambda body: ok({"valid": False, "reason": "revoked"}, 429)
    assert make().check(passport(key), online=True).reason == "issuer_unreachable"


def test_key_is_cached(env):
    _, key, net, make = env
    v = make()
    v.check(passport(key))
    v.check(passport(key))
    assert net.count("/keys") == 1


@pytest.mark.parametrize(
    "make_token,reason",
    [
        (lambda k: "abc.def", "malformed"),
        (lambda k: "a$b.c.d", "malformed"),
        (lambda k: passport(k, header={"typ": "JWT"}), "malformed"),
        (lambda k: passport(k, header={"crit": ["x"]}), "malformed"),
        (lambda k: passport(k, operator=_MISSING), "malformed"),
        (lambda k: passport(k, aud=["api.servflo.ai"]), "malformed"),
        (lambda k: "a" * 10000, "malformed"),
        (lambda k: passport(k, header={"alg": "none"}), "unsupported_alg"),
        (lambda k: passport(k, iss="https://evil.example"), "untrusted_issuer"),
        (lambda k: passport(Key("other")), "unknown_key"),
        (lambda k: passport(Key("k1")), "bad_signature"),
        (lambda k: passport(k, iat=int(T0) - 400, exp=int(T0) - 61), "expired"),
        (lambda k: passport(k, iat=int(T0) + 61, exp=int(T0) + 200), "not_yet_valid"),
        (lambda k: passport(k, exp=int(T0) + 301), "lifetime_too_long"),
        (lambda k: passport(k, aud="api.other.ai"), "wrong_audience"),
    ],
)
def test_failure_reasons(env, make_token, reason):
    _, key, _, make = env
    r = make().check(make_token(key))
    assert (r.status, r.decision, r.blocked, r.reason) == ("invalid", "deny", False, reason)


def test_enforce_blocks_invalid(env):
    *_, make = env
    r = make(policy={"mode": "enforce"}).check("x.y.z")
    assert r.blocked and r.decision == "deny"


def test_tampered_payload(env):
    _, key, _, make = env
    h, _, s = passport(key).split(".")
    forged = f"{h}.{b64j(claims(operator={'id': 'org_2', 'name': 'X', 'domain': None}))}.{s}"
    assert make().check(forged).reason == "bad_signature"


def test_never_raises_on_hostile_input(env):
    *_, make = env
    v = make()
    for bad in [None, 42, {}, [], [(1, 2, 3)], {AGENT_HEADER: 5}, "....", b"\xff\xfe", object()]:
        assert v.check(bad) is not None


def test_skew(env):
    state, key, _, make = env
    exp = int(T0) + 10
    state["now"] = T0 + 69
    assert make().check(passport(key, exp=exp)).status == "verified"
    state["now"] = T0 + 71
    assert make().check(passport(key, exp=exp)).reason == "expired"
    state["now"] = T0
    assert make(clock_skew_seconds=5).check(passport(key, iat=int(T0) + 30, exp=int(T0) + 100)).reason == "not_yet_valid"


def test_unknown_kid_refetch_once_a_minute(env):
    state, _, net, make = env
    v = make()
    k2 = Key("k2")
    v.check(passport(k2))
    v.check(passport(k2))
    assert net.count("/keys") == 1
    net.keys.append(k2)
    state["now"] += 61
    assert v.check(passport(k2, iat=int(state["now"]), exp=int(state["now"]) + 60)).status == "verified"
    assert net.count("/keys") == 2


def test_stale_key_kept_when_refetch_fails(env):
    state, key, net, make = env
    v = make()
    v.check(passport(key))
    state["now"] += 3700
    net.keys = []
    original = net.__call__

    def failing(method, url, headers, body, timeout):
        if "/keys" in url:
            raise OSError("down")
        return original(method, url, headers, body, timeout)

    v._keys._http = failing
    assert v.check(passport(key, iat=int(state["now"]), exp=int(state["now"]) + 60)).status == "verified"


def test_rejects_non_ed25519_jwk(env):
    _, key, _, make = env
    key.jwk = {**key.jwk, "crv": "X25519"}
    assert make().check(passport(key)).reason == "unknown_key"


def test_audience_origin_and_host(env):
    _, key, _, make = env
    assert make().check(passport(key, aud="https://API.servflo.ai")).status == "verified"
    assert make(audience="https://api.servflo.ai").check(passport(key)).status == "verified"
    assert make(audience=["mcp.servflo.ai", "API.SERVFLO.AI"]).check(passport(key)).status == "verified"
    assert not audience_matches("http://api.servflo.ai", ["api.servflo.ai"])
    assert not audience_matches("https://api.servflo.ai/x", ["api.servflo.ai"])
    assert not audience_matches("https://api.servflo.ai:8443", ["api.servflo.ai"])
    assert audience_matches("https://api.servflo.ai:8443", ["https://api.servflo.ai:8443"])
    assert audience_matches("https://api.servflo.ai:8443", ["api.servflo.ai:8443"])
    assert not audience_matches("https://api.servflo.ai", ["http://api.servflo.ai"])
    assert audience_matches("https://api.servflo.ai", ["https://API.servflo.ai"])


def test_replay(env):
    _, key, _, make = env
    v = make()
    token = passport(key)
    assert v.check(token).status == "verified"
    r = v.check(token)
    assert (r.status, r.reason) == ("invalid", "replayed")


def test_pluggable_replay_store(env):
    _, key, _, make = env
    calls = []

    class Store:
        def seen(self, jti, expires_at):
            calls.append((jti, expires_at))
            return False

    make(replay=Store()).check(passport(key))
    assert calls[0][1] == int(T0) + 120 + 60

    class Broken:
        def seen(self, jti, expires_at):
            raise RuntimeError("redis down")

    assert make(replay=Broken()).check(passport(key)).reason == "replay_check_failed"
    calls.clear()
    make(replay=Store()).check(passport(key, aud="elsewhere.ai"))
    assert not calls


def test_memory_replay_store():
    t = {"now": 0}
    s = MemoryReplayStore(max_entries=3, clock=lambda: t["now"])
    assert s.seen("a", 10) is False
    assert s.seen("a", 10) is True
    t["now"] = 11
    assert s.seen("a", 20) is False
    for j in "bcd":
        s.seen(j, 100)
    assert len(s) <= 3


def test_online(env):
    _, key, net, make = env
    net.verify = lambda body: ok({"valid": True})
    token = passport(key)
    assert make().check(token, online=True).status == "verified"
    verify_call = [c for c in net.calls if c[1].endswith("/verify")][0]
    assert json.loads(verify_call[3]) == {"passport": token, "audience": "api.servflo.ai"}
    for reason in ("revoked", "unknown_passport"):
        net.verify = lambda body, reason=reason: ok({"valid": False, "reason": reason})
        assert make().check(passport(key), online=True).reason == reason
    net.verify = lambda body: ok({"valid": False, "reason": "revoked"})
    assert make(policy={"online": True}).check(passport(key)).reason == "revoked"


def test_online_unreachable(env):
    _, key, net, make = env
    r = make().check(passport(key), online=True)
    assert (r.status, r.decision, r.reason) == ("verified", "allow", "issuer_unreachable")
    net.verify = lambda body: (503, b"busy")
    r = make(online_failure="deny").check(passport(key), online=True)
    assert (r.status, r.decision, r.reason) == ("invalid", "deny", "issuer_unreachable")


def test_policy(env):
    _, key, _, make = env
    r = make(policy={"operators": ["other.com"]}).check(passport(key))
    assert (r.status, r.decision, r.blocked, r.reason) == ("verified", "deny", False, "operator_not_allowed")
    assert make(policy={"operators": ["other.com"], "mode": "enforce"}).check(passport(key)).blocked
    r = make().check({})
    assert (r.status, r.decision, r.reason) == ("absent", "allow", "absent")
    r = make(policy=AgentPolicy(mode="enforce", require_agent=True)).check({})
    assert (r.decision, r.blocked) == ("deny", True)
    assert make(policy={"operators": ["org_1"]}).check(passport(key)).decision == "allow"
    assert make(policy={"operators": ["ACME.com"]}).check(passport(key)).decision == "allow"
    no_domain = passport(key, operator={"id": "org_9", "name": "N", "domain": None})
    assert make(policy={"operators": ["acme.com"]}).check(no_domain).reason == "operator_not_allowed"
    v = make(policy={"requireOnBehalfOf": True})
    assert v.check(passport(key)).reason == "on_behalf_of_required"
    assert v.check(passport(key, act={"sub": "p", "domain": "acme.com"})).decision == "allow"


REMOTE = {
    "mode": "enforce",
    "requireAgent": True,
    "operators": ["org_1"],
    "requireOnBehalfOf": False,
    "online": False,
    "minAssurance": "named",
}


def test_policy_from_caches_and_sends_bearer(env):
    state, _, net, make = env
    net.policy = lambda: ok(REMOTE)
    v = make(policy_from={"api_key": "sk-test", "base_url": "https://console.example/"})
    assert v.policy().to_dict() == REMOTE
    v.policy()
    calls = [c for c in net.calls if "/policy" in c[1]]
    assert len(calls) == 1
    assert calls[0][1] == "https://console.example/api/inbound-agents/policy"
    assert calls[0][2]["Authorization"] == "Bearer sk-test"
    state["now"] += 61
    v.policy()
    v._policies.wait()
    assert net.count("/policy") == 2


def test_policy_from_wrapped_and_local_override(env):
    _, _, net, make = env
    net.policy = lambda: ok({"policy": REMOTE})
    v = make(policy_from={"apiKey": "k"}, policy={"mode": "observe"})
    assert v.policy().to_dict() == {**REMOTE, "mode": "observe"}


def test_policy_from_failure_keeps_last_good(env):
    state, _, net, make = env
    net.policy = lambda: ok(REMOTE)
    v = make(policy_from={"api_key": "k"})
    v.policy()
    net.policy = lambda: ok({"error": "x"}, 500)
    state["now"] += 61
    v.policy()
    v._policies.wait()
    assert v.policy().to_dict() == REMOTE
    net.policy = None
    p = make(policy_from={"api_key": "k"}, policy={"operators": ["x"]}).policy()
    assert p.to_dict() == {
        "mode": "observe",
        "requireAgent": False,
        "operators": ["x"],
        "requireOnBehalfOf": False,
        "online": False,
        "minAssurance": "none",
    }


def test_policy_from_ignores_ill_typed(env):
    _, _, net, make = env
    net.policy = lambda: ok({"mode": "block-all", "requireAgent": "yes", "operators": [1, "ok"], "minAssurance": "high"})
    p = make(policy_from={"api_key": "k"}).policy()
    assert (p.mode, p.require_agent, p.operators, p.min_assurance) == ("observe", False, ("ok",), "none")


def test_report_batches_without_passport(env):
    _, key, net, make = env
    v = make(report={"api_key": "rk", "base_url": "https://console.example"})
    token = passport(key)
    v.check(token, route="/v1/jobs?token=secret", method="post")
    v.check("bad", route="/v1/jobs")
    v.check({})
    v.flush()
    assert len(net.decisions) == 1
    a, b = net.decisions[0]
    assert a["status"] == "verified" and a["route"] == "/v1/jobs" and a["method"] == "POST" and a["receiver"] == "api.servflo.ai"
    assert a["at"] == "2026-10-28T12:00:00.000Z"
    assert b["reason"] == "malformed"
    assert token not in json.dumps(net.decisions)
    call = [c for c in net.calls if c[1].endswith("/decisions")][0]
    assert call[1] == "https://console.example/api/inbound-agents/decisions"
    assert call[2]["Authorization"] == "Bearer rk"
    v.close()


def test_report_at_most_100_per_call(env):
    *_, net, make = env
    v = make(report={"api_key": "rk"})
    v._reporter._stop.set()  # keep the background thread out of the count
    v._reporter._wake.set()
    v._reporter._thread.join(5)
    for _ in range(250):
        v.check("bad")
    v.flush()
    assert [len(d) for d in net.decisions] == [100, 100, 50]
    v.close()


def test_report_failure_never_raises(env, caplog):
    *_, net, make = env
    net.decision_status = 401
    v = make(report={"api_key": "rk"})
    assert v.check("bad").status == "invalid"
    v.flush()
    assert "refused" in caplog.text
    v.close()


def test_inputs(env):
    _, key, _, make = env
    v = make()

    class Req:
        def __init__(self, headers):
            self.headers = headers

    results = [
        v.check({"SHIELD360-AGENT": passport(key)}),
        v.check({"HTTP_SHIELD360_AGENT": passport(key), "PATH_INFO": "/"}),
        v.check([(b"shield360-agent", passport(key).encode())]),
        v.check(Req({"Shield360-Agent": passport(key)})),
        check(v, passport(key)),
    ]
    assert [r.status for r in results] == ["verified"] * 5
    two = [(b"shield360-agent", passport(key).encode()), (b"shield360-agent", passport(key).encode())]
    assert v.check(two).reason == "malformed"


def test_parse_rejects_short_signature(env):
    _, key, _, _ = env
    h, p, _ = passport(key).split(".")
    assert parse_passport(f"{h}.{p}.{b64(bytes(63))}") == (None, "malformed")


def _asgi_app(seen):
    async def app(scope, receive, send):
        seen.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    return app


def _asgi_call(mw, headers):
    sent = []

    async def send(msg):
        sent.append(msg)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "GET", "path": "/v1/jobs", "headers": headers}
    asyncio.run(mw(scope, receive, send))
    return scope, sent


def test_asgi_middleware(env):
    _, key, _, make = env
    seen = []
    scope, sent = _asgi_call(AgentVerifierASGIMiddleware(_asgi_app(seen), make()), [(b"shield360-agent", passport(key).encode())])
    assert sent[0]["status"] == 200 and scope["state"]["shield360_agent"].status == "verified"
    seen.clear()
    scope, sent = _asgi_call(make(policy={"mode": "enforce", "require_agent": True}).asgi(_asgi_app(seen)), [])
    assert not seen and sent[0]["status"] == 403
    assert json.loads(sent[1]["body"]) == {"error": "agent_not_allowed", "reason": "absent"}


def test_wsgi_middleware(env):
    _, key, _, make = env

    def app(environ, start_response):
        start_response("200 OK", [])
        return [b"ok"]

    statuses = []

    def start_response(status, headers):
        statuses.append(status)

    environ = {"HTTP_SHIELD360_AGENT": passport(key), "PATH_INFO": "/v1/jobs", "REQUEST_METHOD": "GET"}
    assert AgentVerifierWSGIMiddleware(app, make())(environ, start_response) == [b"ok"]
    assert environ["shield360.agent"].status == "verified"
    body = make(policy={"mode": "enforce", "requireAgent": True}).wsgi(app)({"PATH_INFO": "/"}, start_response)
    assert statuses[-1].startswith("403") and json.loads(body[0]) == {"error": "agent_not_allowed", "reason": "absent"}


MANDATE = {"id": "m1", "expiresAt": "2026-11-28T12:00:00.000Z"}


def _act(**over):
    return {"sub": "pairwise0123456789abcd", "domain": "acme.com", **over}


def test_new_claims_pass_through(env):
    _, key, _, make = env
    agent = {
        "id": "a1",
        "name": "Dispatch bot",
        "status": "enrolled",
        "environment": "production",
        "risk": "low",
        "owner": {"domain": "acme.com"},
        "reviewedAt": "2026-10-01T00:00:00.000Z",
        "enrolledAt": None,
    }
    r = make().check(passport(key, agent=agent, act=_act(assurance="delegated", mandate=MANDATE)))
    assert r.status == "verified"
    assert r.agent.status == "enrolled" and r.agent.owner.domain == "acme.com" and r.agent.enrolled_at is None
    assert r.on_behalf_of.assurance == "delegated" and r.on_behalf_of.mandate.expires_at == MANDATE["expiresAt"]
    d = r.to_dict()
    assert d["agent"] == {k: v for k, v in agent.items() if v is not None}
    assert d["onBehalfOf"] == {"id": "pairwise0123456789abcd", "domain": "acme.com", "assurance": "delegated", "mandate": MANDATE}


def test_assurance_defaults(env):
    _, key, _, make = env
    assert make().check(passport(key, act=_act())).on_behalf_of.assurance == "named"
    assert make().check(passport(key, act=_act(assurance="super"))).on_behalf_of.assurance == "unverified"


def test_ill_typed_optional_fields_are_dropped(env):
    _, key, _, make = env
    agent = {"id": "a1", "name": "B", "status": "weird", "risk": 5, "owner": "x"}
    r = make().check(passport(key, agent=agent, act=_act(mandate={"id": 1})))
    assert r.status == "verified"
    assert r.agent.to_dict() == {"id": "a1", "name": "B"}
    assert r.on_behalf_of.mandate is None


@pytest.mark.parametrize(
    "minimum,assurance,decision",
    [
        ("none", _MISSING, "allow"),
        ("unverified", _MISSING, "deny"),
        ("unverified", "unverified", "allow"),
        ("named", "unverified", "deny"),
        ("named", None, "allow"),
        ("named", "named", "allow"),
        ("delegated", "named", "deny"),
        ("delegated", "delegated", "allow"),
    ],
)
def test_min_assurance(env, minimum, assurance, decision):
    _, key, _, make = env
    over = {} if assurance is _MISSING else {"act": _act() if assurance is None else _act(assurance=assurance)}
    r = make(policy={"minAssurance": minimum, "mode": "enforce"}).check(passport(key, **over))
    assert r.decision == decision
    if decision == "deny":
        assert (r.reason, r.blocked, r.status) == ("assurance_too_low", True, "verified")


def test_require_on_behalf_of_with_min_assurance(env):
    _, key, _, make = env
    strict = make(policy={"require_on_behalf_of": True, "min_assurance": "delegated"})
    assert strict.check(passport(key)).reason == "on_behalf_of_required"
    assert make(policy={"require_on_behalf_of": True}).check(passport(key, act=_act(assurance="unverified"))).decision == "allow"


def test_online_lowers_assurance(env):
    _, key, net, make = env
    net.verify = lambda body: ok({"valid": True, "assurance": "named", "reason": "mandate_revoked"})
    r = make().check(passport(key, act=_act(assurance="delegated", mandate=MANDATE)), online=True)
    assert (r.status, r.decision, r.reason, r.on_behalf_of.assurance) == ("verified", "allow", "mandate_revoked", "named")
    assert r.on_behalf_of.mandate is None
    token = passport(key, act=_act(assurance="delegated", mandate=MANDATE))
    d = make(policy={"min_assurance": "delegated"}).check(token, online=True)
    assert (d.decision, d.reason) == ("deny", "assurance_too_low")
    net.verify = lambda body: ok({"valid": True, "assurance": "delegated"})
    assert make().check(passport(key, act=_act(assurance="unverified")), online=True).on_behalf_of.assurance == "unverified"


def test_report_carries_new_fields(env):
    _, key, net, make = env
    v = make(report={"api_key": "rk"})
    v.check(passport(key, agent={"id": "a1", "name": "B", "risk": "high"}, act=_act(assurance="delegated", mandate=MANDATE)))
    v.flush()
    entry = net.decisions[0][0]
    assert entry["agent"]["risk"] == "high"
    assert entry["onBehalfOf"]["assurance"] == "delegated" and entry["onBehalfOf"]["mandate"] == MANDATE
    v.close()
