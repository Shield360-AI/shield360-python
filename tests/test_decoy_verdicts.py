"""SHIELD: decoy and trap verdicts (agent-guides/edge-deception-spec.md, "What each layer does";
sdk/rasp/README.md "Deception"): a decoy or Defend trap hit behind Edge carries a signed
X-Shield360-Verdict, so Edge blocks the client fleet-wide; never without a verified context,
for a verified crawler, a red team run or the simulated client."""

import asyncio
import base64
import hashlib
import hmac
import io
import json
import time

import pytest

from shield360.rasp import RaspASGIMiddleware, RaspWSGIMiddleware
from shield360.rasp._deception import SuspiciousTable, set_suspicious_table
from shield360.rasp._edge_context import VERDICT_HEADER, _open, parse_edge_keys, path_hash
from shield360.rasp._engine import RemoteConfig, configure_engine, set_event_sink, set_remote_config

EDGE_KEY = b"0123456789abcdef0123456789abcdef"
SECRET = b"0123456789abcdef0123456789abcdef"


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


KEYS = parse_edge_keys({"keys": [{"kid": "0a1b2c3d", "key": b64(EDGE_KEY)}]})
_n = [0]


def ctx(path, **over):
    _n[0] += 1
    now = int(time.time())
    rid = f"req_dv_{_n[0]:06d}"
    payload = {"rid": rid, "iat": now, "exp": now + 30, "m": "GET", "ph": path_hash(path), "ct": "unknown", "risk": 0, "trap": 0, "fl": False}
    payload.update(over)
    p = b64(json.dumps(payload).encode())
    return rid, f"v1.0a1b2c3d.{p}.{b64(hmac.new(EDGE_KEY, ('s360-ctx|v1|' + p).encode(), hashlib.sha256).digest())}"


def verdict_of(value):
    return _open(KEYS, "s360-verdict|v1|", value, {"rid", "iat", "act", "cat", "src", "ttl"})


class _Sink:
    def __init__(self):
        self.events = []

    def add(self, event, fold_key):
        self.events.append(event)


@pytest.fixture
def sink():
    s = _Sink()
    configure_engine(enabled=True, application_name="orders-api", attacks={"ai_attack_agent": "off"}, env={})
    set_event_sink(s)
    set_suspicious_table(SuspiciousTable())
    yield s
    set_event_sink(None)
    set_remote_config(None)
    set_suspicious_table()
    configure_engine(enabled=False, application_name="default", env={})


def signed(action="block", keyed=True):
    set_remote_config(
        RemoteConfig(
            version="v-dv",
            exp=time.time() + 3600,
            kill_switch=False,
            attacks={},
            deception={"paths": ["/wp-admin"], "action": action, "ttlSeconds": 1200},
            edge_keys=KEYS if keyed else [],
        )
    )


def wsgi(path, ip="203.0.113.7", rid=None, header=None):
    env = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "SCRIPT_NAME": "", "QUERY_STRING": "", "wsgi.input": io.BytesIO(b""), "REMOTE_ADDR": ip}
    if header:
        env["HTTP_X_SHIELD360_EDGE_CONTEXT"] = header
        env["HTTP_X_REQUEST_ID"] = rid
    out = {}

    def start_response(status, headers, exc_info=None):
        out["status"], out["headers"] = status, dict(headers)

    calls = []

    def app(e, sr):
        calls.append(e["PATH_INFO"])
        sr("200 OK", [])
        return [b"ok"]

    b"".join(RaspWSGIMiddleware(app)(env, start_response))
    assert not calls
    return out


def test_rasp_decoy_hit_behind_edge_blocks_with_the_deception_ttl(sink):
    signed("block")
    rid, h = ctx("/wp-admin/setup.php")
    out = wsgi("/wp-admin/setup.php", rid=rid, header=h)
    assert out["status"].startswith("404")
    v = verdict_of(out["headers"][VERDICT_HEADER])
    assert v == {**v, "rid": rid, "act": "block", "cat": "deception", "src": "rasp", "ttl": 1200}
    assert sink.events[-1]["attrs"]["shield360.rasp.rule"] == "deception.hit"


def test_rasp_decoy_hit_flags_in_monitor_and_sends_nothing_when_exempt(sink):
    signed("monitor")
    rid, h = ctx("/wp-admin")
    assert verdict_of(wsgi("/wp-admin", rid=rid, header=h)["headers"][VERDICT_HEADER])["act"] == "flag"
    signed("block")
    assert VERDICT_HEADER not in wsgi("/wp-admin")["headers"]
    for over, ip in (({"ct": "verified_crawler"}, "203.0.113.8"), ({"rt": "crun12345678"}, "203.0.113.9"), ({}, "192.0.2.1")):
        rid, h = ctx("/wp-admin", **over)
        assert VERDICT_HEADER not in wsgi("/wp-admin", ip=ip, rid=rid, header=h)["headers"]
    rid, h = ctx("/wp-admin")
    assert VERDICT_HEADER not in wsgi("/wp-admin", rid=rid, header=h[:-2] + "xx")["headers"]
    assert sum(1 for e in sink.events if e["attrs"]["shield360.rasp.rule"] == "deception.hit") == 6
    signed("block", keyed=False)
    rid, h = ctx("/wp-admin")
    assert VERDICT_HEADER not in wsgi("/wp-admin", rid=rid, header=h)["headers"]


def test_rasp_asgi_decoy_404_carries_the_verdict(sink):
    signed("block")
    rid, h = ctx("/wp-admin")
    sent = []

    async def app(scope, receive, send):
        raise AssertionError("the decoy reached the app")

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(m):
        sent.append(m)

    scope = {"type": "http", "method": "GET", "path": "/wp-admin", "raw_path": b"/wp-admin", "query_string": b"", "client": ("203.0.113.7", 1), "headers": [(b"x-shield360-edge-context", h.encode()), (b"x-request-id", rid.encode())]}
    asyncio.run(RaspASGIMiddleware(app)(scope, receive, send))
    start = sent[0]
    assert start["status"] == 404
    got = dict((bytes(k).decode(), bytes(v).decode()) for k, v in start["headers"])
    assert verdict_of(got[VERDICT_HEADER.lower()])["cat"] == "deception"


def test_defend_trap_hit_behind_edge_blocks_cat_trap_src_defend(tmp_path):
    from test_defend import Server, claims, make  # pylint: disable=import-outside-toplevel

    edge = {"keys": [{"kid": "0a1b2c3d", "key": b64(EDGE_KEY)}]}
    hp = {"enabled": True, "mode": "block", "secret": b64(SECRET)}
    d = make(Server(claims(honeypots=hp, edgeContext=edge, traps={"action": "block", "ttlSeconds": 1800})), tmp_path, report=False)
    ip = "203.0.113.40"
    path = d.crumbs({"method": "GET", "path": "/", "ip": ip, "headers": {"user-agent": "agent/1"}})["path"]

    def hit(ip, **over):
        rid, h = ctx(path, **over)
        return rid, d.defend({"method": "GET", "path": path, "ip": ip, "headers": {"user-agent": "agent/1", "x-shield360-edge-context": h, "x-request-id": rid}})

    rid, r = hit(ip)
    assert r["decoy"]
    v = verdict_of(r["verdict"])
    assert v == {**v, "rid": rid, "act": "block", "cat": "trap", "src": "defend", "ttl": 1800}
    for over, other in (({"ct": "verified_crawler"}, "203.0.113.41"), ({"rt": "crun12345678"}, "203.0.113.42"), ({}, "192.0.2.1")):
        path = d.crumbs({"method": "GET", "path": "/", "ip": other, "headers": {"user-agent": "agent/1"}})["path"]
        assert "verdict" not in hit(other, **over)[1]

    # The WSGI middleware puts it on the decoy answer.
    path = d.crumbs({"method": "GET", "path": "/", "ip": "203.0.113.43", "headers": {"user-agent": "agent/1"}})["path"]
    rid, h = ctx(path)
    seen = {}

    def start_response(status, headers, exc_info=None):
        seen.update(dict(headers))

    env = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": "", "REMOTE_ADDR": "203.0.113.43", "HTTP_USER_AGENT": "agent/1", "HTTP_X_SHIELD360_EDGE_CONTEXT": h, "HTTP_X_REQUEST_ID": rid}
    d.wsgi(lambda e, sr: [b"app"])(env, start_response)
    assert verdict_of(seen[VERDICT_HEADER])["act"] == "block"
