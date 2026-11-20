"""SHIELD: protection triangle — Edge's context header and the app's verdict
(the shared wire format; the verdict matches the Go and TypeScript vector)."""

import base64
import hashlib
import hmac
import json

from shield360.rasp._edge_context import ReplayCache, edge_says_suspect, parse_edge_keys, path_hash, sign_verdict, verify_edge_context

KEY = b"0123456789abcdef0123456789abcdef"
KEYS = [("0a1b2c3d", KEY)]
NOW = 1800000000


def _b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def context(**over):
    body = {"rid": "req_0123456789", "iat": NOW, "exp": NOW + 30, "m": "POST", "ph": path_hash("/api/orders"), "ct": "suspected_agent", "risk": 80, "trap": 2, "fl": True}
    body.update(over)
    p = _b64(json.dumps(body).encode())
    return "v1.0a1b2c3d.%s.%s" % (p, _b64(hmac.new(KEY, b"s360-ctx|v1|" + p.encode(), hashlib.sha256).digest()))


def test_context_verifies_and_is_bound():
    c = verify_edge_context(KEYS, context(), "POST", "/api/orders", "req_0123456789", NOW, ReplayCache())
    assert c and c["risk"] == 80 and edge_says_suspect(c)
    assert verify_edge_context(KEYS, context(), "POST", "/api/admin", None, NOW, None) is None
    assert verify_edge_context(KEYS, context(), "GET", "/api/orders", None, NOW, None) is None
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", "req_other_1234", NOW, None) is None
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", None, NOW + 120, None) is None
    assert verify_edge_context(KEYS, context()[:-3] + "AAA", "POST", "/api/orders", None, NOW, None) is None
    assert verify_edge_context(KEYS, context(extra=1), "POST", "/api/orders", None, NOW, None) is None
    cache = ReplayCache()
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", None, NOW, cache)
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", None, NOW, cache) is None
    assert not edge_says_suspect({"ct": "human", "fl": False, "trap": 0, "risk": 10})


def test_verdict_matches_the_shared_vector():
    v = sign_verdict(KEYS, "req_0123456789", "block", "sql_injection", "rasp", 600, iat=1800000000)
    assert v == "v1.0a1b2c3d.eyJyaWQiOiJyZXFfMDEyMzQ1Njc4OSIsImlhdCI6MTgwMDAwMDAwMCwiYWN0IjoiYmxvY2siLCJjYXQiOiJzcWxfaW5qZWN0aW9uIiwic3JjIjoicmFzcCIsInR0bCI6NjAwfQ.oMGW2qT7G2DmQ6YrtxWyfCwzxWUhrAZUAo2cfbf5Nj8"
    assert sign_verdict(KEYS, "x", "block", "sql_injection") is None


def test_keys_parse_strictly():
    assert parse_edge_keys({"keys": [{"kid": "0a1b2c3d", "key": _b64(KEY)}]}) == KEYS
    assert parse_edge_keys({"keys": [{"kid": "nope", "key": _b64(KEY)}]}) == []
    assert parse_edge_keys(None) == []


# --- RASP with Edge in front (WSGI) ------------------------------------------

import io  # noqa: E402
import time as _time  # noqa: E402

from shield360.rasp import RaspWSGIMiddleware  # noqa: E402
from shield360.rasp._edge_context import verify_edge_context as _verify  # noqa: E402,F401
from shield360.rasp._engine import RemoteConfig, configure_engine, handle_finding, set_event_sink, set_remote_config  # noqa: E402
from shield360.rasp._types import Finding, RaspBlockedError  # noqa: E402

EVENTS = []


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)


_SEQ = [0]


def _live(**over):
    now = int(_time.time())
    _SEQ[0] += 1
    rid = "req_%d_%d" % (now, _SEQ[0])
    body = {"rid": rid, "iat": now, "exp": now + 30, "m": "POST", "ph": path_hash("/api/orders"), "ct": "suspected_agent", "risk": 80, "trap": 2, "fl": True}
    body.update(over)
    p = _b64(json.dumps(body).encode())
    return rid, "v1.0a1b2c3d.%s.%s" % (p, _b64(hmac.new(KEY, b"s360-ctx|v1|" + p.encode(), hashlib.sha256).digest()))


def _app(environ, start_response):
    try:
        handle_finding(Finding(attack="sql_injection", rule="sql.tautology"), "sql.query")
    except RaspBlockedError:
        raise
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


def _call(header, rid):
    out = {}

    def start_response(status, headers, exc_info=None):
        out["status"] = status
        out["headers"] = dict(headers)

    env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/api/orders", "QUERY_STRING": "", "wsgi.input": io.BytesIO(b""), "REMOTE_ADDR": "198.51.100.7", "HTTP_X_SHIELD360_EDGE_CONTEXT": header, "HTTP_X_SHIELD360_REQUEST_ID": rid}
    b"".join(RaspWSGIMiddleware(_app)(env, start_response))
    return out


def _setup():
    EVENTS.clear()
    configure_engine(enabled=True, application_name="orders-api", attacks={"sql_injection": "monitor"}, env={})
    set_remote_config(RemoteConfig(version="v", exp=_time.time() + 3600, attacks={"sql_injection": "monitor"}, edge_keys=KEYS))
    set_event_sink(_Sink())


def test_wsgi_tightens_for_a_flagged_client_and_answers_edge():
    _setup()
    try:
        rid, header = _live()
        out = _call(header, rid)
        assert out["status"].startswith("403")
        from shield360.rasp._edge_context import _open  # the verdict verifies with the shared key

        verdict = _open(KEYS, "s360-verdict|v1|", out["headers"]["X-Shield360-Verdict"], {"rid", "iat", "act", "cat", "src", "ttl"})
        assert verdict["rid"] == rid and verdict["act"] == "block" and verdict["cat"] == "sql_injection"
        assert EVENTS and EVENTS[0]["attrs"]["shield360.edge.request_id"] == rid
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})


def test_wsgi_unverified_header_changes_nothing():
    _setup()
    try:
        rid, header = _live()
        out = _call(header[:-3] + "AAA", rid)
        assert out["status"].startswith("200") and "X-Shield360-Verdict" not in out["headers"]
        _rid2, calm = _live(fl=False, trap=0, risk=5)
        out = _call(calm, _rid2)
        assert out["status"].startswith("200")
        assert out["headers"].get("X-Shield360-Verdict")  # monitored detection: Edge is told to flag
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})
