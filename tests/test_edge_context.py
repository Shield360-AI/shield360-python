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
    # Edge always sends X-Request-Id: without it the context is never trusted.
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", None, NOW, None) is None
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", "req_0123456789", NOW + 120, None) is None
    assert verify_edge_context(KEYS, context()[:-3] + "AAA", "POST", "/api/orders", "req_0123456789", NOW, None) is None
    assert verify_edge_context(KEYS, context(extra=1), "POST", "/api/orders", "req_0123456789", NOW, None) is None
    cache = ReplayCache()
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", "req_0123456789", NOW, cache)
    assert verify_edge_context(KEYS, context(), "POST", "/api/orders", "req_0123456789", NOW, cache) is None
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

    env = {"REQUEST_METHOD": "POST", "PATH_INFO": "/api/orders", "QUERY_STRING": "", "wsgi.input": io.BytesIO(b""), "REMOTE_ADDR": "198.51.100.7", "HTTP_X_SHIELD360_EDGE_CONTEXT": header, "HTTP_X_REQUEST_ID": rid}
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


# --- RASP with Edge in front (ASGI, Django, a virtual patch) ------------------

import asyncio  # noqa: E402
import sys  # noqa: E402
import types  # noqa: E402

from rasp_corpus import request_for  # noqa: E402
from shield360.otel.edge_request import current_edge_ids  # noqa: E402
from shield360.rasp import RaspASGIMiddleware, RaspDjangoMiddleware  # noqa: E402
from shield360.rasp._vpatch import BUILT_IN_RULES  # noqa: E402

_VERDICT_FIELDS = {"rid", "iat", "act", "cat", "src", "ttl"}
_HEAD_RULE = next(r for r in BUILT_IN_RULES if r.get("example"))


def _verdict(value):
    from shield360.rasp._edge_context import _open

    return _open(KEYS, "s360-verdict|v1|", value, _VERDICT_FIELDS)


def _live_for(method, path, **over):
    now = int(_time.time())
    _SEQ[0] += 1
    rid = f"req_{now}_{_SEQ[0]}"
    body = {"rid": rid, "iat": now, "exp": now + 30, "m": method, "ph": path_hash(path), "ct": "suspected_agent", "risk": 80, "trap": 2, "fl": True}
    body.update(over)
    p = _b64(json.dumps(body).encode())
    return rid, f"v1.0a1b2c3d.{p}.{_b64(hmac.new(KEY, b's360-ctx|v1|' + p.encode(), hashlib.sha256).digest())}"


def _edge_headers(rid, header, extra=None):
    h = {"x-shield360-edge-context": header, "x-request-id": rid}
    h.update(extra or {})
    return h


def _asgi(app, method="POST", path="/api/orders", headers=None):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(), "query_string": b"", "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()]}
    asyncio.run(RaspASGIMiddleware(app)(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"], {k.decode(): v.decode() for k, v in start.get("headers") or []}


async def _asgi_app(scope, receive, send):
    handle_finding(Finding(attack="sql_injection", rule="sql.tautology"), "sql.query")
    await send({"type": "http.response.start", "status": 201, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"ok"})


def test_asgi_tightens_for_a_flagged_client_and_answers_edge():
    _setup()
    try:
        rid, header = _live()
        status, headers = _asgi(_asgi_app, headers=_edge_headers(rid, header))
        assert status == 403
        v = _verdict(headers["x-shield360-verdict"])
        assert v["rid"] == rid and v["act"] == "block" and v["cat"] == "sql_injection"
        assert EVENTS[0]["attrs"]["shield360.edge.request_id"] == rid
        assert EVENTS[0]["attrs"]["shield360.rasp.tightened_by_edge"] == "true"
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})


def test_asgi_flags_on_the_apps_own_response_and_nothing_without_a_verified_context():
    _setup()
    try:
        rid, calm = _live(fl=False, trap=0, risk=5)
        status, headers = _asgi(_asgi_app, headers=_edge_headers(rid, calm))
        assert status == 201 and headers["content-type"] == "text/plain"
        assert _verdict(headers["x-shield360-verdict"])["act"] == "flag"
        rid2, header = _live()
        status, headers = _asgi(_asgi_app, headers=_edge_headers(rid2, header[:-3] + "AAA"))
        assert status == 201 and "x-shield360-verdict" not in headers
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})


def test_asgi_stamps_edges_request_id_on_what_the_app_logs():
    _setup()
    seen = {}

    async def app(scope, receive, send):
        seen.update(current_edge_ids())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    try:
        rid, header = _live(fl=False, trap=0, risk=5)
        _asgi(app, headers=_edge_headers(rid, header))
        assert seen["request_id"] == rid
        tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
        _asgi(app, headers={"x-request-id": "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6", "traceparent": tp})
        assert seen == {"request_id": "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6", "trace_id": "0af7651916cd43dd8448eb211c80319c", "span_active": False}
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})


def _vp_block_setup():
    _setup()
    set_remote_config(RemoteConfig(version="v", exp=_time.time() + 3600, attacks={"virtual_patch": "block"}, edge_keys=KEYS))


def test_a_request_a_virtual_patch_blocks_still_tells_edge():
    shape = request_for(_HEAD_RULE)
    _vp_block_setup()
    try:
        # ASGI
        rid, header = _live_for(shape.method, "/checkout")
        status, headers = _asgi(_asgi_app, shape.method, "/checkout", _edge_headers(rid, header, shape.headers))
        assert status == 403 and _verdict(headers["x-shield360-verdict"])["cat"] == "virtual_patch"
        # WSGI
        rid, header = _live_for(shape.method, "/checkout")
        out = {}

        def start_response(status, hs, exc_info=None):
            out["status"], out["headers"] = status, dict(hs)

        env = {"REQUEST_METHOD": shape.method, "PATH_INFO": "/checkout", "QUERY_STRING": "", "wsgi.input": io.BytesIO(b""), "HTTP_X_SHIELD360_EDGE_CONTEXT": header, "HTTP_X_REQUEST_ID": rid}
        env.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in shape.headers.items()})
        b"".join(RaspWSGIMiddleware(_app)(env, start_response))
        assert out["status"].startswith("403") and _verdict(out["headers"]["X-Shield360-Verdict"])["act"] == "block"
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})


def test_django_answers_edge_on_the_response_and_on_a_403(monkeypatch):
    class JsonResponse(dict):
        def __init__(self, data, status=200):
            super().__init__()
            self.data, self.status_code = data, status

    class HttpResponse(dict):
        status_code = 200

    http = types.ModuleType("django.http")
    http.JsonResponse = JsonResponse
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    monkeypatch.setitem(sys.modules, "django.http", http)

    def meta(method, path, rid, header, extra=None):
        m = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "", "wsgi.input": io.BytesIO(b""), "HTTP_X_SHIELD360_EDGE_CONTEXT": header, "HTTP_X_REQUEST_ID": rid}
        m.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in (extra or {}).items()})
        return types.SimpleNamespace(META=m, body=b"")

    _setup()
    try:
        rid, calm = _live(fl=False, trap=0, risk=5)

        def view(req):
            handle_finding(Finding(attack="sql_injection", rule="sql.tautology"), "sql.query")
            return HttpResponse()

        resp = RaspDjangoMiddleware(view)(meta("POST", "/api/orders", rid, calm))
        assert _verdict(resp["X-Shield360-Verdict"])["act"] == "flag"

        shape = request_for(_HEAD_RULE)
        _vp_block_setup()
        rid, header = _live_for(shape.method, "/checkout")
        blocked = RaspDjangoMiddleware(lambda req: "ran")(meta(shape.method, "/checkout", rid, header, shape.headers))
        assert blocked.status_code == 403 and _verdict(blocked["X-Shield360-Verdict"])["cat"] == "virtual_patch"
    finally:
        set_event_sink(None)
        configure_engine(enabled=False, application_name="default", env={})
