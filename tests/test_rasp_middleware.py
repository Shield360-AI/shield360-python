"""Middleware: inputs recorded in the request's context (query, params, body,
cookies, the input headers), virtual patches run before the handler, the
block error mapped to the contract's 403. Frameworks are not dependencies of
the SDK, so everything is driven through the WSGI and ASGI interfaces; the
Flask and Django adapters run against small stand-ins for the framework.

Mirrors sdk/typescript/src/rasp/__tests__/middleware.test.ts.
"""

import asyncio
import io
import json
import sys
import types

import pytest

from rasp_corpus import request_for
from shield360.rasp import (
    BLOCK_MESSAGE,
    RaspASGIMiddleware,
    RaspBlockedError,
    RaspDjangoMiddleware,
    RaspWSGIMiddleware,
    rasp_flask,
    record_model_response,
    record_request_body,
)
from shield360.rasp._capture import capture_request
from shield360.rasp._context import current_context, inputs_of, reset_context, run_in_rasp_scope, run_with_inputs, set_context
from shield360.rasp._engine import configure_engine, set_event_sink
from shield360.rasp._vpatch import BUILT_IN_RULES

EXAMPLE_RULE = next(r for r in BUILT_IN_RULES if r.get("example"))
EXAMPLE_HEADERS = request_for(EXAMPLE_RULE).headers
EVENTS = []


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)


def set_mode(vp, **extra):
    configure_engine(enabled=True, application_name="orders-api", attacks={"virtual_patch": vp, **extra}, env={})
    set_event_sink(_Sink())


@pytest.fixture(autouse=True)
def _engine():
    EVENTS.clear()
    set_mode("monitor")
    yield
    set_event_sink(None)
    configure_engine(enabled=False, application_name="default", env={})


def keys():
    ctx = current_context()
    return {i.key: i.value for i in inputs_of(ctx)} if ctx else None


# ---- WSGI ----


def environ(path="/", query="", method="GET", headers=None, body=b""):
    env = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "SCRIPT_NAME": "",
        "QUERY_STRING": query,
        "wsgi.input": io.BytesIO(body),
    }
    if body:
        env["CONTENT_LENGTH"] = str(len(body))
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            env["CONTENT_TYPE"] = v
        else:
            env["HTTP_" + k.upper().replace("-", "_")] = v
    return env


def call_wsgi(app, env):
    out = {}

    def start_response(status, headers, exc_info=None):
        out["status"] = status
        out["headers"] = dict(headers)

    result = app(env, start_response)
    try:
        out["body"] = b"".join(result)
    finally:
        if hasattr(result, "close"):
            result.close()
    return out


def json_app(produce):
    def app(env, start_response):
        body = json.dumps(produce(env)).encode()
        start_response("200 OK", [("Content-Type", "application/json")])
        return [body]

    return app


def test_wsgi_records_query_cookies_and_input_headers_in_the_request_context_only():
    app = RaspWSGIMiddleware(json_app(lambda env: keys()))
    got = json.loads(
        call_wsgi(
            app,
            environ(
                "/items/42",
                "q=hello%20world",
                headers={"Cookie": "sid=abc123; theme=dark", "User-Agent": "test-agent/1", "X-Other": "skip"},
            ),
        )["body"]
    )
    assert got["query.q"] == "hello world"
    assert got["cookie.sid"] == "abc123"
    assert got["header.user-agent"] == "test-agent/1"
    assert "header.x-other" not in got
    assert current_context() is None


def test_wsgi_virtual_patch_in_block_mode_answers_403_monitor_lets_it_through():
    set_mode("block")
    app = RaspWSGIMiddleware(json_app(lambda env: {"ok": True}))
    blocked = call_wsgi(app, environ(headers=EXAMPLE_HEADERS))
    assert blocked["status"].startswith("403")
    assert blocked["headers"]["Content-Type"] == "application/json"
    assert json.loads(blocked["body"]) == {
        "error": BLOCK_MESSAGE,
        "attack": "virtual_patch",
        "rule": EXAMPLE_RULE["id"],
        "event": EVENTS[0]["attrs"]["shield360.rasp.event_id"],
    }
    a = EVENTS[0]["attrs"]
    assert a["shield360.rasp.decision"] == "blocked" and a["shield360.rasp.framework"] == "wsgi"
    assert a["shield360.rasp.sink"] == "server.request"
    set_mode("monitor")
    assert call_wsgi(app, environ(headers=EXAMPLE_HEADERS))["status"].startswith("200")
    assert EVENTS[1]["attrs"]["shield360.rasp.decision"] == "monitored"


def test_wsgi_reads_the_body_records_its_leaves_and_hands_it_to_the_app_unchanged():
    payload = json.dumps({"user": {"name": "O'Brien"}, "tags": ["a1", "b2"]}).encode()

    def produce(env):
        return {"keys": keys(), "body": env["wsgi.input"].read().decode()}

    env = environ("/orders", "sort=name", "POST", {"Content-Type": "application/json"}, payload)
    got = json.loads(call_wsgi(RaspWSGIMiddleware(json_app(produce)), env)["body"])
    assert got["body"] == payload.decode()
    assert got["keys"]["query.sort"] == "name"
    assert got["keys"]["body.user.name"] == "O'Brien"
    assert got["keys"]["body.tags.0"] == "a1"


def test_wsgi_form_body_fields():
    got = json.loads(
        call_wsgi(
            RaspWSGIMiddleware(json_app(lambda env: keys())),
            environ(
                "/form", method="POST", headers={"Content-Type": "application/x-www-form-urlencoded"}, body=b"name=Ana&city=Lisbon"
            ),
        )["body"]
    )
    assert got["body.city"] == "Lisbon"


def test_wsgi_maps_a_block_error_from_the_app_and_from_a_streamed_body_to_403():
    def raising(env, start_response):
        raise RaspBlockedError("sql_injection", "sqli.userinput", "e" * 32)

    out = call_wsgi(RaspWSGIMiddleware(raising), environ())
    assert out["status"].startswith("403")
    assert json.loads(out["body"]) == {"error": BLOCK_MESSAGE, "attack": "sql_injection", "rule": "sqli.userinput", "event": "e" * 32}

    def streaming(env, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        assert current_context() is not None  # the body is produced in the request's context
        raise RaspBlockedError("ssrf", "ssrf.internal", "f" * 32)
        yield b"never"  # pylint: disable=unreachable

    out = call_wsgi(RaspWSGIMiddleware(streaming), environ())
    assert out["status"].startswith("403") and json.loads(out["body"])["rule"] == "ssrf.internal"


def test_wsgi_other_errors_propagate():
    def broken(env, start_response):
        raise ValueError("app error")

    with pytest.raises(ValueError):
        call_wsgi(RaspWSGIMiddleware(broken), environ())


def test_wsgi_inactive_the_app_runs_with_no_context():
    configure_engine(enabled=False, application_name="a", env={})
    app = RaspWSGIMiddleware(json_app(lambda env: {"ctx": keys()}))
    got = json.loads(call_wsgi(app, environ(query="q=x", headers=EXAMPLE_HEADERS))["body"])
    assert got == {"ctx": None}


def test_record_request_body_adds_the_body_and_runs_the_body_rules():
    set_mode("block")
    clause = {"target": "body", "op": "contains_any", "values": ["marker-xyz"]}
    body_rule = {"id": "vp.test-body", "action": "block", "match": [clause]}
    from shield360.rasp._engine import RemoteConfig, set_remote_config

    set_remote_config(RemoteConfig(version="v", exp=9e9, attacks={"virtual_patch": "block"}, rules=[body_rule]))
    ctx = capture_request("wsgi", "POST", "/form", {})
    token = set_context(ctx)
    try:
        record_request_body("name=Ana&city=Lisbon", "application/x-www-form-urlencoded")
        assert keys()["body.city"] == "Lisbon"
    finally:
        reset_context(token)
    ctx = capture_request("wsgi", "POST", "/action", {})
    token = set_context(ctx)
    try:
        with pytest.raises(RaspBlockedError) as err:
            record_request_body("x marker-xyz y", "text/plain")
        assert err.value.rule == "vp.test-body"
    finally:
        reset_context(token)


# ---- ASGI ----


def run_asgi(app, method="GET", path="/", query=b"", headers=None, chunks=None):
    sent = []
    chunks = chunks or [b""]
    pending = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]

    async def receive():
        if pending:
            return pending.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": query,
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    asyncio.run(app(scope, receive, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return (start or {}).get("status"), body


def asgi_json(produce):
    async def app(scope, receive, send):
        body = json.dumps(await produce(scope, receive)).encode()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})

    return app


async def read_all(receive):
    data = b""
    while True:
        m = await receive()
        data += m.get("body", b"")
        if not m.get("more_body"):
            return data


def test_asgi_records_query_headers_and_a_chunked_body_and_replays_the_body():
    async def produce(scope, receive):
        body = await read_all(receive)
        return {"keys": keys(), "body": body.decode()}

    payload = json.dumps({"profile": {"bio": "hello there"}}).encode()
    status, body = run_asgi(
        RaspASGIMiddleware(asgi_json(produce), framework="fastapi"),
        "POST",
        "/users/7",
        b"expand=roles",
        {"user-agent": "ua/1", "content-type": "application/json"},
        [payload[:10], payload[10:]],
    )
    got = json.loads(body)
    assert status == 200
    assert got["body"] == payload.decode()
    assert got["keys"]["query.expand"] == "roles"
    assert got["keys"]["header.user-agent"] == "ua/1"
    assert got["keys"]["body.profile.bio"] == "hello there"


def test_asgi_blocks_a_virtual_patch_before_the_app_and_maps_a_block_error_from_it():
    set_mode("block")
    ran = []

    async def produce(scope, receive):
        ran.append(True)
        return {}

    status, body = run_asgi(RaspASGIMiddleware(asgi_json(produce)), headers=EXAMPLE_HEADERS)
    assert status == 403 and not ran
    assert json.loads(body)["rule"] == EXAMPLE_RULE["id"]
    assert EVENTS[0]["attrs"]["shield360.rasp.framework"] == "asgi"

    async def raising(scope, receive, send):
        raise RaspBlockedError("code_injection", "code.eval", "a" * 32)

    status, body = run_asgi(RaspASGIMiddleware(raising))
    assert status == 403 and json.loads(body)["event"] == "a" * 32

    async def broken(scope, receive, send):
        raise ValueError("app error")

    with pytest.raises(ValueError):
        run_asgi(RaspASGIMiddleware(broken))


def test_asgi_a_block_error_after_the_response_started_ends_the_response():
    async def late(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"part", "more_body": True})
        raise RaspBlockedError("xxe", "xxe.file", "b" * 32)

    status, body = run_asgi(RaspASGIMiddleware(late))
    assert status == 200 and body == b"part"


def test_asgi_passes_other_scopes_and_inactive_requests_straight_through():
    calls = []

    async def app(scope, receive, send):
        calls.append(current_context())

    asyncio.run(RaspASGIMiddleware(app)({"type": "lifespan"}, None, None))
    configure_engine(enabled=False, application_name="a", env={})
    run_asgi(RaspASGIMiddleware(app), headers=EXAMPLE_HEADERS)
    assert calls == [None, None]


# ---- Flask ----


def test_flask_adapter_wraps_wsgi_app_maps_the_block_error_and_records_the_route(monkeypatch):
    class FakeFlask:
        def __init__(self):
            self.wsgi_app = json_app(lambda env: keys())
            self.handlers = {}
            self.before = []

        def register_error_handler(self, exc, fn):
            self.handlers[exc] = fn

        def before_request(self, fn):
            self.before.append(fn)

    app = rasp_flask(FakeFlask())
    assert isinstance(app.wsgi_app, RaspWSGIMiddleware) and app.wsgi_app.framework == "flask"
    body, status, headers = app.handlers[RaspBlockedError](RaspBlockedError("sql_injection", "sqli.userinput", "c" * 32))
    assert status == 403 and body["error"] == BLOCK_MESSAGE and headers["Cache-Control"] == "no-store"

    fake = types.ModuleType("flask")
    fake.request = types.SimpleNamespace(url_rule=types.SimpleNamespace(rule="/orders/<int:order_id>"), view_args={"order_id": "17"})
    monkeypatch.setitem(sys.modules, "flask", fake)
    token = set_context(capture_request("flask", "GET", "/orders/17", {}))
    try:
        app.before[0]()
        assert current_context().route == "/orders/:order_id"
        assert keys()["params.order_id"] == "17"
    finally:
        reset_context(token)


# ---- Django ----


def test_django_middleware_records_the_request_route_and_maps_the_block_error(monkeypatch):
    class JsonResponse(dict):
        def __init__(self, data, status=200):
            super().__init__()
            self.data, self.status_code = data, status

    http = types.ModuleType("django.http")
    http.JsonResponse = JsonResponse
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    monkeypatch.setitem(sys.modules, "django.http", http)

    payload = json.dumps({"note": "later"}).encode()
    meta = environ("/api/orders/9", "view=full", "POST", {"Content-Type": "application/json", "User-Agent": "dj"}, payload)
    request = types.SimpleNamespace(META=meta, body=payload, resolver_match=types.SimpleNamespace(route="api/orders/<int:pk>"))
    seen = {}

    def get_response(req):
        mw.process_view(req, None, (), {"pk": "9"})
        seen.update(keys() or {})
        seen["route"] = current_context().route
        return "ok"

    mw = RaspDjangoMiddleware(get_response)
    assert mw(request) == "ok"
    assert seen["query.view"] == "full" and seen["body.note"] == "later" and seen["params.pk"] == "9"
    assert seen["route"] == "/api/orders/:pk"
    assert current_context() is None

    resp = mw.process_exception(request, RaspBlockedError("ssrf", "ssrf.internal", "d" * 32))
    assert resp.status_code == 403 and resp.data["rule"] == "ssrf.internal" and resp["Cache-Control"] == "no-store"
    assert mw.process_exception(request, ValueError("x")) is None

    set_mode("block")
    blocked = RaspDjangoMiddleware(lambda req: "ran")(types.SimpleNamespace(META=environ(headers=EXAMPLE_HEADERS), body=b""))
    assert blocked.status_code == 403 and blocked.data["rule"] == EXAMPLE_RULE["id"]


# ---- model output as input ----


def in_request(fn):
    token = set_context(capture_request("wsgi", "POST", "/chat", {}))
    try:
        return fn()
    finally:
        reset_context(token)


def test_records_completion_fragments_and_tool_call_argument_leaves_openai_shape():
    def run():
        record_model_response(
            {
                "choices": [
                    {
                        "message": {
                            "content": "first line\nsecond line",
                            "tool_calls": [{"function": {"name": "run_query", "arguments": json.dumps({"sql": "select 1"})}}],
                        }
                    }
                ]
            }
        )
        return inputs_of(current_context())

    got = in_request(run)
    assert [(i.key, i.value) for i in got if i.source == "model_output"] == [
        ("model.completion", "first line"),
        ("model.completion", "second line"),
        ("model.tool.run_query.sql", "select 1"),
    ]


def test_records_openai_responses_and_anthropic_shapes_and_sdk_objects():
    def run():
        call = {"type": "function_call", "name": "lookup", "arguments": '{"id": "A-1"}'}
        record_model_response({"output": [call, {"content": [{"text": "done"}]}]})
        tool = {"type": "tool_use", "name": "fetch_page", "input": {"url": "https://example.com"}}
        record_model_response({"content": [{"type": "text", "text": "hello"}, tool]})

        class Obj:
            def model_dump(self):
                return {"content": [{"type": "text", "text": "from object"}]}

        record_model_response(Obj())
        return [i.key for i in inputs_of(current_context())]

    assert in_request(run) == [
        "model.tool.lookup.id",
        "model.completion",
        "model.completion",
        "model.tool.fetch_page.url",
        "model.completion",
    ]


def test_records_nothing_when_rasp_is_off_or_model_output_is_false():
    def recorded():
        record_model_response({"content": [{"type": "text", "text": "x"}]})
        return len(current_context().inputs)

    configure_engine(enabled=True, application_name="a", model_output=False, env={})
    assert in_request(recorded) == 0
    configure_engine(enabled=False, application_name="a", env={})
    assert in_request(recorded) == 0


def test_outside_a_request_model_output_starts_a_scope_and_run_in_rasp_scope_isolates_it():
    def job():
        record_model_response({"content": [{"type": "text", "text": "rm -rf build"}]})
        ctx = current_context()
        return ctx is not None and not ctx.in_request and [i.value for i in ctx.inputs]

    assert run_in_rasp_scope(job) == ["rm -rf build"]
    assert current_context() is None

    async def ajob():
        await asyncio.sleep(0)
        return job()

    assert asyncio.run(run_in_rasp_scope(ajob)) == ["rm -rf build"]
    assert run_with_inputs([("v1", "query.a", "request")], lambda: [i.key for i in current_context().inputs]) == ["query.a"]


def test_django_streaming_body_keeps_the_request_context_and_leaves_none_behind(monkeypatch):
    """Django iterates a StreamingHttpResponse after the middleware returns: the
    body is produced with the request's inputs, and nothing is left set on the thread."""
    http = types.ModuleType("django.http")
    http.JsonResponse = dict
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    monkeypatch.setitem(sys.modules, "django.http", http)
    seen = []

    def body():
        seen.append(dict(keys() or {}))
        record_model_response({"content": [{"type": "text", "text": "streamed answer"}]})
        seen.append([i.value for i in inputs_of(current_context()) if i.source == "model_output"])
        yield b"chunk"

    class Streaming:
        streaming = True
        is_async = False

        def __init__(self, content):
            self.streaming_content = content

    request = types.SimpleNamespace(META=environ("/stream", "q=abc"), body=b"")
    response = RaspDjangoMiddleware(lambda req: Streaming(body()))(request)
    assert current_context() is None
    assert b"".join(response.streaming_content) == b"chunk"
    assert seen[0]["query.q"] == "abc"
    assert seen[1] == ["streamed answer"]
    assert current_context() is None


def test_model_output_outside_any_context_never_leaves_a_context_set():
    record_model_response({"content": [{"type": "text", "text": "worker answer"}]})
    assert current_context() is None  # a plain (pooled) thread: nothing set for the next job

    async def task():
        record_model_response({"content": [{"type": "text", "text": "task answer"}]})
        return [i.value for i in current_context().inputs]

    assert asyncio.run(task()) == ["task answer"]  # inside a task: recorded, and ended with the task
    assert current_context() is None


def test_environ_url_keeps_the_query_when_the_raw_uri_has_none():
    """Werkzeug's test client sets RAW_URI / REQUEST_URI to the path alone; the query is still input."""
    from shield360.rasp._middleware import _environ_url  # pylint: disable=import-outside-toplevel

    assert _environ_url({"RAW_URI": "/a", "QUERY_STRING": "q=1"}) == "/a?q=1"
    assert _environ_url({"REQUEST_URI": "/a?q=1", "QUERY_STRING": "q=1"}) == "/a?q=1"
    assert _environ_url({"RAW_URI": "/a"}) == "/a"
