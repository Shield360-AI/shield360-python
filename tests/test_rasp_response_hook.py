"""Response sink hook: an HTML response reflecting request input is reported
through the WSGI, ASGI and Django middleware (monitor only), and the
response itself is never changed or blocked.

Mirrors the response part of sdk/typescript/src/rasp/__tests__/code-hook.test.ts.
"""

import asyncio
import io
import sys
import types

import pytest

from rasp_hook_kit import stop_engine, use_engine
from shield360.rasp import RaspASGIMiddleware, RaspDjangoMiddleware, RaspWSGIMiddleware
from shield360.rasp._hooks.response import MAX_BODY, install_response_hook, uninstall_response_hook

PAYLOAD = "<script>alert(document.domain)</script>"
QUERY = "q=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E"


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_response_hook()
    stop_engine()


def wsgi_app(body, content_type="text/html; charset=utf-8", chunks=1):
    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", content_type)])
        size = max(1, len(body) // chunks)
        return [body[i : i + size] for i in range(0, len(body), size)]

    return app


def call_wsgi(app, query=QUERY):
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/search", "QUERY_STRING": query, "wsgi.input": io.BytesIO()}
    status = []
    out = b"".join(RaspWSGIMiddleware(app)(environ, lambda s, h, *e: status.append(s)))
    return status[0], out


def test_wsgi_reflected_input_is_reported_and_the_response_is_unchanged():
    events = use_engine("block")
    install_response_hook()
    page = f"<html><body>Results for {PAYLOAD}</body></html>".encode()
    status, out = call_wsgi(wsgi_app(page, chunks=3))
    assert status == "200 OK" and out == page
    assert events.attacks() == [("xss", "xss.reflected", "monitored")]
    assert events.sinks() == ["http.response"]


def test_wsgi_escaped_output_json_and_large_bodies_pass():
    events = use_engine("monitor")
    install_response_hook()
    escaped = b"<html>Results for &lt;script&gt;alert(document.domain)&lt;/script&gt;</html>"
    assert call_wsgi(wsgi_app(escaped))[1] == escaped
    assert call_wsgi(wsgi_app(PAYLOAD.encode(), content_type="application/json"))[0] == "200 OK"
    big = PAYLOAD.encode() + b" " * (MAX_BODY + 1)
    assert len(call_wsgi(wsgi_app(big))[1]) == len(big)
    assert not events


def test_nothing_is_collected_while_the_hook_is_off():
    events = use_engine("monitor")
    page = f"<html>{PAYLOAD}</html>".encode()
    assert call_wsgi(wsgi_app(page))[1] == page
    install_response_hook()
    uninstall_response_hook()
    assert call_wsgi(wsgi_app(page))[1] == page
    assert not events


def test_asgi_reflected_input_is_reported_once_across_body_messages():
    events = use_engine("monitor")
    install_response_hook()
    page = f"<html><body>{PAYLOAD}</body></html>".encode()

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/html")]})
        await send({"type": "http.response.body", "body": page[:10], "more_body": True})
        await send({"type": "http.response.body", "body": page[10:]})

    sent = []

    async def run():
        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "GET", "path": "/s", "raw_path": b"/s", "query_string": QUERY.encode(), "headers": []}
        await RaspASGIMiddleware(app)(scope, receive, send)

    asyncio.run(run())
    assert b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body") == page
    assert events.attacks() == [("xss", "xss.reflected", "monitored")]


def test_django_responses_are_checked(monkeypatch):
    events = use_engine("monitor")
    install_response_hook()
    page = f"<html>{PAYLOAD}</html>".encode()

    class Response(dict):
        streaming = False
        content = page

    request = types.SimpleNamespace(
        META={"REQUEST_METHOD": "GET", "PATH_INFO": "/s", "QUERY_STRING": QUERY, "wsgi.input": io.BytesIO()}, body=b""
    )
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    response = RaspDjangoMiddleware(lambda r: Response({"Content-Type": "text/html"}))(request)
    assert response.content == page
    assert events.attacks() == [("xss", "xss.reflected", "monitored")]
