"""Outbound HTTP sink hook: urllib, http.client, requests and httpx, the URL
checks before anything is sent, and the check against the addresses the
connection resolves (DNS rebinding). Everything is local: a server on
127.0.0.1, a stand-in resolver, and stand-in httpx and requests modules
(plus the real requests over the local server and the stand-in resolver).

Mirrors sdk/typescript/src/rasp/__tests__/http-hook.test.ts.
"""

import asyncio
import http.client
import http.server
import socket
import sys
import threading
import types
import urllib.error
import urllib.request

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError, _detect, always_allowed_hosts
from shield360.rasp._hooks.http import connection_url, install_http_hooks, uninstall_http_hooks

REBIND = "rebind.example"
REAL_GETADDRINFO = socket.getaddrinfo


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_http_hooks()
    stop_engine()


@pytest.fixture(name="server")
def _server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # pylint: disable=invalid-name
            if self.path.startswith("/redirect"):
                self.send_response(302)
                self.send_header("Location", "http://forbidden.example/landing")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # pylint: disable=arguments-differ
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(name="rebinding")
def _rebinding(monkeypatch):
    """A resolver that answers REBIND with a private address (the second answer of a rebinding server)."""
    asked = []

    def fake(host, port, *args, **kwargs):
        asked.append(host)
        if host == REBIND:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port or 80))]
        return REAL_GETADDRINFO(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return asked


def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read()


def test_connection_url_rebuilds_what_http_client_requests():
    class Conn:
        host, port, default_port = "api.example.com", 8080, 80

    class Tls:
        host, port, default_port = "::1", 443, 443

    class Tunnel:
        host, port, default_port, _tunnel_host, _tunnel_port = "proxy", 3128, 443, "inner.example", 443

    assert connection_url(Conn(), "/v1?q=1") == "http://api.example.com:8080/v1?q=1"
    assert connection_url(Tls(), "/") == "https://[::1]/"
    assert connection_url(Tunnel(), "/x") == "https://inner.example/x"
    assert connection_url(Conn(), "http://other.example/abs") == "http://other.example/abs"


def test_a_tainted_literal_is_blocked_before_anything_is_sent():
    events = use_engine("block")
    install_http_hooks([])
    url = "http://127.0.0.1:9/fixture"
    with pytest.raises(RaspBlockedError) as e:
        in_request([url], lambda: get(url))
    assert e.value.rule == "ssrf.internal"
    assert events.sinks() == ["urllib.request.urlopen"]


def test_untainted_loopback_passes_and_monitor_reports_once(server):
    events = use_engine("monitor")
    install_http_hooks([])
    assert get(server + "/a") == b"ok"
    assert in_request(["hello"], lambda: get(server + "/b")) == b"ok"
    assert not events
    assert in_request([server + "/c"], lambda: get(server + "/c")) == b"ok"
    # The http.client request underneath urlopen is part of the same call.
    assert events.attacks() == [("ssrf", "ssrf.internal", "monitored")]


def test_the_outbound_allow_list_applies_without_taint_and_always_allowed_hosts_pass(server):
    events = use_engine("block", allow={"outbound_hosts": ["api.example.com"]})
    install_http_hooks([])
    with pytest.raises(RaspBlockedError) as e:
        get(server + "/x")
    assert e.value.rule == "outbound.not_allowed"
    uninstall_http_hooks()
    install_http_hooks(["127.0.0.1"])
    assert get(server + "/x") == b"ok"
    assert events.attacks() == [("outbound", "outbound.not_allowed", "blocked")]


def test_always_allowed_hosts_are_the_shield360_and_otlp_hosts():
    assert always_allowed_hosts(["https://app.shield360.ai/x", None, "http://otel:4318"]) == ["app.shield360.ai", "otel"]


def test_http_client_on_its_own_is_checked(server):
    events = use_engine("block")
    install_http_hooks([])
    port = int(server.rsplit(":", 1)[1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    with pytest.raises(RaspBlockedError):
        in_request([server + "/admin"], lambda: conn.request("GET", "/admin"))
    conn.close()
    assert events.sinks() == ["http.client.HTTPConnection.request"]


def test_the_address_the_connection_resolves_is_checked(rebinding):
    events = use_engine("block")
    install_http_hooks([])
    # The URL alone passes (a public-looking name); the resolver's answer does not.
    conn = http.client.HTTPConnection(REBIND, 80, timeout=5)
    with pytest.raises(RaspBlockedError) as e:
        in_request([f"http://{REBIND}/"], lambda: conn.request("GET", "/"))
    assert e.value.rule == "ssrf.internal"
    assert rebinding == [REBIND]
    with pytest.raises(RaspBlockedError):
        in_request([f"http://{REBIND}/"], lambda: get(f"http://{REBIND}/"))
    assert events.sinks() == ["http.client.HTTPConnection.request", "urllib.request.urlopen"]


def test_an_untainted_call_is_not_checked_against_its_addresses(rebinding, server):
    events = use_engine("block")
    install_http_hooks([])
    with pytest.raises(urllib.error.URLError):
        # Nothing listens on 10.0.0.5 here, and the short timeout ends the attempt; RASP lets it go.
        in_request(["unrelated"], lambda: urllib.request.urlopen(f"http://{REBIND}:9/", timeout=0.2))  # pylint: disable=consider-using-with
    assert not events


def test_requests_is_checked_once_and_at_its_resolution(rebinding, server):
    requests = pytest.importorskip("requests")
    events = use_engine("monitor")
    install_http_hooks([])
    assert in_request([server + "/r"], lambda: requests.get(server + "/r", timeout=5).text) == "ok"
    assert events.sinks() == ["requests.Session.send"]
    use_engine("block")
    with pytest.raises(RaspBlockedError) as e:
        in_request([f"http://{REBIND}/"], lambda: requests.get(f"http://{REBIND}/", timeout=5))
    assert e.value.rule == "ssrf.internal"


class _Request:
    def __init__(self, url):
        self.url = url


def _fake_httpx():
    module = types.ModuleType("httpx")
    seen = []

    class Client:
        def send(self, request, **kwargs):
            seen.append(("sync", request.url))
            socket.getaddrinfo(REBIND, 80)
            return "sent"

    class AsyncClient:
        async def send(self, request, **kwargs):
            seen.append(("async", request.url))
            await asyncio.get_running_loop().getaddrinfo(REBIND, 80)
            return "sent"

    module.Client, module.AsyncClient, module.seen = Client, AsyncClient, seen
    return module


def test_httpx_sync_and_async_are_checked_and_resolved(rebinding, monkeypatch):
    httpx = _fake_httpx()
    monkeypatch.setitem(sys.modules, "httpx", httpx)
    events = use_engine("block")
    install_http_hooks([])
    assert in_request(["unrelated"], lambda: httpx.Client().send(_Request("https://api.example.com/v1"))) == "sent"
    with pytest.raises(RaspBlockedError):
        in_request([f"http://{REBIND}/"], lambda: httpx.Client().send(_Request(f"http://{REBIND}/")))

    async def call():
        return await httpx.AsyncClient().send(_Request(f"http://{REBIND}/"))

    with pytest.raises(RaspBlockedError):
        in_request([f"http://{REBIND}/"], lambda: asyncio.run(call()))
    assert events.sinks() == ["httpx.Client.send", "httpx.AsyncClient.send"]
    assert [kind for kind, _ in httpx.seen] == ["sync", "sync", "async"]


def test_a_fake_requests_session_is_wrapped_when_imported(monkeypatch):
    sessions = types.ModuleType("requests.sessions")

    class Session:
        def send(self, request, **kwargs):
            return request.url

    sessions.Session = Session
    monkeypatch.setitem(sys.modules, "requests.sessions", sessions)
    events = use_engine("block")
    install_http_hooks([])
    with pytest.raises(RaspBlockedError):
        in_request(["http://169.254.169.254/latest"], lambda: Session().send(_Request("http://169.254.169.254/latest")))
    assert events.attacks() == [("ssrf", "ssrf.metadata", "blocked")]


def test_off_does_not_run_detection(monkeypatch, server):
    stop_engine()
    calls = []
    monkeypatch.setattr(_detect, "detect_ssrf", lambda *a: calls.append(a))
    install_http_hooks([])
    assert in_request([server + "/x"], lambda: get(server + "/x")) == b"ok"
    assert not calls


def test_detector_errors_fail_open(monkeypatch, server):
    events = use_engine("block")

    def broken(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(_detect, "detect_ssrf", broken)
    install_http_hooks([])
    assert in_request([server + "/x"], lambda: get(server + "/x")) == b"ok"
    assert not events


def test_install_is_idempotent_and_uninstall_restores_exactly():
    before = (vars(urllib.request.OpenerDirector)["open"], vars(http.client.HTTPConnection)["putrequest"], socket.getaddrinfo)
    assert install_http_hooks([]) and install_http_hooks([])
    assert socket.getaddrinfo is not before[2] and socket.getaddrinfo.__name__ == "getaddrinfo"
    uninstall_http_hooks()
    uninstall_http_hooks()
    after = (vars(urllib.request.OpenerDirector)["open"], vars(http.client.HTTPConnection)["putrequest"], socket.getaddrinfo)
    assert after == before


# ---- review fixes ------------------------------------------------------------------


def test_urllib_and_requests_redirects_are_checked_at_each_hop(server):
    events = use_engine("block", allow={"outbound_hosts": ["127.0.0.1"]})
    install_http_hooks([])
    with pytest.raises(RaspBlockedError) as e:
        get(server + "/redirect")
    assert e.value.rule == "outbound.not_allowed"
    requests = pytest.importorskip("requests")
    with pytest.raises(RaspBlockedError):
        requests.get(server + "/redirect", timeout=5)
    assert events.sinks() == ["urllib.request.urlopen", "requests.Session.send"]


def _redirecting_httpx(target):
    """Stands in for httpx 0.28: send follows the redirect itself, each hop through _send_single_request."""
    module = types.ModuleType("httpx")

    class Client:
        def send(self, request, **kwargs):
            self._send_single_request(request)
            return self._send_single_request(_Request(target))

        def _send_single_request(self, request):
            host = request.url.split("/")[2]
            if host == REBIND:  # only the stand-in resolver's name; nothing reaches real DNS
                socket.getaddrinfo(host, 80)
            return request.url

    class AsyncClient:
        async def send(self, request, **kwargs):
            await self._send_single_request(request)
            return await self._send_single_request(_Request(target))

        async def _send_single_request(self, request):
            return request.url

    module.Client, module.AsyncClient = Client, AsyncClient
    return module


def test_httpx_redirect_hops_get_the_url_check_sync_and_async(monkeypatch):
    httpx = _redirecting_httpx("http://forbidden.example/landing")
    monkeypatch.setitem(sys.modules, "httpx", httpx)
    events = use_engine("block", allow={"outbound_hosts": ["api.example.com"]})
    install_http_hooks([])
    with pytest.raises(RaspBlockedError):
        httpx.Client().send(_Request("http://api.example.com/start"))

    async def call():
        return await httpx.AsyncClient().send(_Request("http://api.example.com/start"))

    with pytest.raises(RaspBlockedError):
        asyncio.run(call())
    assert events.attacks() == [("outbound", "outbound.not_allowed", "blocked")] * 2


def test_httpx_redirect_hop_is_resolved_against_its_own_host(monkeypatch, rebinding):
    httpx = _redirecting_httpx(f"http://{REBIND}/landing")
    monkeypatch.setitem(sys.modules, "httpx", httpx)
    events = use_engine("block")
    install_http_hooks([])
    with pytest.raises(RaspBlockedError) as e:
        in_request([f"next={REBIND}"], lambda: httpx.Client().send(_Request("http://api.example.com/start")))
    assert e.value.rule == "ssrf.internal"
    assert REBIND in rebinding
    assert events.sinks() == ["httpx.Client.send"]


def test_an_outbound_finding_in_monitor_does_not_hide_an_ssrf_block():
    events = use_engine("block", attacks={"outbound": "monitor", "ssrf": "block"}, allow={"outbound_hosts": ["api.example.com"]})
    install_http_hooks([])
    url = "http://127.0.0.1:9/admin"
    with pytest.raises(RaspBlockedError) as e:
        in_request([url], lambda: get(url))
    assert e.value.rule == "ssrf.internal"
    assert events.attacks() == [("ssrf", "ssrf.internal", "blocked")]


def test_inputs_of_an_abandoned_request_never_reach_a_later_use_of_the_connection(monkeypatch, server):
    port = int(server.rsplit(":", 1)[1])

    def fake(host, p, *args, **kwargs):
        if host == REBIND:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return REAL_GETADDRINFO(host, p, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    events = use_engine("block")
    install_http_hooks([])
    conn = http.client.HTTPConnection(REBIND, port, timeout=5)
    # A request checked inside a request, then abandoned before it connected.
    in_request([f"http://{REBIND}:{port}/"], lambda: conn.putrequest("GET", "/"))
    conn.close()
    # The same connection used later, outside any request: nothing from that request applies.
    conn.request("GET", "/")
    assert conn.getresponse().read() == b"ok"
    conn.close()
    assert not events
