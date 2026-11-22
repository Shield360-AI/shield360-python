"""Deception (sdk/rasp/README.md "Deception"): the shared conformance file
(testdata/deception.json), the suspicious-address table, the mode and the
decision, and every middleware: a decoy never reaches the handler and gets
the app's 404, a later request from the same address is suspicious, errors
fail open. Frameworks are not dependencies of the SDK, so the Flask and
Django adapters run against small stand-ins here; the real frameworks are in
test_rasp_deception_frameworks.py."""

import asyncio
import io
import json
import sys
import time
import types

import pytest

from rasp_corpus import load_json
from shield360 import rasp
from shield360.rasp import BLOCK_MESSAGE, RaspASGIMiddleware, RaspDjangoMiddleware, RaspWSGIMiddleware, rasp_flask
from shield360.rasp._deception import (
    SuspiciousTable,
    decode_target,
    match_decoy,
    parse_deception,
    set_suspicious_table,
    suspicious_table,
)
from shield360.rasp._engine import (
    RemoteConfig,
    configure_engine,
    deception_config,
    deception_mode,
    set_event_sink,
    set_monitor_only,
    set_remote_config,
    set_runtime_disabled,
)
from shield360.rasp._middleware import _asgi_target, _environ_target

CORPUS = load_json("testdata/deception.json")
EVENTS = []


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def normalized(d):
    return None if d is None else {"paths": list(d.paths), "action": d.action, "ttlSeconds": d.ttl_seconds}


def signed(deception=None, attacks=None, kill_switch=False, **extra):
    set_remote_config(
        RemoteConfig(
            version="v7", exp=time.time() + 3600, kill_switch=kill_switch, attacks=attacks or {}, deception=deception, **extra
        )
    )


DECOYS = {"paths": ["/wp-admin", "/.env"], "action": "block", "ttlSeconds": 60}


@pytest.fixture(autouse=True)
def _engine():
    EVENTS.clear()
    # SHIELD: AI attack agents — off here (decoy hits add to its score); test_rasp_attack_agents.py covers the two together.
    configure_engine(enabled=True, application_name="orders-api", attacks={"ai_attack_agent": "off"}, env={})
    set_event_sink(_Sink())
    clock = Clock()
    set_suspicious_table(SuspiciousTable(clock=clock))
    yield clock
    set_event_sink(None)
    set_suspicious_table()
    configure_engine(enabled=False, application_name="default", env={})


def attrs(i=-1):
    return EVENTS[i]["attrs"]


def rules():
    return [(e["attrs"]["shield360.rasp.rule"], e["attrs"]["shield360.rasp.decision"]) for e in EVENTS]


# ---- conformance (testdata/deception.json) ----


def test_corpus_is_version_1_with_config_and_match_cases():
    assert CORPUS["version"] == 1 and CORPUS["config"] and CORPUS["match"]


@pytest.mark.parametrize("case", CORPUS["config"], ids=[c["name"] for c in CORPUS["config"]])
def test_conformance_config(case):
    assert normalized(parse_deception(case.get("deception"))) == case["expect"]
    # The same through the signed config's claims, as the SDK applies them.
    claims = {"version": "v1", "exp": time.time() + 3600}
    if "deception" in case:
        claims["deception"] = case["deception"]
    set_remote_config(rasp._to_remote(claims))  # pylint: disable=protected-access
    assert normalized(deception_config()) == case["expect"]


def _match_ids():
    return [f"{c.get('decoys', 'default')} {c['target']}" for c in CORPUS["match"]]


@pytest.mark.parametrize("case", CORPUS["match"], ids=_match_ids())
def test_conformance_match(case):
    decoys = parse_deception({"paths": case.get("decoys", CORPUS["decoys"])}).paths
    target = case["target"]
    assert match_decoy(decode_target(target.encode("latin-1")), decoys) == case["expect"]
    # Through the middleware's own path extraction: WSGI RAW_URI and ASGI raw_path.
    _, decoded = _environ_target({"RAW_URI": target, "PATH_INFO": "/ignored"})
    assert match_decoy(decoded, decoys) == case["expect"]
    _, decoded = _asgi_target({"raw_path": target.split("?", 1)[0].encode("latin-1"), "path": "/ignored"})
    assert match_decoy(decoded, decoys) == case["expect"]


# ---- suspicious addresses ----


def test_table_marks_expires_and_lookup_does_not_extend(_engine):
    clock = _engine
    t = SuspiciousTable(clock=clock)
    t.mark("203.0.113.9", 60)
    assert t.is_suspicious("203.0.113.9") and not t.is_suspicious("203.0.113.10")
    clock.t += 59
    assert t.is_suspicious("203.0.113.9")
    clock.t += 1
    assert not t.is_suspicious("203.0.113.9") and len(t) == 0
    t.mark("", 60)
    t.mark(None, 60)
    assert len(t) == 0


def test_table_cap_evicts_expired_then_closest_to_expiring_and_remarking_refreshes_order(_engine):
    clock = _engine
    t = SuspiciousTable(cap=3, clock=clock)
    for ip in ("a", "b", "c"):
        t.mark(ip, 100)
    t.mark("a", 100)  # re-marking moves it to the end, the size stays
    assert t.addresses() == ("b", "c", "a")
    for ip in ("d", "e"):
        t.mark(ip, 100)
    assert len(t) == 3 and t.addresses() == ("a", "d", "e")
    # Expired marks go first, before any live one.
    t2 = SuspiciousTable(cap=3, clock=clock)
    t2.mark("short", 1)
    t2.mark("x", 100)
    t2.mark("y", 100)
    clock.t += 5
    t2.mark("z", 100)
    assert t2.addresses() == ("x", "y", "z")
    # A flood never grows the table.
    for i in range(50):
        t2.mark(f"10.0.0.{i}", 100)
    assert len(t2) == 3 and t2.addresses() == ("10.0.0.47", "10.0.0.48", "10.0.0.49")


def test_table_drops_every_expired_mark_before_a_live_one_after_a_ttl_change(_engine):
    clock = _engine
    t = SuspiciousTable(cap=3, clock=clock)
    t.mark("a", 3600)
    t.mark("b", 3600)
    t.mark("c", 1)  # a lower TTL: c expires before the older a and b
    clock.t += 2
    t.mark("d", 3600)
    assert len(t) == 3
    assert t.is_suspicious("a") and t.is_suspicious("b") and t.is_suspicious("d")
    assert not t.is_suspicious("c")


def test_table_at_the_cap_evicts_the_mark_closest_to_expiring(_engine):
    t = SuspiciousTable(cap=2, clock=_engine)
    t.mark("a", 3600)
    t.mark("b", 10)
    t.mark("c", 3600)
    assert t.addresses() == ("a", "c")
    assert t.is_suspicious("a") and t.is_suspicious("c") and not t.is_suspicious("b")


def test_the_default_table_holds_10000_addresses():
    assert suspicious_table()._cap == 10_000  # pylint: disable=protected-access
    assert SuspiciousTable()._cap == 10_000  # pylint: disable=protected-access


# ---- mode and decision ----


def test_mode_follows_action_capped_by_attacks_deception_and_monitor_only():
    signed(DECOYS)
    assert deception_mode("block") == "block" and deception_mode("monitor") == "monitor"
    signed(DECOYS, attacks={"deception": "monitor"})
    assert deception_mode("block") == "monitor"
    signed(DECOYS, attacks={"deception": "block"})
    assert deception_mode("monitor") == "monitor" and deception_mode("block") == "block"
    signed(DECOYS, attacks={"deception": "off"})
    assert deception_mode("block") is None
    # Never the config's default mode.
    signed(DECOYS, mode="block")
    assert deception_mode("monitor") == "monitor"
    signed(DECOYS, mode="off")
    assert deception_mode("block") == "block"
    set_monitor_only(True)
    signed(DECOYS)
    assert deception_mode("block") == "monitor"


def test_local_off_turns_deception_off():
    configure_engine(enabled=True, application_name="orders-api", attacks={"deception": "off"}, env={})
    signed(DECOYS)
    assert deception_mode("block") is None


def test_dropping_the_signed_config_turns_deception_off_and_keeps_marks():
    signed(DECOYS)
    assert deception_config() is not None
    suspicious_table().mark("203.0.113.9", 60)
    signed({"paths": ["/other"]})
    assert suspicious_table().is_suspicious("203.0.113.9")
    set_remote_config(None)
    assert deception_config() is None


# ---- WSGI ----


def environ(path="/", query="", method="GET", ip="203.0.113.9", raw=None, script=""):
    env = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "SCRIPT_NAME": script,
        "QUERY_STRING": query,
        "wsgi.input": io.BytesIO(b""),
    }
    if ip is not None:
        env["REMOTE_ADDR"] = ip
    if raw is not None:
        env["RAW_URI"] = raw
    return env


def call_wsgi(app, env):
    out = {}

    def start_response(status, headers, exc_info=None):
        out["status"] = status
        out["headers"] = dict(headers)

    result = app(env, start_response)
    out["body"] = b"".join(result)
    return out


class Handler:
    """A WSGI app that answers its routes and 404s anything else, the way
    a small app does; ``calls`` records what reached it."""

    def __init__(self, routes=("/", "/orders")):
        self.routes = routes
        self.calls = []

    def __call__(self, env, start_response):
        self.calls.append(env["PATH_INFO"])
        if env["PATH_INFO"] in self.routes:
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]
        return own_not_found(env, start_response)


def own_not_found(env, start_response):
    start_response("404 Not Found", [("Content-Type", "text/html"), ("X-App", "1")])
    return [b"<h1>nothing here</h1>"]


def test_wsgi_decoy_never_reaches_the_app_and_gets_a_plain_404():
    signed(DECOYS)
    app = Handler()
    out = call_wsgi(RaspWSGIMiddleware(app), environ("/wp-admin/setup.php"))
    assert not app.calls
    assert out["status"] == "404 Not Found" and out["body"] == b"Not Found"
    assert out["headers"]["Content-Type"] == "text/plain; charset=utf-8"
    a = attrs()
    assert a["shield360.rasp.attack"] == "deception" and a["shield360.rasp.rule"] == "deception.hit"
    assert a["shield360.rasp.decision"] == "blocked" and a["shield360.rasp.mode"] == "block"
    assert a["shield360.rasp.sink"] == "http.deception" and a["shield360.rasp.framework"] == "wsgi"
    assert a["shield360.rasp.route"] == "/wp-admin" and a["shield360.rasp.method"] == "GET"
    assert a["shield360.rasp.config_version"] == "v7"
    assert "shield360.rasp.input_key" not in a and "shield360.rasp.snippet" not in a


def test_wsgi_not_found_option_answers_like_an_unknown_path():
    signed(DECOYS)
    app = Handler()
    mw = RaspWSGIMiddleware(app, not_found=own_not_found)
    decoy = call_wsgi(mw, environ("/.env"))
    unknown = call_wsgi(mw, environ("/no-such-page", ip="198.51.100.1"))
    assert app.calls == ["/no-such-page"]
    assert decoy == unknown


def test_wsgi_hit_marks_the_address_then_suspicious_blocks_or_monitors(_engine):
    clock = _engine
    signed(DECOYS)
    app = Handler()
    mw = RaspWSGIMiddleware(app)
    call_wsgi(mw, environ("/wp-admin"))
    out = call_wsgi(mw, environ("/orders"))
    assert out["status"].startswith("403") and not app.calls
    body = json.loads(out["body"])
    assert body == {
        "error": BLOCK_MESSAGE,
        "attack": "deception",
        "rule": "deception.suspicious",
        "event": attrs()["shield360.rasp.event_id"],
    }
    assert out["headers"]["Cache-Control"] == "no-store"
    assert attrs()["shield360.rasp.route"] == "/orders" and attrs()["shield360.rasp.sink"] == "http.deception"
    # Another address is untouched.
    assert call_wsgi(mw, environ("/orders", ip="198.51.100.1"))["body"] == b"ok"
    # Expiry un-marks.
    clock.t += 60
    assert call_wsgi(mw, environ("/orders"))["body"] == b"ok"
    assert rules() == [("deception.hit", "blocked"), ("deception.suspicious", "blocked")]

    EVENTS.clear()
    signed({**DECOYS, "action": "monitor"})
    call_wsgi(mw, environ("/.env"))
    assert call_wsgi(mw, environ("/orders"))["body"] == b"ok"
    assert rules() == [("deception.hit", "monitored"), ("deception.suspicious", "monitored")]
    assert attrs()["shield360.rasp.mode"] == "monitor"


def test_wsgi_hitting_again_restarts_the_time(_engine):
    clock = _engine
    signed(DECOYS)
    mw = RaspWSGIMiddleware(Handler())
    call_wsgi(mw, environ("/wp-admin"))
    clock.t += 50
    call_wsgi(mw, environ("/wp-admin"))
    clock.t += 50
    assert call_wsgi(mw, environ("/orders"))["status"].startswith("403")


def test_wsgi_monitor_only_caps_block():
    set_monitor_only(True)
    signed(DECOYS)
    app = Handler()
    mw = RaspWSGIMiddleware(app)
    assert call_wsgi(mw, environ("/wp-admin"))["status"] == "404 Not Found"
    assert call_wsgi(mw, environ("/orders"))["body"] == b"ok"
    assert rules() == [("deception.hit", "monitored"), ("deception.suspicious", "monitored")]


def test_wsgi_attacks_deception_off_lets_decoys_through_and_reports_nothing():
    for attacks, local in (({"deception": "off"}, None), ({}, {"deception": "off"})):
        configure_engine(enabled=True, application_name="orders-api", attacks=local, env={})
        signed(DECOYS, attacks=attacks)
        app = Handler(routes=("/wp-admin",))
        mw = RaspWSGIMiddleware(app)
        assert call_wsgi(mw, environ("/wp-admin"))["body"] == b"ok"
        assert app.calls == ["/wp-admin"] and not EVENTS and len(suspicious_table()) == 0


def test_wsgi_kill_switch_and_disabled_leave_requests_untouched():
    suspicious_table().mark("203.0.113.9", 60)
    for off in ("kill", "runtime", "env"):
        configure_engine(enabled=True, application_name="orders-api", env={"SHIELD360_RASP": "off"} if off == "env" else {})
        signed(DECOYS, kill_switch=off == "kill")
        set_runtime_disabled(off == "runtime")
        app = Handler(routes=("/wp-admin", "/orders"))
        mw = RaspWSGIMiddleware(app)
        assert call_wsgi(mw, environ("/wp-admin"))["body"] == b"ok"
        assert call_wsgi(mw, environ("/orders"))["body"] == b"ok"
        assert app.calls == ["/wp-admin", "/orders"] and not EVENTS


def test_wsgi_without_a_client_address_still_answers_404_and_marks_nothing():
    signed(DECOYS)
    app = Handler()
    out = call_wsgi(RaspWSGIMiddleware(app), environ("/wp-admin", ip=None))
    assert out["status"] == "404 Not Found" and not app.calls and len(suspicious_table()) == 0
    assert call_wsgi(RaspWSGIMiddleware(app), environ("/orders", ip=""))["body"] == b"ok"


def test_wsgi_raw_uri_is_decoded_once_path_info_never_again():
    signed(DECOYS)
    app = Handler(routes=("/%2Eenv", "/.env"))
    mw = RaspWSGIMiddleware(app)
    # RAW_URI as sent: decoded once.
    assert call_wsgi(mw, environ("/.env", raw="/%2Eenv?x=1"))["status"] == "404 Not Found"
    # PATH_INFO is already decoded: a literal %2E stays as it is.
    assert call_wsgi(mw, environ("/%2Eenv", ip="198.51.100.1"))["body"] == b"ok"
    # The mount prefix counts: /app/.env is not /.env, and SCRIPT_NAME + PATH_INFO is the full path.
    assert call_wsgi(mw, environ("/.env", script="/app", ip="198.51.100.2"))["body"] == b"ok"
    signed({"paths": ["/app/.env", "/café"]})
    assert call_wsgi(mw, environ("/.env", script="/app", ip="198.51.100.3"))["status"] == "404 Not Found"
    # PEP 3333: PATH_INFO is the latin-1 text of the bytes the server decoded.
    assert call_wsgi(mw, environ("/cafÃ©/menu", ip="198.51.100.4"))["status"] == "404 Not Found"
    assert app.calls == ["/%2Eenv", "/.env"]


class Boom:
    def __call__(self, *a, **k):
        raise RuntimeError("boom")


def test_wsgi_failures_in_deception_fail_open(_engine):
    signed(DECOYS)

    class BrokenTable(SuspiciousTable):
        def mark(self, ip, ttl_seconds):
            raise RuntimeError("table")

        def is_suspicious(self, ip):
            raise RuntimeError("table")

    for table in (BrokenTable(), SuspiciousTable(clock=Boom())):
        set_suspicious_table(table)
        app = Handler(routes=("/wp-admin", "/orders"))
        mw = RaspWSGIMiddleware(app)
        assert call_wsgi(mw, environ("/wp-admin"))["body"] == b"ok"
        assert call_wsgi(mw, environ("/orders"))["body"] == b"ok"
        assert app.calls == ["/wp-admin", "/orders"]
    # A failing reporter never breaks the request: the decoy still gets its 404.
    set_suspicious_table(SuspiciousTable(clock=_engine))

    class BrokenSink:
        def add(self, event, fold_key):
            raise RuntimeError("sink")

    set_event_sink(BrokenSink())
    app = Handler()
    assert call_wsgi(RaspWSGIMiddleware(app), environ("/wp-admin"))["status"] == "404 Not Found" and not app.calls
    # A target that cannot be read lets the request through.
    app = Handler(routes=("/x",))
    assert call_wsgi(RaspWSGIMiddleware(app), environ("/x", raw="/Ā"))["body"] == b"ok"


def test_wsgi_without_deception_config_runs_as_before():
    signed(None)
    app = Handler(routes=("/wp-admin",))
    assert call_wsgi(RaspWSGIMiddleware(app), environ("/wp-admin"))["body"] == b"ok"
    assert not EVENTS


# ---- ASGI ----


def run_asgi(app, path="/", raw_path=None, root_path=None, client=("203.0.113.9", 5000), method="GET", extra=None):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": method, "path": path, "query_string": b"", "headers": []}
    if raw_path is not None:
        scope["raw_path"] = raw_path
    if root_path is not None:
        scope["root_path"] = root_path
    if client is not None:
        scope["client"] = client
    scope.update(extra or {})
    asyncio.run(app(scope, receive, send))
    start = next((m for m in sent if m["type"] == "http.response.start"), {})
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start.get("status"), dict(start.get("headers") or []), body


def asgi_handler(calls):
    async def app(scope, receive, send):
        calls.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    return app


def test_asgi_decoy_never_reaches_the_app_and_gets_a_plain_404():
    signed(DECOYS)
    calls = []
    status, headers, body = run_asgi(RaspASGIMiddleware(asgi_handler(calls)), "/wp-admin", b"/wp-admin")
    assert not calls and status == 404 and body == b"Not Found"
    assert headers[b"content-type"] == b"text/plain; charset=utf-8"
    assert attrs()["shield360.rasp.framework"] == "asgi" and attrs()["shield360.rasp.rule"] == "deception.hit"
    # The address is now suspicious: blocked with the contract's 403.
    status, _, body = run_asgi(RaspASGIMiddleware(asgi_handler(calls)), "/orders/42", b"/orders/42")
    assert status == 403 and not calls
    assert json.loads(body)["rule"] == "deception.suspicious" and attrs()["shield360.rasp.route"] == "/orders/:id"


def test_asgi_framework_fastapi_answers_like_fastapi_and_not_found_option_wins():
    signed(DECOYS)
    calls = []
    status, headers, body = run_asgi(RaspASGIMiddleware(asgi_handler(calls), framework="fastapi"), "/.env", client=None)
    assert status == 404 and json.loads(body) == {"detail": "Not Found"} and headers[b"content-type"] == b"application/json"

    async def custom(scope, receive, send):
        await send({"type": "http.response.start", "status": 404, "headers": [(b"x-app", b"1")]})
        await send({"type": "http.response.body", "body": b"gone"})

    status, _, body = run_asgi(RaspASGIMiddleware(asgi_handler(calls), not_found=custom), "/.env", client=None)
    assert (status, body) == (404, b"gone") and not calls


def test_asgi_raw_path_decoded_once_path_as_is_and_root_path_prefixed():
    signed({"paths": ["/.env", "/api/admin"], "action": "monitor"})
    calls = []
    mw = RaspASGIMiddleware(asgi_handler(calls))
    assert run_asgi(mw, "/.env", b"/%2Eenv", client=None)[0] == 404
    # Without raw_path the decoded path is used as it is (a literal %2E stays).
    assert run_asgi(mw, "/%2Eenv", client=None)[0] == 200
    # root_path the server left out of path / raw_path is put back.
    assert run_asgi(mw, "/admin", b"/admin", root_path="/api", client=None)[0] == 404
    assert run_asgi(mw, "/admin", root_path="/api", client=None)[0] == 404
    # ... and not doubled when the server already included it.
    assert run_asgi(mw, "/api/admin", b"/api/admin", root_path="/api", client=None)[0] == 404
    assert run_asgi(mw, "/.env", b"/.env", root_path="/api", client=None)[0] == 200
    assert calls == ["/%2Eenv", "/.env"]


def test_asgi_failures_fail_open_and_inactive_passes_through():
    signed(DECOYS)
    set_suspicious_table(SuspiciousTable(clock=Boom()))
    calls = []
    assert run_asgi(RaspASGIMiddleware(asgi_handler(calls)), "/wp-admin", b"/wp-admin")[0] == 200
    set_suspicious_table(SuspiciousTable())
    set_runtime_disabled(True)
    assert run_asgi(RaspASGIMiddleware(asgi_handler(calls)), "/wp-admin", b"/wp-admin")[0] == 200
    assert calls == ["/wp-admin", "/wp-admin"] and not EVENTS


# ---- Flask (stand-in) ----


class FakeFlask:
    def __init__(self):
        self.calls = []
        self.handlers = {}
        self.before = []
        self.url_value_preprocessors = {None: [self.app_preprocessor]}

        def wsgi_app(env, start_response):
            # Flask's request handling, cut down: URL value preprocessors first, then the view.
            fake = types.ModuleType("flask")
            fake.request = types.SimpleNamespace(environ=env)
            sys.modules["flask"] = fake
            try:
                for fn in self.url_value_preprocessors[None]:
                    fn(None, None)
            except NotFoundError:
                start_response("404 NOT FOUND", [("Content-Type", "text/html")])
                return [b"app 404 handler"]
            self.calls.append(env["PATH_INFO"])
            start_response("200 OK", [])
            return [b"view"]

        self.wsgi_app = wsgi_app

    def app_preprocessor(self, endpoint, values):
        self.calls.append("app hook")

    def register_error_handler(self, exc, fn):
        self.handlers[exc] = fn

    def before_request(self, fn):
        self.before.append(fn)


class NotFoundError(Exception):
    pass


def test_flask_decoy_goes_through_flask_as_not_found_before_any_app_hook(monkeypatch):
    monkeypatch.setitem(sys.modules, "flask", types.ModuleType("flask"))
    exceptions = types.ModuleType("werkzeug.exceptions")
    exceptions.NotFound = NotFoundError
    monkeypatch.setitem(sys.modules, "werkzeug", types.ModuleType("werkzeug"))
    monkeypatch.setitem(sys.modules, "werkzeug.exceptions", exceptions)
    signed(DECOYS)
    app = rasp_flask(FakeFlask())
    out = call_wsgi(app.wsgi_app, environ("/wp-admin"))
    assert out["body"] == b"app 404 handler" and not app.calls
    assert attrs()["shield360.rasp.framework"] == "flask"
    assert call_wsgi(app.wsgi_app, environ("/orders", ip="198.51.100.1"))["body"] == b"view"
    assert app.calls == ["app hook", "/orders"]


def test_flask_without_preprocessors_falls_back_to_the_plain_404():
    signed(DECOYS)
    app = FakeFlask()
    del app.url_value_preprocessors
    rasp_flask(app)
    out = call_wsgi(app.wsgi_app, environ("/wp-admin"))
    assert out["status"] == "404 Not Found" and not app.calls


# ---- Django (stand-in) ----


class Http404(Exception):
    pass


class Resolver404(Http404):
    pass


def stand_in_django(monkeypatch, routes):
    class JsonResponse(dict):
        def __init__(self, data, status=200):
            super().__init__()
            self.data, self.status_code = data, status

    http = types.ModuleType("django.http")
    http.JsonResponse, http.Http404 = JsonResponse, Http404
    urls = types.ModuleType("django.urls")
    urls.Resolver404 = Resolver404

    class Resolver:
        def resolve(self, path):
            if path not in routes:
                raise Resolver404({"path": path})
            return object()

    urls.get_resolver = lambda urlconf=None: Resolver()
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    monkeypatch.setitem(sys.modules, "django.http", http)
    monkeypatch.setitem(sys.modules, "django.urls", urls)


def django_request(path, ip="203.0.113.9", raw=None):
    meta = environ(path, ip=ip, raw=raw)
    return types.SimpleNamespace(META=meta, body=b"", path=path, path_info=path)


def test_django_decoy_raises_what_an_unknown_url_raises(monkeypatch):
    stand_in_django(monkeypatch, routes=("/admin/backup.zip", "/orders"))
    signed({"paths": ["/wp-admin", "/admin/backup.zip"], "action": "block"})
    calls = []
    mw = RaspDjangoMiddleware(lambda req: calls.append(req.path) or "view")
    with pytest.raises(Resolver404):
        mw(django_request("/wp-admin/x"))
    # A decoy that is a real route is still a 404, never the view.
    with pytest.raises(Http404) as raised:
        mw(django_request("/admin/backup.zip", ip="198.51.100.1"))
    assert not isinstance(raised.value, Resolver404)
    assert not calls and attrs()["shield360.rasp.framework"] == "django"
    blocked = mw(django_request("/orders"))
    assert blocked.status_code == 403 and blocked.data["rule"] == "deception.suspicious" and not calls
    assert mw(django_request("/orders", ip="192.0.2.1")) == "view"


def test_django_uses_the_raw_uri_else_the_decoded_path(monkeypatch):
    stand_in_django(monkeypatch, routes=())
    signed({"paths": ["/.env", "/café"], "action": "monitor"})
    mw = RaspDjangoMiddleware(lambda req: "view")
    with pytest.raises(Http404):
        mw(django_request("/.env", raw="/%2eenv", ip=None))
    with pytest.raises(Http404):
        mw(django_request("/café/menu", ip=None))
    assert mw(django_request("/%2eenv", ip=None)) == "view"
