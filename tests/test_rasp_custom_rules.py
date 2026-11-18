"""Custom rules in the SDK (README "Custom rules"): rules arrive inside the
signed config, invalid ones are skipped with one warning and never break the
config, request rules run with the request's capture, finding rules when a
built-in check fires, the custom_rule mode caps every action, and evaluation
fails open.

Mirrors sdk/typescript/src/rasp/__tests__/custom-rules.test.ts.
"""

import base64
import io
import json
import logging
import time

import pytest

from shield360 import rasp
from shield360.rasp import RaspWSGIMiddleware
from shield360.rasp._capture import capture_body, capture_request, run_virtual_patches
from shield360.rasp._config_client import JWS_TYPE
from shield360.rasp._context import current_context, reset_context, set_context
from shield360.rasp._custom_rules import parse_custom_rules, request_subject, reset_custom_rule_warnings
from shield360.rasp._engine import (
    RemoteConfig,
    configure_engine,
    custom_rules,
    handle_finding,
    mode_for,
    set_event_sink,
    set_remote_config,
)
from shield360.rasp._types import Finding, RaspBlockedError, RaspInput

EVENTS = []


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)
        return True


def rule(**over):
    r = {"id": "r1", "name": "Rule one", "expression": 'request.path.startsWith("/admin")', "action": "monitor", "enabled": True}
    r.update(over)
    return r


def remote(rules, attacks=None):
    return RemoteConfig(
        version="v1", exp=time.time() + 3600, mode="monitor", attacks=attacks or {}, rules=[], custom_rules=rules
    )


def rules_of():
    return [e["attrs"]["shield360.rasp.rule"] for e in EVENTS]


@pytest.fixture(autouse=True)
def _engine():
    reset_custom_rule_warnings()
    EVENTS.clear()
    configure_engine(enabled=True, application_name="orders-api", env={})
    set_event_sink(_Sink())
    yield
    set_event_sink(None)
    configure_engine(enabled=False, application_name="default", env={})


def request(url, **extra):
    args = {"framework": "test", "method": "GET", "url": url, "ip": "::ffff:10.1.2.3"}
    args["headers"] = {"user-agent": "curl/8.4", "host": "a"}
    args.update(extra)
    return capture_request(**args)


def in_ctx(ctx, fn):
    token = set_context(ctx)
    try:
        return fn()
    finally:
        reset_context(token)


# ---- parse_custom_rules ---------------------------------------------------------


def test_keeps_valid_enabled_rules_for_this_app_in_order(caplog):
    with caplog.at_level(logging.WARNING, logger="shield360.rasp"):
        rules = parse_custom_rules(
            [rule(), rule(id="r2", apps=["orders-api", "billing"]), rule(id="r3", apps=["billing"]), rule(id="r4", enabled=False)],
            "orders-api",
        )
    assert [r.id for r in rules] == ["r1", "r2"]
    assert not caplog.records


def test_skips_each_invalid_rule_with_one_warning_and_never_warns_twice(caplog):
    raw = [
        rule(id="Bad Id"),
        rule(id="ok-1"),
        rule(id="ok-1"),
        rule(id="x2", action="allow"),
        rule(id="x3", enabled="yes"),
        rule(id="x4", expression='request.method = "GET"'),
        rule(id="x5", apps="orders-api"),
        rule(id="x6", name=7),
        None,
        "rule",
    ]
    with caplog.at_level(logging.WARNING, logger="shield360.rasp"):
        assert [r.id for r in parse_custom_rules(raw, "orders-api")] == ["ok-1"]
        assert len(caplog.records) == 9
        assert "expression: syntax" in "\n".join(r.getMessage() for r in caplog.records)
        parse_custom_rules(raw, "orders-api")
        assert len(caplog.records) == 9


def test_keeps_at_most_64():
    assert len(parse_custom_rules([rule(id=f"r{i}") for i in range(70)], "a")) == 64


def test_is_empty_for_anything_but_a_list():
    for v in (None, {}, "x", 3):
        assert not parse_custom_rules(v, "a")


def test_reads_the_request_as_the_language_sees_it():
    ctx = request("/api/orders/42?id=42&id=43&q=%252e%252e", method="post", headers={"user-agent": "curl/8.4", "x-multi": ["a", "b"]})
    capture_body(ctx, {"user": {"role": "admin"}}, "application/json")
    s = request_subject(ctx, "orders-api")
    req = s["request"]
    assert req["method"] == "POST" and req["path"] == "/api/orders/42" and req["route"] == "/api/orders/:id"
    assert req["ip"] == "::ffff:10.1.2.3"
    assert req["query"] == {"id": "42", "q": "%2e%2e"} and req["body"] == {"user.role": "admin"}
    assert req["headers"]["user-agent"] == "curl/8.4" and req["headers"]["x-multi"] == "a, b"
    assert any(i.key == "query.q" and i.value == ".." for i in s["inputs"])


# ---- request rules ------------------------------------------------------------


def test_report_a_match_as_a_custom_rule_event_and_let_the_request_through_in_monitor():
    set_remote_config(remote([rule(action="alert")]))
    run_virtual_patches(request("/admin/users"))
    assert len(EVENTS) == 1
    a = EVENTS[0]["attrs"]
    assert a["shield360.rasp.attack"] == "custom_rule"
    assert a["shield360.rasp.rule"] == "custom.r1"
    assert a["shield360.rasp.decision"] == "monitored"
    assert a["shield360.rasp.sink"] == "server.request"
    assert a["shield360.rasp.route"] == "/admin/users"
    assert a["shield360.rasp.config_version"] == "v1"


def test_block_only_when_the_rule_says_block_and_the_custom_rule_mode_is_block():
    set_remote_config(remote([rule(action="block")]))
    run_virtual_patches(request("/admin"))
    assert EVENTS[0]["attrs"]["shield360.rasp.decision"] == "monitored"

    set_remote_config(remote([rule(action="monitor")], {"custom_rule": "block"}))
    run_virtual_patches(request("/admin"))

    set_remote_config(remote([rule(action="block")], {"custom_rule": "block"}))
    with pytest.raises(RaspBlockedError) as e:
        run_virtual_patches(request("/admin"))
    assert (e.value.attack, e.value.rule) == ("custom_rule", "custom.r1")

    set_remote_config(remote([rule(action="block")], {"custom_rule": "off"}))
    EVENTS.clear()
    run_virtual_patches(request("/admin"))
    assert not EVENTS


def test_match_each_rule_once_per_request_input_rules_run_again_when_the_body_arrives():
    set_remote_config(
        remote(
            [
                rule(id="path", expression='request.path == "/upload"'),
                rule(id="traversal", expression='input.value.contains("../")'),
                rule(id="role", expression='request.body["role"] == "admin"'),
                rule(id="ip", expression='request.ip.inCidr("10.0.0.0/8") && request.headers["user-agent"].startsWith("curl/")'),
            ]
        )
    )
    ctx = request("/upload", method="POST")
    run_virtual_patches(ctx)
    assert rules_of() == ["custom.path", "custom.ip"]
    capture_body(ctx, {"role": "admin", "file": "../../etc/passwd"}, "application/json")
    run_virtual_patches(ctx)
    assert rules_of() == ["custom.path", "custom.ip", "custom.traversal", "custom.role"]
    assert EVENTS[2]["attrs"]["shield360.rasp.input_key"] == "body.file"


def test_stop_at_the_first_rule_that_blocks():
    set_remote_config(remote([rule(id="a", action="block"), rule(id="b")], {"custom_rule": "block"}))
    with pytest.raises(RaspBlockedError):
        run_virtual_patches(request("/admin"))
    assert rules_of() == ["custom.a"]


def test_fail_open_when_the_work_budget_runs_out():
    set_remote_config(remote([rule(expression='input.value.matches("a{100}x")', action="block")], {"custom_rule": "block"}))
    query = "&".join(f"k{i}={'a' * 4096}" for i in range(200))
    run_virtual_patches(request(f"/x?{query}"))
    assert not EVENTS


# ---- when request rules run (README "When rules run") ---------------------------

PHASE_RULES = [
    rule(id="evil", expression='input.value.contains("evil-xyz")'),
    rule(id="path", expression='request.path == "/p"'),
    rule(id="nobody", expression='request.body["x"] == null'),
]


def test_head_rules_see_only_the_inputs_known_before_the_body():
    # The body is captured before the head is judged: the input rule still waits for the body phase.
    set_remote_config(remote(PHASE_RULES))
    ctx = request("/p?q=1", method="POST")
    capture_body(ctx, {"note": "evil-xyz"}, "application/json")
    run_virtual_patches(ctx)
    assert rules_of() == ["custom.path", "custom.evil", "custom.nobody"]
    assert EVENTS[1]["attrs"]["shield360.rasp.input_key"] == "body.note"


def test_head_rules_see_only_the_inputs_known_before_the_body_through_record_request_body():
    set_remote_config(remote(PHASE_RULES))
    ctx = request("/p", method="POST")
    in_ctx(ctx, lambda: rasp.record_request_body('{"note": "evil-xyz"}', "application/json"))
    assert rules_of() == ["custom.path", "custom.evil", "custom.nobody"]


def test_head_inputs_still_match_at_head():
    set_remote_config(remote(PHASE_RULES))
    ctx = request("/p?q=evil-xyz", method="POST")
    capture_body(ctx, {"x": "1"}, "application/json")
    run_virtual_patches(ctx)
    assert rules_of() == ["custom.evil", "custom.path"]
    assert EVENTS[0]["attrs"]["shield360.rasp.input_key"] == "query.q"


def _ok_wsgi(env, start_response):  # pylint: disable=unused-argument
    start_response("200 OK", [])
    return [b"ok"]


def _wsgi(environ, app=_ok_wsgi):
    status = []

    base = {"REQUEST_METHOD": "GET", "PATH_INFO": "/p", "REMOTE_ADDR": "10.1.2.3", "wsgi.input": io.BytesIO()}
    base.update(environ)
    b"".join(RaspWSGIMiddleware(app)(base, lambda s, h, *_: status.append(s)))
    return status


async def _ok_asgi(scope, receive, send):  # pylint: disable=unused-argument
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


def _asgi(method, headers, chunks, app=_ok_asgi, **scope_extra):
    import asyncio  # pylint: disable=import-outside-toplevel

    messages = [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1} for i, c in enumerate(chunks)]
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(m):
        sent.append(m)

    scope = {"type": "http", "method": method, "path": "/p", "headers": headers, "client": ("10.1.2.3", 5000), **scope_extra}
    asyncio.run(rasp.RaspASGIMiddleware(app)(scope, receive, send))
    return sent


def test_middleware_judges_the_head_before_the_body_is_captured():
    set_remote_config(remote(PHASE_RULES))
    body = b'{"note": "evil-xyz", "x": "1"}'
    _wsgi({"REQUEST_METHOD": "POST", "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body)),
           "wsgi.input": io.BytesIO(body)})
    assert rules_of() == ["custom.path", "custom.evil"]
    EVENTS.clear()
    _asgi("POST", [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())], [body])
    assert rules_of() == ["custom.path", "custom.evil"]


def test_a_request_with_no_body_or_an_empty_one_still_runs_the_body_phase():
    set_remote_config(remote(PHASE_RULES))
    cases = [
        lambda: _wsgi({}),
        lambda: _wsgi({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": "0"}),
        lambda: _wsgi({"REQUEST_METHOD": "POST", "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": "2",
                       "wsgi.input": io.BytesIO(b"{}")}),
        lambda: _asgi("GET", [], []),
        lambda: _asgi("POST", [(b"content-length", b"0")], [b""]),
        lambda: _asgi("POST", [(b"content-type", b"application/json")], [b"{}"]),
    ]
    for i, case in enumerate(cases):
        EVENTS.clear()
        case()
        assert rules_of() == ["custom.path", "custom.nobody"], i


def test_a_body_the_sdk_did_not_read_stays_unknown():
    set_remote_config(remote(PHASE_RULES))
    cases = [
        # chunked (no length) and over 1 MiB: never read by the middleware
        lambda: _wsgi({"REQUEST_METHOD": "POST", "HTTP_TRANSFER_ENCODING": "chunked", "wsgi.input": io.BytesIO(b"x=1")}),
        lambda: _wsgi({"REQUEST_METHOD": "POST", "CONTENT_LENGTH": str(2 * 1024 * 1024)}),
        lambda: _asgi("POST", [(b"content-length", str(2 * 1024 * 1024).encode())], [b""]),
        lambda: _asgi("GET", [(b"transfer-encoding", b"chunked")], [b""]),
    ]
    for i, case in enumerate(cases):
        EVENTS.clear()
        case()
        assert rules_of() == ["custom.path"], i


def _late_body_keys():
    """Records two bodies the app read itself; returns the body inputs seen."""
    rasp.record_request_body({"x": "late"})
    rasp.record_request_body({"x": "twice"})
    ctx = current_context()
    return [(i.key, i.value) for i in ctx.inputs if i.key.startswith("body")] if ctx else None


def test_a_body_recorded_after_a_known_empty_one_still_reaches_the_built_in_checks():
    set_remote_config(remote(PHASE_RULES))
    seen = []

    def wsgi_app(env, start_response):
        seen.append(_late_body_keys())
        return _ok_wsgi(env, start_response)

    async def asgi_app(scope, receive, send):
        seen.append(_late_body_keys())
        await _ok_asgi(scope, receive, send)

    _wsgi({}, app=wsgi_app)
    # The body phase ran once, on the empty body, and does not run again.
    assert rules_of() == ["custom.path", "custom.nobody"]
    EVENTS.clear()
    _asgi("GET", [], [], app=asgi_app)
    assert rules_of() == ["custom.path", "custom.nobody"]
    # The built-in checks still see the body the app read, recorded once.
    assert seen == [[("body.x", "late")], [("body.x", "late")]]


def test_an_unframed_http2_body_is_not_assumed_absent():
    set_remote_config(remote(PHASE_RULES))
    unknown = [
        lambda: _wsgi({"REQUEST_METHOD": "POST", "SERVER_PROTOCOL": "HTTP/2", "wsgi.input": io.BytesIO(b"x=1")}),
        lambda: _wsgi({"SERVER_PROTOCOL": "HTTP/2.0"}),
        lambda: _asgi("GET", [], [b""], http_version="2"),
    ]
    for i, case in enumerate(unknown):
        EVENTS.clear()
        case()
        assert rules_of() == ["custom.path"], i
    known = [
        lambda: _wsgi({"SERVER_PROTOCOL": "HTTP/2", "CONTENT_LENGTH": "0"}),
        lambda: _asgi("GET", [(b"content-length", b"0")], [b""], http_version="2"),
        lambda: _asgi("GET", [], [], http_version="1.1"),
    ]
    for i, case in enumerate(known):
        EVENTS.clear()
        case()
        assert rules_of() == ["custom.path", "custom.nobody"], i


def test_virtual_patch_findings_are_judged_with_the_request_current():
    vp = {"id": "vp.test-path", "action": "monitor", "match": [{"target": "path", "op": "equals", "values": ["/p"]}]}
    finding_rule = rule(
        id="vp-ctx",
        expression='attack.type == "virtual_patch" && request.path == "/p" && request.ip == "10.1.2.3" && input.value == "1"',
    )
    set_remote_config(
        RemoteConfig(
            version="v1", exp=time.time() + 3600, mode="monitor", attacks={"virtual_patch": "monitor"}, rules=[vp],
            custom_rules=[finding_rule],
        )
    )
    _wsgi({"QUERY_STRING": "q=1"})
    assert rules_of() == ["vp.test-path", "custom.vp-ctx"]
    EVENTS.clear()
    import asyncio  # pylint: disable=import-outside-toplevel

    scope = {"type": "http", "method": "GET", "path": "/p", "query_string": b"q=1", "headers": [], "client": ("10.1.2.3", 1)}

    async def noop(*_):
        return None

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    asyncio.run(rasp.RaspASGIMiddleware(app)(scope, receive, noop))
    assert rules_of() == ["vp.test-path", "custom.vp-ctx"]


def test_do_nothing_while_rasp_is_off():
    set_remote_config(remote([rule(action="block")], {"custom_rule": "block"}))
    configure_engine(enabled=False, application_name="orders-api", env={})
    run_virtual_patches(request("/admin"))
    assert not EVENTS


def test_block_through_the_middleware_with_the_contract_403_and_record_the_client_address():
    set_remote_config(
        remote(
            [rule(expression='request.headers["x-debug"] == "1" && request.ip.inCidr("127.0.0.0/8")', action="block")],
            {"custom_rule": "block"},
        )
    )
    called = []
    status = []

    def app(environ, start_response):
        called.append(True)
        start_response("200 OK", [])
        return [b"ok"]

    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/a", "HTTP_X_DEBUG": "1", "REMOTE_ADDR": "127.0.0.1", "wsgi.input": io.BytesIO()}
    body = b"".join(RaspWSGIMiddleware(app)(environ, lambda s, h, *_: status.append(s)))
    assert not called
    assert status == ["403 Forbidden"]
    assert json.loads(body)["attack"] == "custom_rule" and json.loads(body)["rule"] == "custom.r1"


def test_asgi_records_the_client_address():
    set_remote_config(remote([rule(expression='request.ip == "203.0.113.9"', action="block")], {"custom_rule": "block"}))
    sent = []

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(m):
        sent.append(m)

    import asyncio  # pylint: disable=import-outside-toplevel

    scope = {"type": "http", "method": "GET", "path": "/a", "headers": [], "client": ("203.0.113.9", 5000)}
    asyncio.run(rasp.RaspASGIMiddleware(app)(scope, receive, send))
    assert sent[0]["status"] == 403


# ---- finding rules ------------------------------------------------------------

SQLI = Finding("sql_injection", "sqli.userinput", RaspInput("1 OR 1=1", "query.q"))


def test_finding_rules_see_the_built_in_finding_its_sink_and_the_request():
    set_remote_config(
        remote(
            [
                rule(
                    id="admin-sqli",
                    expression='attack.type == "sql_injection" && sink.name == "pg.query" && request.path.startsWith("/admin")',
                    action="alert",
                )
            ]
        )
    )
    ctx = request("/admin/search?q=1%20OR%201%3D1")
    in_ctx(ctx, lambda: handle_finding(SQLI, "pg.query"))
    got = [(e["attrs"]["shield360.rasp.attack"], e["attrs"]["shield360.rasp.rule"], e["attrs"]["shield360.rasp.sink"]) for e in EVENTS]
    assert got == [("sql_injection", "sqli.userinput", "pg.query"), ("custom_rule", "custom.admin-sqli", "pg.query")]
    assert EVENTS[1]["attrs"]["shield360.rasp.input_key"] == "query.q"


def test_finding_rules_never_run_in_the_request_phase_and_request_rules_never_on_findings():
    set_remote_config(remote([rule(id="f", expression="attack.type != null"), rule(id="q", expression='request.path == "/a"')]))
    ctx = request("/a")
    run_virtual_patches(ctx)
    assert rules_of() == ["custom.q"]
    EVENTS.clear()
    in_ctx(ctx, lambda: handle_finding(SQLI, "pg.query"))
    assert rules_of() == ["sqli.userinput", "custom.f"]


def test_a_finding_rule_can_block_what_the_attack_type_only_monitors_the_built_in_block_wins():
    set_remote_config(remote([rule(id="stop", expression='attack.type == "sql_injection"', action="block")], {"custom_rule": "block"}))
    with pytest.raises(RaspBlockedError) as e:
        in_ctx(request("/a"), lambda: handle_finding(SQLI, "pg.query"))
    assert e.value.attack == "custom_rule"
    set_remote_config(
        remote(
            [rule(id="stop", expression='attack.type == "sql_injection"', action="block")],
            {"custom_rule": "block", "sql_injection": "block"},
        )
    )
    with pytest.raises(RaspBlockedError) as e:
        in_ctx(request("/a"), lambda: handle_finding(SQLI, "pg.query"))
    assert e.value.attack == "sql_injection"


def test_finding_rules_skip_attack_types_that_are_off():
    set_remote_config(remote([rule(expression='attack.type == "sql_injection"')], {"sql_injection": "off"}))
    assert mode_for("sql_injection") == "off"
    in_ctx(request("/a"), lambda: handle_finding(SQLI, "pg.query"))
    assert not EVENTS


def test_finding_rules_run_outside_a_request_with_the_request_fields_null():
    set_remote_config(
        remote([rule(expression='request.path == null && app.name == "orders-api" && attack.type == "sql_injection"')])
    )
    handle_finding(SQLI, "pg.query")
    assert rules_of() == ["sqli.userinput", "custom.r1"]


# ---- signed config round trip ---------------------------------------------------

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

_PRIV = ed25519.Ed25519PrivateKey.generate()


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_JWK = {
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "k1",
    "x": _b64(_PRIV.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
}


def _jws(c):
    head = _b64(json.dumps({"alg": "EdDSA", "typ": JWS_TYPE, "kid": "k1"}).encode())
    body = _b64(json.dumps(c).encode())
    return f"{head}.{body}.{_b64(_PRIV.sign(f'{head}.{body}'.encode()))}"


def _init(token, tmp_path):
    def fetch(url, headers, timeout):
        if "/api/rasp/config" in url:
            return 200, {}, json.dumps({"config": token}).encode()
        return 200, {}, b"{}"

    rasp.init_rasp(
        {"enabled": True, "config_public_key": _JWK, "components": False, "cache_dir": str(tmp_path)},
        application_name="orders-api",
        url="https://s.example.com",
        api_key="k",
        env={},
        fetch=fetch,
        urlopen=lambda *a, **k: None,
    )


def test_applies_the_signed_rules_an_invalid_rule_is_skipped_and_the_rest_holds(tmp_path, caplog):
    now = int(time.time())
    claims = {
        "v": 1,
        "app": "orders-api",
        "iat": now,
        "exp": now + 600,
        "version": "cfg-1",
        "mode": "monitor",
        "attacks": {"ssrf": "block", "custom_rule": "block"},
        "rules": None,
        "customRules": [rule(action="block"), rule(id="broken", expression='request.path.matches("(a+)+")')],
    }
    try:
        with caplog.at_level(logging.WARNING, logger="shield360.rasp"):
            _init(_jws(claims), tmp_path)
            deadline = time.time() + 5
            while not custom_rules() and time.time() < deadline:
                time.sleep(0.01)
        assert [r.id for r in custom_rules()] == ["r1"]
        assert mode_for("ssrf") == "block"
        warned = [r.getMessage() for r in caplog.records if "custom rule" in r.getMessage()]
        assert len(warned) == 1 and '"broken"' in warned[0] and "expression: regex" in warned[0]
        with pytest.raises(RaspBlockedError):
            run_virtual_patches(request("/admin"))
    finally:
        rasp.shutdown_rasp()


def test_a_tampered_rule_fails_the_signature_and_the_rules_are_not_applied(tmp_path, caplog):
    claims = {"v": 1, "app": "orders-api", "exp": int(time.time()) + 600, "version": "cfg-2", "customRules": [rule()]}
    parts = _jws(claims).split(".")
    parts[1] = _b64(json.dumps({**claims, "customRules": [rule(expression="true", action="block")]}).encode())
    try:
        with caplog.at_level(logging.WARNING, logger="shield360.rasp"):
            _init(".".join(parts), tmp_path)
            time.sleep(0.2)
        assert custom_rules() == []
        assert "signature" in "\n".join(r.getMessage() for r in caplog.records)
    finally:
        rasp.shutdown_rasp()


# ---- review fixes ---------------------------------------------------------------


def _heavy_rules(n):
    expr = " || ".join(f'input.value.lowerAscii().lowerAscii() == "{i}"' for i in range(10))
    return [rule(id=f"h{i}", expression=expr, action="block") for i in range(n)]


def _heavy_request():
    ctx = request("/x")
    ctx.inputs[:] = [RaspInput("A" * 4096, f"query.k{i}") for i in range(256)]
    return ctx


def test_custom_rules_stop_at_the_per_request_time_budget_and_warn_once(caplog):
    set_remote_config(remote(_heavy_rules(8), {"custom_rule": "block"}))
    with caplog.at_level(logging.WARNING, logger="shield360.rasp"):
        t0 = time.monotonic()
        run_virtual_patches(_heavy_request())
        assert time.monotonic() - t0 < 1.0
        run_virtual_patches(_heavy_request())
    assert not EVENTS
    warned = [r.getMessage() for r in caplog.records if "budget" in r.getMessage()]
    assert len(warned) == 1 and "time budget" in warned[0]


def test_the_time_budget_is_configurable():
    from shield360.rasp._custom_rules import new_budget, resolve_rules_time_budget_ms  # pylint: disable=import-outside-toplevel

    assert resolve_rules_time_budget_ms(None, {}) == 25
    assert resolve_rules_time_budget_ms(50, {}) == 50
    assert resolve_rules_time_budget_ms(50, {"SHIELD360_RULES_TIME_BUDGET_MS": "10"}) == 10
    assert resolve_rules_time_budget_ms("x", {"SHIELD360_RULES_TIME_BUDGET_MS": "-1"}) == 25
    configure_engine(enabled=True, application_name="orders-api", env={}, rules_time_budget_ms=40)
    assert new_budget().time_left == pytest.approx(0.04)
    configure_engine(enabled=True, application_name="orders-api", env={"SHIELD360_RULES_TIME_BUDGET_MS": "0"})
    assert new_budget().time_left is None
    rasp.init_rasp({"enabled": True, "components": False, "rules_time_budget_ms": 5}, application_name="a", env={})
    try:
        assert new_budget().time_left == pytest.approx(0.005)
    finally:
        rasp.shutdown_rasp()


def test_finding_rules_see_the_request_while_the_middleware_runs_virtual_patches():
    # A monitored virtual-patch finding, judged before the middleware makes the context current.
    from rasp_corpus import request_for  # pylint: disable=import-outside-toplevel
    from shield360.rasp._vpatch import BUILT_IN_RULES  # pylint: disable=import-outside-toplevel

    example = next(r for r in BUILT_IN_RULES if r.get("example"))
    cfg = remote(
        [rule(expression='attack.type == "virtual_patch" && request.path == "/a"', action="block")],
        {"custom_rule": "block", "virtual_patch": "monitor"},
    )
    cfg.rules = None  # the built-in virtual patches
    set_remote_config(cfg)
    called = []
    status = []

    def app(environ, start_response):
        called.append(True)
        start_response("200 OK", [])
        return [b"ok"]

    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/a", "wsgi.input": io.BytesIO()}
    for name, value in request_for(example).headers.items():
        environ["HTTP_" + name.upper().replace("-", "_")] = value
    body = b"".join(RaspWSGIMiddleware(app)(environ, lambda s, h, *_: status.append(s)))
    assert not called and status == ["403 Forbidden"]
    assert json.loads(body)["rule"] == "custom.r1"
