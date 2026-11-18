"""Passive IAST (README "Passive IAST"): the shared conformance corpus
(sdk/rasp/testdata/iast.json), the thresholds, and how the engine arms,
samples, dedupes and reports vulnerabilities without ever blocking.

Mirrors sdk/typescript/src/rasp/__tests__/iast.test.ts.
"""

import os
import sys

import pytest

from rasp_corpus import load_json, normalize
from shield360 import rasp
from shield360.rasp._context import run_with_inputs
from shield360.rasp._detect import (
    detect_argv,
    detect_code,
    detect_command,
    detect_deserialization,
    detect_include,
    detect_path,
    detect_shell_spawn,
    detect_sql,
    detect_ssrf,
    detect_xml,
    shell_script_of,
)
from shield360.rasp._engine import check, configure_engine, set_event_sink, set_remote_config, set_runtime_disabled
from shield360.rasp._hooks import install_hooks, uninstall_hooks
from shield360.rasp._iast import (
    IAST_REPORT_EVERY_S,
    RASP_VULNERABILITY,
    code_location,
    configure_iast,
    format_location,
    iast_enabled,
    iast_sample_rate,
    is_app_frame,
    reset_iast,
    set_iast_remote,
    set_iast_sink,
    vuln_fingerprint,
)
from shield360.rasp._iast_rules import VULN_RULES, qualifies
from shield360.rasp._iast_scope import capture_vulnerability, iast_armed
from shield360.rasp._types import RaspBlockedError, RaspInput

CORPUS = load_json("testdata/iast.json")


def run_iast_case(c):
    """Runs one corpus case through the detectors with an IAST slot armed."""
    inputs = normalize(c.get("inputs"))
    check_ = c["check"]

    def run():
        if check_ == "sql":
            return detect_sql(c["query"], inputs, c.get("dialect") or "generic")
        if check_ == "command":
            if isinstance(c.get("command"), str):
                return detect_command(c["command"], inputs) or detect_shell_spawn(command=c["command"], in_request=True)
            argv = c["argv"]
            script = shell_script_of(argv)
            return (
                detect_argv(argv, inputs)
                or (detect_command(script, inputs) if script else None)
                or detect_shell_spawn(argv0=argv[0], in_request=True)
            )
        if check_ == "path":
            return detect_path(c["path"], c.get("op") or "read", inputs, c.get("fileRoots") or [])
        if check_ == "ssrf":
            return detect_ssrf(c["url"], inputs, c.get("resolved") or [])
        if check_ == "code":
            return detect_code(c["code"], inputs)
        if check_ == "include":
            return detect_include(c["specifier"], inputs)
        if check_ == "deser":
            return detect_deserialization(c["format"], c["data"], inputs)
        if check_ == "xml":
            return detect_xml(c["xml"], inputs, bool(c.get("resolvesExternal")))
        raise ValueError(f"unknown check {check_}")

    return capture_vulnerability(run)


def test_corpus_is_version_1_with_cases_for_every_rule():
    assert CORPUS["version"] == 1
    assert sorted({c["expect"]["rule"] for c in CORPUS["cases"] if c["expect"]["rule"]}) == sorted(VULN_RULES)


@pytest.mark.parametrize("case", CORPUS["cases"], ids=[c["name"] for c in CORPUS["cases"]])
def test_corpus_case(case):
    finding, vuln = run_iast_case(case)
    # Every case is harmless: the attack checks fire nothing.
    assert finding is None
    expect = case["expect"]
    if expect["rule"] is None:
        assert vuln is None
    else:
        assert vuln is not None and vuln.rule == expect["rule"]
        if expect.get("position"):
            assert vuln.position == expect["position"]
        if expect.get("input_key"):
            assert vuln.input.key == expect["input_key"]


@pytest.mark.parametrize("fp", CORPUS["fingerprints"], ids=[f["fingerprint"] for f in CORPUS["fingerprints"]])
def test_fingerprint_vector(fp):
    assert vuln_fingerprint(fp["route"], fp["sink"], fp["input_key"], fp["rule"]) == fp["fingerprint"]


def test_notes_nothing_when_no_slot_is_armed():
    assert not iast_armed()
    inputs = [RaspInput("alice@example.com", "query.email")]
    assert detect_sql("SELECT 1 FROM t WHERE e = 'alice@example.com'", inputs) is None
    assert not iast_armed()


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", False),
        ("42", False),
        ("100", False),
        ("true", False),
        ("active", False),
        ("desc", False),
        ("aaaaaaaaaa", False),
        ("----", False),
        ("1234", True),
        ("created_at", True),
        ("en-GB", True),
        ("alice@example.com", True),
        ("Saint Paul", True),
        ("password", True),
        ("Zürich-8001", True),
    ],
)
def test_thresholds(value, expected):
    assert qualifies(value) is expected


# ---- in the engine --------------------------------------------------------------

EVENTS = []
CLOCK = [1_000.0]
EMAIL = [RaspInput("alice@example.com", "query.email")]
QUERY = "SELECT id FROM orders WHERE customer_email = 'alice@example.com'"


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)
        return True


def run_sql(inputs=None, q=QUERY, **ctx):
    inputs = EMAIL if inputs is None else inputs
    init = {"in_request": True, "method": "get", "route": "/api/orders/:id", "framework": "flask"}
    init.update(ctx)

    def body():
        return check("pg.query", lambda: detect_sql(q, inputs, "postgres"))

    return _run_in(inputs, init, body)


def _run_in(inputs, init, fn):
    from shield360.rasp._context import new_context, reset_context, set_context  # pylint: disable=import-outside-toplevel

    token = set_context(new_context(inputs=list(inputs), **init))
    try:
        return fn()
    finally:
        reset_context(token)


def setup(iast=None, env=None, mode="block", environment=None, random=None):
    configure_engine(enabled=True, application_name="orders-api", mode=mode, env={})
    set_event_sink(_Sink())
    configure_iast(iast, application_name="orders-api", environment=environment, env=env or {}, now=lambda: CLOCK[0], random=random)
    set_iast_sink(_Sink())


@pytest.fixture(autouse=True)
def _clean():
    EVENTS.clear()
    CLOCK[0] = 1_000.0
    yield
    reset_iast()
    set_event_sink(None)
    set_remote_config(None)
    configure_engine(enabled=False, application_name="a", env={})


def vulns():
    return [e for e in EVENTS if e["name"] == RASP_VULNERABILITY]


def test_is_off_by_default():
    setup()
    assert not iast_enabled()
    assert run_sql() is None
    assert vulns() == []


def test_reports_once_with_locations_and_no_value_and_never_blocks():
    setup(iast=True, mode="block")
    assert run_sql() is None
    assert len(vulns()) == 1
    a = vulns()[0]["attrs"]
    expected = {
        "shield360.rasp.kind": "vulnerability",
        "shield360.rasp.app": "orders-api",
        "shield360.rasp.rule": "vuln.sql_concat",
        "shield360.rasp.sink": "pg.query",
        "shield360.rasp.source": "request",
        "shield360.rasp.input_key": "query.email",
        "shield360.rasp.route": "/api/orders/:id",
        "shield360.rasp.method": "GET",
        "shield360.rasp.framework": "flask",
        "shield360.rasp.language": "python",
        "shield360.rasp.config_version": "local",
        "shield360.rasp.vuln.position": "string",
        "shield360.rasp.count": "1",
    }
    assert {k: a.get(k) for k in expected} == expected
    assert a["shield360.rasp.vuln.fingerprint"] == vuln_fingerprint("/api/orders/:id", "pg.query", "query.email", "vuln.sql_concat")
    assert len(a["shield360.rasp.event_id"]) == 32 and int(a["shield360.rasp.event_id"], 16) >= 0
    # This test file is the app's code here.
    loc = a["shield360.rasp.vuln.location"]
    assert loc.rsplit(":", 1)[0].endswith("tests/test_rasp_iast.py") and loc.rsplit(":", 1)[1].isdigit()
    assert "alice@example.com" not in repr(vulns())
    assert "shield360.rasp.snippet" not in a
    assert [e for e in EVENTS if e["name"] == "shield360.rasp.event"] == []


def test_reports_each_fingerprint_at_most_once_an_hour_with_the_count_seen_since():
    setup(iast=True)
    run_sql()
    run_sql()
    run_sql()
    assert len(vulns()) == 1
    CLOCK[0] += IAST_REPORT_EVERY_S
    run_sql()
    assert len(vulns()) == 2
    assert vulns()[1]["attrs"]["shield360.rasp.count"] == "3"


def test_reports_nothing_for_an_attack():
    setup(iast=True, mode="monitor")
    attack = [RaspInput("x' OR '1'='1", "query.q")]
    run_sql(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'")
    assert [e["name"] for e in EVENTS] == ["shield360.rasp.event"]


def test_works_whatever_the_attack_mode_even_off():
    configure_engine(enabled=True, application_name="orders-api", attacks={"sql_injection": "off"}, env={})
    configure_iast(True, application_name="orders-api", env={}, now=lambda: CLOCK[0])
    set_iast_sink(_Sink())
    run_sql()
    assert len(vulns()) == 1


def test_stands_down_with_the_kill_switch():
    setup(iast=True)
    set_runtime_disabled(True)
    run_sql()
    set_runtime_disabled(False)
    assert vulns() == []


def test_does_nothing_without_request_input_in_scope():
    setup(iast=True)
    check("pg.query", lambda: detect_sql(QUERY, [], "postgres"))
    assert vulns() == []


def test_samples_checks():
    setup(iast={"sample_rate": 0.5}, random=lambda: 0.9)
    run_sql()
    assert vulns() == []
    setup(iast={"sample_rate": 0.5}, random=lambda: 0.1)
    run_sql()
    assert len(vulns()) == 1


def test_defaults_to_every_check_a_tenth_in_production():
    setup(iast=True)
    assert iast_sample_rate() == 1
    setup(iast=True, environment="production")
    assert iast_sample_rate() == 0.1
    setup(iast=True, env={"NODE_ENV": "production", "SHIELD360_IAST_SAMPLE_RATE": "0.5"})
    assert iast_sample_rate() == 0.5
    setup(iast=True, env={"SHIELD360_IAST_SAMPLE_RATE": "7"})
    assert iast_sample_rate() == 1


def test_is_switched_by_the_env_and_the_signed_config_env_off_winning():
    setup(env={"SHIELD360_IAST": "on"})
    assert iast_enabled()
    set_iast_remote({"iast": "off", "version": "v2"})
    assert not iast_enabled()
    setup(random=lambda: 0.1)
    set_iast_remote({"iast": "on", "iastSampleRate": 0.25, "version": "v3"})
    assert iast_enabled()
    assert iast_sample_rate() == 0.25
    run_sql()
    assert vulns()[0]["attrs"]["shield360.rasp.config_version"] == "v3"
    setup(iast=True, env={"SHIELD360_IAST": "off"})
    set_iast_remote({"iast": "on", "version": "v4"})
    assert not iast_enabled()
    set_iast_remote(None)
    assert not iast_enabled()


def test_fails_open_when_a_rule_raises():
    setup(iast=True)

    class Throwing:
        source = "request"
        key = "query.x"

        @property
        def value(self):
            raise RuntimeError("boom")

    inputs = [EMAIL[0], Throwing()]
    _run_in([EMAIL[0]], {}, lambda: check("pg.query", lambda: detect_sql(QUERY, inputs)))


def test_never_exports_a_secret_looking_path_segment_without_a_route_template():
    setup(iast=True)
    run_sql(route=None, path="/api/v2/reset/AbCdEfGhIjKlMnOpQrSt/confirm")
    assert len(vulns()) == 1
    assert vulns()[0]["attrs"]["shield360.rasp.route"] == "/api/v2/reset/:id/confirm"
    assert "AbCdEfGhIjKlMnOpQrSt" not in repr(vulns())


def test_retries_a_report_the_reporter_refused_keeping_the_count():
    setup(iast=True)
    accepted = []
    refuse = [True]

    class Refusing:
        def add(self, event, fold_key):
            if refuse[0]:
                return False
            accepted.append(event)
            return True

    set_iast_sink(Refusing())
    run_sql()
    assert not accepted
    refuse[0] = False
    CLOCK[0] += 61
    run_sql()
    assert len(accepted) == 1
    assert accepted[0]["attrs"]["shield360.rasp.count"] == "2"
    run_sql()
    assert len(accepted) == 1


def test_reaches_the_real_file_hook():
    setup(iast=True)
    install_hooks()
    try:
        inputs = [RaspInput("invoice-2026-0193", "query.file")]
        init = {"in_request": True, "route": "/files/:name"}
        _run_in(inputs, init, lambda: os.path.exists("/nonexistent-shield360-iast/invoice-2026-0193.pdf"))

        def read():
            try:
                with open("/nonexistent-shield360-iast/invoice-2026-0193.pdf", "rb"):
                    pass
            except OSError:
                pass  # missing on purpose

        _run_in(inputs, init, read)
    finally:
        uninstall_hooks()
    found = [e for e in vulns() if e["attrs"]["shield360.rasp.rule"] == "vuln.path_from_input"]
    assert found
    assert found[0]["attrs"]["shield360.rasp.input_key"] == "query.file"


def test_a_blocking_attack_still_blocks_with_iast_on():
    setup(iast=True, mode="block")
    attack = [RaspInput("x' OR '1'='1", "query.q")]
    with pytest.raises(RaspBlockedError):
        run_sql(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'")
    assert not iast_armed()


def test_init_rasp_reads_the_local_option():
    try:
        rasp.init_rasp({"enabled": True, "iast": True, "components": False}, application_name="a", env={})
        assert iast_enabled()
        rasp.init_rasp({"enabled": True, "iast": {"sample_rate": 0.3}, "components": False}, application_name="a", env={})
        assert iast_enabled() and iast_sample_rate() == 0.3
        rasp.init_rasp({"enabled": True, "components": False}, application_name="a", env={"SHIELD360_IAST": "on"})
        assert iast_enabled()
        rasp.init_rasp({"enabled": True, "components": False}, application_name="a", env={})
        assert not iast_enabled()
    finally:
        rasp.shutdown_rasp()


def test_run_with_inputs_reports_too():
    setup(iast=True)
    run_with_inputs(EMAIL, lambda: check("pg.query", lambda: detect_sql(QUERY, EMAIL, "postgres")))
    assert len(vulns()) == 1


# ---- code location --------------------------------------------------------------


def test_takes_the_first_app_frame_outside_packages_the_stdlib_and_the_sdk():
    assert not is_app_frame("/app/.venv/lib/python3.12/site-packages/psycopg2/extras.py")
    assert not is_app_frame("/usr/lib/python3/dist-packages/x.py")
    assert not is_app_frame("<frozen importlib._bootstrap>")
    assert not is_app_frame(os.__file__)
    assert not is_app_frame(rasp.__file__)
    assert is_app_frame(__file__)
    line = sys._getframe().f_lineno + 1  # pylint: disable=protected-access
    assert code_location() == format_location(__file__, line)


def test_formats_relative_to_the_working_directory_else_the_last_three_segments():
    assert format_location("/srv/app/routes/orders.py", 42, cwd="/srv/app") == "routes/orders.py:42"
    assert format_location("/opt/other/app/lib/db/run.py", 3, cwd="/srv/app") == "lib/db/run.py:3"
    assert format_location("/srv/app/my routes/o#rders.py", 7, cwd="/srv/app") == "my_routes/o_rders.py:7"


# ---- review fixes ---------------------------------------------------------------


def test_concurrent_first_sightings_send_one_report():
    import threading  # pylint: disable=import-outside-toplevel

    setup(iast=True)
    entered, release = threading.Event(), threading.Event()
    sent = []

    class Slow:
        def add(self, event, fold_key):
            sent.append(event)
            if len(sent) == 1:
                entered.set()
                release.wait(5)
            return True

    set_iast_sink(Slow())
    t = threading.Thread(target=run_sql)
    t.start()
    assert entered.wait(5)
    run_sql()  # while the first report is being sent
    release.set()
    t.join(5)
    assert len(sent) == 1
    CLOCK[0] += IAST_REPORT_EVERY_S
    run_sql()
    assert len(sent) == 2 and sent[1]["attrs"]["shield360.rasp.count"] == "2"


def test_refused_reports_are_not_double_counted_by_the_reporter():
    from shield360.rasp._reporter import PER_MINUTE, RaspReporter  # pylint: disable=import-outside-toplevel

    setup(iast=True)
    reporter = RaspReporter("https://s.example.com", "k", "orders-api", now=lambda: CLOCK[0])
    for i in range(PER_MINUTE):
        reporter.add({"name": "x", "time": "t", "attrs": {}}, f"filler{i}")
    set_iast_sink(reporter)
    run_sql()  # refused: rate limit
    CLOCK[0] += 1
    run_sql()  # refused again
    CLOCK[0] += 60  # a new minute, any fold window long closed
    run_sql()
    with reporter._lock:  # pylint: disable=protected-access
        reporter._close_folds(float("inf"))  # pylint: disable=protected-access
    counts = [e["attrs"]["shield360.rasp.count"] for e in reporter.pending() if e["name"] == RASP_VULNERABILITY]
    assert counts == ["3"]
