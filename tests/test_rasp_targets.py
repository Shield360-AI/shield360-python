"""Allow-list targets (sdk/rasp/README.md "Events", "Allow-list targets"): the
shared conformance cases (sdk/rasp/testdata/targets.json), the detectors that
fill a finding's target and dialect, and the event, which carries
``shield360.rasp.target`` only with the signed ``reportTargets`` and
``shield360.rasp.sql.dialect`` on every SQL finding.
"""

import time

import pytest

from rasp_corpus import load_json
from shield360.rasp import _to_remote
from shield360.rasp._detect import detect_outbound, detect_path, detect_shell_spawn, detect_sql, target_directory
from shield360.rasp._engine import (
    RemoteConfig,
    configure_engine,
    handle_finding,
    mask_target,
    set_event_sink,
    set_remote_config,
)
from shield360.rasp._types import Finding, RaspInput

DATA = load_json("testdata/targets.json")
EVENTS = []


class _Sink:
    def add(self, event, fold_key):  # pylint: disable=unused-argument
        EVENTS.append(event)


@pytest.fixture(autouse=True)
def _engine():
    EVENTS.clear()
    configure_engine(enabled=True, application_name="orders-api", mode="monitor", env={})
    set_event_sink(_Sink())
    yield
    set_event_sink(None)
    configure_engine(enabled=False, application_name="default", env={})


def remote(**kw):
    return RemoteConfig(version="v1", exp=time.time() + 3600, **kw)


def attrs_of(f, sink="subprocess.Popen"):
    handle_finding(f, sink)
    return EVENTS[-1]["attrs"]


@pytest.mark.parametrize("case", DATA["mask"], ids=[c["raw"][:40] for c in DATA["mask"]])
def test_mask_conformance(case):
    assert mask_target(case["raw"]) == case["target"]


@pytest.mark.parametrize("case", DATA["directory"], ids=[c["resolved"] for c in DATA["directory"]])
def test_directory_conformance(case):
    assert target_directory(case["resolved"]) == case["directory"]


def test_detectors_fill_the_target_and_the_dialect():
    assert detect_shell_spawn(argv0="/bin/BASH.exe", in_request=True).target == "bash"
    assert detect_outbound("https://user@API.Example.com:8443/x?q=1", ["allowed.example.com"]).target == "api.example.com"
    f = detect_path("/var/data/../etc/x.txt", "read", [RaspInput("x.txt", "query.f", "request")], ["/srv/app"])
    assert f.rule == "path.outside_root" and f.target == "/var/etc"
    sql = detect_sql("SELECT * FROM t WHERE id = 1 OR 1=1", [RaspInput("1 OR 1=1", "query.id", "request")], "postgres")
    assert sql.attack == "sql_injection" and sql.dialect == "postgres"


def test_signed_config_parses_report_targets_strictly():
    base = {"version": "v1", "exp": time.time() + 3600}
    assert _to_remote({**base, "reportTargets": True}).report_targets is True
    assert _to_remote({**base, "reportTargets": "true"}).report_targets is False
    assert _to_remote(base).report_targets is False


SHELL = Finding("shell_spawn", "shell_spawn.shell", target="bash")


def test_target_only_with_report_targets_true():
    assert "shield360.rasp.target" not in attrs_of(SHELL)  # local options: never
    set_remote_config(remote())
    assert "shield360.rasp.target" not in attrs_of(SHELL)
    set_remote_config(remote(report_targets=False))
    assert "shield360.rasp.target" not in attrs_of(SHELL)
    set_remote_config(remote(report_targets=True))
    assert attrs_of(SHELL)["shield360.rasp.target"] == "bash"


def test_target_only_for_the_three_allow_list_rules():
    set_remote_config(remote(report_targets=True))
    other = Finding("path_traversal", "path.traversal", RaspInput("../x", "query.f", "request"), target="/var/data")
    assert "shield360.rasp.target" not in attrs_of(other, "open")
    a = attrs_of(Finding("path_traversal", "path.outside_root", target="/var/data"), "open")
    assert a["shield360.rasp.target"] == "/var/data"


def test_target_is_masked_and_capped():
    set_remote_config(remote(report_targets=True))
    host = Finding("outbound", "outbound.not_allowed", target="abcdefghijklmnopqrstuvwxyz0123.example.com")
    assert attrs_of(host, "urllib.request")["shield360.rasp.target"] == "***.example.com"
    long = Finding("path_traversal", "path.outside_root", target="/ab" * 100)
    assert "shield360.rasp.target" not in attrs_of(long, "open")


def test_sql_findings_carry_the_dialect_whatever_report_targets_says():
    f = Finding("sql_injection", "sqli.userinput", RaspInput("1 OR 1=1", "query.id", "request"), dialect="mysql")
    assert attrs_of(f, "pymysql.execute")["shield360.rasp.sql.dialect"] == "mysql"
    odd = Finding("sql_injection", "sqli.userinput", RaspInput("1 OR 1=1", "query.id", "request"), dialect="nope")
    assert "shield360.rasp.sql.dialect" not in attrs_of(odd, "pymysql.execute")
