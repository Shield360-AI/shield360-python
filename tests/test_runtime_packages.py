"""Runtime package report: component records through the guard events
transport, on by default, off by option or env, bounded.

Mirrors sdk/typescript/src/__tests__/runtime-packages.test.ts.
"""

import json
import threading
import urllib.error

from shield360 import runtime_packages as rp


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def recorder(status=200):
    posts = []

    def urlopen(req, timeout=10):
        posts.append({"url": req.full_url, "auth": req.get_header("Authorization"), "body": json.loads(req.data)})
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, "refused", {}, None)
        return _Resp()

    return posts, urlopen


def one():
    return [{"ecosystem": "pypi", "name": "flask", "version": "3.1.0"}]


def teardown_function():
    rp.stop_runtime_packages()


def test_enabled_by_default_and_off_by_option_or_env():
    assert rp.runtime_packages_enabled(None, {}) is True
    assert rp.runtime_packages_enabled(True, {}) is True
    assert rp.runtime_packages_enabled(False, {}) is False
    for v in ("off", "false", "0", "NO"):
        assert rp.runtime_packages_enabled(None, {"SHIELD360_RUNTIME_PACKAGES": v}) is False
    assert rp.runtime_packages_enabled(None, {"SHIELD360_RUNTIME_PACKAGES": "on"}) is True


def test_report_sends_names_and_versions_to_guard_events_with_the_api_key():
    posts, urlopen = recorder()
    ok = rp.report_runtime_packages(
        "https://shield.example.com/", "test-api-key", "orders-api", "prod", "1.2.0", collect=one, urlopen=urlopen
    )
    assert ok is True
    assert posts[0]["url"] == "https://shield.example.com/api/guard/events"
    assert posts[0]["auth"] == "Bearer test-api-key"
    body = posts[0]["body"]
    assert body["resource"]["service.name"] == "orders-api"
    assert body["resource"]["deployment.environment"] == "prod"
    assert body["events"][0]["name"] == "shield360.rasp.component"
    assert body["events"][0]["attrs"] == {
        "shield360.rasp.app": "orders-api",
        "shield360.rasp.component.ecosystem": "pypi",
        "shield360.rasp.component.name": "flask",
        "shield360.rasp.component.version": "3.1.0",
    }


def test_report_batches_by_100_and_caps_at_500():
    posts, urlopen = recorder()
    many = [{"ecosystem": "pypi", "name": f"p{i}", "version": "1.0"} for i in range(700)]
    rp.report_runtime_packages("https://s.example", "k", "app", collect=lambda: many, urlopen=urlopen)
    assert [len(p["body"]["events"]) for p in posts] == [100, 100, 100, 100, 100]


def test_report_stops_at_a_refusal_and_never_raises():
    posts, urlopen = recorder(status=401)
    many = [{"ecosystem": "pypi", "name": f"p{i}", "version": "1.0"} for i in range(250)]
    assert rp.report_runtime_packages("https://s.example", "k", "app", collect=lambda: many, urlopen=urlopen) is False
    assert len(posts) == 1

    def boom():
        raise RuntimeError("boom")

    assert rp.report_runtime_packages("https://s.example", "k", "app", collect=boom, urlopen=urlopen) is False
    assert rp.report_runtime_packages(None, "k", "app", collect=one, urlopen=urlopen) is False


def test_start_reports_after_the_delay_once_per_process():
    _, urlopen = recorder()
    done = threading.Event()

    def collect():
        done.set()
        return one()

    assert rp.start_runtime_packages(
        "https://s.example", "k", "app", start_delay=0.01, every=3600, env={}, collect=collect, urlopen=urlopen
    )
    assert rp.start_runtime_packages("https://s.example", "k", "app", env={}, collect=collect, urlopen=urlopen) is False
    assert rp.runtime_packages_active() is True
    assert done.wait(5)
    rp.stop_runtime_packages()
    assert rp.runtime_packages_active() is False


def test_start_does_nothing_when_off_or_without_a_key():
    assert rp.start_runtime_packages("https://s.example", "k", "app", option=False, env={}) is False
    assert rp.start_runtime_packages("https://s.example", "k", "app", env={"SHIELD360_RUNTIME_PACKAGES": "off"}) is False
    assert rp.start_runtime_packages(None, "k", "app", env={}) is False
    assert rp.runtime_packages_active() is False


def test_the_default_collector_sends_no_paths():
    comps = rp.collect_components()
    assert comps[0]["ecosystem"] == "runtime"
    assert all(set(c) == {"ecosystem", "name", "version"} for c in comps)
    assert all("/" not in c["name"] for c in comps)
