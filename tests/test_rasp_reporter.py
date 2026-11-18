"""RASP reporter: batched events through the guard events transport, folding
of repeats, the per-minute cap, the components report.

Mirrors sdk/typescript/src/rasp/__tests__/reporter.test.ts.
"""

import json
import platform

from shield360.rasp._reporter import FOLD_S, PER_MINUTE, RaspReporter, collect_components


def event(rule="sqli.userinput"):
    return {
        "name": "shield360.rasp.event",
        "time": "1970-01-01T00:00:00.000Z",
        "attrs": {"shield360.rasp.attack": "sql_injection", "shield360.rasp.rule": rule},
    }


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def reporter():
    posts = []
    clock = {"now": 1_000.0}

    def urlopen(req, timeout=10):
        posts.append({"url": req.full_url, "auth": req.get_header("Authorization"), "body": json.loads(req.data)})
        return _Resp()

    r = RaspReporter(
        "https://shield.example.com/",
        "test-api-key",
        "orders-api",
        environment="prod",
        sdk_version="1.2.0",
        urlopen=urlopen,
        now=lambda: clock["now"],
        retry_delay=0.001,
    )

    def advance(s):
        clock["now"] += s

    return r, posts, advance


def sent(posts):
    return [e for p in posts for e in p["body"]["events"]]


def test_posts_batches_to_guard_events_with_the_resource_and_the_api_key():
    r, posts, _ = reporter()
    r.add(event(), "k1")
    r.flush()
    assert len(posts) == 1
    assert posts[0]["url"] == "https://shield.example.com/api/guard/events"
    assert posts[0]["auth"] == "Bearer test-api-key"
    res = posts[0]["body"]["resource"]
    assert res["service.name"] == "orders-api" and res["deployment.environment"] == "prod" and res["service.version"] == "1.2.0"
    assert posts[0]["body"]["events"][0]["name"] == "shield360.rasp.event"


def test_folds_repeats_within_10_s_into_one_more_event_with_count():
    r, posts, advance = reporter()
    assert r.add(event(), "same")
    assert not r.add(event(), "same")
    assert not r.add(event(), "same")
    assert r.add(event("sqli.stacked"), "other")
    advance(FOLD_S)
    r.flush()
    out = sent(posts)
    assert len(out) == 3
    assert out[2]["attrs"]["shield360.rasp.count"] == "2"
    assert out[2]["attrs"]["shield360.rasp.rule"] == "sqli.userinput"


def test_caps_events_at_100_a_minute_per_process():
    r, posts, advance = reporter()
    for i in range(PER_MINUTE + 20):
        r.add(event(), f"k{i}")
    assert len(r.pending()) == PER_MINUTE
    advance(60)
    assert r.add(event(), "later")
    r.flush()
    assert len(sent(posts)) == PER_MINUTE + 1


def test_stop_closes_open_folds_and_sends_them():
    r, posts, _ = reporter()
    r.add(event(), "k")
    r.add(event(), "k")
    r.stop(wait=5)
    assert [e["attrs"].get("shield360.rasp.count") for e in sent(posts)] == [None, "1"]


def test_components_names_and_versions_only():
    r, posts, _ = reporter()
    r.report_components([{"ecosystem": "pypi", "name": "flask", "version": "3.1.0"}])
    r.flush()
    e = posts[0]["body"]["events"][0]
    assert e["name"] == "shield360.rasp.component"
    assert e["attrs"] == {
        "shield360.rasp.app": "orders-api",
        "shield360.rasp.component.ecosystem": "pypi",
        "shield360.rasp.component.name": "flask",
        "shield360.rasp.component.version": "3.1.0",
    }


def test_never_raises_when_the_transport_fails():
    def offline(req, timeout=10):
        raise OSError("offline")

    r = RaspReporter("https://shield.example.com", "k", "a", urlopen=offline, retry_delay=0.001)
    r.add(event(), "k")
    r.flush()


class _Dist:
    def __init__(self, name, version):
        self.metadata = {"Name": name, "description": "not sent"}
        self.version = version


def test_collect_components_runtime_loaded_then_installed_no_other_fields():
    dists = [_Dist("left", "1.4.0"), _Dist("pytest", "8.0.0"), _Dist("bad name!", "1.0"), _Dist("left", "1.4.0")]
    got = collect_components(modules={"pytest": object()}, distributions=dists)
    assert got[0] == {"ecosystem": "runtime", "name": "python", "version": platform.python_version()}
    assert {"ecosystem": "pypi", "name": "left", "version": "1.4.0"} in got
    assert {"ecosystem": "pypi", "name": "pytest", "version": "8.0.0"} in got
    assert all(set(c) == {"ecosystem", "name", "version"} for c in got)
    assert len([c for c in got if c["name"] == "left"]) == 1
    assert not any(c["name"] == "bad name!" for c in got)


def test_stop_never_waits_on_the_network():
    """init_rasp() stops the previous reporter: an unreachable endpoint must not hold it up."""
    import threading  # pylint: disable=import-outside-toplevel
    import time  # pylint: disable=import-outside-toplevel

    release = threading.Event()
    posts = []

    def hanging(req, timeout=10):
        release.wait(5)
        posts.append(req.full_url)
        raise OSError("unreachable")

    for started in (False, True):
        posts.clear()
        release.clear()
        r = RaspReporter("https://shield.example.com", "k", "a", urlopen=hanging, retry_delay=0.001)
        if started:
            r.start()
        r.add(event(), "k")
        t0 = time.monotonic()
        r.stop()
        assert time.monotonic() - t0 < 0.5
        release.set()
        r._thread.join(5)  # pylint: disable=protected-access
        assert posts  # the queued event was still attempted, off the caller's thread
