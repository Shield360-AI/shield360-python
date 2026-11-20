"""Defend's honeypots in Python: the shared crumb spec (the same test vector as Edge and the TypeScript
SDK), depth, attribution, rotation, never for trusted or private clients, and the fast local block."""

import base64
import time

from shield360.defend._honeypots import Crumbs, Honeypots, canonical_ip, fingerprint, parse_honeypots

SECRET = b"0123456789abcdef0123456789abcdef"
DAY = 86_400


def test_spec_test_vector():
    assert fingerprint("192.0.2.1", "Agent/1.0").hex() == "5330e5f83644"
    assert (
        Crumbs(SECRET, clock=lambda: 20000 * DAY).token("p", fingerprint("192.0.2.1", "Agent/1.0"))
        == "aeaaatraobjtbzpygzcgysx5gll3ruka"
    )
    assert canonical_ip("::ffff:192.0.2.1") == "192.0.2.1"


def test_depth_attribution_rotation():
    now = [20000 * DAY]
    hp = Honeypots(
        parse_honeypots({"enabled": True, "mode": "block", "secret": base64.urlsafe_b64encode(SECRET).decode().rstrip("=")}),
        ["orders"],
        lambda: now[0],
    )
    c = hp.crumbs_for("203.0.113.5", "agent/1")
    fp = fingerprint("203.0.113.5", "agent/1").hex()
    assert hp.check("/.env", "", {}, fp)["level"] == 1
    assert hp.check(c["path"], "", {}, fp)["level"] == 2
    assert hp.check("/api/x", "", {"authorization": "Bearer " + c["apiKey"]}, fp)["level"] == 3
    assert hp.check(c["path"], "", {}, fingerprint("198.51.100.7", "agent/1").hex())["foreign"] is True
    now[0] += 2 * DAY
    assert hp.check(c["path"], "", {}, fp)["state"] == "burned"
    assert "key_" in hp.serve("/.env", "203.0.113.5", "a")["body"]


def test_defend_blocks_next_request_and_spares_private(tmp_path):
    from test_defend import Server, claims, make  # pylint: disable=import-outside-toplevel

    secret = base64.urlsafe_b64encode(SECRET).decode().rstrip("=")
    s = Server(claims(honeypots={"enabled": True, "mode": "block", "secret": secret}))
    d = make(s, tmp_path)
    req = {"method": "GET", "path": "/", "ip": "203.0.113.5", "headers": {"user-agent": "agent/1"}}
    c = d.crumbs(req)
    started = time.perf_counter()
    on_crumb = d.defend({**req, "path": c["path"]})
    assert on_crumb["decoy"]["status"] == 200
    assert d.defend({**req, "path": "/api/users"})["decision"] == "deny"
    assert time.perf_counter() - started < 0.05
    assert d.crumbs({**req, "ip": "10.0.0.4"}) is None
    assert "decoy" not in d.defend({**req, "ip": "10.0.0.4", "path": "/.env"})
