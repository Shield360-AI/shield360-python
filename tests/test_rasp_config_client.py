"""Signed config client: verified only against a pinned key; the response's
own keys are never trusted unless allow_unpinned_config (trust on first use);
JWKS rotation; expiry; ETag; cache re-verification; the kill switch.

Mirrors sdk/typescript/src/rasp/__tests__/config-client.test.ts.
"""

import base64
import json
import logging
import time

import pytest

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")

# pylint: disable=wrong-import-position,redefined-outer-name
from shield360 import rasp
from shield360.rasp._config_client import BACKOFF_S, JWS_TYPE, RaspConfigClient, parse_public_keys, verify_config_jws
from shield360.rasp._engine import configure_engine, is_active, mode_for, set_remote_config

NOW = 1_800_000_000


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64json(o) -> str:
    return b64(json.dumps(o).encode())


class Pair:
    def __init__(self, kid):
        self.kid = kid
        self.priv = ed25519.Ed25519PrivateKey.generate()
        pub = self.priv.public_key()
        self.x = b64(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        self.pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def renamed(self, kid):
        other = Pair.__new__(Pair)
        other.kid, other.priv, other.x, other.pem = kid, self.priv, self.x, self.pem
        return other


def claims(**over):
    c = {
        "v": 1,
        "app": "orders-api",
        "iat": NOW,
        "exp": NOW + 3600,
        "version": "abc123",
        "killSwitch": False,
        "snippets": False,
        "mode": "monitor",
        "attacks": {},
        "allow": {"commands": [], "outboundHosts": [], "fileRoots": []},
        "rules": None,
    }
    c.update(over)
    return c


def jws(key, c, **header):
    head = b64json({"alg": "EdDSA", "typ": JWS_TYPE, "kid": key.kid, **header})
    body = b64json(c)
    return f"{head}.{body}.{b64(key.priv.sign(f'{head}.{body}'.encode()))}"


def jwk(k):
    return {"kty": "OKP", "crv": "Ed25519", "x": k.x, "kid": k.kid}


K1 = Pair("k1")
K2 = Pair("k2")
PINNED = parse_public_keys(jwk(K1))


# ---- verify_config_jws ----


def test_accepts_a_config_signed_by_the_pinned_key():
    r = verify_config_jws(jws(K1, claims()), PINNED, "orders-api", NOW)
    assert r["ok"] and r["claims"]["version"] == "abc123"


def test_refuses_another_key_whatever_kid_it_names():
    assert verify_config_jws(jws(K2, claims()), PINNED, "orders-api", NOW) == {"ok": False, "reason": "signature"}
    assert verify_config_jws(jws(K2.renamed("k1"), claims()), PINNED, "orders-api", NOW) == {"ok": False, "reason": "signature"}


def test_refuses_wrong_typ_alg_app_version_or_expired():
    assert verify_config_jws(jws(K1, claims(), typ="JWT"), PINNED, "orders-api", NOW)["reason"] == "typ"
    assert verify_config_jws(jws(K1, claims(), alg="none"), PINNED, "orders-api", NOW)["reason"] == "alg"
    assert verify_config_jws(jws(K1, claims(app="other")), PINNED, "orders-api", NOW)["reason"] == "app"
    assert verify_config_jws(jws(K1, claims(v=2)), PINNED, "orders-api", NOW)["reason"] == "version"
    assert verify_config_jws(jws(K1, claims(v=True)), PINNED, "orders-api", NOW)["reason"] == "version"
    assert verify_config_jws(jws(K1, claims(exp=NOW - 61)), PINNED, "orders-api", NOW)["reason"] == "expired"
    assert verify_config_jws(jws(K1, claims(exp=NOW - 30)), PINNED, "orders-api", NOW)["ok"]


def test_refuses_a_tampered_payload():
    h, _, s = jws(K1, claims()).split(".")
    assert verify_config_jws(f"{h}.{b64json(claims(killSwitch=True))}.{s}", PINNED, "orders-api", NOW)["reason"] == "signature"


def test_jwks_rotation_either_pinned_kid_verifies_an_unpinned_kid_does_not():
    k3 = Pair("k3")
    keys = parse_public_keys(json.dumps({"keys": [jwk(K1), jwk(K2)]}))
    assert len(keys) == 2
    assert verify_config_jws(jws(K1, claims()), keys, "orders-api", NOW)["ok"]
    assert verify_config_jws(jws(K2, claims()), keys, "orders-api", NOW)["ok"]
    assert not verify_config_jws(jws(k3, claims()), keys, "orders-api", NOW)["ok"]


def test_parses_jwk_jwks_or_bare_x_refuses_anything_else():
    assert len(parse_public_keys(K1.x)) == 1
    assert parse_public_keys(json.dumps(jwk(K1)))[0].kid == "k1"
    assert parse_public_keys({"keys": [jwk(K1)]})[0].x == K1.x
    assert parse_public_keys(K1.pem) == []
    assert parse_public_keys("not-a-key") == []
    assert parse_public_keys({"kty": "RSA", "crv": "x", "x": K1.x}) == []
    # A bare key (no kid) verifies whatever kid the header names; so does a JWKS when the header's kid is not listed.
    assert verify_config_jws(jws(K1, claims()), parse_public_keys(K1.x), "orders-api", NOW)["ok"]
    either = parse_public_keys({"keys": [jwk(K2), jwk(K1)]})
    assert verify_config_jws(jws(K1.renamed("unlisted"), claims()), either, "orders-api", NOW)["ok"]


def test_pure_python_verifier_agrees(monkeypatch):
    from shield360.ai_security import _config

    monkeypatch.setattr(_config, "ed25519_verify", _config._verify_pure)
    assert verify_config_jws(jws(K1, claims()), PINNED, "orders-api", NOW)["ok"]
    assert not verify_config_jws(jws(K2, claims()), PINNED, "orders-api", NOW)["ok"]


# ---- RaspConfigClient ----


class Served:
    def __init__(self, status=200, config=None, keys=None, etag=None):
        self.status, self.config, self.keys, self.etag = status, config, keys or [], etag


class FakeFetch:
    def __init__(self, serve):
        self.serve = serve
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append({"url": url, "headers": dict(headers)})
        s = self.serve()
        body = b"" if s.status == 304 else json.dumps({"config": s.config, "keys": s.keys}).encode()
        return s.status, ({"etag": s.etag} if s.etag else {}), body


@pytest.fixture
def env(tmp_path):
    state = {"applied": [], "warnings": [], "now": float(NOW)}

    def make(serve, **over):
        fetch = FakeFetch(serve)
        opts = {
            "url": "https://shield.example.com/",
            "api_key": "test-api-key",
            "app": "orders-api",
            "pinned": parse_public_keys(jwk(K1)),
            "cache_dir": str(tmp_path),
            "on_config": state["applied"].append,
            "on_warning": state["warnings"].append,
            "fetch": fetch,
            "now": lambda: state["now"],
        }
        opts.update(over)
        return RaspConfigClient(**opts), fetch

    state["make"] = make
    return state


def test_pinned_fetches_with_the_api_key_and_applies_a_verified_config(env):
    c, fetch = env["make"](lambda: Served(config=jws(K1, claims()), keys=[jwk(K1)], etag='"e1"'))
    assert c.poll() == "updated"
    assert fetch.calls[0]["url"] == "https://shield.example.com/api/rasp/config?app=orders-api"
    assert fetch.calls[0]["headers"]["Authorization"] == "Bearer test-api-key"
    assert env["applied"][0]["version"] == "abc123"


def test_pinned_the_responses_own_key_is_not_trusted(env):
    c, _ = env["make"](lambda: Served(config=jws(K2, claims()), keys=[jwk(K2)]))
    assert c.poll() == "rejected"
    assert env["applied"] == []
    assert env["warnings"] == ["signature"]


def test_unpinned_refused_without_fetching(env):
    c, fetch = env["make"](lambda: Served(config=jws(K1, claims()), keys=[jwk(K1)]), pinned=[])
    assert c.poll() == "rejected"
    assert fetch.calls == []
    assert env["applied"] == []
    assert env["warnings"] == ["unpinned"]


def test_allow_unpinned_trusts_the_first_key_then_refuses_a_different_one(env):
    key = {"k": K1}
    c, _ = env["make"](lambda: Served(config=jws(key["k"], claims()), keys=[jwk(key["k"])]), pinned=[], allow_unpinned=True)
    assert c.poll() == "updated"
    assert "trust_on_first_use" in env["warnings"]
    key["k"] = K2
    assert c.poll() == "rejected"


def test_etag_sends_if_none_match_and_keeps_the_config_on_304(env):
    status = {"s": 200}
    c, fetch = env["make"](lambda: Served(status=status["s"], config=jws(K1, claims()), etag='"e1"'))
    c.poll()
    status["s"] = 304
    assert c.poll() == "unchanged"
    assert fetch.calls[1]["headers"]["If-None-Match"] == '"e1"'
    assert c.current["version"] == "abc123"


def test_expiry_refused_and_the_one_in_force_dropped_once_it_expires(env):
    stale, _ = env["make"](lambda: Served(config=jws(K1, claims(exp=NOW - 3600))))
    assert stale.poll() == "rejected"
    up = {"v": True}
    c, _ = env["make"](lambda: Served(config=jws(K1, claims(exp=NOW + 120))) if up["v"] else Served(status=503))
    c.poll()
    up["v"] = False
    env["now"] += 600
    assert c.poll() == "failed"
    assert env["applied"][-1] is None
    assert c.current is None


def test_failures_back_off_to_5_minutes_success_polls_about_every_minute(env):
    c, _ = env["make"](Served, rand=lambda: 1.0)
    assert c.next_delay("failed") == BACKOFF_S
    assert c.next_delay("rejected") == BACKOFF_S
    assert c.next_delay("updated") == 70.0


def test_cache_re_verified_on_load_a_tampered_cache_is_refused(env):
    c, _ = env["make"](lambda: Served(config=jws(K1, claims(version="cached"))))
    c.poll()
    fresh, _ = env["make"](lambda: Served(status=503))
    assert fresh.load_cache()
    assert fresh.current["version"] == "cached"
    with open(fresh.cache_file(), "w", encoding="utf-8") as f:
        json.dump({"config": jws(K2, claims(version="forged")), "tofu": [jwk(K2)]}, f)
    other, _ = env["make"](lambda: Served(status=503))
    assert not other.load_cache()
    assert other.current is None


def test_never_raises_on_a_network_error_or_a_malformed_body(env):
    def offline(*_):
        raise OSError("offline")

    boom, _ = env["make"](Served, fetch=offline)
    assert boom.poll() == "failed"
    c, _ = env["make"](lambda: Served(config="not.a.jws"))
    assert c.poll() == "rejected"


# ---- init_rasp and the signed config ----


@pytest.fixture
def clean():
    yield
    rasp.shutdown_rasp()
    configure_engine(enabled=False, application_name="default", env={})


def test_without_a_pin_no_fetch_monitor_defaults_one_log_line(clean, caplog):
    rasp.reset_rasp_warnings()
    urls = []

    def fetch(url, headers, timeout):
        urls.append(url)
        return 200, {}, b"{}"

    def urlopen(req, timeout=10):
        urls.append(req.full_url)
        raise OSError("offline")

    with caplog.at_level(logging.WARNING, logger="shield360.rasp"):
        ctx = {
            "application_name": "orders-api",
            "url": "https://shield.example.com",
            "api_key": "k",
            "env": {},
            "fetch": fetch,
            "urlopen": urlopen,
        }
        assert rasp.init_rasp({"enabled": True, "mode": "block", "attacks": {"ssrf": "off"}, "components": False}, **ctx)
        assert mode_for("sql_injection") == "monitor"
        assert mode_for("ssrf") == "off"
        rasp.init_rasp({"enabled": True, "components": False}, **ctx)
        rasp.shutdown_rasp()
    assert [u for u in urls if "/api/rasp/config" in u] == []
    assert [u for u in urls if "/api/guard/events" in u] == []
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1 and "config_public_key" in warnings[0].getMessage()


def test_trust_on_first_use_only_with_the_opt_in_never_in_production(clean, tmp_path):
    assert rasp.tofu_allowed(True, {})
    assert rasp.tofu_allowed(None, {"SHIELD360_CONFIG_TOFU": "dev"})
    assert not rasp.tofu_allowed(None, {})
    assert not rasp.tofu_allowed(True, {"NODE_ENV": "production"})
    assert not rasp.tofu_allowed(None, {"SHIELD360_CONFIG_TOFU": "dev", "ENVIRONMENT": "production"})
    assert not rasp.tofu_allowed(True, {}, environment="production")

    def down(*_):
        return 503, {}, b"{}"

    base = {"application_name": "a", "url": "https://s.example.com", "api_key": "k", "fetch": down}
    opts = {"enabled": True, "mode": "block", "components": False}
    rasp.init_rasp({**opts, "allow_unpinned_config": True}, env={"NODE_ENV": "production"}, **base)
    assert mode_for("sql_injection") == "monitor"
    rasp.init_rasp({**opts, "cache_dir": str(tmp_path)}, env={"SHIELD360_CONFIG_TOFU": "dev"}, **base)
    assert mode_for("sql_injection") == "block"


def test_with_a_pin_from_the_env_the_signed_kill_switch_turns_checks_off(clean, tmp_path):
    def fetch(url, headers, timeout):
        if "/api/rasp/config" in url:
            return 200, {}, json.dumps({"config": jws(K1, claims(exp=int(time.time()) + 600, killSwitch=True))}).encode()
        return 200, {}, b"{}"

    rasp.init_rasp(
        {"enabled": True, "components": False, "cache_dir": str(tmp_path)},
        application_name="orders-api",
        url="https://shield.example.com",
        api_key="k",
        env={"SHIELD360_CONFIG_PUBLIC_KEY": json.dumps({"keys": [jwk(K1)]})},
        fetch=fetch,
        urlopen=lambda *a, **k: None,
    )
    deadline = time.time() + 5
    while is_active() and time.time() < deadline:
        time.sleep(0.01)
    assert not is_active()


def test_env_off_wins_no_url_means_local_options_only(clean):
    assert not rasp.init_rasp({"enabled": True}, application_name="a", env={"SHIELD360_RASP": "off"})
    assert rasp.init_rasp({"enabled": True, "mode": "block"}, application_name="a", env={})
    assert mode_for("sql_injection") == "block"
    assert rasp.init_rasp(None, application_name="a", env={"SHIELD360_RASP": "monitor"})
    assert not rasp.init_rasp(None, application_name="a", env={})
    set_remote_config(None)


def test_runtime_switch_disable_and_enable(clean):
    assert rasp.init_rasp(True, application_name="a", env={})
    rasp.disable()
    assert not rasp.rasp_active()
    rasp.enable_rasp()
    assert rasp.rasp_active()
    rasp.disable_rasp()
    assert not rasp.rasp_active()
    rasp.enable()


def test_a_stopped_client_never_applies_or_caches_a_fetch_still_in_flight(env):
    """Re-init for another app while a fetch is pending: the old client's answer must not reach the engine."""
    import threading  # pylint: disable=import-outside-toplevel

    entered, release = threading.Event(), threading.Event()

    def slow():
        entered.set()
        release.wait(5)
        return Served(config=jws(K1, claims(killSwitch=True)))

    c, _ = env["make"](slow)
    result = {}
    t = threading.Thread(target=lambda: result.setdefault("r", c.poll()))
    t.start()
    assert entered.wait(5)
    c.stop()
    release.set()
    t.join(5)
    assert result["r"] == "rejected"
    assert env["applied"] == []
    assert c.current is None
    assert not c.load_cache()  # nothing was cached either
