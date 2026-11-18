"""Web Bot Auth on the agent verifier: signatures in both Signature-Agent forms (the draft's
dictionary and Cloudflare's bare string), every failure reason, the key directory's rules, the
fetch budget, the receiver policy and the request shapes (headers, WSGI environ, ASGI scope,
request objects). Signatures are built from hand-written signature bases, not from the code under
test. Mirrors sdk/typescript/src/agents/__tests__/web-bot-auth.test.ts."""
# pylint: disable=redefined-outer-name

import asyncio
import base64
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from shield360.agents import AgentVerifier, AgentVerifierASGIMiddleware, AgentVerifierWSGIMiddleware, jwk_thumbprint
from shield360.agents._structured import InnerList, parse_dictionary, serialize_inner_list
from shield360.agents._web_bot_auth import directory_url

T0 = datetime(2026, 11, 9, 12, 0, 0, tzinfo=timezone.utc).timestamp()
NOW = int(T0)
SIGNER = "https://signer.example.com"
WELL_KNOWN = f"{SIGNER}/.well-known/http-message-signatures-directory"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Key:
    def __init__(self):
        self.private = Ed25519PrivateKey.generate()
        x = b64url(self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        self.jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
        self.key_id = jwk_thumbprint("OKP", "Ed25519", x)


class Directory:
    """A fake transport serving one JWKS (or an error status) and recording the URLs asked for."""

    def __init__(self, keys, status=200):
        self.keys = keys
        self.status = status
        self.calls = []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append(url)
        if self.status != 200:
            return self.status, b""
        return 200, json.dumps({"keys": self.keys}).encode()


def signed(  # pylint: disable=too-many-arguments
    key, form="legacy", authority="api.servflo.ai", created=None, expires=None, nonce="n-1", agent=SIGNER, extra=(), tag="web-bot-auth"
):
    """Signed headers for a request to ``authority``, the signature base written out by hand."""
    created = NOW if created is None else created
    expires = NOW + 60 if expires is None else expires
    agent_header = f'"{agent}"' if form == "legacy" else f'sig1="{agent}"'
    agent_component = '"signature-agent"' if form == "legacy" else '"signature-agent";key="sig1"'
    components = ['"@authority"', agent_component, *[c for c, _ in extra]]
    nonce_param = f';nonce="{nonce}"' if nonce else ""
    params = f';created={created};expires={expires};keyid="{key.key_id}";alg="ed25519"{nonce_param};tag="{tag}"'
    sig_params = f"({' '.join(components)}){params}"
    lines = [f'"@authority": {authority}', f'{agent_component}: "{agent}"', *[f"{c}: {v}" for c, v in extra]]
    base = "\n".join([*lines, f'"@signature-params": {sig_params}'])
    signature = base64.b64encode(key.private.sign(base.encode())).decode()
    return {
        "host": authority,
        "signature-agent": agent_header,
        "signature-input": f"sig1={sig_params}",
        "signature": f"sig1=:{signature}:",
    }


def verifier(net, **over):
    clock = over.pop("clock", lambda: T0)
    return AgentVerifier(audience="api.servflo.ai", http=net, clock=clock, **over)


# ---------------------------------------------------------------- signatures that verify


def test_verifies_cloudflares_bare_string_and_fetches_the_well_known_directory():
    key = Key()
    net = Directory([key.jwk])
    r = verifier(net).check(signed(key))
    assert (r.status, r.decision, r.blocked, r.via) == ("verified", "allow", False, "web-bot-auth")
    assert (r.agent.id, r.agent.name) == ("signer.example.com", "signer.example.com")
    assert (r.operator.id, r.operator.domain) == ("signer.example.com", "signer.example.com")
    assert r.issuer == SIGNER
    assert (r.signature.agent, r.signature.key_id) == (SIGNER, key.key_id)
    assert r.on_behalf_of is None
    assert r.expires_at == datetime.fromtimestamp(NOW + 60, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    assert net.calls == [WELL_KNOWN]
    assert r.to_dict()["via"] == "web-bot-auth"
    assert r.to_dict()["signature"] == {"agent": SIGNER, "keyId": key.key_id}


def test_verifies_the_drafts_dictionary_form():
    key = Key()
    assert verifier(Directory([key.jwk])).check(signed(key, form="dictionary")).status == "verified"


def test_covers_method_path_and_query_of_a_wsgi_request():
    key = Key()
    extra = (('"@method"', "POST"), ('"@path"', "/v1/jobs"), ('"@query"', "?page=2"))
    h = signed(key, form="dictionary", extra=extra)
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/v1/jobs",
        "QUERY_STRING": "page=2",
        "wsgi.url_scheme": "https",
        "wsgi.version": (1, 0),
    }
    environ.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in h.items()})
    net = Directory([key.jwk])
    assert verifier(net).check(environ).status == "verified"
    # The same signature on another path does not verify.
    again = signed(key, form="dictionary", nonce="n-2", extra=extra)
    other = {**environ, "PATH_INFO": "/v1/admin", **{"HTTP_" + k.upper().replace("-", "_"): v for k, v in again.items()}}
    r = verifier(net).check(other)
    assert (r.status, r.decision, r.reason, r.via) == ("invalid", "deny", "bad_signature", "web-bot-auth")


def test_reads_bare_headers_with_route_method_and_query_arguments():
    key = Key()
    h = signed(key, extra=(('"@method"', "GET"), ('"@path"', "/v1/jobs"), ('"@query"', "?a=1")))
    assert verifier(Directory([key.jwk])).check(h, route="/v1/jobs", method="get", query="a=1").status == "verified"


def test_reads_a_request_object_with_a_url():
    key = Key()

    class URL:
        path, query, scheme, netloc = "/v1/jobs", "", "https", "api.servflo.ai"

    class Request:
        method = "GET"
        url = URL()

        def __init__(self, headers):
            self.headers = headers

    h = signed(key, extra=(('"@path"', "/v1/jobs"),))
    assert verifier(Directory([key.jwk])).check(Request(h)).status == "verified"


def test_caches_the_directory():
    key = Key()
    net = Directory([key.jwk])
    v = verifier(net)
    v.check(signed(key, nonce="a"))
    v.check(signed(key, nonce="b"))
    assert len(net.calls) == 1


def test_reads_the_directory_from_a_signature_agent_url_with_a_path():
    key = Key()
    net = Directory([key.jwk])
    assert verifier(net).check(signed(key, agent="https://signer.example.com/keys.json")).status == "verified"
    assert net.calls == ["https://signer.example.com/keys.json"]


# ---------------------------------------------------------------- signatures that do not verify


@pytest.mark.parametrize(
    "opts, reason",
    [
        ({"created": NOW - 600, "expires": NOW - 300}, "expired"),
        ({"created": NOW + 600, "expires": NOW + 900}, "not_yet_valid"),
        ({"created": NOW - 10, "expires": NOW + 86_400}, "lifetime_too_long"),
        ({"created": NOW + 10, "expires": NOW}, "malformed"),
        ({"authority": "shop.example.org"}, "wrong_audience"),
        ({"agent": "http://signer.example.com"}, "untrusted_signature_agent"),
        ({"agent": "https://10.0.0.5"}, "untrusted_signature_agent"),
        ({"agent": "https://keys.internal"}, "untrusted_signature_agent"),
        ({"extra": (('"@status"', "200"),)}, "unsupported_component"),
    ],
)
def test_refuses(opts, reason):
    key = Key()
    r = verifier(Directory([key.jwk])).check(signed(key, **opts))
    assert (r.status, r.decision, r.reason, r.via) == ("invalid", "deny", reason, "web-bot-auth")


def test_refuses_a_signature_presented_twice_with_or_without_a_nonce():
    key = Key()
    v = verifier(Directory([key.jwk]))
    for nonce in ("once", None):
        h = signed(key, nonce=nonce)
        assert v.check(h).status == "verified"
        r = v.check(h)
        assert (r.status, r.reason) == ("invalid", "replayed")


def test_refuses_a_key_the_directory_does_not_list_or_lists_as_expired():
    key, other = Key(), Key()
    assert verifier(Directory([other.jwk])).check(signed(key)).reason == "unknown_key"
    assert verifier(Directory([{**key.jwk, "exp": NOW - 3600}])).check(signed(key)).reason == "unknown_key"


def test_refuses_a_signature_by_a_different_key_than_the_one_named():
    key, thief = Key(), Key()
    thief.key_id = key.key_id
    assert verifier(Directory([key.jwk])).check(signed(thief)).reason == "bad_signature"


def test_requires_the_signature_to_cover_the_signature_agent():
    key = Key()
    h = signed(key)
    h["signature-input"] = h["signature-input"].replace(' "signature-agent"', "")
    assert verifier(Directory([key.jwk])).check(h).reason == "malformed"


def test_never_takes_a_private_key_from_a_directory():
    key = Key()
    assert verifier(Directory([{**key.jwk, "d": b64url(b"\0" * 32)}])).check(signed(key)).reason == "unknown_key"


# ---------------------------------------------------------------- unreachable directories and the budget


@pytest.mark.parametrize("status", [500, 302])
def test_an_unreachable_directory_reads_as_unsigned(status):
    key = Key()
    net = Directory([key.jwk], status)
    r = verifier(net).check(signed(key))
    assert (r.status, r.decision, r.reason) == ("absent", "allow", "directory_unreachable")
    strict = verifier(net, policy={"require_agent": True, "mode": "enforce"})
    r = strict.check(signed(key, nonce="x"))
    assert (r.status, r.decision, r.blocked) == ("absent", "deny", True)


def test_starts_at_most_30_directory_fetches_a_minute():
    key = Key()
    net = Directory([key.jwk])
    t = [T0]
    v = verifier(net, clock=lambda: t[0])
    for i in range(40):
        v.check(signed(key, agent=f"https://signer{i}.example.com", nonce=f"n{i}"))
    assert len(net.calls) == 30
    r = v.check(signed(key, agent="https://late.example.com", nonce="late"))
    assert (r.status, r.reason) == ("absent", "directory_unreachable")
    t[0] += 61
    later = signed(key, agent="https://late.example.com", nonce="later", created=int(t[0]), expires=int(t[0]) + 60)
    assert v.check(later).status == "verified"


# ---------------------------------------------------------------- the receiver policy


def test_applies_the_operators_list_to_the_signer_host():
    key = Key()
    net = Directory([key.jwk])
    assert verifier(net, policy={"operators": ["signer.example.com"]}).check(signed(key)).decision == "allow"
    r = verifier(net, policy={"operators": ["acme.com"], "mode": "enforce"}).check(signed(key, nonce="z"))
    assert (r.status, r.decision, r.blocked, r.reason) == ("verified", "deny", True, "operator_not_allowed")


def test_denies_a_signature_when_the_policy_wants_a_person():
    key = Key()
    net = Directory([key.jwk])
    assert verifier(net, policy={"require_on_behalf_of": True}).check(signed(key)).reason == "on_behalf_of_required"
    assert verifier(net, policy={"min_assurance": "named"}).check(signed(key, nonce="q")).reason == "assurance_too_low"


def test_ignores_signatures_when_switched_off_and_untagged_ones():
    key = Key()
    net = Directory([key.jwk])
    assert verifier(net, web_bot_auth=False).check(signed(key)).status == "absent"
    assert verifier(net).check(signed(key, tag="something-else")).status == "absent"
    assert not net.calls


# ---------------------------------------------------------------- middleware


def test_asgi_middleware_passes_the_raw_path_query_and_scheme():
    key = Key()
    h = signed(key, extra=(('"@path"', "/v1/a%20b"), ('"@query"', "?x=1"), ('"@scheme"', "https")))
    v = verifier(Directory([key.jwk]))
    seen = {}

    async def app(scope, receive, send):
        seen["result"] = scope["shield360_agent"]

    scope = {
        "type": "http",
        "method": "GET",
        "scheme": "https",
        "path": "/v1/a b",
        "raw_path": b"/v1/a%20b",
        "query_string": b"x=1",
        "headers": [(k.encode(), val.encode()) for k, val in h.items()],
    }
    asyncio.run(AgentVerifierASGIMiddleware(app, v)(scope, None, None))
    assert seen["result"].status == "verified"


def test_wsgi_middleware_reads_the_environ():
    key = Key()
    h = signed(key, extra=(('"@method"', "POST"), ('"@path"', "/hook")))
    environ = {"REQUEST_METHOD": "POST", "PATH_INFO": "/hook", "wsgi.url_scheme": "https", "wsgi.version": (1, 0)}
    environ.update({"HTTP_" + k.upper().replace("-", "_"): v for k, v in h.items()})
    out = []
    def app(env, _start):
        out.append(env["shield360.agent"])
        return [b""]

    AgentVerifierWSGIMiddleware(app, verifier(Directory([key.jwk])))(environ, lambda *a: None)
    assert out[0].status == "verified"


# ---------------------------------------------------------------- helpers


def test_computes_the_rfc9421_ed25519_test_key_thumbprint():
    x = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    assert jwk_thumbprint("OKP", "Ed25519", x) == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


def test_round_trips_a_signature_input_member_byte_for_byte():
    v = '("@authority" "signature-agent";key="sig1");created=1;expires=2;keyid="k";alg="ed25519";nonce="a/b+c==";tag="web-bot-auth"'
    m = parse_dictionary(f"sig1={v}")["sig1"]
    assert isinstance(m, InnerList)
    assert serialize_inner_list(m) == v


def test_finds_the_directory_of_a_signature_agent():
    assert directory_url("https://Signer.Example.com") == (WELL_KNOWN, "signer.example.com")
    assert directory_url("https://signer.example.com:8443") is None
    assert directory_url("https://user@signer.example.com") is None
    assert directory_url("https://localhost") is None
