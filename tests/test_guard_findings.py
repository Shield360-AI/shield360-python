"""Masked, fingerprinted findings: never the value."""

import hashlib
import hmac
import json

from shield360.guard import _findings, _report
from shield360.guard._base import GuardPhase
from shield360.guard._pipeline import Pipeline
from shield360.guard.pii import PII

SSN = "123-45-" + "6789"
CARD = "4111 1111 " + "1111 1111"
OPENAI = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz0123"


def teardown_function():
    _findings.set_key(None)


def test_masks_show_no_character_of_the_value():
    assert _findings.mask("ssn", SSN) == "[ssn]"
    assert _findings.mask("credit-card", CARD) == "[payment_card]"
    assert _findings.mask("openai-api-key", OPENAI) == "[api_key]"
    assert _findings.mask("email", "ana@acme.test") == "[email]"
    assert _findings.mask("env-secret", "pass" + "word=Hunter2Hunter2!") == "[password]"
    _findings.set_key("org-secret")
    fp = _findings.fingerprint("openai-api-key", OPENAI)
    assert _findings.mask("openai-api-key", OPENAI) == f"[api_key:fp_{fp[:8]}]"


def test_token_vectors_match_guard_core():
    import pathlib

    here = pathlib.Path(__file__).resolve()
    # Beside this SDK in the monorepo (sdk/guard-core), or inside the SDK's public mirror (guard-core/).
    candidates = [
        here.parents[2] / "guard-core" / "testdata" / "tokens.json",
        here.parents[1] / "guard-core" / "testdata" / "tokens.json",
    ]
    path = next((p for p in candidates if p.exists()), candidates[0])
    for case in json.loads(path.read_text())["cases"]:
        assert _findings.token(case["kind"], case["fingerprint"]) == case["token"]


def test_fingerprints_are_keyed_and_match_the_cli():
    assert _findings.fingerprint("ssn", SSN) == ""  # no key, no fingerprint
    _findings.set_key("org-secret")
    expected = hmac.new(b"org-secret", b"ssn:123456789", hashlib.sha256).hexdigest()[:16]
    assert _findings.fingerprint("ssn", SSN) == expected
    # A card fingerprints as the CLI's payment_card, with or without spaces.
    assert _findings.fingerprint("credit-card", CARD) == _findings.fingerprint("credit-card", CARD.replace(" ", ""))
    assert _findings.fingerprint("credit-card", CARD) == hmac.new(
        b"org-secret", b"payment_card:4111111111111111", hashlib.sha256
    ).hexdigest()[:16]


def test_pii_results_carry_findings_not_values():
    _findings.set_key("org-secret")
    result = PII(action="deny").run(
        f"SSN {SSN}, card {CARD}", phase=GuardPhase.PREFLIGHT
    )
    masked = {f["kind"]: f["masked"] for f in result.findings}
    assert masked["ssn"] == "[ssn:fp_" + _findings.fingerprint("ssn", SSN)[:8] + "]"
    assert all(f.get("fingerprint") for f in result.findings if f["kind"] in ("ssn", "credit-card"))
    assert SSN not in json.dumps(result.findings) and CARD not in json.dumps(result.findings)


def test_reports_carry_masked_findings(monkeypatch):
    _findings.set_key("org-secret")
    sent = []

    class FakeReporter:
        application_name = "app"

        def add(self, event):
            sent.append(event)

    monkeypatch.setattr(_report, "_reporter", FakeReporter())
    Pipeline(guards=[PII(action="redact")]).evaluate(f"my SSN is {SSN}", phase="preflight")
    attrs = sent[0]["attrs"]
    findings = json.loads(attrs["shield360.guard.findings"])
    assert findings[0]["masked"] == "[ssn:fp_" + findings[0]["fingerprint"][:8] + "]"
    assert attrs["shield360.guard.fingerprints"] == findings[0]["fingerprint"]
    assert SSN not in json.dumps(sent)
