"""
What a reviewer may see of a sensitive value a guard found.

A *finding* is a value's kind, a token (``[api_key:fp_3f9c2a1b]``, see
``token()``) and a fingerprint that is the same every time the same value
turns up, in this app or anywhere else in the organisation. No character of
the value is ever kept or reported.

The fingerprint is an HMAC keyed with the organisation's secret, which
Shield360 hands to apps with an API key. Unkeyed, a fingerprint could be
reversed (there are only a billion SSNs), so without a key none is made.

Must stay in sync with: cli/internal/coding/guard/findings.go
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Dict, List, Optional

_key: Optional[bytes] = None

MAX_FINDINGS = 10

# The CLI's kind for each SDK label, so the same value fingerprints the same
# whether a coding agent or an app stopped it.
_CANONICAL = {
    "credit-card": "payment_card",
    "env-secret": "password",
    "private-key": "private_key",
    "connection-string": "connection_string",
    "aws-access-key": "cloud_credential",
    "openai-api-key": "api_key",
    "anthropic-api-key": "api_key",
    "github-token": "api_key",
    "github-fine-grained": "api_key",
    "stripe-key": "api_key",
    "slack-token": "api_key",
    "gcp-api-key": "api_key",
}


def set_key(key: Optional[str]) -> None:
    """Set (or clear) the organisation's fingerprint key."""
    global _key  # pylint: disable=global-statement
    _key = key.encode() if key else None


def canonical_kind(label: str) -> str:
    return _CANONICAL.get(label, label)


def _digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _assignment_value(value: str) -> str:
    m = re.search(r"[:=]", value)
    return value[m.end():].strip(" \"'") if m else value


def _normalise(kind: str, value: str) -> str:
    if kind in ("ssn", "payment_card", "phone-us"):
        return _digits(value)
    if kind == "password":
        return _assignment_value(value)
    return value.strip()


def fingerprint(label: str, value: str) -> str:
    if not _key:
        return ""
    kind = canonical_kind(label)
    digest = hmac.new(_key, f"{kind}:{_normalise(kind, value)}".encode(), hashlib.sha256)
    return digest.hexdigest()[:16]


TOKEN_PRINT_LENGTH = 8
_HEX = re.compile(r"^[0-9a-f]+$")


def token(kind: str, fp: str = "") -> str:
    """What is kept of a value: ``[kind:fp_<8 hex>]``, or ``[kind]`` without a key.

    No character of the value is part of it: a key's prefix and last four or a
    card's last four help an attacker narrow a guess. Byte-compatible with
    guard-core's ``token()`` and the Go guard's ``Token()``.
    """
    if fp and len(fp) >= TOKEN_PRINT_LENGTH and _HEX.match(fp):
        return f"[{kind}:fp_{fp[:TOKEN_PRINT_LENGTH]}]"
    return f"[{kind}]"


def mask(label: str, value: str) -> str:
    """The token for a value under the current key; never any character of it."""
    return token(canonical_kind(label), fingerprint(label, value))


def make(label: str, value: str) -> Dict[str, str]:
    fp = fingerprint(label, value)
    finding = {"kind": label, "masked": token(canonical_kind(label), fp)}
    if fp:
        finding["fingerprint"] = fp
    return finding


def collect(matches) -> List[Dict[str, str]]:
    """Findings for ``(label, value)`` pairs, de-duplicated and capped."""
    out: List[Dict[str, str]] = []
    seen = set()
    for label, value in matches:
        f = make(label, value)
        key = (f["kind"], f.get("fingerprint", ""), f["masked"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
        if len(out) >= MAX_FINDINGS:
            break
    return out
