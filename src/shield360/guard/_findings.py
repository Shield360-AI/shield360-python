"""
What a reviewer may see of a sensitive value a guard found.

A *finding* is a value's kind, a masked form (the last four digits of an SSN,
the prefix of an API key) and a fingerprint that is the same every time the
same value turns up, in this app or anywhere else in the organisation. The
value itself is never kept or reported.

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


def mask(label: str, value: str) -> str:
    """Enough of a value to recognise it, never enough to use it."""
    v = value.strip()
    kind = canonical_kind(label)
    if kind == "ssn":
        return "***-**-" + _digits(v)[-4:]
    if kind == "payment_card":
        return "•••• " + _digits(v)[-4:]
    if kind == "phone-us":
        return "***-***-" + _digits(v)[-4:]
    if kind == "private_key":
        return v
    if kind == "email":
        local, _, domain = v.partition("@")
        return (local[:1] + "***@" + domain) if domain else "***"
    if kind == "ipv4":
        parts = v.split(".")
        return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else "x.x.x.x"
    if kind == "connection_string":
        m = re.match(r"^([a-z+]+://[^:/@\s]+:)[^@\s]*(@.*)?$", v, re.IGNORECASE)
        if m:
            return m.group(1) + "****@" + (m.group(2) or "@")[1:].split("/")[0]
        return re.split(r"://", v)[0] + "://****"
    if kind == "password":
        m = re.search(r"[:=]", v)
        name = v[: m.start()].strip(" \"'") if m else ""
        return f"{name} = ••••••••" if name else "••••••••"
    if kind in ("bearer-token", "basic-auth"):
        scheme = v.split()[0] if v.split() else ""
        return f"{scheme} …{v[-4:]}"
    # Keys and tokens: the public prefix names the service, the last four
    # tell two keys apart.
    prefix = v[:12]
    cut = max(prefix.rfind("-"), prefix.rfind("_"))
    prefix = prefix[: cut + 1] if cut >= 2 else prefix[:4]
    if len(v) <= len(prefix) + 4:
        return prefix + "…"
    return prefix + "…" + v[-4:]


def make(label: str, value: str) -> Dict[str, str]:
    finding = {"kind": label, "masked": mask(label, value)}
    fp = fingerprint(label, value)
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
