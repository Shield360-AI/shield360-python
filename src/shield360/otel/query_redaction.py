"""SHIELD: credentials in URLs stay out of spans.

Mirrors sdk/typescript/src/otel/query-redaction.ts.

The HTTP client and server instrumentations record the request URL with its
query string (``url.full``, ``url.query``, and the older ``http.url`` /
``http.target``). Query strings carry credentials more often than they
should: ``?key=`` on some model APIs, ``?token=`` on password-reset and magic
links, ``?code=`` on OAuth callbacks, pre-signed ``?X-Amz-Signature=``.

This processor runs when a span starts and replaces the value of every query
parameter whose name looks like a credential with ``REDACTED``, and any
user:password in the URL, so the value never reaches an exporter. Parameter
names and every other value are kept.
"""

import re
from typing import Any, Optional
from urllib.parse import unquote_plus

from opentelemetry.sdk.trace import SpanProcessor

REDACTED = "REDACTED"

# The span attributes that hold a URL or a query string.
_URL_ATTRIBUTES = ("url.full", "http.url")
_QUERY_ATTRIBUTES = ("url.query",)
_TARGET_ATTRIBUTES = ("http.target",)

_EXACT = frozenset(
    {"key", "code", "sig", "auth", "pwd", "passwd", "jwt", "otp", "session", "sessionid", "sid", "awsaccesskeyid", "hmac"}
)
_PARTS = (
    "token",
    "secret",
    "password",
    "passphrase",
    "apikey",
    "accesskey",
    "privatekey",
    "signature",
    "credential",
    "authorization",
    "clientsecret",
    "securitytoken",
)
_NON_ALNUM = re.compile(r"[^a-z0-9]")
_USERINFO = re.compile(r"^([a-z][a-z0-9+.-]*://)([^/@?#]*)@", re.IGNORECASE)


def is_credential_param(name: Any) -> bool:
    """Whether a query parameter's name names a credential (``api_key``, ``X-Goog-Api-Key``, ``access_token``, ``code``...)."""
    n = _NON_ALNUM.sub("", str(name).lower())
    if not n:
        return False
    if n in _EXACT:
        return True
    return any(p in n for p in _PARTS)


def redact_query_string(query: Any) -> Any:
    """A query string (with or without its leading ``?``) with credential values replaced.

    The text is rewritten only when something is redacted, so an ordinary
    query keeps its exact spelling.
    """
    if not isinstance(query, str) or not query:
        return query
    lead = "?" if query.startswith("?") else ""
    body = query[1:] if lead else query
    changed = False
    parts = []
    for pair in body.split("&"):
        eq = pair.find("=")
        raw_name = pair if eq == -1 else pair[:eq]
        try:
            name = unquote_plus(raw_name)
        except Exception:  # pylint: disable=broad-exception-caught
            name = raw_name
        if eq == -1 or not is_credential_param(name) or pair[eq + 1 :] == REDACTED:
            parts.append(pair)
            continue
        changed = True
        parts.append(f"{raw_name}={REDACTED}")
    return lead + "&".join(parts) if changed else query


def redact_url(url: Any) -> Any:
    """A URL (absolute, or a path with a query) with credential query values and any user:password replaced."""
    if not isinstance(url, str) or not url:
        return url
    hash_at = url.find("#")
    no_hash = url if hash_at == -1 else url[:hash_at]
    fragment = "" if hash_at == -1 else url[hash_at:]
    q = no_hash.find("?")
    base = no_hash if q == -1 else no_hash[:q]
    query = "" if q == -1 else no_hash[q:]

    def _userinfo(m: "re.Match[str]") -> str:
        if m.group(2) == f"{REDACTED}:{REDACTED}":
            return m.group(0)
        return f"{m.group(1)}{REDACTED}:{REDACTED}@"

    base = _USERINFO.sub(_userinfo, base, count=1)
    out = base + (redact_query_string(query) if query else "") + ("#" + redact_query_string(fragment[1:]) if fragment else "")
    return url if out == url else out


def redact_span_urls(span: Any) -> None:
    """Rewrites a started span's URL attributes in place."""
    attrs = getattr(span, "attributes", None)
    if not attrs:
        return
    for keys, fn in ((_URL_ATTRIBUTES, redact_url), (_QUERY_ATTRIBUTES, redact_query_string), (_TARGET_ATTRIBUTES, redact_url)):
        for key in keys:
            value = attrs.get(key)
            if isinstance(value, str):
                redacted = fn(value)
                if redacted != value:
                    span.set_attribute(key, redacted)


class QueryRedactionSpanProcessor(SpanProcessor):
    """Replaces credential query values in a span's URL attributes when it starts."""

    def on_start(self, span, parent_context: Optional[Any] = None) -> None:
        try:
            redact_span_urls(span)
        except Exception:  # pylint: disable=broad-exception-caught
            # Never affects the span.
            pass

    def on_end(self, span) -> None:
        # Attributes set after start are read-only by now; the HTTP
        # instrumentations set their URL attributes at start.
        pass

    def shutdown(self) -> None:
        pass

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True
