"""
Where telemetry goes when nobody said.

The SDK has always exported over OTLP to ``OTEL_EXPORTER_OTLP_ENDPOINT``, with
``OTEL_EXPORTER_OTLP_HEADERS`` for whatever authorises it. That is the right
shape for a collector of your own. It is the wrong first experience for a
Shield360 customer, who already holds a URL and an API key for the platform
and reasonably expects them to be enough.

They are, now: with no OTLP endpoint given, a Shield360 URL and API key
resolve to the platform's authenticated ingest route, with the key as the
bearer token. An explicit endpoint always wins, and an explicit Authorization
header is never overwritten. The TypeScript SDK resolves identically.
"""

import os
from typing import Mapping, Optional, Union

INGEST_PATH = "/api/ingest/otlp"

Headers = Union[Mapping[str, str], str, None]


def _has_header(headers: Headers, name: str) -> bool:
    wanted = name.lower()
    if headers is None:
        return False
    if isinstance(headers, str):
        return any(part.split("=", 1)[0].strip().lower() == wanted for part in headers.split(","))
    return any(key.lower() == wanted for key in headers)


def resolve_destination(
    otlp_endpoint: Optional[str],
    otlp_headers: Headers,
    shield360_url: Optional[str],
    shield360_api_key: Optional[str],
    env: Optional[Mapping[str, str]] = None,
):
    """Return ``(otlp_endpoint, otlp_headers)`` as the exporters should see them."""
    env = os.environ if env is None else env

    explicit = (otlp_endpoint or env.get("OTEL_EXPORTER_OTLP_ENDPOINT") or "").strip()
    if explicit:
        return otlp_endpoint, otlp_headers

    url = (shield360_url or "").strip().rstrip("/")
    api_key = (shield360_api_key or "").strip()
    if not url or not api_key:
        return otlp_endpoint, otlp_headers

    headers = otlp_headers if otlp_headers is not None else env.get("OTEL_EXPORTER_OTLP_HEADERS")
    if _has_header(headers, "Authorization"):
        return f"{url}{INGEST_PATH}", otlp_headers

    bearer = f"Bearer {api_key}"
    if isinstance(headers, str) and headers.strip():
        merged: Headers = f"{headers},Authorization={bearer}"
    elif isinstance(headers, Mapping):
        merged = {**headers, "Authorization": bearer}
    else:
        merged = {"Authorization": bearer}
    return f"{url}{INGEST_PATH}", merged
