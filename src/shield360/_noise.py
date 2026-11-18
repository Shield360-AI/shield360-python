"""
SHIELD: request tracing without the noise.

Health probes (Kubernetes, load balancers, uptime checks) arrive every few
seconds and say nothing about the app, and the SDK's own calls to Shield360
(guard reports, heartbeats, config) are not the app's work. Neither is traced.
The OpenTelemetry web-framework and HTTP-client instrumentations read the
excluded URLs from OTEL_PYTHON_EXCLUDED_URLS (comma-separated regular
expressions, searched in the full URL); this sets it when the app has not.

Must stay in sync with: sdk/typescript/src/instrumentation/http-noise.ts
"""

import os
import re
from urllib.parse import urlparse

ENV = "OTEL_PYTHON_EXCLUDED_URLS"

# A well-known health path, ending the path (or followed by a query string), so
# /healthz is excluded and /healthy-recipes is not.
HEALTH_PATTERNS = [
    r"/health(z|check)?(\?|$)",
    r"/ready(z)?(\?|$)",
    r"/live(z)?(\?|$)",
    r"/ping(\?|$)",
    r"/status(\?|$)",
    r"/metrics(\?|$)",
    r"/api/health(\?|$)",
]


def shield360_host(url):
    """The Shield360 host the SDK reports to, or ''."""
    try:
        return (urlparse(url).netloc or "").lower() if url else ""
    except Exception:
        return ""


def default_excluded_urls(shield360_url=None):
    """The patterns to exclude: health paths, and the Shield360 host when known."""
    patterns = list(HEALTH_PATTERNS)
    host = shield360_host(shield360_url or os.environ.get("SHIELD360_URL"))
    if host:
        patterns.append("//" + re.escape(host) + "(/|$)")
    return ",".join(patterns)


def apply_default_excluded_urls(shield360_url=None, env=None):
    """Sets OTEL_PYTHON_EXCLUDED_URLS unless the app set it; returns the value in force."""
    target = os.environ if env is None else env
    if target.get(ENV, "").strip():
        return target[ENV]
    target[ENV] = default_excluded_urls(shield360_url)
    return target[ENV]
