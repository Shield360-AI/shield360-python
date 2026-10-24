# pylint: disable=missing-function-docstring, missing-class-docstring, too-few-public-methods
"""
A Shield360 URL and API key are enough to send telemetry.

Before this, they configured prompt management, the vault and evaluations,
and telemetry silently went to the console unless somebody also set the OTLP
variables — which every customer had to discover by finding nothing in their
dashboard. The TypeScript SDK carries the same test.
"""

from shield360._destination import INGEST_PATH, resolve_destination

URL = "https://app.shield360.ai"


def test_points_at_the_platform_ingest_with_the_key_as_bearer():
    endpoint, headers = resolve_destination(None, None, URL, "k-1", env={})
    assert endpoint == f"{URL}{INGEST_PATH}"
    assert headers == {"Authorization": "Bearer k-1"}


def test_tolerates_a_trailing_slash():
    endpoint, _ = resolve_destination(None, None, URL + "/", "k", env={})
    assert endpoint == f"{URL}{INGEST_PATH}"


def test_an_explicit_endpoint_wins_untouched():
    endpoint, headers = resolve_destination(
        "http://collector:4318", {"X-Team": "ai"}, URL, "k", env={}
    )
    assert endpoint == "http://collector:4318"
    assert headers == {"X-Team": "ai"}


def test_an_endpoint_from_the_environment_also_wins():
    endpoint, headers = resolve_destination(
        None, None, URL, "k", env={"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318"}
    )
    assert endpoint is None
    assert headers is None


def test_never_overwrites_an_authorization_header():
    _, headers = resolve_destination(None, {"authorization": "Basic abc"}, URL, "k", env={})
    assert headers == {"authorization": "Basic abc"}


def test_merges_into_string_headers_from_the_environment():
    _, headers = resolve_destination(
        None, None, URL, "k", env={"OTEL_EXPORTER_OTLP_HEADERS": "X-Team=ai"}
    )
    assert headers == "X-Team=ai,Authorization=Bearer k"


def test_resolves_to_nowhere_with_only_one_of_the_two():
    assert resolve_destination(None, None, URL, None, env={}) == (None, None)
    assert resolve_destination(None, None, None, "k", env={}) == (None, None)
