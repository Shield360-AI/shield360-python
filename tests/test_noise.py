"""SHIELD: health probes and the SDK's own calls are not traced (mirrors the TS http-noise tests)."""

from opentelemetry.util.http import ExcludeList

from shield360._instrumentors import INSTRUMENTOR_MAP, MODULE_NAME_MAP
from shield360._noise import ENV, apply_default_excluded_urls, default_excluded_urls, shield360_host


def excluded(url, shield360_url="https://app.shield360.ai"):
    return ExcludeList(default_excluded_urls(shield360_url).split(",")).url_disabled(url)


def test_health_paths_are_excluded():
    for url in [
        "http://orders:8080/healthz",
        "http://orders:8080/health",
        "http://orders:8080/healthcheck?deep=1",
        "http://orders:8080/readyz",
        "http://orders:8080/livez",
        "http://orders:8080/metrics",
        "http://orders:8080/api/health",
    ]:
        assert excluded(url), url


def test_app_routes_are_kept():
    for url in [
        "http://orders:8080/api/orders",
        "http://orders:8080/healthy-recipes",
        "http://orders:8080/status-page/1",
        "https://api.anthropic.com/v1/messages",
    ]:
        assert not excluded(url), url


def test_calls_to_shield360_are_excluded():
    assert excluded("https://app.shield360.ai/api/guard/events")
    assert excluded("https://app.shield360.ai/api/ingest/otlp/v1/traces")
    assert not excluded("https://app.shield360.ai.evil.example/x")
    assert shield360_host("not a url") == ""


def test_an_app_setting_wins():
    env = {ENV: "/internal"}
    assert apply_default_excluded_urls("https://app.shield360.ai", env) == "/internal"
    env = {}
    assert "/health" in apply_default_excluded_urls("https://app.shield360.ai", env)


def test_data_store_instrumentors_are_registered():
    names = [
        "sqlalchemy", "asyncpg", "psycopg2", "pymysql", "pymongo", "redis",
        "celery", "grpc-client", "grpc-server", "botocore", "kafka-python",
        "mysqlclient", "confluent-kafka",
    ]
    for name in names:
        assert name in INSTRUMENTOR_MAP and name in MODULE_NAME_MAP, name
