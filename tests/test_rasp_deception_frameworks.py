"""Deception against the real frameworks (README "Deception"): a decoy never
reaches a view and gets exactly what a genuinely unknown path gets from the
same app (Flask's error handler or Werkzeug's page, Django's handler404 or
debug page, FastAPI's and Starlette's not-found). Each part is skipped when
its framework is not installed (the CI job installs none of them)."""

import sys
import time
import types

import pytest

from shield360.rasp import RaspASGIMiddleware, rasp_flask
from shield360.rasp._deception import SuspiciousTable, set_suspicious_table
from shield360.rasp._engine import RemoteConfig, configure_engine, set_event_sink, set_remote_config

EVENTS = []


class _Sink:
    def add(self, event, fold_key):
        EVENTS.append(event)


@pytest.fixture(autouse=True)
def _engine():
    EVENTS.clear()
    configure_engine(enabled=True, application_name="orders-api", env={})
    set_event_sink(_Sink())
    set_suspicious_table(SuspiciousTable())
    # monitor: the client that hit the decoy keeps reaching the app (the comparisons below reuse it).
    set_remote_config(
        RemoteConfig(
            version="v1",
            exp=time.time() + 3600,
            deception={"paths": ["/wp-admin", "/admin/backup.zip"], "action": "monitor"},
        )
    )
    yield
    set_event_sink(None)
    set_suspicious_table()
    configure_engine(enabled=False, application_name="default", env={})


def hits():
    return [e["attrs"]["shield360.rasp.rule"] for e in EVENTS]


# ---- Flask ----


def flask_app(custom_404):
    flask = pytest.importorskip("flask")
    app = flask.Flask("deception")
    calls = []

    @app.route("/orders")
    def orders():
        calls.append("orders")
        return "orders"

    @app.route("/admin/backup.zip")
    def backup():
        calls.append("backup")
        return "backup"

    @app.before_request
    def hook():
        calls.append("before_request")

    if custom_404:

        @app.errorhandler(404)
        def missing(e):
            return {"missing": True, "code": e.code}, 404, {"X-App-404": "1"}

    rasp_flask(app)
    return app, calls


@pytest.mark.parametrize("custom_404", [True, False])
def test_flask_decoy_answers_like_an_unknown_route(custom_404):
    app, calls = flask_app(custom_404)
    client = app.test_client()
    unknown = client.get("/no-such-page")
    calls.clear()
    for path in ("/wp-admin", "/wp-admin/setup.php?x=1", "/admin/backup.zip"):
        decoy = client.get(path)
        assert decoy.status_code == 404
        assert decoy.get_data() == unknown.get_data()
        assert decoy.headers == unknown.headers
    assert not calls  # neither the view nor the app's hooks ran
    assert hits() == ["deception.hit"] * 3
    if custom_404:
        assert unknown.get_json() == {"missing": True, "code": 404}
    else:
        assert b"The requested URL was not found on the server." in unknown.get_data()
    # A real route still works (the client is only monitored).
    assert client.get("/orders").get_data() == b"orders"
    assert hits()[-1] == "deception.suspicious"


def test_flask_percent_encoded_decoy_hits_through_raw_uri():
    app, calls = flask_app(True)
    assert app.test_client().get("/wp%2Dadmin").status_code == 404
    assert not calls and hits() == ["deception.hit"]


# ---- Django ----

_DJANGO_CALLS = []


def _django_view(request, pk=None):
    _DJANGO_CALLS.append(request.path)
    from django.http import HttpResponse

    return HttpResponse("view")


def django_settings(debug):
    """Django set up for these tests; the settings are overridden per test, as
    another test in the process may have configured Django already."""
    pytest.importorskip("django")
    import django
    from django.apps import apps
    from django.conf import settings
    from django.test import override_settings
    from django.urls import path

    from django.core.exceptions import ImproperlyConfigured

    if not settings.configured:
        settings.configure(INSTALLED_APPS=[])
    try:
        settings.SECRET_KEY  # pylint: disable=pointless-statement
    except ImproperlyConfigured:
        # A placeholder (the debug page reads it); nothing is signed.
        settings.SECRET_KEY = "placeholder-for-tests"
    if not apps.ready:
        django.setup()
    urls = types.ModuleType("shield360_deception_urls")
    urls.urlpatterns = [path("orders/<int:pk>", _django_view), path("admin/backup.zip", _django_view)]
    sys.modules["shield360_deception_urls"] = urls
    return override_settings(
        DEBUG=debug,
        ROOT_URLCONF="shield360_deception_urls",
        ALLOWED_HOSTS=["*"],
        MIDDLEWARE=["shield360.rasp.RaspDjangoMiddleware"],
        TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": False}],
    )


@pytest.mark.parametrize("debug", [False, True])
def test_django_decoy_answers_like_an_unknown_url(debug):
    with django_settings(debug):
        from django.test import Client

        client = Client()
        _DJANGO_CALLS.clear()
        unknown = client.get("/wp-admin-not-a-decoy/x")
        decoy = client.get("/wp-admin/x")
        real_route_decoy = client.get("/admin/backup.zip")
        assert unknown.status_code == decoy.status_code == real_route_decoy.status_code == 404
        assert decoy.content.replace(b"wp-admin/x", b"P") == unknown.content.replace(b"wp-admin-not-a-decoy/x", b"P")
        assert decoy["Content-Type"] == unknown["Content-Type"]
        if not debug:
            assert real_route_decoy.content == decoy.content.replace(b"/wp-admin/x", b"/admin/backup.zip")
        assert not _DJANGO_CALLS
        assert hits() == ["deception.hit", "deception.hit"]
        assert client.get("/orders/7").content == b"view" and _DJANGO_CALLS == ["/orders/7"]


# ---- FastAPI / Starlette ----


def _test_client(app, **kw):
    pytest.importorskip("httpx")
    from starlette.testclient import TestClient

    return TestClient(app, **kw)


def test_fastapi_decoy_answers_like_an_unknown_path():
    fastapi = pytest.importorskip("fastapi")
    app = fastapi.FastAPI()
    calls = []

    @app.get("/admin/backup.zip")
    def backup():
        calls.append("backup")
        return {"backup": True}

    app.add_middleware(RaspASGIMiddleware, framework="fastapi")
    client = _test_client(app)
    unknown = client.get("/no-such-page")
    for path in ("/wp-admin", "/admin/backup.zip"):
        decoy = client.get(path)
        assert (decoy.status_code, decoy.content) == (unknown.status_code, unknown.content) == (404, b'{"detail":"Not Found"}')
        assert decoy.headers["content-type"] == unknown.headers["content-type"] == "application/json"
    assert not calls and hits() == ["deception.hit", "deception.hit"]


def test_fastapi_custom_404_handler_and_wrapping_from_outside():
    fastapi = pytest.importorskip("fastapi")
    from fastapi.responses import PlainTextResponse
    from starlette.exceptions import HTTPException

    app = fastapi.FastAPI()

    @app.exception_handler(HTTPException)
    async def custom(request, exc):
        return PlainTextResponse(f"custom {exc.status_code} {request.app is app}", status_code=exc.status_code)

    client = _test_client(RaspASGIMiddleware(app))
    unknown = client.get("/no-such-page")
    decoy = client.get("/wp-admin")
    assert (decoy.status_code, decoy.text) == (unknown.status_code, unknown.text) == (404, "custom 404 True")


def test_starlette_decoy_answers_like_an_unknown_path():
    pytest.importorskip("starlette")
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    calls = []

    def backup(request):
        calls.append("backup")
        return PlainTextResponse("backup")

    for handlers in ({}, {404: lambda request, exc: PlainTextResponse("sync custom", status_code=404)}):
        app = Starlette(
            routes=[Route("/admin/backup.zip", backup)],
            middleware=[Middleware(RaspASGIMiddleware, framework="starlette")],
            exception_handlers=handlers,
        )
        client = _test_client(app)
        unknown = client.get("/no-such-page")
        decoy = client.get("/admin/backup.zip/x")
        assert (decoy.status_code, decoy.text) == (unknown.status_code, unknown.text)
        assert decoy.text == ("sync custom" if handlers else "Not Found")
        assert decoy.headers["content-type"] == unknown.headers["content-type"]
    assert not calls


def test_starlette_root_path_counts_toward_the_decoy():
    pytest.importorskip("starlette")
    from starlette.applications import Starlette

    app = Starlette(middleware=[])
    # Served behind a proxy that strips /admin.
    client = _test_client(RaspASGIMiddleware(app, framework="starlette"), root_path="/admin")
    assert client.get("/backup.zip").status_code == 404
    assert hits() == ["deception.hit"]
