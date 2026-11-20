"""End to end: apps that never import Shield360 are started through the
zero-code launcher (``shield360-instrument <cmd>``) and Shield360 starts from
SHIELD360_* variables alone: it is loaded before the app's first line, RASP is
active, and in Flask, FastAPI and Django apps the RASP middleware is in place
(a virtual patch answers 403) with no code change.

The framework tests skip when the framework is not installed.
"""

import json
import os
import subprocess
import sys
import textwrap

import pytest

RESULT = "RESULT "


def _env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SHIELD360_", "OTEL_")) and k != "PYTHONPATH"}
    env.update(
        {
            "OTEL_SERVICE_NAME": "zero-code-e2e",
            # Nothing listens there: telemetry export fails quietly, the app is unaffected.
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:9",
            "SHIELD360_DISABLE_METRICS": "true",
            "SHIELD360_RASP": "block",
        }
    )
    env.update(extra)
    return env


def _launch(tmp_path, source, env=None, launcher_flags=()):
    app = tmp_path / "app.py"
    app.write_text(textwrap.dedent(source))
    cmd = [sys.executable, *launcher_flags, "-m", "shield360.cli.main", sys.executable, str(app)]
    proc = subprocess.run(cmd, cwd=tmp_path, env=env or _env(tmp_path), capture_output=True, text=True, timeout=120, check=False)
    lines = [line for line in proc.stdout.splitlines() if line.startswith(RESULT)]
    assert proc.returncode == 0, proc.stderr
    assert lines, f"no result line\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    return json.loads(lines[-1][len(RESULT):]), proc.stderr


PLAIN_APP = """
    import json, sys
    # The app never imports shield360; it only looks at what is already loaded.
    loaded_first = "shield360" in sys.modules
    rasp = sys.modules.get("shield360.rasp")
    print("RESULT " + json.dumps({"loaded_first": loaded_first, "rasp": bool(rasp and rasp.rasp_active())}))
"""


def test_plain_app_starts_with_shield360_and_rasp_active(tmp_path):
    result, _ = _launch(tmp_path, PLAIN_APP)
    assert result == {"loaded_first": True, "rasp": True}


def test_rasp_off_leaves_rasp_inactive(tmp_path):
    result, _ = _launch(tmp_path, PLAIN_APP, _env(tmp_path, SHIELD360_RASP="off"))
    assert result == {"loaded_first": True, "rasp": False}


def test_rasp_is_on_in_monitor_mode_when_nothing_chose_a_mode(tmp_path):
    env = _env(tmp_path)
    del env["SHIELD360_RASP"]
    result, _ = _launch(
        tmp_path,
        """
        import json, os, sys
        rasp = sys.modules.get("shield360.rasp")
        print("RESULT " + json.dumps({"rasp": bool(rasp and rasp.rasp_active()), "mode": os.environ.get("SHIELD360_RASP")}))
        """,
        env,
    )
    assert result == {"rasp": True, "mode": "monitor"}


def test_import_shield360_auto_starts_shield360_and_rasp_without_the_launcher(tmp_path):
    env = _env(tmp_path)
    del env["SHIELD360_RASP"]
    app = tmp_path / "app.py"
    app.write_text(
        textwrap.dedent(
            """
            import shield360.auto  # the only change to the app
            import json, os, shield360
            print("RESULT " + json.dumps({"rasp": shield360.rasp.rasp_active(), "mode": os.environ.get("SHIELD360_RASP")}))
            """
        )
    )
    proc = subprocess.run([sys.executable, str(app)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stderr
    line = [l for l in proc.stdout.splitlines() if l.startswith(RESULT)][-1]
    assert json.loads(line[len(RESULT):]) == {"rasp": True, "mode": "monitor"}


def test_a_later_init_in_app_code_is_a_no_op(tmp_path):
    result, stderr = _launch(
        tmp_path,
        """
        import json
        import shield360
        shield360.init(rasp=False)
        shield360.init(rasp=False)
        print("RESULT " + json.dumps({"rasp": shield360.rasp.rasp_active()}))
        """,
    )
    assert result == {"rasp": True}
    assert stderr.count("this shield360.init() call is ignored") == 1


def test_fails_open_with_one_warning_when_shield360_cannot_load(tmp_path):
    # A broken shield360 first on the app's path; the launcher itself runs isolated (-I) with the real one.
    broken = tmp_path / "broken" / "shield360"
    broken.mkdir(parents=True)
    (broken / "__init__.py").write_text("raise RuntimeError('broken install')\n")
    env = _env(tmp_path, PYTHONPATH=str(tmp_path / "broken"))
    result, stderr = _launch(tmp_path, 'import json\nprint("RESULT " + json.dumps({"ran": True}))\n', env, ("-I",))
    assert result == {"ran": True}
    assert stderr.count("the app runs without Shield360") == 1


def test_the_apps_own_sitecustomize_still_runs(tmp_path):
    own = tmp_path / "own"
    own.mkdir()
    (own / "sitecustomize.py").write_text("import os\nos.environ['APP_SITECUSTOMIZE'] = 'ran'\nHELPER = 'from the app'\n")
    result, _ = _launch(
        tmp_path,
        """
        import json, os, sys
        import sitecustomize  # the app's own, with what it exports
        print("RESULT " + json.dumps({
            "own": os.environ.get("APP_SITECUSTOMIZE"),
            "helper": getattr(sitecustomize, "HELPER", None),
            "loaded": "shield360" in sys.modules,
        }))
        """,
        _env(tmp_path, PYTHONPATH=str(own)),
    )
    assert result == {"own": "ran", "helper": "from the app", "loaded": True}


def test_flask_app_gets_the_rasp_middleware(tmp_path):
    pytest.importorskip("flask")
    result, _ = _launch(
        tmp_path,
        """
        import json
        from flask import Flask
        app = Flask(__name__)

        @app.get("/")
        def index():
            return "ok"

        c = app.test_client()
        ok = c.get("/").status_code
        attack = c.get("/", headers={"x-shield360-rasp-test": "exploit"}).status_code
        print("RESULT " + json.dumps({"ok": ok, "attack": attack}))
        """,
    )
    assert result == {"ok": 200, "attack": 403}


def test_fastapi_app_gets_the_rasp_middleware(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    result, _ = _launch(
        tmp_path,
        """
        import json
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()

        @app.get("/")
        def index():
            return {"ok": True}

        c = TestClient(app)
        ok = c.get("/").status_code
        attack = c.get("/", headers={"x-shield360-rasp-test": "exploit"}).status_code
        print("RESULT " + json.dumps({"ok": ok, "attack": attack}))
        """,
    )
    assert result == {"ok": 200, "attack": 403}


def test_django_app_gets_the_rasp_middleware(tmp_path):
    pytest.importorskip("django")
    # Django apps name their settings in DJANGO_SETTINGS_MODULE (manage.py and wsgi.py set it).
    (tmp_path / "zc_settings.py").write_text(
        'DEBUG = False\nSECRET_KEY = "zero-code-e2e"\nROOT_URLCONF = "zc_urls"\nALLOWED_HOSTS = ["*"]\nMIDDLEWARE = []\n'
    )
    (tmp_path / "zc_urls.py").write_text(
        "from django.http import HttpResponse\n"
        "from django.urls import path\n"
        'urlpatterns = [path("", lambda request: HttpResponse("ok"))]\n'
    )
    result, _ = _launch(
        tmp_path,
        """
        import json
        import django
        django.setup()
        from django.conf import settings
        from django.test import Client

        c = Client()
        ok = c.get("/").status_code
        attack = c.get("/", headers={"x-shield360-rasp-test": "exploit"}).status_code
        print("RESULT " + json.dumps({"ok": ok, "attack": attack, "middleware": list(settings.MIDDLEWARE)}))
        """,
        _env(tmp_path, DJANGO_SETTINGS_MODULE="zc_settings"),
    )
    assert result["ok"] == 200
    assert result["attack"] == 403
    assert result["middleware"][0] == "shield360.rasp.RaspDjangoMiddleware"


SINK_ATTACK = "x; cat /etc/passwd"


def test_flask_sink_block_answers_403(tmp_path):
    pytest.importorskip("flask")
    result, _ = _launch(
        tmp_path,
        f"""
        import json, subprocess
        from flask import Flask, request
        app = Flask(__name__)

        @app.get("/")
        def index():
            return subprocess.run("echo " + request.args.get("q", ""), shell=True, capture_output=True, text=True).stdout

        c = app.test_client()
        ok = c.get("/?q=hi")
        attack = c.get("/", query_string={{"q": {SINK_ATTACK!r}}})
        print("RESULT " + json.dumps({{"ok": [ok.status_code, ok.get_data(as_text=True)], "attack": attack.status_code}}))
        """,
    )
    assert result == {"ok": [200, "hi\n"], "attack": 403}


def test_fastapi_sink_block_answers_403(tmp_path):
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    result, _ = _launch(
        tmp_path,
        f"""
        import json, subprocess
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        app = FastAPI()

        @app.get("/")
        def index(q: str = ""):
            return subprocess.run("echo " + q, shell=True, capture_output=True, text=True).stdout

        c = TestClient(app, raise_server_exceptions=False)
        ok = c.get("/", params={{"q": "hi"}})
        attack = c.get("/", params={{"q": {SINK_ATTACK!r}}})
        print("RESULT " + json.dumps({{"ok": [ok.status_code, ok.json()], "attack": attack.status_code}}))
        """,
    )
    assert result == {"ok": [200, "hi\n"], "attack": 403}


def test_django_sink_block_answers_403(tmp_path):
    pytest.importorskip("django")
    (tmp_path / "zc_settings.py").write_text(
        'DEBUG = False\nSECRET_KEY = "zero-code-e2e"\nROOT_URLCONF = "zc_urls"\nALLOWED_HOSTS = ["*"]\nMIDDLEWARE = []\n'
    )
    (tmp_path / "zc_urls.py").write_text(
        "import subprocess\n"
        "from django.http import HttpResponse\n"
        "from django.urls import path\n"
        "def index(request):\n"
        '    q = request.GET.get("q", "")\n'
        '    return HttpResponse(subprocess.run("echo " + q, shell=True, capture_output=True, text=True).stdout)\n'
        'urlpatterns = [path("", index)]\n'
    )
    result, _ = _launch(
        tmp_path,
        f"""
        import json
        import django
        django.setup()
        from django.test import Client

        c = Client()
        ok = c.get("/", {{"q": "hi"}})
        attack = c.get("/", {{"q": {SINK_ATTACK!r}}})
        print("RESULT " + json.dumps({{"ok": [ok.status_code, ok.content.decode()], "attack": attack.status_code}}))
        """,
        _env(tmp_path, DJANGO_SETTINGS_MODULE="zc_settings"),
    )
    assert result == {"ok": [200, "hi\n"], "attack": 403}
