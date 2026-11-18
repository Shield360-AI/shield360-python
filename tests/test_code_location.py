"""Hermetic tests for code.* attributes on GenAI spans."""

import os
import sys

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from opentelemetry.trace import ProxyTracerProvider, SpanKind

from shield360.otel import code_location, tracing
from shield360.otel.code_location import (
    CodeLocationSpanProcessor,
    _PathNormaliser,
    anonymise_absolute_path,
    call_capture_enabled,
    capture_enabled,
)

GENAI = {"gen_ai.operation.name": "chat"}
THIS_FILE = os.path.abspath(__file__)


@pytest.fixture(name="setup")
def fixture_setup():
    """A provider with the code-location processor and an in-memory exporter."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    processor = CodeLocationSpanProcessor()
    provider.add_span_processor(processor)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter, processor


def _only_span(exporter):
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    return spans[0]


def _line_of(marker):
    with open(THIS_FILE, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if marker in line and "_line_of" not in line:
                return number
    raise AssertionError(marker)


def test_genai_span_gets_call_site(setup):
    provider, exporter, _ = setup
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("chat", attributes=GENAI):  # CALL-SITE-A
        pass
    attrs = _only_span(exporter).attributes
    assert attrs["code.function.name"] == (
        f"{__name__}.test_genai_span_gets_call_site"
    )
    assert attrs["code.line.number"] == _line_of("# CALL-SITE-A")
    path = attrs["code.file.path"]
    assert path.endswith("tests/test_code_location.py")
    assert not path.startswith("/")
    assert os.path.expanduser("~") not in path


def test_method_uses_qualified_name(setup):
    provider, exporter, _ = setup

    class Agent:  # pylint: disable=too-few-public-methods
        """Holder for a method call site."""

        def run(self):
            """Start a GenAI span from a method."""
            provider.get_tracer("t").start_span("chat", attributes=GENAI).end()

    Agent().run()
    name = _only_span(exporter).attributes["code.function.name"]
    if sys.version_info >= (3, 11):
        assert name.endswith("test_method_uses_qualified_name.<locals>.Agent.run")
    else:
        assert name == f"{__name__}.run"


def _function_in(filename):
    """Compile a span-starting helper as if it lived in ``filename``."""
    source = "def start(tracer):\n    tracer.start_span('chat', attributes=GENAI).end()\n"
    namespace = {"GENAI": GENAI, "__name__": "lib_under_test"}
    exec(compile(source, filename, "exec"), namespace)  # pylint: disable=exec-used
    return namespace["start"]


@pytest.mark.parametrize(
    "filename",
    [
        os.path.join(code_location._SDK_DIR, "instrumentation", "fake.py"),
        "/opt/venv/lib/python3.12/site-packages/openai/fake.py",
        "/usr/lib/python3/dist-packages/openai/fake.py",
        "<frozen importlib._bootstrap>",
    ],
)
def test_sdk_and_third_party_frames_are_skipped(setup, filename):
    provider, exporter, _ = setup
    start = _function_in(filename)
    start(provider.get_tracer("t"))  # CALL-SITE-B
    attrs = _only_span(exporter).attributes
    assert attrs["code.line.number"] == _line_of("# CALL-SITE-B")
    assert attrs["code.file.path"].endswith("tests/test_code_location.py")


def test_non_genai_span_is_untouched(setup):
    provider, exporter, _ = setup
    provider.get_tracer("app").start_span("http", attributes={"x": 1}).end()
    attrs = _only_span(exporter).attributes
    assert not any(key.startswith("code.") for key in attrs)


def test_sdk_instrumentation_scope_counts_as_genai(setup):
    provider, exporter, _ = setup
    provider.get_tracer("shield360.instrumentation.openai").start_span("chat").end()
    provider.get_tracer("shield360.instrumentation.pinecone").start_span("q").end()
    openai_span, pinecone_span = exporter.get_finished_spans()
    assert "code.line.number" in openai_span.attributes
    assert "code.line.number" not in pinecone_span.attributes


def test_existing_code_attributes_are_kept(setup):
    provider, exporter, _ = setup
    preset = dict(GENAI, **{"code.function.name": "mine"})
    provider.get_tracer("t").start_span("chat", attributes=preset).end()
    attrs = _only_span(exporter).attributes
    assert attrs["code.function.name"] == "mine"
    assert "code.file.path" not in attrs


def test_file_cache_is_reused(setup):
    provider, exporter, processor = setup
    tracer = provider.get_tracer("t")
    for _ in range(3):
        tracer.start_span("chat", attributes=GENAI).end()
    assert processor._files[__file__].endswith("tests/test_code_location.py")
    lines = {span.attributes["code.line.number"] for span in exporter.get_finished_spans()}
    assert len(lines) == 1


def test_failure_adds_nothing(setup, monkeypatch):
    provider, exporter, processor = setup

    def boom(_frame):
        raise RuntimeError("no")

    monkeypatch.setattr(processor, "find_location", boom)
    provider.get_tracer("t").start_span("chat", attributes=GENAI).end()
    assert "code.file.path" not in _only_span(exporter).attributes


@pytest.mark.parametrize("value", ["false", "0", "NO", "Off"])
def test_env_opt_out(monkeypatch, value):
    monkeypatch.setenv("SHIELD360_CAPTURE_CODE_LOCATION", value)
    assert capture_enabled() is False
    assert capture_enabled(True) is True


def test_default_and_option_opt_out(monkeypatch):
    monkeypatch.delenv("SHIELD360_CAPTURE_CODE_LOCATION", raising=False)
    assert capture_enabled() is True
    assert capture_enabled(False) is False


def _setup_tracing(monkeypatch, **kwargs):
    """Run setup_tracing against a private global provider slot."""
    holder = {}
    monkeypatch.setattr(tracing, "TRACER_SET", False)
    monkeypatch.setattr(
        tracing.trace, "get_tracer_provider", lambda: holder.get("p", ProxyTracerProvider())
    )
    monkeypatch.setattr(tracing.trace, "set_tracer_provider", lambda p: holder.update(p=p))
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "none")
    monkeypatch.setenv("HAYSTACK_AUTO_TRACE_ENABLED", "false")
    tracing.setup_tracing("app", "test", None, None, None, True, **kwargs)
    return holder["p"]


def _has_code_processor(provider):
    processors = provider._active_span_processor._span_processors
    return any(isinstance(p, CodeLocationSpanProcessor) for p in processors)


def test_setup_tracing_adds_processor_and_resource(monkeypatch):
    monkeypatch.delenv("SHIELD360_CAPTURE_CODE_LOCATION", raising=False)
    provider = _setup_tracing(
        monkeypatch, resource_attributes={"service.version": "1.2.3"}
    )
    assert _has_code_processor(provider)
    assert provider.resource.attributes["service.version"] == "1.2.3"


def test_setup_tracing_respects_opt_out(monkeypatch):
    monkeypatch.setenv("SHIELD360_CAPTURE_CODE_LOCATION", "off")
    assert not _has_code_processor(_setup_tracing(monkeypatch))
    monkeypatch.delenv("SHIELD360_CAPTURE_CODE_LOCATION")
    assert not _has_code_processor(_setup_tracing(monkeypatch, capture_code_location=False))


# --- path normalisation -------------------------------------------------------


def test_code_root_wins(tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    file = tmp_path / "repo" / "svc" / "app" / "main.py"
    normaliser = _PathNormaliser(code_root=str(tmp_path / "repo" / "svc"), cwd="/", home="/nohome")
    assert normaliser.normalise(str(file)) == "app/main.py"


def test_code_root_from_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELD360_CODE_ROOT", str(tmp_path))
    normaliser = _PathNormaliser(cwd="/", home="/nohome")
    assert normaliser.normalise(str(tmp_path / "a" / "b.py")) == "a/b.py"


def test_git_root_is_stripped_and_probed_once(tmp_path, monkeypatch):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    normaliser = _PathNormaliser(cwd="/", home="/nohome")
    first = tmp_path / "repo" / "pkg" / "a.py"
    assert normaliser.normalise(str(first)) == "pkg/a.py"

    def no_probe(_path):
        raise AssertionError("probed again")

    monkeypatch.setattr(code_location.os.path, "exists", no_probe)
    assert normaliser.normalise(str(tmp_path / "repo" / "pkg" / "b.py")) == "pkg/b.py"


def test_cwd_is_stripped(tmp_path):
    normaliser = _PathNormaliser(cwd=str(tmp_path), home="/nohome")
    normaliser._git_roots[str(tmp_path / "src")] = None
    assert normaliser.normalise(str(tmp_path / "src" / "x.py")) == "src/x.py"


def test_home_is_never_emitted(tmp_path):
    home = tmp_path / "home" / "bob"
    normaliser = _PathNormaliser(cwd="/elsewhere", home=str(home))
    normaliser._git_roots[str(home / "proj")] = None
    assert normaliser.normalise(str(home / "proj" / "x.py")) == "proj/x.py"


def test_other_paths_stay_absolute(tmp_path):
    normaliser = _PathNormaliser(cwd="/elsewhere", home="/nohome")
    normaliser._git_roots[str(tmp_path)] = None
    assert normaliser.normalise(str(tmp_path / "x.py")) == str(tmp_path / "x.py")


@pytest.mark.parametrize(
    "path,expected",
    [
        ("/home/runner/work/api/api/app/billing.py", "app/billing.py"),
        ("/github/workspace/app/billing.py", "app/billing.py"),
        ("/builds/acme/api/app/billing.py", "app/billing.py"),
        ("/Users/alice/dev/api/x.py", "dev/api/x.py"),
        ("/home/alice/dev/api/x.py", "dev/api/x.py"),
        ("C:/Users/alice/dev/api/x.py", "dev/api/x.py"),
        ("/root/api/x.py", "api/x.py"),
        ("/srv/app/x.py", "/srv/app/x.py"),
    ],
)
def test_build_host_paths_are_anonymised(path, expected):
    assert anonymise_absolute_path(path) == expected


def test_another_users_home_is_never_emitted():
    # Running as one user, code in another user's home.
    normaliser = _PathNormaliser(cwd="/elsewhere", home="/home/app")
    normaliser._git_roots["/home/alice/proj"] = None
    assert normaliser.normalise("/home/alice/proj/x.py") == "proj/x.py"


def test_real_openai_instrumentation_span(setup):
    """The OpenAI wrapper sets gen_ai.operation.name after creation; scope covers it."""
    # pylint: disable=import-outside-toplevel
    from types import SimpleNamespace

    from shield360._config import Shield360Config
    from shield360.instrumentation.openai.openai import chat_completions

    provider, exporter, _ = setup
    Shield360Config.reset_to_defaults()
    wrapper = chat_completions(
        version="test",
        environment="test",
        application_name="test",
        tracer=provider.get_tracer("shield360.instrumentation.openai"),
        pricing_info={},
        capture_message_content=False,
        metrics=None,
        disable_metrics=True,
    )

    def fail(*_args, **_kwargs):
        raise RuntimeError("offline")

    instance = SimpleNamespace(_client=SimpleNamespace(base_url="http://localhost/v1"))
    kwargs = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    with pytest.raises(RuntimeError):
        wrapper(fail, instance, [], kwargs)  # CALL-SITE-C
    attrs = _only_span(exporter).attributes
    assert attrs["gen_ai.operation.name"] == "chat"
    assert attrs["code.line.number"] == _line_of("# CALL-SITE-C")
    assert attrs["code.function.name"].endswith("test_real_openai_instrumentation_span")


# SHIELD: code cost — outbound calls carry their call site, so a costly pattern
# shield360 scan found can be priced by what that call cost.
@pytest.mark.parametrize(
    "kind, attributes",
    [
        (SpanKind.CLIENT, {"db.system": "postgresql"}),
        (SpanKind.CLIENT, {"db.system.name": "mongodb"}),
        (SpanKind.CLIENT, {"http.request.method": "GET"}),
        (SpanKind.CLIENT, {"rpc.system": "aws-api"}),
        (SpanKind.PRODUCER, {"messaging.system": "aws_sqs"}),
    ],
)
def test_call_spans_get_call_site(setup, kind, attributes):
    provider, exporter, _ = setup
    provider.get_tracer("app").start_span("call", kind=kind, attributes=attributes).end()  # CALL-SITE-CALL
    attrs = _only_span(exporter).attributes
    assert attrs["code.line.number"] == _line_of("# CALL-SITE-CALL")
    assert attrs["code.file.path"].endswith("tests/test_code_location.py")


@pytest.mark.parametrize(
    "kind, attributes",
    [
        (SpanKind.SERVER, {"http.request.method": "GET"}),
        (SpanKind.INTERNAL, {"db.system": "postgresql"}),
        (SpanKind.CLIENT, {"peer.service": "x"}),
    ],
)
def test_other_spans_get_no_call_site(setup, kind, attributes):
    provider, exporter, _ = setup
    provider.get_tracer("app").start_span("call", kind=kind, attributes=attributes).end()
    assert not any(key.startswith("code.") for key in _only_span(exporter).attributes)


def test_calls_switched_off_leaves_genai_only(monkeypatch):
    monkeypatch.setenv("SHIELD360_CAPTURE_CALL_LOCATION", "false")
    assert call_capture_enabled() is False
    assert call_capture_enabled(True) is True
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(CodeLocationSpanProcessor())
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("app")
    tracer.start_span("q", kind=SpanKind.CLIENT, attributes={"db.system": "postgresql"}).end()
    tracer.start_span("chat", kind=SpanKind.CLIENT, attributes=GENAI).end()
    db, chat = exporter.get_finished_spans()
    assert "code.file.path" not in db.attributes
    assert "code.file.path" in chat.attributes
