"""Module include hook (README "Code", ``code.include``): importlib.import_module,
explicit ``__import__`` calls and runpy are checked; ``import`` statements,
whose names are written in the source, never are.

Mirrors sdk/typescript/src/rasp/__tests__/include-hook.test.ts.
"""

import builtins
import importlib
import runpy

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError
from shield360.rasp._hooks.include import install_include_hooks, uninstall_include_hooks
from shield360.rasp._iast import RASP_VULNERABILITY, configure_iast, reset_iast, set_iast_sink


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_include_hooks()
    reset_iast()
    stop_engine()


def test_import_module_with_a_name_from_input_is_refused():
    events = use_engine("block")
    install_include_hooks()
    with pytest.raises(RaspBlockedError) as e:
        in_request(["json"], lambda: importlib.import_module("json"))
    assert (e.value.attack, e.value.rule) == ("code_injection", "code.include")
    with pytest.raises(RaspBlockedError):
        in_request(["../../tmp/evil"], lambda: importlib.import_module("plugins.../../tmp/evil"))
    assert events.sinks() == ["importlib.import_module", "importlib.import_module"]


def test_an_explicit_dunder_import_call_is_checked():
    events = use_engine("block")
    install_include_hooks()
    with pytest.raises(RaspBlockedError):
        in_request(["json"], lambda: __import__("json"))
    assert events.sinks() == ["builtins.__import__"]


def test_import_statements_are_never_checked():
    events = use_engine("block")
    install_include_hooks()

    def handler():
        import json  # pylint: disable=import-outside-toplevel,unused-import,reimported
        from os import path  # pylint: disable=import-outside-toplevel,unused-import

        return True

    assert in_request(["json", "os", "path"], handler)
    assert not events


def test_a_fixed_module_name_with_no_input_in_it_passes():
    events = use_engine("block")
    install_include_hooks()
    assert in_request(["alice@example.com"], lambda: importlib.import_module("json")).__name__ == "json"
    assert not events


def test_runpy_is_checked():
    events = use_engine("block")
    install_include_hooks()
    with pytest.raises(RaspBlockedError):
        in_request(["/tmp/evil.py"], lambda: runpy.run_path("/tmp/evil.py"))
    with pytest.raises(RaspBlockedError):
        in_request(["json.tool"], lambda: runpy.run_module("json.tool"))
    assert events.sinks() == ["runpy.run_path", "runpy.run_module"]


def test_nothing_is_checked_outside_a_request_or_with_rasp_off():
    events = use_engine("block")
    install_include_hooks()
    assert importlib.import_module("json").__name__ == "json"
    stop_engine()
    assert in_request(["json"], lambda: importlib.import_module("json")).__name__ == "json"
    assert not events


def test_passive_iast_reports_input_inside_a_module_name():
    events = use_engine("monitor")
    configure_iast(True, application_name="kit", env={})
    set_iast_sink(events)
    install_include_hooks()

    def load():
        try:
            importlib.import_module("app_locales.lang_en_GB_2026")
        except ImportError:
            pass  # no such module: only the check matters

    in_request(["en_GB_2026"], load, route="/i18n/:lang")
    vulns = [e for e in events if e["name"] == RASP_VULNERABILITY]
    assert len(vulns) == 1
    assert vulns[0]["attrs"]["shield360.rasp.rule"] == "vuln.include_from_input"
    assert vulns[0]["attrs"]["shield360.rasp.sink"] == "importlib.import_module"


def test_uninstall_puts_the_original_import_back():
    original = builtins.__import__
    install_include_hooks()
    assert builtins.__import__ is not original
    uninstall_include_hooks()
    assert builtins.__import__ is original


# ---- review fixes ---------------------------------------------------------------


def test_an_import_statement_stays_unchecked_under_another_import_wrapper():
    events = use_engine("block")
    install_include_hooks()
    inner = builtins.__import__

    def tracing_import(*args, **kwargs):  # another tool's wrapper, put on top of RASP's
        return inner(*args, **kwargs)

    builtins.__import__ = tracing_import
    try:

        def handler():
            import json  # pylint: disable=import-outside-toplevel,unused-import,reimported
            import json.decoder  # pylint: disable=import-outside-toplevel,unused-import

            return True

        assert in_request(["json", "json.decoder"], handler)
        assert not events
        # A computed name through the same wrapper is still checked.
        with pytest.raises(RaspBlockedError):
            in_request(["json"], lambda: __import__("json"))
    finally:
        builtins.__import__ = inner


_DENY_FRAMES = [False]


def _deny_frames(event, args):  # pylint: disable=unused-argument
    if _DENY_FRAMES[0] and event == "sys._getframe":
        raise PermissionError("frame inspection denied")


def test_imports_fail_open_when_frame_inspection_is_denied():
    import sys  # pylint: disable=import-outside-toplevel

    use_engine("monitor")
    install_include_hooks()
    if not getattr(_deny_frames, "added", False):
        sys.addaudithook(_deny_frames)
        _deny_frames.added = True

    def handler():
        _DENY_FRAMES[0] = True
        try:
            import json  # pylint: disable=import-outside-toplevel,unused-import,reimported

            return importlib.import_module("json").__name__
        finally:
            _DENY_FRAMES[0] = False

    assert in_request([], handler) == "json"


def test_runpy_internal_imports_of_a_fixed_module_do_not_block():
    events = use_engine("block")
    install_include_hooks()

    def run():
        try:
            runpy.run_module("json.tool", run_name="probe")
        except SystemExit:
            pass
        return True

    assert in_request(["json"], run)
    assert not events


def test_imports_directed_by_importlib_metadata_are_checked():
    events = use_engine("block")
    install_include_hooks()
    # The call importlib.metadata's EntryPoint.load() makes, from a frame in that module.
    caller = {"__name__": "importlib.metadata", "importlib": importlib}
    with pytest.raises(RaspBlockedError):
        in_request(["json"], lambda: eval("importlib.import_module('json')", caller))  # pylint: disable=eval-used
    assert events.sinks() == ["importlib.import_module"]


# ---- statement detection across Python versions ------------------------------------


def test_reads_the_module_an_import_statement_names_on_this_python():
    import sys  # pylint: disable=import-outside-toplevel

    from shield360.rasp._hooks import include  # pylint: disable=import-outside-toplevel

    seen = []
    original = builtins.__import__

    def recording(name, *args, **kwargs):
        seen.append((name, include._literal_import(sys._getframe(1))))  # pylint: disable=protected-access
        return original(name, *args, **kwargs)

    builtins.__import__ = recording
    try:
        import json  # pylint: disable=import-outside-toplevel,unused-import,reimported
        import json.decoder  # pylint: disable=import-outside-toplevel,unused-import
        from os import path  # pylint: disable=import-outside-toplevel,unused-import
    finally:
        builtins.__import__ = original
    assert seen[:3] == [("json", "json"), ("json.decoder", "json.decoder"), ("os", "os")]


def test_when_the_instruction_cannot_be_read_the_call_counts_as_a_statement(monkeypatch):
    from shield360.rasp._hooks import include  # pylint: disable=import-outside-toplevel

    events = use_engine("block")
    install_include_hooks()
    monkeypatch.setattr(include, "_opcode", lambda frame: -1)
    assert in_request(["json"], lambda: __import__("json")).__name__ == "json"
    monkeypatch.setattr(include, "_IMPORT_NAME", -1)
    assert in_request(["json"], lambda: __import__("json")).__name__ == "json"
    assert not events
    # importlib.import_module never depends on reading bytecode.
    with pytest.raises(RaspBlockedError):
        in_request(["json"], lambda: importlib.import_module("json"))


def test_an_unreadable_operand_up_the_stack_counts_as_a_statement(monkeypatch):
    from shield360.rasp._hooks import include  # pylint: disable=import-outside-toplevel

    events = use_engine("block")
    install_include_hooks()
    monkeypatch.setattr(include, "_NAME_SHIFT", 60)  # an operand encoding this hook does not know
    inner = builtins.__import__

    def tracing_import(*args, **kwargs):
        return inner(*args, **kwargs)

    builtins.__import__ = tracing_import
    try:

        def handler():
            import json  # pylint: disable=import-outside-toplevel,unused-import,reimported

            return True

        assert in_request(["json"], handler)
    finally:
        builtins.__import__ = inner
    assert not events
