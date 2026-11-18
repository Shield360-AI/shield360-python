"""Code, deserialization and XML sink hooks: the compile audit hook for
eval/exec/compile (which are never replaced), pickle and marshal, PyYAML,
jsonpickle and lxml (stand-in modules), and the standard library's XML
parsers. Payloads are harmless: tiny pickles of plain values, YAML and XML
that are only inspected.

Mirrors sdk/typescript/src/rasp/__tests__/code-hook.test.ts.
"""

import builtins
import io
import marshal
import pickle
import sys
import types
import xml.etree.ElementTree as ET

import pytest

from rasp_hook_kit import in_request, stop_engine, use_engine
from shield360.rasp import RaspBlockedError, _detect
from shield360.rasp._hooks.code import install_code_hooks, uninstall_code_hooks, yaml_unsafe
from shield360.rasp._types import RaspInput

PICKLED = pickle.dumps(["harmless"])
DOCTYPE_XML = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://attacker.example/x">]><r>&x;</r>'


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    uninstall_code_hooks()
    stop_engine()


def body(value):
    return RaspInput(value, "body.data", "request")


# ---- code ------------------------------------------------------------------------


def test_eval_exec_and_compile_of_tainted_code_are_refused_by_the_audit_hook():
    events = use_engine("block")
    install_code_hooks()
    with pytest.raises(RaspBlockedError):
        in_request(["1 + 2"], lambda: eval("1 + 2"))  # pylint: disable=eval-used
    with pytest.raises(RaspBlockedError):
        in_request(["__import__('os')"], lambda: exec("x = __import__('os')"))  # pylint: disable=exec-used
    with pytest.raises(RaspBlockedError):
        in_request(["a.b(c)"], lambda: compile("a.b(c)", "<input>", "eval"))
    assert events.sinks() == ["compile", "compile", "compile"]


def test_eval_is_left_alone_so_it_keeps_the_callers_scope():
    install_code_hooks()
    assert builtins.eval.__module__ == "builtins" and builtins.exec.__module__ == "builtins"
    use_engine("monitor")

    def scoped():
        local_value = 41  # pylint: disable=unused-variable  # read by the eval below
        return eval("local_value + 1")  # pylint: disable=eval-used

    assert in_request(["unrelated"], scoped) == 42


def test_monitor_evaluates_harmless_code_and_reports():
    events = use_engine("monitor")
    install_code_hooks()
    assert in_request(["1 + 2"], lambda: eval("1 + 2")) == 3  # pylint: disable=eval-used
    assert events.attacks() == [("code_injection", "code.eval", "monitored")]


def test_the_audit_hook_is_inert_outside_contexts_and_after_uninstall():
    events = use_engine("block")
    install_code_hooks()
    assert eval("1 + 2") == 3  # pylint: disable=eval-used
    uninstall_code_hooks()
    assert in_request(["1 + 2"], lambda: eval("1 + 2")) == 3  # pylint: disable=eval-used
    assert not events


# ---- deserialization ---------------------------------------------------------------


def test_pickle_of_request_data_is_blocked_before_it_runs():
    events = use_engine("block")
    install_code_hooks()
    with pytest.raises(RaspBlockedError) as e:
        in_request([body(PICKLED.decode("latin-1"))], lambda: pickle.loads(PICKLED))
    assert e.value.rule == "deser.pickle"
    with pytest.raises(RaspBlockedError):
        in_request([body(PICKLED.decode("latin-1"))], lambda: pickle.load(io.BytesIO(PICKLED)))
    assert events.sinks() == ["pickle.loads", "pickle.load"]


def test_pickle_of_own_data_passes_and_monitor_reports_once():
    events = use_engine("monitor")
    install_code_hooks()
    assert in_request(["unrelated input"], lambda: pickle.loads(PICKLED)) == ["harmless"]
    assert in_request([body(PICKLED.decode("latin-1"))], lambda: pickle.loads(PICKLED)) == ["harmless"]
    assert events.attacks() == [("deserialization", "deser.pickle", "monitored")]


def test_marshal_is_checked_but_not_the_import_systems_pyc_reads(tmp_path, monkeypatch):
    events = use_engine("block")
    install_code_hooks()
    data = marshal.dumps("harmless value")
    with pytest.raises(RaspBlockedError):
        in_request([body(data.decode("latin-1"))], lambda: marshal.loads(data))
    events.clear()
    # A module imported during a request, holding the request's text as a constant, imports normally.
    (tmp_path / "rasp_marshal_probe.py").write_text('VALUE = "request text here"\n', encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    import importlib  # pylint: disable=import-outside-toplevel

    importlib.import_module("rasp_marshal_probe")
    sys.modules.pop("rasp_marshal_probe")
    module = in_request(["request text here"], lambda: importlib.import_module("rasp_marshal_probe"))
    sys.modules.pop("rasp_marshal_probe", None)
    assert module.VALUE == "request text here"
    assert not events


def _fake_yaml(version):
    yaml = types.ModuleType("yaml")
    constructor = types.ModuleType("yaml.constructor")

    class BaseConstructor:
        pass

    class SafeConstructor(BaseConstructor):
        pass

    class FullConstructor(SafeConstructor):
        pass

    class UnsafeConstructor(FullConstructor):
        pass

    constructor.BaseConstructor = BaseConstructor
    constructor.SafeConstructor = SafeConstructor
    constructor.FullConstructor = FullConstructor
    constructor.UnsafeConstructor = UnsafeConstructor
    yaml.constructor = constructor
    yaml.__version__ = version
    yaml.SafeLoader = type("SafeLoader", (SafeConstructor,), {})
    yaml.FullLoader = type("FullLoader", (FullConstructor,), {})
    yaml.UnsafeLoader = type("UnsafeLoader", (UnsafeConstructor,), {})

    def load(stream, Loader=None):  # pylint: disable=invalid-name
        return stream

    def unsafe_load(stream):
        # As PyYAML: the module's own load, looked up when called.
        return yaml.load(stream, yaml.UnsafeLoader)

    def load_all(stream, Loader=None):  # pylint: disable=invalid-name
        return [stream]

    yaml.load, yaml.unsafe_load, yaml.load_all = load, unsafe_load, load_all
    return yaml


def test_yaml_with_an_unsafe_loader_and_a_python_tag_is_blocked(monkeypatch):
    yaml = _fake_yaml("6.0.1")
    monkeypatch.setitem(sys.modules, "yaml", yaml)
    events = use_engine("block")
    install_code_hooks()
    doc = "!!python/object/apply:builtins.print ['hi']"
    with pytest.raises(RaspBlockedError):
        in_request([body(doc)], lambda: yaml.unsafe_load(doc))
    assert in_request([body(doc)], lambda: yaml.load(doc, Loader=yaml.SafeLoader)) == doc
    assert in_request([body(doc)], lambda: yaml.load(doc, yaml.FullLoader)) == doc
    assert in_request([body("a: 1")], lambda: yaml.load("a: 1", yaml.UnsafeLoader)) == "a: 1"
    assert events.sinks() == ["yaml.load"]


def test_yaml_loader_safety_follows_the_version():
    old, new = _fake_yaml("5.3.1"), _fake_yaml("6.0")
    assert yaml_unsafe(old, old.FullLoader) and not yaml_unsafe(new, new.FullLoader)
    assert yaml_unsafe(old, None) and not yaml_unsafe(new, None)
    assert yaml_unsafe(new, new.UnsafeLoader) and not yaml_unsafe(new, new.SafeLoader)


def test_jsonpickle_markers_in_request_data_are_blocked(monkeypatch):
    jsonpickle = types.ModuleType("jsonpickle")
    jsonpickle.decode = lambda string, **kwargs: string
    monkeypatch.setitem(sys.modules, "jsonpickle", jsonpickle)
    use_engine("block")
    install_code_hooks()
    doc = '{"py/object": "builtins.dict"}'
    with pytest.raises(RaspBlockedError):
        in_request([body(doc)], lambda: jsonpickle.decode(doc))
    assert in_request([body('{"a": 1}')], lambda: jsonpickle.decode('{"a": 1}')) == '{"a": 1}'


# ---- XML ---------------------------------------------------------------------------


def test_stdlib_xml_with_an_external_entity_is_a_doctype_hint():
    events = use_engine("monitor")
    install_code_hooks()
    with pytest.raises(ET.ParseError):
        # ElementTree refuses the undefined external entity itself; RASP only reported it.
        in_request([body(DOCTYPE_XML)], lambda: ET.fromstring(DOCTYPE_XML))
    assert events.attacks() == [("xxe", "xxe.doctype", "monitored")]
    assert in_request([body("<r>ok</r>")], lambda: ET.fromstring("<r>ok</r>").text) == "ok"


def test_lxml_default_parser_before_5_resolves_external_entities(monkeypatch):
    seen = []
    etree = types.ModuleType("lxml.etree")
    etree.__version__ = "4.9.3"
    etree.fromstring = lambda text, parser=None: seen.append(text) or "parsed"
    etree.XML = etree.fromstring
    lxml = types.ModuleType("lxml")
    lxml.etree = etree
    monkeypatch.setitem(sys.modules, "lxml", lxml)
    monkeypatch.setitem(sys.modules, "lxml.etree", etree)
    events = use_engine("block")
    install_code_hooks()
    with pytest.raises(RaspBlockedError) as e:
        in_request([body(DOCTYPE_XML)], lambda: etree.fromstring(DOCTYPE_XML))
    assert e.value.rule == "xxe.external_entity" and not seen
    events = use_engine("monitor")
    assert in_request([body(DOCTYPE_XML)], lambda: etree.XML(DOCTYPE_XML, object())) == "parsed"
    assert events.attacks()[-1] == ("xxe", "xxe.doctype", "monitored")


def test_off_and_detector_failures_leave_everything_alone(monkeypatch):
    stop_engine()
    install_code_hooks()
    assert in_request([body(PICKLED.decode("latin-1"))], lambda: pickle.loads(PICKLED)) == ["harmless"]

    def broken(*a):
        raise RuntimeError("boom")

    monkeypatch.setattr(_detect, "detect_deserialization", broken)
    monkeypatch.setattr(_detect, "detect_code", broken)
    events = use_engine("block")
    assert in_request([body(PICKLED.decode("latin-1"))], lambda: pickle.loads(PICKLED)) == ["harmless"]
    assert in_request(["1 + 2"], lambda: eval("1 + 2")) == 3  # pylint: disable=eval-used
    assert not events


def test_install_and_uninstall_restore_the_modules_exactly():
    before = (pickle.loads, marshal.loads, ET.fromstring, builtins.eval)
    assert install_code_hooks() and install_code_hooks()
    assert pickle.loads is not before[0] and pickle.loads.__name__ == "loads"
    uninstall_code_hooks()
    uninstall_code_hooks()
    assert (pickle.loads, marshal.loads, ET.fromstring, builtins.eval) == before


# ---- review fixes ------------------------------------------------------------------

INNER = pickle.dumps(7)


def _load_inner():
    return pickle.loads(INNER)


class _Rebuilt:  # pylint: disable=too-few-public-methods
    def __reduce__(self):
        return (_load_inner, ())


def test_a_load_made_while_another_payload_is_rebuilt_is_checked_too():
    events = use_engine("block")
    install_code_hooks()
    outer = pickle.dumps(_Rebuilt())
    with pytest.raises(RaspBlockedError):
        in_request([body(INNER.decode("latin-1"))], lambda: pickle.loads(outer))
    assert events.sinks() == ["pickle.loads"]


def test_the_pickle_c_module_and_unpickler_load_are_checked():
    import _pickle  # pylint: disable=import-outside-toplevel

    original = pickle.Unpickler
    events = use_engine("block")
    install_code_hooks()
    tainted = [body(PICKLED.decode("latin-1"))]
    with pytest.raises(RaspBlockedError):
        in_request(tainted, lambda: _pickle.loads(PICKLED))
    with pytest.raises(RaspBlockedError):
        in_request(tainted, lambda: pickle.Unpickler(io.BytesIO(PICKLED)).load())
    unpickler = pickle.Unpickler(io.BytesIO(PICKLED))
    assert isinstance(unpickler, original) and pickle.Unpickler.__name__ == "Unpickler"
    assert in_request(["unrelated"], unpickler.load) == ["harmless"]
    assert events.sinks() == ["_pickle.loads", "pickle.Unpickler.load"]
    uninstall_code_hooks()
    assert pickle.Unpickler is original and _pickle.Unpickler is original


def test_a_doctype_from_a_parser_that_never_fetches_never_blocks_the_parse():
    events = use_engine("block", attacks={"xxe": "block"})
    install_code_hooks()
    with pytest.raises(ET.ParseError):
        # ElementTree's own refusal of the undefined entity, not RASP's block.
        in_request([body(DOCTYPE_XML)], lambda: ET.fromstring(DOCTYPE_XML))
    assert events.attacks() == [("xxe", "xxe.doctype", "monitored")]
