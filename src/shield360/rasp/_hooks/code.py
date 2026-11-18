"""Code, deserialization and XML sink hooks (README "Code",
"Deserialization", "XXE").

**Code.** ``eval``, ``exec`` and ``compile`` are deliberately not replaced.
Called with no namespaces they use the *caller's* globals, locals and
``from __future__`` flags; a wrapper would be the caller, so every bare
``eval(x)`` in the app (and in ``dataclasses``, ``typing``,
``namedtuple``) would run against the wrapper's scope and flags and break,
the same reason the TypeScript hook leaves ``eval`` alone. Instead a PEP 578
audit hook watches the ``compile`` event that all three raise for source
text, which changes nothing about how the code runs and can still refuse
it. An audit hook cannot be removed once added: uninstall switches it off,
and a switched-off hook returns at its first comparison.

While a template engine call is in progress (``template.py``), the inputs
found in its source were judged by the template check, so the code the
engine generates from it is checked against the other inputs only.

**Deserialization.** ``pickle.loads`` and ``_pickle.loads`` (and ``load`` and
``Unpickler(...).load()`` from an in-memory buffer), ``marshal.loads``, ``dill.loads``, ``cloudpickle.loads``,
``jsonpickle.decode``, and PyYAML's ``load``/``load_all`` with an unsafe
loader (``unsafe_load``, ``full_load`` before 5.4 and the ``*_all`` forms
call these). Each load is checked on its own: a load an app callback makes
while another payload is being rebuilt is checked too. Data read from a
file cannot be checked without reading it, so ``pickle.load`` or an
``Unpickler`` on a file, ``joblib.load``, ``shelve`` and ``torch.load`` are
not covered. ``Unpickler`` is a built-in type whose ``load`` cannot be
wrapped: while the hook is installed ``pickle.Unpickler`` and
``_pickle.Unpickler`` are a subclass that checks, and the original class is
put back on uninstall (an ``Unpickler`` captured before install is not
covered).

**XML.** ``xml.etree.ElementTree`` (``fromstring``, ``XML``),
``xml.dom.minidom.parseString`` and ``xml.sax.parseString`` never fetch
external entities: their ``xxe.doctype`` (and ``xxe.protocol`` / ``xxe.file``,
which only matter to a parser that fetches) are capped at monitor, so they
never block a parse; ``lxml.etree``
(``fromstring``, ``XML``) resolves them with its default parser before lxml
5. lxml parser objects do not expose their options, so with an explicit
parser the hook cannot tell and reports ``xxe.doctype``.
"""

from __future__ import annotations

import io
import sys
import weakref
from typing import Any, Callable, Dict, List, Optional, Sequence

from shield360.rasp import _detect
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Entry, argument, in_check, mark, restore, run_check, wrap_call
from shield360.rasp._hooks.template import unjudged_inputs
from shield360.rasp._types import Finding, RaspBlockedError

_TAG = "rasp.code"
_entries: List[Entry] = []
_installed = False
_audit_on = False
_audit_added = False


def _inputs() -> list:
    ctx = current_context()
    return inputs_of(ctx) if ctx is not None else []


def _text(data: Any) -> Optional[str]:
    """Data as the detectors compare it: text as is, bytes as latin-1."""
    if isinstance(data, str):
        return data
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data).decode("latin-1")
    return None


# ---- code ------------------------------------------------------------------------


def _audit(event: str, args: Any) -> None:
    # Called for every audit event in the process: the first comparison must be cheap.
    if event != "compile" or not _audit_on:
        return
    try:
        source = args[0]
        if in_check() or current_context() is None or not isinstance(source, (str, bytes)):
            return
        # The import system compiles module sources through the same event; those are not the app's code.
        caller = sys._getframe(1).f_globals.get("__name__", "")  # pylint: disable=protected-access
        if isinstance(caller, str) and (caller.startswith("importlib") or caller.startswith("_frozen_importlib")):
            return
        # eval and exec hand the event their source encoded.
        text = source.decode("utf-8", "replace") if isinstance(source, bytes) else source
        # Code a template engine generates from a source the template check judged skips that source's inputs.
        inputs = unjudged_inputs(_inputs())
        if inputs:
            run_check("compile", lambda: _detect.detect_code(text, inputs))
    except RaspBlockedError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def install_audit_hook() -> None:
    global _audit_on, _audit_added
    if not _audit_added:
        sys.addaudithook(_audit)
        _audit_added = True
    _audit_on = True


# ---- deserialization ---------------------------------------------------------------


def _deser_before(sink: str, fmt: str, read: Callable[[Sequence[Any], Dict[str, Any]], Any]) -> Callable[..., None]:
    def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
        if current_context() is None:
            return

        def run() -> Optional[Finding]:
            inputs = _inputs()
            data = _text(read(args, kwargs)) if inputs else None
            return _detect.detect_deserialization(fmt, data, inputs) if data else None

        run_check(sink, run)

    return before


def _first(name: str) -> Callable[[Sequence[Any], Dict[str, Any]], Any]:
    return lambda args, kwargs: argument(args, kwargs, 0, name)


def _buffered(args: Sequence[Any], kwargs: Dict[str, Any]) -> Any:
    f = argument(args, kwargs, 0, "file")
    if isinstance(f, io.BytesIO):
        return f.getbuffer()[f.tell() :].tobytes()
    return None


def _add(entry: Optional[Entry]) -> None:
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _from_importlib() -> bool:
    """Whether the ``marshal.loads`` being checked is the import system reading a ``.pyc``."""
    try:
        # 0 this function, 1 before, 2 the wrapper, 3 its caller.
        caller = sys._getframe(3).f_globals.get("__name__", "")  # pylint: disable=protected-access
    except (ValueError, AttributeError):
        return False
    return isinstance(caller, str) and (caller.startswith("importlib") or caller.startswith("_frozen_importlib"))


def _patch_pickle_like(name: str, fmt: str) -> Callable[[Any], None]:
    def patch(module: Any) -> None:
        checked = _deser_before(f"{name}.loads", fmt, _first("data"))

        def unless_importing(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
            # Imports during a request read .pyc files through marshal; those are not the app's data.
            if not _from_importlib():
                checked(args, kwargs)

        _add(wrap_call(module, "loads", unless_importing if name == "marshal" else checked))

    return patch


_unpicklers: List[tuple] = []
_unpickler_classes: Dict[type, type] = {}


def checking_unpickler(base: type, sink: str) -> type:
    """A subclass of ``Unpickler`` whose ``load()`` checks the data still to be
    read when the file is an in-memory buffer."""
    known = _unpickler_classes.get(base)
    if known is not None:
        return known
    files: "weakref.WeakKeyDictionary[Any, Any]" = weakref.WeakKeyDictionary()
    before = _deser_before(sink, "pickle", _buffered)

    def __init__(self: Any, file: Any, *args: Any, **kwargs: Any) -> None:  # pylint: disable=invalid-name
        base.__init__(self, file, *args, **kwargs)
        try:
            files[self] = file
        except TypeError:
            pass

    def load(self: Any) -> Any:
        if _installed:
            f = files.get(self)
            if f is not None:
                before((f,), {})
        return base.load(self)

    for fn, name in ((__init__, "__init__"), (load, "load")):
        fn.__qualname__ = f"{base.__qualname__}.{name}"
        fn.__doc__ = getattr(getattr(base, name, None), "__doc__", None)
        mark(fn)
    namespace = {"__init__": __init__, "load": load, "__module__": base.__module__, "__qualname__": base.__qualname__}
    cls = type(base.__name__, (base,), namespace)
    _unpickler_classes[base] = cls
    return cls


def _swap_unpickler(module: Any, sink: str) -> None:
    base = vars(module).get("Unpickler")
    if not isinstance(base, type) or base in _unpickler_classes.values():
        return
    try:
        cls = checking_unpickler(base, sink)
        setattr(module, "Unpickler", cls)
        _unpicklers.append((module, base, cls))
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _restore_unpicklers() -> None:
    for module, base, cls in reversed(_unpicklers):
        try:
            if vars(module).get("Unpickler") is cls:
                setattr(module, "Unpickler", base)
        except Exception:  # pylint: disable=broad-exception-caught
            pass
    _unpicklers.clear()


def _patch_pickle_module(name: str) -> Callable[[Any], None]:
    """``pickle`` and ``_pickle``: loads, load from a buffer, and Unpickler."""
    loads = _patch_pickle_like(name, "pickle")

    def patch(module: Any) -> None:
        loads(module)
        _add(wrap_call(module, "load", _deser_before(f"{name}.load", "pickle", _buffered)))
        _swap_unpickler(module, f"{name}.Unpickler.load")

    return patch


def _patch_jsonpickle(module: Any) -> None:
    _add(wrap_call(module, "decode", _deser_before("jsonpickle.decode", "jsonpickle", _first("string"))))


def yaml_unsafe(module: Any, loader: Any) -> bool:
    """Whether a PyYAML loader constructs arbitrary Python objects: the unsafe
    loader, or the full loader before 5.4 (and the old default, no loader, before 5.1)."""
    constructor = getattr(module, "constructor", None)
    unsafe = getattr(constructor, "UnsafeConstructor", None) or getattr(constructor, "Constructor", None)
    full = getattr(constructor, "FullConstructor", None)
    try:
        version = tuple(int(p) for p in str(getattr(module, "__version__", "6")).split(".")[:2])
    except ValueError:
        version = (6, 0)
    if loader is None:
        return version < (5, 4)
    if not isinstance(loader, type):
        return False
    if unsafe is not None and issubclass(loader, unsafe):
        return True
    return full is not None and issubclass(loader, full) and version < (5, 4)


def _patch_yaml(module: Any) -> None:
    for name in ("load", "load_all"):

        def before(args: Sequence[Any], kwargs: Dict[str, Any], name: str = name) -> None:
            if current_context() is None or not yaml_unsafe(module, argument(args, kwargs, 1, "Loader")):
                return
            stream = argument(args, kwargs, 0, "stream")
            if isinstance(stream, (bytes, bytearray)):
                stream = bytes(stream).decode("utf-8", "replace")
            if isinstance(stream, str):
                run_check(f"yaml.{name}", lambda: _detect.detect_deserialization("yaml", stream, _inputs()))

        _add(wrap_call(module, name, before))


# ---- XML ---------------------------------------------------------------------------


_FETCH_ONLY = frozenset(("xxe.doctype", "xxe.protocol", "xxe.file"))


def cap_xml(found: Optional[Finding], resolves_external: bool) -> Optional[Finding]:
    """A parser that never fetches external entities: the findings about
    fetching them are hints (README: ``xxe.doctype`` is monitor-level), capped
    at monitor. Entity expansion (``xxe.billion_laughs``) is not capped."""
    if found is not None and not resolves_external and found.rule in _FETCH_ONLY:
        found.action = "monitor"
    return found


def _xml_before(sink: str, resolves: Callable[[Sequence[Any], Dict[str, Any]], bool]) -> Callable[..., None]:
    def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
        if current_context() is None:
            return
        text = argument(args, kwargs, 0, "text", "string")
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        if isinstance(text, str) and "<!DOCTYPE" in text:
            fetches = resolves(args, kwargs)
            run_check(sink, lambda: cap_xml(_detect.detect_xml(text, _inputs(), fetches), fetches))

    return before


def _never(_args: Sequence[Any], _kwargs: Dict[str, Any]) -> bool:
    return False


def _patch_stdlib_xml(module_name: str, names: Sequence[str]) -> Callable[[Any], None]:
    def patch(module: Any) -> None:
        for name in names:
            _add(wrap_call(module, name, _xml_before(f"{module_name}.{name}", _never)))

    return patch


def _patch_lxml(module: Any) -> None:
    try:
        major = int(str(getattr(module, "__version__", "5")).split(".", maxsplit=1)[0])
    except ValueError:
        major = 5

    def resolves(args: Sequence[Any], kwargs: Dict[str, Any]) -> bool:
        # The default parser resolves external entities before lxml 5; an explicit parser's options are not readable.
        return major < 5 and argument(args, kwargs, 1, "parser") is None

    for name in ("fromstring", "XML"):
        _add(wrap_call(module, name, _xml_before(f"lxml.etree.{name}", resolves)))


_PATCHES = (
    ("pickle", _patch_pickle_module("pickle")),
    ("_pickle", _patch_pickle_module("_pickle")),
    ("marshal", _patch_pickle_like("marshal", "marshal")),
    ("dill", _patch_pickle_like("dill", "pickle")),
    ("cloudpickle", _patch_pickle_like("cloudpickle", "pickle")),
    ("jsonpickle", _patch_jsonpickle),
    ("yaml", _patch_yaml),
    ("xml.etree.ElementTree", _patch_stdlib_xml("xml.etree.ElementTree", ("fromstring", "XML"))),
    ("xml.dom.minidom", _patch_stdlib_xml("xml.dom.minidom", ("parseString",))),
    ("xml.sax", _patch_stdlib_xml("xml.sax", ("parseString",))),
    ("lxml.etree", _patch_lxml),
)


def install_code_hooks() -> bool:
    """Adds (or switches back on) the code audit hook and patches the
    deserializers and XML parsers the app has loaded, and the others when it
    loads them. Idempotent; never raises."""
    global _installed
    if _installed:
        return True
    try:
        _installed = True
        install_audit_hook()
        for name, patch in _PATCHES:
            _imports.when_imported(name, _TAG, patch)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_code_hooks()
        return False


def uninstall_code_hooks() -> None:
    """Switches the audit hook off and puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed, _audit_on
    _installed = _audit_on = False
    _imports.forget(_TAG)
    _restore_unpicklers()
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()
