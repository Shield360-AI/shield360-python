"""Module include hook (README "Code", ``code.include``): loading a module
whose name or path came from request input.

Checked: ``importlib.import_module(name)``, ``builtins.__import__(name)``
called as a function, ``runpy.run_module(mod_name)`` and
``runpy.run_path(path_name)``. Each goes through ``_detect.detect_include``
(and so passive IAST's ``vuln.include_from_input``).

An ``import x`` / ``from x import y`` statement also calls
``builtins.__import__``, with a name written in the source: it can never come
from input, so the hook skips a call when the caller is executing an
``IMPORT_NAME`` instruction (the statement itself), or a frame a few wrappers
up (another tool's ``__import__`` wrapper above RASP's) is executing one that
names exactly that module. Only a call made by a call instruction counts as
explicit: whatever the hook cannot read (an unknown instruction, an operand
encoding it does not know) counts as a statement, so an ordinary import is
never blocked; a missed check only fails open. It also skips the import system's own calls (the bootstrap, and ``runpy``
resolving a module's package; ``importlib.util`` relays count for their
caller). ``importlib.metadata`` and other library code are checked like the
app. Frame inspection that fails lets the import through. ``from importlib
import import_module`` bound before RASP was installed keeps the original
function and is not checked.
"""

from __future__ import annotations

import builtins
import dis
import importlib
import os
import sys
import threading
from typing import Any, Callable, List, Optional, Tuple

from shield360.rasp import _detect
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Entry, argument, in_check, restore, run_check, wrap
from shield360.rasp._types import RaspBlockedError
from shield360.rasp._upload_taint import detect_upload_include, location_count

_TAG = "rasp.include"
_IMPORT_NAME = dis.opmap.get("IMPORT_NAME", -1)
_entries: List[Entry] = []
_installed = False
_local = threading.local()


# Modules whose imports are the import system's own work, never the app's choice of
# module: the bootstrap, and runpy resolving the package of a module it was given
# (run_module itself is checked).
_IMPORT_SYSTEM = frozenset(
    ("importlib._bootstrap", "importlib._bootstrap_external", "_frozen_importlib", "_frozen_importlib_external", "runpy")
)
# Thin helpers that only relay an import for their caller: judged by who called them.
_RELAYS = frozenset(("importlib", "importlib.util"))
_EXTENDED_ARG = dis.opmap.get("EXTENDED_ARG", -1)
# How far up a literal import is looked for (other tools' import wrappers in between).
_MAX_WRAPPERS = 8


def _module_of(frame: Any) -> str:
    name = frame.f_globals.get("__name__", "")
    return name if isinstance(name, str) else ""


def _from_import_system(frame: Any) -> bool:
    """Whether the import system made the call itself (a relay such as
    ``importlib.util.find_spec`` counts for whoever called it)."""
    f = frame
    for _ in range(_MAX_WRAPPERS):
        if f is None:
            return False
        mod = _module_of(f)
        if mod in _IMPORT_SYSTEM:
            return True
        if mod not in _RELAYS:
            return False
        f = f.f_back
    return False


# Instructions that call a function: an explicit ``__import__(...)`` call is one of these.
_CALL_OPS = frozenset(op for opname, op in dis.opmap.items() if opname.startswith("CALL"))
# IMPORT_NAME's operand is the name's index in ``co_names``; from 3.15 it sits above two
# flag bits (lazy / eager imports, PEP 810), as ``dis`` decodes it.
_NAME_SHIFT = 2 if sys.version_info >= (3, 15) else 0
# A frame executing IMPORT_NAME whose operand could not be read.
_UNREADABLE = "\0unreadable"


_CACHE = dis.opmap.get("CACHE", -1)


def _instruction(frame: Any) -> Tuple[bytes, int]:
    """The frame's bytecode and the offset of the instruction it is executing.
    From 3.11 ``f_lasti`` can point into the inline ``CACHE`` entries that follow
    an instruction (a specialized ``CALL`` does): step back to the instruction."""
    code = frame.f_code.co_code
    i = frame.f_lasti
    while 0 < i < len(code) and code[i] == _CACHE:
        i -= 2
    return code, i


def _opcode(frame: Any) -> int:
    code, i = _instruction(frame)
    return code[i] if 0 <= i < len(code) else -1


def _literal_import(frame: Any) -> Optional[str]:
    """The module name an ``import`` statement the frame is executing names (a
    literal in its code), ``_UNREADABLE`` when it is executing one whose operand
    cannot be read, or None when it is not executing one."""
    code, i = _instruction(frame)
    if i < 0 or i + 1 >= len(code) or code[i] != _IMPORT_NAME:
        return None
    arg = code[i + 1]
    shift = 8
    j = i - 2
    while j >= 0 and code[j] == _EXTENDED_ARG:
        arg |= code[j + 1] << shift
        shift += 8
        j -= 2
    names = frame.f_code.co_names
    index = arg >> _NAME_SHIFT
    return names[index] if 0 <= index < len(names) and isinstance(names[index], str) else _UNREADABLE


def _is_import_statement(caller: Any, name: Any) -> bool:
    """Whether a ``builtins.__import__`` call serves an ``import`` statement. True
    unless the call is positively an explicit one: when the hook cannot tell (an
    unknown instruction, an unreadable operand, a runtime without IMPORT_NAME), it
    says statement, so an ordinary import is never blocked (a missed check only
    fails open)."""
    if _IMPORT_NAME < 0 or not _CALL_OPS:
        return True
    op = _opcode(caller)
    if op == _IMPORT_NAME:
        return True  # the statement itself
    if op not in _CALL_OPS:
        return True  # cannot tell
    # An explicit call, unless it is another tool's __import__ wrapper relaying a
    # statement: a frame a few wrappers up executing IMPORT_NAME for exactly this module.
    f = caller.f_back
    for _ in range(_MAX_WRAPPERS):
        if f is None:
            return False
        literal = _literal_import(f)
        if literal is not None and literal in (name, _UNREADABLE):
            return True
        f = f.f_back
    return False


def _check(sink: str, specifier: Any) -> None:
    if not isinstance(specifier, str) or not specifier or getattr(_local, "busy", False):
        return
    ctx = current_context()
    if ctx is None:
        return
    _local.busy = True
    try:
        run_check(sink, lambda: _detect.detect_include(specifier, inputs_of(ctx)))
    finally:
        _local.busy = False


def _build(sink: str, index: int, *names: str) -> Callable[[Callable[..., Any], Entry], Callable[..., Any]]:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def checked(*args: Any, **kwargs: Any) -> Any:
            if entry.on and not in_check() and current_context() is not None:
                # Fail open: only the block error gets out (a frame lookup an audit hook denies lets the call through).
                try:
                    if not _from_import_system(sys._getframe(1)):  # pylint: disable=protected-access
                        _check(sink, argument(args, kwargs, index, *names))
                except RaspBlockedError:
                    raise
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
            return fn(*args, **kwargs)

        return checked

    return build


def _build_dunder_import(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
    def checked_import(*args: Any, **kwargs: Any) -> Any:
        # Every import statement in the process comes through here: the common path must stay cheap.
        if entry.on and current_context() is not None and not in_check():
            try:
                name = args[0] if args else kwargs.get("name")
                caller = sys._getframe(1)  # pylint: disable=protected-access
                if not _is_import_statement(caller, name) and not _from_import_system(caller):
                    _check("builtins.__import__", name)
            except RaspBlockedError:
                raise
            except Exception:  # pylint: disable=broad-exception-caught
                pass  # fail open
        return fn(*args, **kwargs)

    return checked_import


def _add(entry: Optional[Entry]) -> None:
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _upload_before(sink: str, index: int, *names: str) -> Callable[[Callable[..., Any], Entry], Callable[..., Any]]:
    """SHIELD: uploads — loading an uploaded file as code (``backdoor.include``), in a request or not."""

    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def checked(*args: Any, **kwargs: Any) -> Any:
            if entry.on and location_count():
                path = argument(args, kwargs, index, *names)
                if isinstance(path, (str, os.PathLike)):
                    run_check(sink, lambda: detect_upload_include(os.fspath(path)))
            return fn(*args, **kwargs)

        return checked

    return build


def _patch_runpy(module: Any) -> None:
    _add(wrap(module, "run_module", _build("runpy.run_module", 0, "mod_name"), _TAG))
    # SHIELD: uploads — the upload check runs first, whether or not the call is in a request.
    inner = _build("runpy.run_path", 0, "path_name")
    outer = _upload_before("runpy.run_path", 0, "path_name")
    _add(wrap(module, "run_path", lambda fn, entry: outer(inner(fn, entry), entry), _TAG))


def _patch_importlib_util(module: Any) -> None:
    _add(wrap(module, "spec_from_file_location", _upload_before("importlib.util.spec_from_file_location", 1, "location"), _TAG))


def install_include_hooks() -> bool:
    """Wraps ``importlib.import_module`` and ``builtins.__import__`` now, and
    ``runpy`` when the app loads it. Idempotent; never raises."""
    global _installed  # pylint: disable=global-statement
    if _installed:
        return True
    try:
        _installed = True
        _add(wrap(importlib, "import_module", _build("importlib.import_module", 0, "name"), _TAG))
        _add(wrap(builtins, "__import__", _build_dunder_import, _TAG))
        _imports.when_imported("runpy", _TAG, _patch_runpy)
        _imports.when_imported("importlib.util", _TAG, _patch_importlib_util)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_include_hooks()
        return False


def uninstall_include_hooks() -> None:
    """Puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed  # pylint: disable=global-statement
    _installed = False
    _imports.forget(_TAG)
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()
