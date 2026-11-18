"""File sink hook (README "Path"): reads, writes, deletes, renames, copies
and directory listings are checked for path traversal and script writes
before the call.

Covered: ``builtins.open`` and ``io.open`` (so ``pathlib.Path.open``,
``read_text`` and ``write_bytes``, which call ``io.open``), ``os.open``,
``os.remove``/``unlink``/``rmdir``, ``os.rename``/``replace``/``renames``,
``os.listdir``/``scandir``, and ``shutil.copyfile``/``copy``/``copy2``/
``copytree``/``move``/``rmtree``. ``pathlib`` reaches the ``os`` functions
by module attribute from Python 3.11; on 3.10 it holds its own references
in ``pathlib._NormalAccessor``, which are wrapped too.

A path is checked once per logical call: the files ``shutil.copy`` opens,
or the ``os.rename`` inside ``shutil.move``, belong to the outer call.
File descriptors (integers) are not paths and are not checked.
"""

from __future__ import annotations

import builtins
import io
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from shield360.rasp import _detect
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._engine import allow_lists
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Depth, Entry, argument, restore, run_check, strongest, wrap_call
from shield360.rasp._types import Finding

_TAG = "rasp.files"
_depth = Depth()
_entries: List[Entry] = []
_installed = False

# Name -> the operation on the first path and, for two-path calls, on the second.
OS_APIS: Dict[str, Tuple[str, Optional[str]]] = {
    "open": ("open", None),
    "remove": ("delete", None),
    "unlink": ("delete", None),
    "rmdir": ("delete", None),
    "rename": ("rename", "rename"),
    "replace": ("rename", "rename"),
    "renames": ("rename", "rename"),
    "listdir": ("list", None),
    "scandir": ("list", None),
}
SHUTIL_APIS: Dict[str, Tuple[str, Optional[str]]] = {
    "copyfile": ("read", "write"),
    "copy": ("read", "write"),
    "copy2": ("read", "write"),
    "copytree": ("read", "write"),
    "move": ("rename", "rename"),
    "rmtree": ("delete", None),
}
# Python 3.10's pathlib accessor attributes and the os function each stands for.
_ACCESSOR_APIS = ("open", "listdir", "scandir", "unlink", "rmdir", "rename", "replace")
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def path_text(v: Any) -> Optional[str]:
    """A path as text; None for a file descriptor or anything that is not a path."""
    if isinstance(v, (str, bytes, os.PathLike)):
        try:
            p = os.fspath(v)
        except TypeError:
            return None
        if isinstance(p, bytes):
            return os.fsdecode(p)
        return p if isinstance(p, str) else None
    return None


def mode_op(mode: Any) -> str:
    """``open()`` mode: write when it writes or appends, else read."""
    if not isinstance(mode, str):
        return "read"
    if "a" in mode:
        return "append"
    return "write" if any(c in mode for c in "wx+") else "read"


def flags_op(flags: Any) -> str:
    """``os.open`` flags: write when they can write or create, else read."""
    return "write" if isinstance(flags, int) and flags & _WRITE_FLAGS else "read"


def _detect_one(path: Optional[str], op: str) -> Optional[Finding]:
    if path is None:
        return None
    ctx = current_context()
    inputs = inputs_of(ctx) if ctx is not None else []
    in_request = bool(ctx is not None and ctx.in_request)
    # With no input in scope only the NTFS stream check can fire, and only on a write.
    if not inputs and not in_request and "::$" not in path:
        return None
    return _detect.detect_path(path, op, inputs, allow_lists()["file_roots"], in_request)


def destination(sink: str, src: Any, dst: Any) -> Any:
    """The file a copy or move writes: ``shutil.copy``, ``copy2`` and ``move``
    into an existing directory write ``dst/<name of src>``."""
    if sink not in ("shutil.copy", "shutil.copy2", "shutil.move"):
        return dst
    s, d = path_text(src), path_text(dst)
    if s is None or d is None or not os.path.isdir(d):
        return dst
    return os.path.join(d, os.path.basename(s.rstrip("/\\")))


def _inspect(sink: str, first: Tuple[Any, str], second: Optional[Tuple[Any, str]] = None) -> None:
    def run() -> Optional[Finding]:
        one = _detect_one(path_text(first[0]), first[1])
        if second is None:
            return one
        # Both paths; the stronger decision wins.
        return strongest(one, _detect_one(path_text(destination(sink, first[0], second[0])), second[1]))

    run_check(sink, run)


def _open_before(sink: str) -> Any:
    def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
        _inspect(sink, (argument(args, kwargs, 0, "file"), mode_op(argument(args, kwargs, 1, "mode") or "r")))

    return before


def _two_path_before(sink: str, ops: Tuple[str, Optional[str]]) -> Any:
    def before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
        first = (argument(args, kwargs, 0, "path", "src", "old"), ops[0])
        if ops[0] == "open":
            first = (first[0], flags_op(argument(args, kwargs, 1, "flags")))
        second = (argument(args, kwargs, 1, "dst", "new"), ops[1]) if ops[1] else None
        _inspect(sink, first, second)

    return before


def _add(entry: Optional[Entry]) -> None:
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _patch_os(module: Any) -> None:
    for name, ops in OS_APIS.items():
        _add(wrap_call(module, name, _two_path_before(f"os.{name}", ops), depth=_depth))


def _patch_shutil(module: Any) -> None:
    for name, ops in SHUTIL_APIS.items():
        # copytree's own check covers the two directories; each file it copies is checked as it is written.
        _add(wrap_call(module, name, _two_path_before(f"shutil.{name}", ops), depth=_depth, enter_depth=name != "copytree"))


def _patch_pathlib(module: Any) -> None:
    accessor = getattr(module, "_NormalAccessor", None)
    if not isinstance(accessor, type):
        return  # Python 3.11+: pathlib calls os and io by module attribute
    for name in _ACCESSOR_APIS:
        # The accessor's open is io.open (a mode), the rest are the os functions.
        before = _open_before("pathlib.open") if name == "open" else _two_path_before(f"pathlib.{name}", OS_APIS[name])
        _add(wrap_call(accessor, name, before, depth=_depth))


def install_file_hooks() -> bool:
    """Wraps the file functions of ``builtins``, ``io`` and ``os``, and of
    ``shutil`` and ``pathlib`` when the app imports them. Idempotent; never raises."""
    global _installed
    if _installed:
        return True
    try:
        _installed = True
        _add(wrap_call(builtins, "open", _open_before("open"), depth=_depth))
        _add(wrap_call(io, "open", _open_before("io.open"), depth=_depth))
        _patch_os(sys.modules.get("os", os))
        _imports.when_imported("shutil", _TAG, _patch_shutil)
        _imports.when_imported("pathlib", _TAG, _patch_pathlib)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_file_hooks()
        return False


def uninstall_file_hooks() -> None:
    """Switches every wrapper off and puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed
    _installed = False
    _imports.forget(_TAG)
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()
