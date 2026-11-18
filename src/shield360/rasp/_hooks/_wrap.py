"""The wrapper registry every sink hook uses.

RASP replaces a function on its owner (a module or a class) with a wrapper
of its own: a plain function, not a ``wrapt`` proxy, so the SDK's tracing
(OpenTelemetry instrumentations wrap many of the same functions with
``wrapt``) and RASP stack in either order and neither unwraps the other.

Each replaced attribute has one registry entry however many times it is
patched. Uninstall switches the entry off at once (its wrapper passes
straight through) and puts the original back only while RASP's wrapper is
still the attribute's value: a wrapper put on top later (tracing) is never
torn off, it keeps calling RASP's, which no longer checks. Installing again
switches the same entry back on.

A target that is missing or cannot be replaced (an immutable built-in type)
is skipped on its own; it never aborts the rest of an install.
"""

from __future__ import annotations

import functools
import inspect
import threading
import weakref
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

from shield360.rasp import _engine
from shield360.rasp._types import Finding, RaspBlockedError

_MISSING = object()
_local = threading.local()
_lock = threading.RLock()
# RASP's own wrappers, so a sink rule never wraps a function a built-in hook already checks.
_marks: "weakref.WeakSet[Any]" = weakref.WeakSet()


def mark(fn: Any) -> None:
    try:
        _marks.add(fn)
    except TypeError:
        pass


def is_rasp_wrapper(fn: Any) -> bool:
    try:
        return fn in _marks
    except TypeError:
        return False


def in_check() -> bool:
    """True while a RASP check runs on this thread (sinks it touches are RASP's, not the app's)."""
    return getattr(_local, "checking", False)


class Depth:
    """Synchronous calls of one hook family in progress on this thread:
    a call made inside another (``shutil.copy`` opening its files,
    ``os.popen`` starting a ``Popen``) belongs to the outer call, which was
    checked already (one check per logical call)."""

    def __init__(self) -> None:
        self._local = threading.local()

    @property
    def active(self) -> bool:
        return getattr(self._local, "n", 0) > 0

    def __enter__(self) -> "Depth":
        self._local.n = getattr(self._local, "n", 0) + 1
        return self

    def __exit__(self, *exc: Any) -> None:
        self._local.n -= 1


def run_check(sink: str, run: Callable[[], Optional[Finding]]) -> None:
    """Runs one check at a sink. Raises only the block error; anything else
    (a detector that fails, a bad argument) lets the call through."""
    if in_check():
        return
    try:
        if not _engine.is_active():
            return
        _local.checking = True
        _engine.check(sink, run)
    except RaspBlockedError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    finally:
        _local.checking = False


_RANK = {"off": 0, "monitor": 1, "block": 2}


def strongest(*findings: Optional[Finding]) -> Optional[Finding]:
    """Of several findings for one call, the one whose decision is strongest
    (block over monitor; an attack type that is off never counts), so a finding
    for a type in monitor or off mode cannot hide another that blocks. Ties go
    to the earlier finding."""
    best: Optional[Finding] = None
    best_rank = 0
    for f in findings:
        if f is None:
            continue
        mode = _engine.mode_for(f.attack)
        if f.action in _RANK and _RANK[f.action] < _RANK[mode]:
            mode = f.action
        if f.attack == "xss" and mode == "block":
            mode = "monitor"
        if _RANK[mode] > best_rank:
            best, best_rank = f, _RANK[mode]
    return best


class Entry:  # pylint: disable=too-few-public-methods
    """One replaced attribute: the original, RASP's wrapper, and whether it checks."""

    __slots__ = ("owner", "key", "original", "installed", "wrapper", "on", "bound", "tag")

    def __init__(self, owner: Any, key: str, original: Any, bound: bool, tag: str = ""):
        self.owner = owner
        self.key = key
        # The attribute as it was in the owner's namespace (a function, staticmethod, builtin).
        self.original = original
        self.installed: Any = None
        self.wrapper: Any = None
        self.on = True
        # Called as a method: the first argument is the instance (or class), not the app's argument.
        self.bound = bound
        # Which kind of hook owns the entry (sink rules never take over a built-in hook's).
        self.tag = tag


_registry: Dict[Tuple[int, str], Entry] = {}


def own_attribute(owner: Any, key: str) -> Any:
    try:
        return vars(owner).get(key, _MISSING)
    except TypeError:
        return _MISSING


def _callable_of(raw: Any) -> Tuple[str, Any]:
    if isinstance(raw, staticmethod):
        return "static", raw.__func__
    if isinstance(raw, classmethod):
        return "class", raw.__func__
    return "plain", raw


def _identity(original: Callable[..., Any], wrapper: Callable[..., Any]) -> None:
    """The wrapper keeps the original's name, qualified name, module, docs,
    signature (through ``__wrapped__``) and attributes."""
    try:
        functools.update_wrapper(wrapper, original)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _in_chain(raw: Any, entry: Entry) -> bool:
    """Whether RASP's wrapper is the attribute's value, or under a wrapper that names what it wraps (``__wrapped__``)."""
    current = raw
    for _ in range(16):
        if current is entry.installed or current is entry.wrapper:
            return True
        current = getattr(current, "__func__", current)
        current = getattr(current, "__wrapped__", None)
        if current is None:
            return False
    return False


def wrap(owner: Any, key: str, build: Callable[[Callable[..., Any], Entry], Callable[..., Any]], tag: str = "") -> Optional[Entry]:
    """Replaces ``owner.key`` with ``build(original, entry)``. Returns the
    entry, the existing one (switched back on) when a hook with the same
    ``tag`` already wrapped it, or None when the attribute is missing, not
    callable, already one of RASP's wrappers (another hook's), or cannot be
    replaced. Never raises."""
    try:
        with _lock:
            raw = own_attribute(owner, key)
            known = _registry.get((id(owner), key))
            if known is not None and known.owner is owner:
                if known.tag != tag:
                    return None
                if _in_chain(raw, known):
                    known.on = True
                    return known
                # Put back or replaced by someone else: wrap what is there now. If the
                # old wrapper is still somewhere underneath, it only passes through.
                del _registry[(id(owner), key)]
            if raw is _MISSING:
                return None
            kind, fn = _callable_of(raw)
            if not callable(fn) or is_rasp_wrapper(fn):
                return None
            bound = isinstance(owner, type) and (kind == "class" or (kind == "plain" and inspect.isfunction(fn)))
            entry = Entry(owner, key, raw, bound, tag)
            wrapper = build(fn, entry)
            _identity(fn, wrapper)
            mark(wrapper)
            if kind == "class":
                installed: Any = classmethod(wrapper)
            elif kind == "static" or (isinstance(owner, type) and not bound):
                # A builtin kept on a class does not bind; neither may the wrapper that stands for it.
                installed = staticmethod(wrapper)
            else:
                installed = wrapper
            setattr(owner, key, installed)
            entry.installed = installed
            entry.wrapper = wrapper
            _registry[(id(owner), key)] = entry
            return entry
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def restore(entry: Entry) -> None:
    """Switches the entry off; puts the original back while RASP's wrapper is on top. Never raises."""
    entry.on = False
    try:
        with _lock:
            if own_attribute(entry.owner, entry.key) is entry.installed:
                setattr(entry.owner, entry.key, entry.original)
                if _registry.get((id(entry.owner), entry.key)) is entry:
                    del _registry[(id(entry.owner), entry.key)]
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def wrap_call(
    owner: Any,
    key: str,
    before: Callable[[Sequence[Any], Dict[str, Any]], None],
    depth: Optional[Depth] = None,
    tag: str = "",
    enter_depth: bool = True,
) -> Optional[Entry]:
    """The common wrapper: ``before(args, kwargs)`` runs the check (the
    instance or class already dropped from ``args`` for a method), then the
    original runs. A coroutine function gets a coroutine function. With
    ``depth``, a synchronous call made inside another call of the same family
    is not checked again; with ``enter_depth=False`` the call itself is skipped
    inside another but the calls it makes are still checked (``copytree``'s
    per-file copies)."""

    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        if inspect.iscoroutinefunction(fn):

            async def checked_async(*args: Any, **kwargs: Any) -> Any:
                if entry.on:
                    before(args[1:] if entry.bound else args, kwargs)
                return await fn(*args, **kwargs)

            return checked_async

        def checked(*args: Any, **kwargs: Any) -> Any:
            if depth is None:
                if entry.on:
                    before(args[1:] if entry.bound else args, kwargs)
                return fn(*args, **kwargs)
            if entry.on and not depth.active:
                before(args[1:] if entry.bound else args, kwargs)
            if not enter_depth:
                return fn(*args, **kwargs)
            with depth:
                return fn(*args, **kwargs)

        return checked

    return wrap(owner, key, build, tag)


def argument(args: Sequence[Any], kwargs: Dict[str, Any], index: int, *names: str) -> Any:
    """An argument by position, else by any of its keyword names; None when absent."""
    if index < len(args):
        return args[index]
    for n in names:
        if n in kwargs:
            return kwargs[n]
    return None
