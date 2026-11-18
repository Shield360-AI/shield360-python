"""Post-import hooks: run a callback with a module once the app imports it,
and at once for a module the app imported already. Nothing here imports a
module: a library is patched only when the app loads it.

A meta path finder sits first on ``sys.meta_path`` while any callback is
registered. For a watched name it asks the other finders for the spec and
wraps the loader so the callbacks run after the module executes. The
wrapper is invisible to the module: ``__loader__`` and ``__spec__.loader``
are the original loader again before the module's code runs.
"""

from __future__ import annotations

import importlib.abc
import sys
import threading
from typing import Any, Callable, Dict, Optional

_lock = threading.RLock()
_local = threading.local()
# Module name -> tag -> callback.
_callbacks: Dict[str, Dict[str, Callable[[Any], None]]] = {}


def _fire(name: str, module: Any) -> None:
    with _lock:
        callbacks = list(_callbacks.get(name, {}).values())
    for callback in callbacks:
        try:
            callback(module)
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # a hook that cannot patch leaves the module alone


class _Loader(importlib.abc.Loader):
    """Delegates everything to the real loader; runs the callbacks after ``exec_module``."""

    def __init__(self, loader: Any, name: str):
        self._loader = loader
        self._name = name

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._loader, attr)

    def create_module(self, spec: Any) -> Any:
        create = getattr(self._loader, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module: Any) -> None:
        loader = self._loader
        try:
            module.__loader__ = loader
            if getattr(module, "__spec__", None) is not None:
                module.__spec__.loader = loader
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        loader.exec_module(module)
        _fire(self._name, sys.modules.get(self._name, module))


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        with _lock:
            if fullname not in _callbacks:
                return None
        busy = getattr(_local, "busy", None)
        if busy is None:
            busy = _local.busy = set()
        if fullname in busy:
            return None
        busy.add(fullname)
        try:
            spec = None
            for finder in list(sys.meta_path):
                if isinstance(finder, _Finder):
                    continue
                find = getattr(finder, "find_spec", None)
                if find is None:
                    continue
                spec = find(fullname, path, target)
                if spec is not None:
                    break
            if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
                return None
            spec.loader = _Loader(spec.loader, fullname)
            return spec
        except Exception:  # pylint: disable=broad-exception-caught
            return None
        finally:
            busy.discard(fullname)


_finder: Optional[_Finder] = None


def when_imported(name: str, tag: str, callback: Callable[[Any], None]) -> None:
    """Runs ``callback(module)`` when the app imports ``name``, and now if it
    already has. One callback per (name, tag); registering again replaces it."""
    global _finder
    with _lock:
        _callbacks.setdefault(name, {})[tag] = callback
        if _finder is None:
            _finder = _Finder()
            sys.meta_path.insert(0, _finder)
    module = sys.modules.get(name)
    if module is not None:
        try:
            callback(module)
        except Exception:  # pylint: disable=broad-exception-caught
            pass


def forget(tag: str) -> None:
    """Drops every callback registered under ``tag``; the finder leaves with the last one."""
    global _finder
    with _lock:
        for name in list(_callbacks):
            _callbacks[name].pop(tag, None)
            if not _callbacks[name]:
                del _callbacks[name]
        if not _callbacks and _finder is not None:
            try:
                sys.meta_path.remove(_finder)
            except ValueError:
                pass
            _finder = None
