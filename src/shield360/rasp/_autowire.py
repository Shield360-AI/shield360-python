"""Zero-code request capture for RASP: the zero-code start (``shield360-instrument``)
adds the RASP middleware to Flask, Starlette / FastAPI and Django apps as they
are created, so the app needs no code change.

- Flask: every ``Flask(...)`` gets ``rasp_flask(app)``.
- Starlette and FastAPI: the app's middleware stack is wrapped in
  ``RaspASGIMiddleware``.
- Django: ``shield360.rasp.RaspDjangoMiddleware`` is put first in
  ``settings.MIDDLEWARE`` when the handler loads its middleware.

The patches go in when the framework module is first imported (an import hook
on ``sys.meta_path``), or at once if it already was. Middleware the app adds
itself on top is harmless: an inner Shield360 middleware sees the request is
already captured and passes it through. Fail open: a patch that fails leaves
the framework as it was.
"""

from __future__ import annotations

import functools
import importlib.abc
import logging
import sys
import threading
from typing import Any, Callable, Dict, Optional, Sequence

logger = logging.getLogger(__name__)

_MARK = "_shield360_rasp_autowired"
_DJANGO_MIDDLEWARE = "shield360.rasp.RaspDjangoMiddleware"
_lock = threading.Lock()
_state: Dict[str, Any] = {"finder": None}


def _mark(obj: Any) -> bool:
    """Marks a class once; False when it was already marked."""
    if obj.__dict__.get(_MARK):
        return False
    setattr(obj, _MARK, True)
    return True


def _patch_flask(module: Any) -> None:
    cls = getattr(module, "Flask", None)
    if cls is None or not _mark(cls):
        return
    original = cls.__init__

    @functools.wraps(original)
    def __init__(self, *args, **kwargs):
        original(self, *args, **kwargs)
        try:
            from shield360.rasp._middleware import rasp_flask  # pylint: disable=import-outside-toplevel

            rasp_flask(self)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.debug("Shield360 RASP: could not add the Flask middleware", exc_info=True)

    cls.__init__ = __init__


def _wrap_stack(cls: Any, framework: str) -> None:
    """Adds RaspASGIMiddleware as the app's first user middleware when the stack is built.

    Inside ``ServerErrorMiddleware`` (which would answer a block with a 500 before
    RASP saw it) and outside ``ExceptionMiddleware``, the place
    ``app.add_middleware(RaspASGIMiddleware)`` puts it.
    """
    original = cls.__dict__.get("build_middleware_stack")
    if original is None or not _mark(cls):
        return

    @functools.wraps(original)
    def build_middleware_stack(self):
        try:
            from starlette.middleware import Middleware  # pylint: disable=import-outside-toplevel

            from shield360.rasp._middleware import RaspASGIMiddleware  # pylint: disable=import-outside-toplevel

            stack = getattr(self, "user_middleware", None)
            if isinstance(stack, list) and not any(getattr(m, "cls", None) is RaspASGIMiddleware for m in stack):
                stack.insert(0, Middleware(RaspASGIMiddleware, framework=framework))
        except Exception:  # pylint: disable=broad-exception-caught
            logger.debug("Shield360 RASP: could not add the ASGI middleware", exc_info=True)
        return original(self)

    cls.build_middleware_stack = build_middleware_stack


def _patch_starlette(module: Any) -> None:
    cls = getattr(module, "Starlette", None)
    if cls is not None:
        _wrap_stack(cls, "starlette")


def _patch_fastapi(module: Any) -> None:
    cls = getattr(module, "FastAPI", None)
    if cls is not None:
        _wrap_stack(cls, "fastapi")


def _patch_django(module: Any) -> None:
    cls = getattr(module, "BaseHandler", None)
    if cls is None or not _mark(cls):
        return
    original = cls.load_middleware

    @functools.wraps(original)
    def load_middleware(self, *args, **kwargs):
        try:
            from django.conf import settings  # pylint: disable=import-outside-toplevel

            current = list(getattr(settings, "MIDDLEWARE", None) or [])
            if _DJANGO_MIDDLEWARE not in current:
                settings.MIDDLEWARE = [_DJANGO_MIDDLEWARE, *current]
        except Exception:  # pylint: disable=broad-exception-caught
            logger.debug("Shield360 RASP: could not add the Django middleware", exc_info=True)
        return original(self, *args, **kwargs)

    cls.load_middleware = load_middleware


_TARGETS: Dict[str, Callable[[Any], None]] = {
    "flask.app": _patch_flask,
    "starlette.applications": _patch_starlette,
    "fastapi.applications": _patch_fastapi,
    "django.core.handlers.base": _patch_django,
}


def _apply(name: str, module: Any) -> None:
    try:
        _TARGETS[name](module)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.debug("Shield360 RASP: could not patch %s", name, exc_info=True)


class _Loader(importlib.abc.Loader):
    """Delegates to the real loader and patches the module once it has run."""

    def __init__(self, loader: Any, name: str):
        self._loader = loader
        self._name = name

    def create_module(self, spec):
        create = getattr(self._loader, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module):
        self._loader.exec_module(module)
        _apply(self._name, module)

    def __getattr__(self, attr):
        return getattr(self._loader, attr)


class _Finder(importlib.abc.MetaPathFinder):
    """Finds the framework modules through the other finders and wraps their loader."""

    def find_spec(self, fullname: str, path: Optional[Sequence[str]], target: Any = None):
        if fullname not in _TARGETS:
            return None
        for finder in sys.meta_path:
            if finder is self:
                continue
            find = getattr(finder, "find_spec", None)
            if find is None:
                continue
            try:
                spec = find(fullname, path, target)
            except Exception:  # pylint: disable=broad-exception-caught
                continue
            if spec is None:
                continue
            if spec.loader is not None and hasattr(spec.loader, "exec_module"):
                spec.loader = _Loader(spec.loader, fullname)
            return spec
        return None


def install() -> bool:
    """Adds the import hook (once) and patches frameworks already imported. Never raises."""
    try:
        with _lock:
            if _state["finder"] is None:
                finder = _Finder()
                sys.meta_path.insert(0, finder)
                _state["finder"] = finder
        for name in _TARGETS:
            module = sys.modules.get(name)
            if module is not None:
                _apply(name, module)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def uninstall() -> None:
    """Removes the import hook (tests). Frameworks already patched stay patched."""
    with _lock:
        finder = _state["finder"]
        _state["finder"] = None
    if finder is not None and finder in sys.meta_path:
        sys.meta_path.remove(finder)
