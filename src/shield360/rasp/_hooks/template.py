"""Template-source hooks (README "Template source", ``code.template_injection``).

Jinja2 ``Environment.from_string`` and ``Template(...)``, Mako
``Template(text=...)``, Django ``Template(...)`` and ``Engine.from_string``,
each patched only once the app imports the engine; nothing here imports one.
Only the source argument is checked, never data passed to ``render``.

One check per engine call: while a call runs, its source is on a per-thread
stack, so internal delegation (``Template(...)`` to ``from_string``,
``Engine.from_string`` to ``Template``) skips the inputs already judged in
that source, while other inputs are still checked. Django templates read by
a loader (``origin`` with a loader) are file-based and not checked. Custom
delimiters are outside coverage. Normal ``code_injection`` modes apply;
anything other than the block error fails open.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional, Sequence

from shield360.rasp import _engine, _template
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Entry, argument, restore, run_check, wrap
from shield360.rasp._types import RaspBlockedError, RaspInput

_TAG = "rasp.template"
_entries: List[Entry] = []
_installed = False
_local = threading.local()

SourceOf = Callable[[Sequence[Any], Dict[str, Any]], Any]


def _active() -> List[str]:
    """Template sources whose engine call is in progress on this thread (innermost last)."""
    stack = getattr(_local, "stack", None)
    if stack is None:
        stack = _local.stack = []
    return stack


def unjudged_inputs(inputs: Sequence[RaspInput]) -> List[RaspInput]:
    """Inputs an enclosing template call has not already judged. Internal
    delegation carries the same input, so it is checked once; an independent
    call with other input is still checked."""
    active = _active()
    if not active:
        return list(inputs)
    return [i for i in inputs if not any(i.value in source for source in active)]


def _source_text(source: Any) -> Optional[str]:
    if isinstance(source, str):
        return source
    if isinstance(source, (bytes, bytearray)):
        return bytes(source).decode("utf-8", "replace")
    return None


def _check(engine: str, sink: str, source: str) -> None:
    try:
        if not _engine.is_active() or _engine.mode_for("code_injection") == "off":
            return
        ctx = current_context()
        if ctx is None:
            return
        inputs = unjudged_inputs(inputs_of(ctx))
        if inputs:
            run_check(sink, lambda: _template.detect_template(source, inputs, engine))
    except RaspBlockedError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def _hook(owner: Any, key: str, engine: str, sink: str, source_of: SourceOf, skip: Optional[SourceOf] = None) -> None:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def checked(*args: Any, **kwargs: Any) -> Any:
            if not entry.on:
                return fn(*args, **kwargs)
            own = args[1:] if entry.bound else args
            try:
                source = None if skip is not None and skip(own, kwargs) else _source_text(source_of(own, kwargs))
            except Exception:  # pylint: disable=broad-exception-caught
                source = None
            if source is None:
                return fn(*args, **kwargs)
            _check(engine, sink, source)
            stack = _active()
            stack.append(source)
            try:
                return fn(*args, **kwargs)
            finally:
                stack.pop()

        return checked

    entry = wrap(owner, key, build, _TAG)
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _arg(index: int, *names: str) -> SourceOf:
    return lambda args, kwargs: argument(args, kwargs, index, *names)


def _patch_jinja2(module: Any) -> None:
    environment = getattr(module, "Environment", None)
    if isinstance(environment, type):
        _hook(environment, "from_string", "jinja2", "jinja2.from_string", _arg(0, "source"))
    template = getattr(module, "Template", None)
    if isinstance(template, type):
        # __new__ is a static method: its first argument is the class.
        _hook(template, "__new__", "jinja2", "jinja2.Template", _arg(1, "source"))


def _patch_mako(module: Any) -> None:
    template = getattr(module, "Template", None)
    if isinstance(template, type):
        _hook(template, "__init__", "mako", "mako.Template", _arg(0, "text"))


def _from_loader(args: Sequence[Any], kwargs: Dict[str, Any]) -> bool:
    """A Django template a loader read from a file (file-based rendering is not covered)."""
    return getattr(argument(args, kwargs, 1, "origin"), "loader", None) is not None


def _patch_django_base(module: Any) -> None:
    template = getattr(module, "Template", None)
    if isinstance(template, type):
        _hook(template, "__init__", "django", "django.Template", _arg(0, "template_string"), _from_loader)


def _patch_django_engine(module: Any) -> None:
    engine = getattr(module, "Engine", None)
    if isinstance(engine, type):
        _hook(engine, "from_string", "django", "django.from_string", _arg(0, "template_code"))


_PATCHES = (
    ("jinja2.environment", _patch_jinja2),
    ("mako.template", _patch_mako),
    ("django.template.base", _patch_django_base),
    ("django.template.engine", _patch_django_engine),
)


def install_template_hooks() -> bool:
    """Patches the template engines the app has loaded, and the others when it
    loads them. Idempotent; never raises."""
    global _installed
    if _installed:
        return True
    try:
        _installed = True
        for name, patch in _PATCHES:
            _imports.when_imported(name, _TAG, patch)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_template_hooks()
        return False


def uninstall_template_hooks() -> None:
    """Puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed
    _installed = False
    _imports.forget(_TAG)
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()
