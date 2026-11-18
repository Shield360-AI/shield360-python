"""The checks every RASP sink hook must pass, whoever wrote it. The hooks'
own tests cover what each sink detects; this kit covers how a hook sits in
the process: install once, restore exactly, keep the replaced functions'
shape, check a call once, fail open, stay quiet when RASP is off, and live
alongside another wrapper (OpenTelemetry tracing wraps the same functions)
in either order.

Each hook supplies a harmless trigger: a call its detector flags under the
given inputs, safe to run when RASP only reports.

Python port of sdk/typescript/src/rasp/__tests__/hook-kit.ts.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from shield360.rasp._context import RaspContext, reset_context, set_context
from shield360.rasp._engine import configure_engine, set_event_sink
from shield360.rasp._types import RaspBlockedError, RaspInput

_MISSING = object()

Target = Tuple[Any, str]


@dataclass
class HookSpec:  # pylint: disable=too-many-instance-attributes
    name: str
    install: Callable[[], bool]
    uninstall: Callable[[], None]
    # Attributes the hook replaces (owner, name).
    replaced: List[Target]
    # A harmless call the hook flags under ``inputs``. May return, raise or return a coroutine.
    trigger: Callable[[], Any]
    inputs: List[RaspInput]
    # The detector the trigger goes through (module, function name), to make it fail.
    detector: Tuple[Any, str]
    attack: str
    # The attribute the "wrapper on top" check wraps after install (default: the first replaced).
    outer: Optional[Target] = None
    context: Dict[str, Any] = field(default_factory=dict)
    # Per-test setup and teardown the trigger needs (temp files, fake modules).
    before_each: Optional[Callable[[], Any]] = None
    after_each: Optional[Callable[[], Any]] = None


def req(value: str, key: str = "query.q") -> RaspInput:
    return RaspInput(value, key, "request")


def _raw(owner: Any, key: str) -> Any:
    return vars(owner).get(key, _MISSING)


def _shape(value: Any) -> Tuple[Any, Any, Any]:
    """What must not change about a replaced function: its name, qualified name and signature."""
    fn = value.__func__ if isinstance(value, (staticmethod, classmethod)) else value
    try:
        signature = str(inspect.signature(fn))
    except (TypeError, ValueError):
        signature = None
    return getattr(fn, "__name__", None), getattr(fn, "__qualname__", None), signature


def describe_hook_contract(spec: HookSpec) -> type:
    """A pytest test class with the kit's eight checks for one hook."""

    class Contract:
        events: List[Dict[str, Any]]

        def _mode(self, mode: str) -> None:
            if mode == "disabled":
                configure_engine(enabled=False, application_name="kit", env={})
            else:
                configure_engine(enabled=True, application_name="kit", mode=mode, env={})
            events = self.events

            class Sink:
                def add(self, event: Dict[str, Any], fold_key: str) -> None:  # pylint: disable=unused-argument
                    events.append(event)

            set_event_sink(Sink())

        def _ours(self) -> List[Dict[str, Any]]:
            return [e for e in self.events if e["attrs"]["shield360.rasp.attack"] == spec.attack]

        def _fire(self) -> Tuple[bool, Optional[BaseException]]:
            ctx = RaspContext(inputs=list(spec.inputs), in_request=True, **spec.context)

            async def in_task() -> Any:
                token = set_context(ctx)
                try:
                    out = spec.trigger()
                    if inspect.isawaitable(out):
                        out = await out
                    return out
                finally:
                    reset_context(token)

            try:
                if inspect.iscoroutinefunction(spec.trigger):
                    asyncio.run(in_task())
                else:
                    token = set_context(ctx)
                    try:
                        spec.trigger()
                    finally:
                        reset_context(token)
                return False, None
            except RaspBlockedError as e:
                return True, e
            except Exception as e:  # pylint: disable=broad-exception-caught
                return False, e

        def setup_method(self) -> None:
            self.events = []
            self._mode("block")
            if spec.before_each:
                spec.before_each()

        def teardown_method(self) -> None:
            spec.uninstall()
            set_event_sink(None)
            configure_engine(enabled=False, application_name="default", env={})
            if spec.after_each:
                spec.after_each()

        def test_installs_and_installing_again_changes_nothing(self) -> None:
            assert spec.install() is True
            first = [_raw(o, k) for o, k in spec.replaced]
            assert spec.install() is True
            assert all(a is b for a, b in zip(first, [_raw(o, k) for o, k in spec.replaced]))

        def test_keeps_the_shape_of_what_it_replaces(self) -> None:
            before = [(o, k, _raw(o, k)) for o, k in spec.replaced]
            spec.install()
            for owner, key, original in before:
                now = _raw(owner, key)
                assert now is not original, f"{key} was not replaced"
                assert _shape(now) == _shape(original), key

        def test_uninstall_restores_exactly_and_twice_is_harmless(self) -> None:
            before = [(o, k, _raw(o, k)) for o, k in spec.replaced]
            spec.install()
            spec.uninstall()
            spec.uninstall()
            for owner, key, original in before:
                assert _raw(owner, key) is original, key

        def test_block_refuses_the_trigger_and_reports_once(self) -> None:
            spec.install()
            blocked, error = self._fire()
            assert blocked, error
            assert len(self._ours()) == 1
            assert self._ours()[0]["attrs"]["shield360.rasp.decision"] == "blocked"

        def test_monitor_lets_the_trigger_through_and_reports_exactly_once(self) -> None:
            self._mode("monitor")
            spec.install()
            blocked, _ = self._fire()
            assert not blocked
            assert len(self._ours()) == 1
            assert self._ours()[0]["attrs"]["shield360.rasp.decision"] == "monitored"

        def test_rasp_off_checks_and_reports_nothing(self, monkeypatch: Any) -> None:
            self._mode("disabled")
            calls: List[Any] = []
            module, name = spec.detector
            real = getattr(module, name)

            def spy(*args: Any, **kwargs: Any) -> Any:
                calls.append(args)
                return real(*args, **kwargs)

            monkeypatch.setattr(module, name, spy)
            spec.install()
            blocked, _ = self._fire()
            assert not blocked
            assert not calls
            assert not self.events

        def test_fails_open_when_the_detector_fails(self, monkeypatch: Any) -> None:
            module, name = spec.detector

            def broken(*args: Any, **kwargs: Any) -> Any:
                raise RuntimeError("detector unavailable")

            monkeypatch.setattr(module, name, broken)
            spec.install()
            blocked, _ = self._fire()
            assert not blocked
            assert not self.events

        def test_lives_alongside_a_wrapper_put_on_top_of_it(self) -> None:
            owner, key = spec.outer or spec.replaced[0]
            original = _raw(owner, key)
            spec.install()
            inner = _raw(owner, key)
            fn = inner.__func__ if isinstance(inner, (staticmethod, classmethod)) else inner

            # Shaped like a tracing wrapper: a plain function calling what it found.
            def outer(*args: Any, **kwargs: Any) -> Any:
                return fn(*args, **kwargs)

            placed: Any = staticmethod(outer) if isinstance(inner, staticmethod) else outer
            setattr(owner, key, placed)
            try:
                assert self._fire()[0] is True
                spec.uninstall()
                # Uninstall must not tear the outer wrapper off, and what is left must not check.
                assert _raw(owner, key) is placed
                self.events.clear()
                assert self._fire()[0] is False
                assert not self.events
            finally:
                setattr(owner, key, original)
                spec.uninstall()

    Contract.__name__ = Contract.__qualname__ = f"TestHookContract_{spec.name}"
    return Contract


def names(owner: Any, keys: Sequence[str]) -> List[Target]:
    """The (owner, name) targets among ``keys`` the owner actually has (platform differences)."""
    return [(owner, k) for k in keys if k in vars(owner)]


# ---- helpers the hooks' own tests share ----------------------------------------


class Events(list):
    """An event sink collecting what the engine reports."""

    def add(self, event: Dict[str, Any], fold_key: str) -> None:  # pylint: disable=unused-argument
        self.append(event)

    def attacks(self) -> List[Tuple[str, str, str]]:
        return [
            (e["attrs"]["shield360.rasp.attack"], e["attrs"]["shield360.rasp.rule"], e["attrs"]["shield360.rasp.decision"])
            for e in self
        ]

    def sinks(self) -> List[str]:
        return [e["attrs"]["shield360.rasp.sink"] for e in self]


def use_engine(mode: str = "block", **options: Any) -> Events:
    """Turns RASP on in ``mode`` (``attacks``, ``allow`` as for configure_engine) and returns the event list."""
    configure_engine(enabled=True, application_name="hooks", mode=mode, env={}, **options)
    events = Events()
    set_event_sink(events)
    return events


def stop_engine() -> None:
    set_event_sink(None)
    configure_engine(enabled=False, application_name="default", env={})


def in_request(inputs: Sequence[Any], fn: Callable[[], Any], **context: Any) -> Any:
    """Runs ``fn`` in a request context holding ``inputs`` (strings become query inputs)."""
    items = [i if isinstance(i, RaspInput) else req(i) for i in inputs]
    token = set_context(RaspContext(inputs=items, in_request=True, **context))
    try:
        return fn()
    finally:
        reset_context(token)
