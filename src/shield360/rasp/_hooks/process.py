"""Process sink hook (README "Command"): every way the app starts a process
is checked before the process starts.

- ``subprocess.Popen`` (its ``__init__``), so ``run``, ``call``,
  ``check_call``, ``check_output``, ``getoutput`` and asyncio's subprocesses,
  all built on it, are checked once. ``shell=True`` goes through the command
  checks and ``shell_spawn``; an argv goes through the argv checks, the
  script of ``sh -c <script>``, and ``shell_spawn``.
- ``os.system`` and ``os.popen`` (shell command lines).
- ``os.exec*``, ``os.spawn*`` and ``os.posix_spawn[p]`` (argvs). The ``l``
  forms call the ``v`` forms inside; those inner calls are part of the outer
  one and are not checked again.

A function an app took out of its module before install (``from os import
system`` at import time) is not covered: initialize Shield360 before the
app's modules load. Fail open: anything that goes wrong in the hook lets the
call through, and Python validates its own arguments as before.
"""

from __future__ import annotations

import inspect
import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from shield360.rasp import _detect
from shield360.rasp._context import current_context, inputs_of
from shield360.rasp._engine import allow_lists
from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Depth, Entry, argument, restore, run_check, strongest, wrap_call
from shield360.rasp._types import Finding, RaspInput

_TAG = "rasp.process"
_depth = Depth()
_entries: List[Entry] = []
_installed = False

# (name, index of the program, how the argv is given): "v" a sequence after
# the program, "l" the remaining positional arguments, "le" the same less a
# trailing environment.
_OS_ARGV_APIS: Tuple[Tuple[str, int, str], ...] = (
    ("execv", 0, "v"),
    ("execve", 0, "v"),
    ("execvp", 0, "v"),
    ("execvpe", 0, "v"),
    ("execl", 0, "l"),
    ("execlp", 0, "l"),
    ("execle", 0, "le"),
    ("execlpe", 0, "le"),
    ("spawnv", 1, "v"),
    ("spawnve", 1, "v"),
    ("spawnvp", 1, "v"),
    ("spawnvpe", 1, "v"),
    ("spawnl", 1, "l"),
    ("spawnlp", 1, "l"),
    ("spawnle", 1, "le"),
    ("spawnlpe", 1, "le"),
    ("posix_spawn", 0, "v"),
    ("posix_spawnp", 0, "v"),
)
OS_APIS: Tuple[str, ...] = ("system", "popen") + tuple(n for n, _, _ in _OS_ARGV_APIS)

Target = Dict[str, Union[str, List[str]]]


def _text(v: Any) -> Optional[str]:
    if isinstance(v, (str, bytes, os.PathLike)):
        try:
            return os.fsdecode(os.fspath(v))
        except (TypeError, ValueError):
            return None
    return None


def _argv(values: Any) -> Optional[List[str]]:
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        return None
    out = [_text(v) for v in values]
    return None if any(v is None for v in out) else out  # type: ignore[misc]


def popen_target(args: Any, shell: Any, executable: Any = None) -> Optional[Target]:
    """What ``Popen(args, shell=..., executable=...)`` is about to run, or
    None when the arguments are not ones Python accepts (it then raises its
    own error)."""
    if shell:
        single = _text(args)
        if single is not None:
            return {"command": single}
        seq = _argv(args)
        # With a sequence, the first item is the command line; the rest are the shell's own arguments.
        return {"command": seq[0]} if seq else None
    single = _text(args)
    argv = [single] if single is not None else _argv(args)
    if not argv:
        return None
    exe = _text(executable) if executable is not None else None
    return {"argv": [exe] + argv[1:] if exe else argv}


def os_target(api: str, args: Sequence[Any], kwargs: Dict[str, Any]) -> Optional[Target]:
    """What an ``os`` function call is about to run."""
    if api in ("system", "popen"):
        command = _text(argument(args, kwargs, 0, "command", "cmd"))
        return {"command": command} if command is not None else None
    for name, at, form in _OS_ARGV_APIS:
        if name != api:
            continue
        program = _text(argument(args, kwargs, at, "path", "file"))
        if program is None:
            return None
        if form == "v":
            given = _argv(argument(args, kwargs, at + 1, "argv", "args"))
        else:
            rest = list(args[at + 1 :])
            given = _argv(rest[:-1] if form == "le" else rest)
        if given is None:
            return None
        # The program runs; argv[0] is only its display name.
        return {"argv": [program] + given[1:]}
    return None


def process_findings(target: Target, inputs: Sequence[RaspInput], in_request: bool, allow: Sequence[str]) -> List[Finding]:
    """Every finding of the contract's command checks for one target, in the contract's order."""
    if "command" in target:
        command = str(target["command"])
        found = [
            _detect.detect_command(command, inputs),
            _detect.detect_shell_spawn(command=command, in_request=in_request, allow=allow),
        ]
    else:
        argv = list(target["argv"])
        script = _detect.shell_script_of(argv)
        found = [_detect.detect_argv(argv, inputs)]
        if script:
            found += [
                _detect.detect_command(script, inputs),
                _detect.detect_shell_spawn(command=script, in_request=False, allow=allow),
            ]
        found.append(_detect.detect_shell_spawn(argv0=argv[0], in_request=in_request, allow=allow))
    return [f for f in found if f is not None]


def detect_process(target: Target, inputs: Sequence[RaspInput], in_request: bool, allow: Sequence[str]) -> Optional[Finding]:
    """The first finding of the contract's command checks for one target."""
    found = process_findings(target, inputs, in_request, allow)
    return found[0] if found else None


def _inspect(sink: str, target_of: Any) -> None:
    def run() -> Optional[Finding]:
        target = target_of()
        if not target:
            return None
        ctx = current_context()
        inputs = inputs_of(ctx) if ctx is not None else []
        # All of them, not the first: a command_injection set to off or monitor must not hide a shell_spawn that blocks.
        return strongest(*process_findings(target, inputs, bool(ctx is not None and ctx.in_request), allow_lists()["commands"]))

    run_check(sink, run)


_popen_signature: Any = None


def _popen_before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
    def target() -> Optional[Target]:
        bound = _popen_signature.bind_partial(None, *args, **kwargs).arguments if _popen_signature else {}
        return popen_target(bound.get("args"), bound.get("shell"), bound.get("executable"))

    _inspect("subprocess.Popen", target)


def _patch_subprocess(module: Any) -> None:
    global _popen_signature
    popen = getattr(module, "Popen", None)
    init = vars(popen).get("__init__") if isinstance(popen, type) else None
    if init is None:
        return
    try:
        _popen_signature = inspect.signature(init)
    except (TypeError, ValueError):
        _popen_signature = None
    entry = wrap_call(popen, "__init__", _popen_before, depth=_depth)
    if entry is not None and entry not in _entries:
        _entries.append(entry)


def _patch_os(module: Any) -> None:
    for api in OS_APIS:

        def before(args: Sequence[Any], kwargs: Dict[str, Any], api: str = api) -> None:
            _inspect(f"os.{api}", lambda: os_target(api, args, kwargs))

        entry = wrap_call(module, api, before, depth=_depth)
        if entry is not None and entry not in _entries:
            _entries.append(entry)


def install_process_hooks() -> bool:
    """Wraps ``subprocess.Popen`` (when the app imports subprocess) and the
    ``os`` process functions. Idempotent; never raises."""
    global _installed
    if _installed:
        return True
    try:
        _installed = True
        _patch_os(sys.modules.get("os", os))
        _imports.when_imported("subprocess", _TAG, _patch_subprocess)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_process_hooks()
        return False


def uninstall_process_hooks() -> None:
    """Switches every wrapper off and puts the originals back where RASP's wrapper is on top. Idempotent."""
    global _installed
    _installed = False
    _imports.forget(_TAG)
    for entry in reversed(_entries):
        restore(entry)
    _entries.clear()
