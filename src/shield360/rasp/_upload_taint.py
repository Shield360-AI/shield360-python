"""Backdoor checks (sdk/rasp/README.md "Uploads", "Backdoor checks"): where
uploaded files were saved, per process and in memory only (resolved paths, at
most 10,000, each kept 24 hours), and the checks that fire when the app saves
one somewhere executable or served, loads it as code, runs it, makes it
executable or extracts it with a traversal. Nothing here touches the file
system; the hooks call in before the call they guard."""

from __future__ import annotations

import os
import re
import shlex
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence

from shield360.rasp._context import current_context
from shield360.rasp._detect import resolve_path, target_directory
from shield360.rasp._types import Finding
from shield360.rasp._upload_inspect import UploadVerdict, base_name, is_active_content, is_executable_name
from shield360.rasp._upload_policy import is_served

MAX_LOCATIONS = 10_000
LOCATION_TTL_S = 24 * 60 * 60

_lock = threading.Lock()
_locations: "OrderedDict[str, tuple]" = OrderedDict()
_clock = time.monotonic


def reset_locations(clock: Any = time.monotonic) -> None:
    """Tests only."""
    global _clock  # pylint: disable=global-statement
    with _lock:
        _locations.clear()
    _clock = clock


def location_count() -> int:
    return len(_locations)


def remember_location(path: str, verdict: UploadVerdict) -> str:
    resolved = resolve_path(path)
    with _lock:
        _locations.pop(resolved, None)
        if len(_locations) >= MAX_LOCATIONS:
            now = _clock()
            for k in [k for k, (_, until) in _locations.items() if until <= now]:
                del _locations[k]
            while len(_locations) >= MAX_LOCATIONS:
                _locations.popitem(last=False)
        _locations[resolved] = (verdict, _clock() + LOCATION_TTL_S)
    return resolved


def upload_at(path: Any) -> Optional[UploadVerdict]:
    if not _locations or not isinstance(path, str) or not path:
        return None
    resolved = resolve_path(path)
    with _lock:
        hit = _locations.get(resolved)
        if hit is None:
            return None
        if hit[1] <= _clock():
            del _locations[resolved]
            return None
        return hit[0]


def locations_of(v: UploadVerdict) -> List[str]:
    with _lock:
        return [k for k, (lv, _) in _locations.items() if lv is v or (v.sha256 and lv.sha256 == v.sha256)]


def forget_location(path: str) -> None:
    with _lock:
        _locations.pop(resolve_path(path), None)


def sanitized_name(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", name.lower())


def upload_named(path: str) -> Optional[UploadVerdict]:
    """The upload of the current request a write is named after (as sent, or sanitized)."""
    ctx = current_context()
    uploads = getattr(ctx, "uploads", None) if ctx is not None else None
    if not uploads:
        return None
    name = base_name(path)
    for u in uploads:
        n = base_name(u["name"].replace("\\", "/")) if u.get("name") else ""
        if n and (n == name or sanitized_name(n) == name):
            return u["verdict"]
    return None


def _finding(rule: str, v: UploadVerdict, dest: Optional[str] = None) -> Finding:
    upload: Dict[str, Any] = {"type": v.type, "kind": v.kind, "ext": v.ext, "size": v.size, "sha256": v.sha256}
    if dest:
        upload["dest"] = dest
    return Finding(attack="upload_backdoor", rule=rule, upload=upload)


def check_new_location(path: str, verdict: UploadVerdict) -> Optional[Finding]:
    """A new location of an upload: remembered and checked."""
    resolved = remember_location(path, verdict)
    dest = target_directory(resolved)
    if is_executable_name(resolved):
        return _finding("backdoor.write_executable", verdict, dest)
    if is_served(resolved) and is_active_content(verdict):
        return _finding("backdoor.write_served", verdict, dest)
    return None


def detect_upload_write(path: Optional[str], source: Optional[str] = None) -> Optional[Finding]:
    """A write, or the destination of a rename, copy or move."""
    if not path:
        return None
    v = (upload_at(source) if source else None) or upload_named(path)
    return check_new_location(path, v) if v is not None else None


def detect_upload_include(path: Any) -> Optional[Finding]:
    v = upload_at(path) if isinstance(path, str) else None
    return _finding("backdoor.include", v, target_directory(resolve_path(path))) if v is not None else None


_INTERPRETER = re.compile(r"(sh|bash|zsh|dash|ksh|python[0-9.]*|node|nodejs|perl|php[0-9.]*|ruby|cmd|powershell|pwsh)(\.exe)?", re.IGNORECASE)


def detect_upload_exec(argv: Sequence[str]) -> Optional[Finding]:
    if not _locations or not argv:
        return None
    candidates = [argv[0]]
    if _INTERPRETER.fullmatch(base_name(str(argv[0]).replace("\\", "/"))):
        script = next((a for a in argv[1:] if not str(a).startswith("-")), None)
        if script:
            candidates.append(script)
    for c in candidates:
        v = upload_at(str(c))
        if v is not None:
            return _finding("backdoor.exec", v, target_directory(resolve_path(str(c))))
    return None


def command_words(command: str) -> List[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def detect_upload_chmod(path: Any, mode: Any) -> Optional[Finding]:
    if not isinstance(path, (str, os.PathLike)) or not _locations:
        return None
    if not isinstance(mode, int) or isinstance(mode, bool) or not mode & 0o111:
        return None
    p = os.fspath(path)
    v = upload_at(p)
    return _finding("backdoor.chmod", v, target_directory(resolve_path(p))) if v is not None else None


def detect_upload_extract(archive: Any, escapes: bool) -> Optional[Finding]:
    """``backdoor.extract``: a known location extracted while an entry leaves the target directory."""
    if not escapes or not isinstance(archive, (str, os.PathLike)):
        return None
    p = os.fspath(archive)
    v = upload_at(p)
    return _finding("backdoor.extract", v, target_directory(resolve_path(p))) if v is not None else None
