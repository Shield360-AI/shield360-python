"""Upload hooks (sdk/rasp/README.md "Uploads"): where the SDK sees uploaded
files and where they are extracted.

- Werkzeug/Flask: ``FormDataParser.parse`` (every ``FileStorage`` is
  inspected when the form is parsed) and ``FileStorage.save`` (the saved
  location, checked before the write).
- Django: ``MultiPartParser.parse`` (every ``UploadedFile``; a temporary
  file's path is a known location).
- Starlette/FastAPI: ``MultiPartParser.parse`` (every ``UploadFile``).
- Extraction: ``zipfile.ZipFile.extract``/``extractall``,
  ``tarfile.TarFile.extract``/``extractall`` and ``shutil.unpack_archive`` of
  a known location (``backdoor.extract``).

Libraries are patched when the app imports them. Fail open: a hook that
cannot read a file lets it through; only the block error is raised."""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional, Sequence

from shield360.rasp._hooks import _imports
from shield360.rasp._hooks._wrap import Entry, argument, restore, run_check, wrap, wrap_call
from shield360.rasp._types import RaspBlockedError
from shield360.rasp._upload import inspect_file_object, saved_to, verdict_for
from shield360.rasp._upload_inspect import entry_escapes
from shield360.rasp._upload_taint import detect_upload_extract, upload_at

_TAG = "rasp.uploads"
_entries: List[Entry] = []
_installed = False


def _add(e: Optional[Entry]) -> None:
    if e is not None and e not in _entries:
        _entries.append(e)


def _each_file(files: Any) -> Sequence[tuple]:
    """(field, file) pairs of a Werkzeug/Django MultiDict or a Starlette FormData."""
    out: List[tuple] = []
    try:
        items = files.multi_items() if hasattr(files, "multi_items") else files.lists() if hasattr(files, "lists") else files.items(multi=True) if hasattr(files, "items") else []
        for k, v in items:
            for f in v if isinstance(v, list) else [v]:
                out.append((str(k), f))
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    return out[:32]


def _inspect(field: str, f: Any) -> None:
    name = getattr(f, "filename", None) or getattr(f, "name", None)
    ctype = getattr(f, "content_type", None) or getattr(f, "mimetype", None)
    temp = None
    tfp = getattr(f, "temporary_file_path", None)
    if callable(tfp):
        try:
            temp = tfp()
        except Exception:  # pylint: disable=broad-exception-caught
            temp = None
    stream = getattr(f, "stream", None) or getattr(f, "file", None) or f
    try:
        v = inspect_file_object(field, name if isinstance(name, str) else None, ctype if isinstance(ctype, str) else None, stream, temp)
    except RaspBlockedError:
        raise
    except Exception:  # pylint: disable=broad-exception-caught
        return
    if v is not None:
        try:
            setattr(f, "_shield360_upload", v)
        except Exception:  # pylint: disable=broad-exception-caught
            pass


def _wrap_result(owner: Any, key: str, files_of: Callable[[Any], Any]) -> None:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        import inspect as _inspect_mod  # pylint: disable=import-outside-toplevel

        if _inspect_mod.iscoroutinefunction(fn):

            async def parsed_async(*args: Any, **kwargs: Any) -> Any:
                result = await fn(*args, **kwargs)
                if entry.on:
                    for field, f in _each_file(files_of(result)):
                        if not isinstance(f, str):
                            _inspect(field, f)
                return result

            return parsed_async

        def parsed(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            if entry.on:
                for field, f in _each_file(files_of(result)):
                    if not isinstance(f, str):
                        _inspect(field, f)
            return result

        return parsed

    _add(wrap(owner, key, build, _TAG))


def _patch_werkzeug_formparser(module: Any) -> None:
    parser = getattr(module, "FormDataParser", None)
    if isinstance(parser, type):
        _wrap_result(parser, "parse", lambda r: r[2] if isinstance(r, tuple) and len(r) == 3 else None)


def _patch_werkzeug_datastructures(module: Any) -> None:
    fs = getattr(module, "FileStorage", None)
    if not isinstance(fs, type):
        return

    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def save(self: Any, dst: Any, *args: Any, **kwargs: Any) -> Any:
            if entry.on and isinstance(dst, (str, os.PathLike)):
                v = verdict_for(self)
                if v is None:
                    _inspect(getattr(self, "name", None) or "file", self)
                    v = verdict_for(self)
                if v is not None:
                    try:
                        saved_to(os.fspath(dst), v)
                    except RaspBlockedError:
                        raise
                    except Exception:  # pylint: disable=broad-exception-caught
                        pass
            return fn(self, dst, *args, **kwargs)

        return save

    _add(wrap(fs, "save", build, _TAG))


def _patch_django(module: Any) -> None:
    parser = getattr(module, "MultiPartParser", None)
    if isinstance(parser, type):
        _wrap_result(parser, "parse", lambda r: r[1] if isinstance(r, tuple) and len(r) == 2 else None)


def _patch_starlette(module: Any) -> None:
    parser = getattr(module, "MultiPartParser", None)
    if isinstance(parser, type):
        _wrap_result(parser, "parse", lambda r: r)


# ---- extraction ---------------------------------------------------------------------


def _zip_escapes(z: Any) -> bool:
    try:
        return any(entry_escapes(n) for n in z.namelist())
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _tar_escapes(t: Any) -> bool:
    try:
        return any(entry_escapes(m.name) or m.issym() or m.islnk() for m in t.getmembers())
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def _archive_hook(kind: str) -> Callable[..., Any]:
    def build(fn: Callable[..., Any], entry: Entry) -> Callable[..., Any]:
        def extract(self: Any, *args: Any, **kwargs: Any) -> Any:
            if entry.on:
                path = getattr(self, "filename", None) if kind == "zip" else getattr(self, "name", None)
                if isinstance(path, (str, os.PathLike)) and upload_at(os.fspath(path)) is not None:
                    escapes = _zip_escapes(self) if kind == "zip" else _tar_escapes(self)
                    run_check(f"{kind}file.extract", lambda: detect_upload_extract(path, escapes))
            return fn(self, *args, **kwargs)

        return extract

    return build


def _patch_zipfile(module: Any) -> None:
    for key in ("extract", "extractall"):
        _add(wrap(module.ZipFile, key, _archive_hook("zip"), _TAG))


def _patch_tarfile(module: Any) -> None:
    for key in ("extract", "extractall"):
        _add(wrap(module.TarFile, key, _archive_hook("tar"), _TAG))


def _unpack_before(args: Sequence[Any], kwargs: Dict[str, Any]) -> None:
    archive = argument(args, kwargs, 0, "filename")
    if not isinstance(archive, (str, os.PathLike)) or upload_at(os.fspath(archive)) is None:
        return
    p = os.fspath(archive)
    escapes = False
    try:
        import tarfile  # pylint: disable=import-outside-toplevel
        import zipfile  # pylint: disable=import-outside-toplevel

        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as z:
                escapes = _zip_escapes(z)
        elif tarfile.is_tarfile(p):
            with tarfile.open(p) as t:
                escapes = _tar_escapes(t)
    except Exception:  # pylint: disable=broad-exception-caught
        escapes = False
    run_check("shutil.unpack_archive", lambda: detect_upload_extract(p, escapes))


def _patch_shutil(module: Any) -> None:
    _add(wrap_call(module, "unpack_archive", _unpack_before, tag=_TAG))


def install_upload_hooks() -> bool:
    """Patches the parsers and archive functions when the app imports them. Idempotent; never raises."""
    global _installed  # pylint: disable=global-statement
    if _installed:
        return True
    try:
        _installed = True
        _imports.when_imported("werkzeug.formparser", _TAG, _patch_werkzeug_formparser)
        _imports.when_imported("werkzeug.datastructures", _TAG, _patch_werkzeug_datastructures)
        _imports.when_imported("django.http.multipartparser", _TAG, _patch_django)
        _imports.when_imported("starlette.formparsers", _TAG, _patch_starlette)
        _imports.when_imported("zipfile", _TAG, _patch_zipfile)
        _imports.when_imported("tarfile", _TAG, _patch_tarfile)
        _imports.when_imported("shutil", _TAG, _patch_shutil)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        uninstall_upload_hooks()
        return False


def uninstall_upload_hooks() -> None:
    global _installed  # pylint: disable=global-statement
    _installed = False
    _imports.forget(_TAG)
    for e in reversed(_entries):
        restore(e)
    _entries.clear()
