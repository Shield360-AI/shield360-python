"""Uploads (sdk/rasp/README.md "Uploads"): turns what the inspector, the policy
and the deep scan say about an uploaded file into findings, events and blocks,
and remembers where the file was saved for the backdoor checks. The framework
hooks (``_hooks/uploads.py``) call in when Werkzeug, Django or Starlette parse a
multipart body, so the deep scan runs before the app gets the file (sync).

Fail open: anything that goes wrong lets the upload through; the only error
raised on purpose is the block error."""

from __future__ import annotations

import os
from dataclasses import replace
from typing import Any, Iterable, List, Optional

from shield360.rasp._context import RaspContext, current_context, event_route_of
from shield360.rasp._engine import handle_finding, is_active, would_block
from shield360.rasp._hooks._wrap import strongest
from shield360.rasp._types import Finding, RaspBlockedError, RaspInput
from shield360.rasp._upload_deep import deep_scan, quarantine
from shield360.rasp._upload_inspect import PIECE, TAIL, UploadFinding, UploadScanner, UploadVerdict, name_findings, rule_rank
from shield360.rasp._upload_policy import EffectivePolicy, effective_policy, scan_bytes, upload_config
from shield360.rasp._upload_taint import check_new_location, forget_location, locations_of, remember_location, upload_at

UPLOAD_SINK = "request.upload"
DEEP_SINK = "upload.deep_scan"
_DEEP_ENGINES = ("custom", "clamav", "reputation")


def _route(ctx: Optional[RaspContext]) -> Optional[str]:
    if ctx is None:
        return None
    return ctx.route or (event_route_of(ctx.path) if ctx.path else None)


def _scanner(name: Optional[str], content_type: Optional[str], policy: EffectivePolicy) -> UploadScanner:
    c = upload_config()
    return UploadScanner(name, content_type, scan_bytes=scan_bytes(), trusted=c.trusted, custom=c.rules if policy.deep_scan.mode != "off" else None)


def verdict_of_chunks(chunks: Iterable[bytes], name: Optional[str], content_type: Optional[str], policy: EffectivePolicy) -> UploadVerdict:
    s = _scanner(name, content_type, policy)
    for c in chunks:
        s.push(c)
    return s.finish(True)


def verdict_of_file(path: str, name: Optional[str], content_type: Optional[str], policy: EffectivePolicy) -> Optional[UploadVerdict]:
    """The first ``scan_bytes`` and the last 1 MiB; the whole file (and its hash) when it is no larger."""
    from shield360.rasp._upload_deep import _open  # the original open, before the file hooks

    try:
        size = os.path.getsize(path)
        s = _scanner(name, content_type, policy)
        limit = scan_bytes()
        whole = size <= limit + TAIL
        with _open(path, "rb") as f:
            if whole:
                while True:
                    b = f.read(PIECE)
                    if not b:
                        break
                    s.push(b)
            else:
                read = 0
                while read < limit:
                    b = f.read(min(PIECE, limit - read))
                    if not b:
                        break
                    s.push(b)
                    read += len(b)
                s.skip(size - TAIL - read)
                f.seek(size - TAIL)
                s.push(f.read(TAIL))
        return s.finish(whole)
    except OSError:
        return None


def verdict_of_stream(stream: Any, name: Optional[str], content_type: Optional[str], policy: EffectivePolicy) -> Optional[UploadVerdict]:
    """A seekable file object, read from its start and put back where it was."""
    try:
        pos = stream.tell()
        stream.seek(0)
        s = _scanner(name, content_type, policy)
        while True:
            b = stream.read(PIECE)
            if not b:
                break
            s.push(b if isinstance(b, bytes) else str(b).encode("utf-8"))
        stream.seek(pos)
        return s.finish(True)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def policy_findings(v: UploadVerdict, p: EffectivePolicy) -> List[UploadFinding]:
    out: List[UploadFinding] = []
    if p.allow and v.type not in p.allow and v.kind not in p.allow:
        out.append(UploadFinding("upload.type_not_allowed", engine="policy"))
    if p.max_bytes is not None and v.size > p.max_bytes:
        out.append(UploadFinding("upload.too_large", engine="policy"))
    return out


def upload_finding(f: UploadFinding, v: UploadVerdict, p: EffectivePolicy, field: str) -> Finding:
    deep = f.engine in _DEEP_ENGINES or f.rule == "upload.scan_unavailable"
    mode = p.deep_scan.mode if deep else p.mode
    return Finding(
        attack="malicious_upload",
        rule=f.rule,
        # A location, never a value: the name is not sent, even as a snippet.
        input=RaspInput("", f"body.{field}.filename", "request"),
        mode=mode,
        action="monitor" if f.capped else None,
        upload={"type": v.type, "kind": v.kind, "ext": v.ext, "size": v.size, "sha256": v.sha256, "signature": f.signature, "engine": f.engine},
    )


def _decide(ctx: Optional[RaspContext], finding: Finding, sink: str, saved: Optional[str] = None, sha: Optional[str] = None) -> None:
    try:
        if ctx is not None:
            handle_finding(finding, sink, framework=ctx.framework, route=ctx.route, method=ctx.method, path=ctx.path)
        else:
            handle_finding(finding, sink)
    except RaspBlockedError:
        if saved and quarantine(saved, sha):
            forget_location(saved)
        raise


def apply_upload(ctx: Optional[RaspContext], field: str, name: Optional[str], content_type: Optional[str], v: UploadVerdict, saved: Optional[str] = None, reported: bool = False) -> None:
    """Reports what one upload is (the strongest finding), records it on the request, checks its saved location."""
    policy = effective_policy(_route(ctx))
    if reported:
        found = name_findings(name or "", v.type, content_type)
    else:
        found = [f for f in v.findings if f.engine != "custom" or policy.deep_scan.mode != "off"] + policy_findings(v, policy)
    found.sort(key=lambda f: rule_rank(f.rule))
    if ctx is not None:
        ctx.uploads.append({"field": field, "name": name or "", "verdict": v})
    chosen = strongest(*(upload_finding(f, v, policy, field) for f in found))
    if chosen is not None:
        _decide(ctx, chosen, UPLOAD_SINK, saved, v.sha256)
    if saved:
        b = check_new_location(saved, v)
        if b is not None:
            _decide(ctx, b, UPLOAD_SINK, saved, v.sha256)


def deep_scan_on(p: EffectivePolicy) -> bool:
    return p.deep_scan.mode != "off" and bool(p.deep_scan.clamav or p.deep_scan.reputation)


def apply_deep_scan(ctx: Optional[RaspContext], field: str, v: UploadVerdict, source: Any, saved: Optional[str] = None, sync: Optional[bool] = None) -> None:
    """Runs the deep scan and applies it. Sync: raises the block error. Async: a blocking finding quarantines every saved copy."""
    policy = effective_policy(_route(ctx))
    if not deep_scan_on(policy) or (v.sha256 and v.sha256 in upload_config().trusted):
        return
    is_sync = policy.deep_scan.scan == "sync" if sync is None else sync
    f, failed = deep_scan(policy.deep_scan, source, v.sha256)
    if f is None and failed and policy.deep_scan.fail_mode == "closed":
        f = UploadFinding("upload.scan_unavailable", engine=failed[0])
    if f is None:
        return
    finding = upload_finding(f, v, policy, field)
    if is_sync:
        _decide(ctx, finding, DEEP_SINK, saved, v.sha256)
        return
    moved = False
    if would_block(finding):
        for p in {*([saved] if saved else []), *locations_of(v)}:
            if quarantine(p, v.sha256):
                forget_location(p)
                moved = True
    try:
        _decide(ctx, replace(finding, upload={**(finding.upload or {}), "action": "quarantined"}) if moved else finding, DEEP_SINK)
    except RaspBlockedError:
        pass


def inspect_upload(data: Any, name: Optional[str] = None, content_type: Optional[str] = None, field: str = "file") -> UploadVerdict:
    """Inspects an upload the app holds (bytes, a path or a seekable file
    object) and runs the deep scan (README ``inspect_upload``). Returns the
    verdict; raises the block error when the upload must be refused."""
    ctx = current_context()
    policy = effective_policy(_route(ctx))
    saved: Optional[str] = None
    if isinstance(data, (bytes, bytearray, memoryview)):
        source: Any = bytes(data)
        v: Optional[UploadVerdict] = verdict_of_chunks([source], name, content_type, policy)
    elif isinstance(data, (str, os.PathLike)):
        saved = os.fspath(data)
        source = saved
        v = verdict_of_file(saved, name, content_type, policy)
    else:
        v = verdict_of_stream(data, name, content_type, policy)
        source = _read_all(data)
    if v is None:
        raise ValueError("Shield360: the upload could not be read")
    if not is_active():
        return v
    apply_upload(ctx, field, name, content_type, v, saved)
    apply_deep_scan(ctx, field, v, source, saved)
    return v


def _read_all(stream: Any, cap: int = 256 * 1024 * 1024) -> bytes:
    """A file object's bytes for clamd (bounded), put back where it was."""
    try:
        pos = stream.tell()
        stream.seek(0)
        data = stream.read(cap)
        stream.seek(pos)
        return data if isinstance(data, bytes) else b""
    except Exception:  # pylint: disable=broad-exception-caught
        return b""


def inspect_file_object(field: str, name: Optional[str], content_type: Optional[str], stream: Any, temp_path: Optional[str] = None) -> Optional[UploadVerdict]:
    """A parser's file (Werkzeug FileStorage, Django UploadedFile, Starlette
    UploadFile): inspected, the deep scan held (sync) or scheduled. Raises the block error."""
    if not is_active():
        return None
    ctx = current_context()
    policy = effective_policy(_route(ctx))
    v = verdict_of_file(temp_path, name, content_type, policy) if temp_path else verdict_of_stream(stream, name, content_type, policy)
    if v is None:
        return None
    if temp_path:
        remember_location(temp_path, v)
    apply_upload(ctx, field, name, content_type, v)
    if deep_scan_on(policy):
        source = temp_path or _read_all(stream)
        if policy.deep_scan.scan == "sync":
            apply_deep_scan(ctx, field, v, source, temp_path, sync=True)
        else:
            import threading  # pylint: disable=import-outside-toplevel

            threading.Thread(target=_async_scan, args=(ctx, field, v, source, temp_path), daemon=True).start()
    return v


def _async_scan(ctx: Optional[RaspContext], field: str, v: UploadVerdict, source: Any, saved: Optional[str]) -> None:
    try:
        apply_deep_scan(ctx, field, v, source, saved, sync=False)
    except Exception:  # pylint: disable=broad-exception-caught
        pass


def saved_to(path: str, v: UploadVerdict) -> None:
    """A parser's file was saved (``FileStorage.save``): the new location is checked. Raises the block error."""
    f = check_new_location(path, v)
    if f is not None:
        _decide(current_context(), f, UPLOAD_SINK, path, v.sha256)


def verdict_for(obj: Any) -> Optional[UploadVerdict]:
    v = getattr(obj, "_shield360_upload", None)
    return v if isinstance(v, UploadVerdict) else None


__all__ = ["inspect_upload", "inspect_file_object", "apply_upload", "apply_deep_scan", "upload_at"]
