"""Deep scan (sdk/rasp/README.md "Uploads", "Upload policy and deep scan",
"Scanner status"): the customer's own ClamAV (clamd over a Unix socket or TCP)
and the hash reputation lookup, both opt-in and off by default. Files are
scanned where the app runs; the platform never receives a file, only a hash
when reputation is on. Every engine call is bounded by the deep scan's timeout
and an engine that cannot answer is reported, never silent."""

from __future__ import annotations

import builtins
import json
import os
import re
import shutil
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from shield360.rasp._engine import report_record
from shield360.rasp._upload_inspect import UploadFinding
from shield360.rasp._upload_policy import DeepScan, quarantine_dir

# Captured at import, before the file hooks, so the SDK's own reads never trip RASP.
_open = builtins.open
_rename = os.rename
_chmod = os.chmod
_makedirs = os.makedirs
_copyfile = shutil.copyfile
_unlink = os.unlink

SCANNER_EVENT = "shield360.rasp.scanner"
CHUNK = 64 * 1024
_CLAM_NAME = re.compile(r"[A-Za-z0-9._:/-]{1,128}")


class EngineError(Exception):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


def _connect(address: tuple, timeout: float) -> socket.socket:
    try:
        if address[0] == "unix":
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect(address[1])
        else:
            s = socket.create_connection((address[1], address[2]), timeout=timeout)
            s.settimeout(timeout)
        return s
    except socket.timeout as e:
        raise EngineError("timeout") from e
    except OSError as e:
        raise EngineError("unreachable") from e


def _reply(s: socket.socket, deadline: float) -> str:
    buf = b""
    while b"\x00" not in buf and len(buf) < 4096:
        s.settimeout(max(0.001, deadline - time.monotonic()))
        d = s.recv(4096)
        if not d:
            break
        buf += d
    return buf.split(b"\x00")[0].decode("latin-1").strip()


def clam_scan(address: tuple, source: Any, timeout_ms: int) -> Optional[str]:
    """clamd ``zINSTREAM``: None when clean, the signature name when found; raises EngineError otherwise.
    ``source`` is bytes or a path."""
    deadline = time.monotonic() + timeout_ms / 1000
    s = _connect(address, timeout_ms / 1000)
    try:
        s.sendall(b"zINSTREAM\x00")
        if isinstance(source, (bytes, bytearray, memoryview)):
            data = bytes(source)
            for i in range(0, len(data), CHUNK):
                part = data[i : i + CHUNK]
                s.sendall(struct.pack(">I", len(part)) + part)
        else:
            with _open(source, "rb") as f:
                while True:
                    part = f.read(CHUNK)
                    if not part:
                        break
                    s.sendall(struct.pack(">I", len(part)) + part)
        s.sendall(b"\x00\x00\x00\x00")
        reply = _reply(s, deadline)
    except socket.timeout as e:
        raise EngineError("timeout") from e
    except OSError as e:
        raise EngineError("error") from e
    finally:
        s.close()
    if re.search(r":\s*OK\Z", reply):
        return None
    m = re.search(r":\s*(.+?)\s+FOUND\Z", reply)
    if m:
        return m.group(1) if _CLAM_NAME.fullmatch(m.group(1)) else "unnamed"
    raise EngineError("error")


def clam_ping(address: tuple, timeout_ms: int) -> bool:
    deadline = time.monotonic() + timeout_ms / 1000
    s = _connect(address, timeout_ms / 1000)
    try:
        s.sendall(b"zPING\x00")
        return _reply(s, deadline) == "PONG"
    except socket.timeout as e:
        raise EngineError("timeout") from e
    except OSError as e:
        raise EngineError("error") from e
    finally:
        s.close()


# ---- reputation ---------------------------------------------------------------

_reputation: Dict[str, Any] = {"url": None, "api_key": None}
_cache: "OrderedDict[str, Tuple[str, float]]" = OrderedDict()
_CACHE_TTL = 3600.0
_CACHE_MAX = 1000


def set_reputation_client(url: Optional[str], api_key: Optional[str]) -> None:
    _reputation["url"], _reputation["api_key"] = url, api_key
    _cache.clear()


def reputation_of(sha256: str, timeout_ms: int) -> str:
    """Asks the platform about a hash (only the hash leaves the app); raises EngineError when it cannot answer."""
    hit = _cache.get(sha256)
    if hit and hit[1] > time.monotonic():
        return hit[0]
    url, key = _reputation["url"], _reputation["api_key"]
    if not url or not key:
        raise EngineError("unreachable")
    req = urllib.request.Request(
        url.rstrip("/") + "/api/rasp/upload-reputation",
        data=json.dumps({"sha256": sha256}).encode(),
        headers={"authorization": f"Bearer {key}", "content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as res:  # noqa: S310 — the configured Shield360 URL
            body = json.loads(res.read(65536) or b"null")
    except socket.timeout as e:
        raise EngineError("timeout") from e
    except urllib.error.HTTPError as e:
        raise EngineError("error") from e
    except (urllib.error.URLError, OSError) as e:
        raise EngineError("timeout" if "timed out" in str(e) else "unreachable") from e
    except ValueError as e:
        raise EngineError("error") from e
    v = body.get("verdict") if isinstance(body, dict) else None
    verdict = v if v in ("malicious", "suspicious", "clean") else "unknown"
    if len(_cache) >= _CACHE_MAX:
        _cache.popitem(last=False)
    _cache[sha256] = (verdict, time.monotonic() + _CACHE_TTL)
    return verdict


# ---- status ---------------------------------------------------------------------

_status_lock = threading.Lock()
_states: Dict[str, Dict[str, Any]] = {}
_REPEAT_S = 300.0
_last_test: List[Optional[str]] = [None]


def reset_scanner_status() -> None:
    """Tests only."""
    with _status_lock:
        _states.clear()
    _last_test[0] = None
    _cache.clear()


def _send(engine: str, s: Dict[str, Any], test_id: Optional[str]) -> None:
    s["last_sent"] = time.monotonic()
    attrs = {
        "shield360.rasp.scanner.engine": engine,
        "shield360.rasp.scanner.status": s["status"],
        "shield360.rasp.scanner.fail_mode": s["fail_mode"],
        "shield360.rasp.scanner.since": datetime.fromtimestamp(s["since"], timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z"),
        "shield360.rasp.scanner.failures": str(s["failures"]),
    }
    if test_id:
        attrs["shield360.rasp.scanner.test_id"] = test_id
    report_record(SCANNER_EVENT, attrs)


def note_engine(engine: str, status: str, fail_mode: str, test_id: Optional[str] = None) -> None:
    """Reported when the status changes, every 5 minutes while it is not ok, and for each test."""
    with _status_lock:
        s = _states.get(engine)
        if s is None or s["status"] != status:
            s = {
                "status": status,
                "since": time.time(),
                "failures": 0 if status == "ok" else 1,
                "last_sent": 0.0,
                "fail_mode": fail_mode,
            }
            _states[engine] = s
            send = True
        else:
            s["fail_mode"] = fail_mode
            if status != "ok":
                s["failures"] += 1
            send = bool(test_id) or (status != "ok" and time.monotonic() - s["last_sent"] >= _REPEAT_S)
    if send:
        _send(engine, s, test_id)


def run_connection_test(d: DeepScan) -> None:
    """A new ``testId``: tests each engine once and reports with the id. Never raises."""
    if not d.test_id or d.test_id == _last_test[0]:
        return
    _last_test[0] = d.test_id
    if d.clamav:
        try:
            note_engine("clamav", "ok" if clam_ping(d.clamav, min(d.timeout_ms, 5000)) else "error", d.fail_mode, d.test_id)
        except EngineError as e:
            note_engine("clamav", e.status, d.fail_mode, d.test_id)
        except Exception:  # pylint: disable=broad-exception-caught
            note_engine("clamav", "error", d.fail_mode, d.test_id)
    if d.reputation:
        try:
            reputation_of("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", min(d.timeout_ms, 5000))
            note_engine("reputation", "ok", d.fail_mode, d.test_id)
        except EngineError as e:
            note_engine("reputation", e.status, d.fail_mode, d.test_id)


def deep_scan(d: DeepScan, source: Any, sha256: Optional[str]) -> Tuple[Optional[UploadFinding], List[str]]:
    """Runs the engines that are on within one timeout: (finding, engines that failed)."""
    failed: List[str] = []
    deadline = time.monotonic() + d.timeout_ms / 1000

    def left() -> int:
        return max(1, int((deadline - time.monotonic()) * 1000))

    if d.clamav:
        try:
            name = clam_scan(d.clamav, source, left())
            note_engine("clamav", "ok", d.fail_mode)
            if name:
                return UploadFinding("upload.malware", engine="clamav", signature=name), failed
        except EngineError as e:
            note_engine("clamav", e.status, d.fail_mode)
            failed.append("clamav")
        except Exception:  # pylint: disable=broad-exception-caught
            note_engine("clamav", "error", d.fail_mode)
            failed.append("clamav")
    if d.reputation and sha256:
        try:
            if reputation_of(sha256, left()) == "malicious":
                note_engine("reputation", "ok", d.fail_mode)
                return UploadFinding("upload.reputation", engine="reputation"), failed
            note_engine("reputation", "ok", d.fail_mode)
        except EngineError as e:
            note_engine("reputation", e.status, d.fail_mode)
            failed.append("reputation")
    return None, failed


def quarantine(path: str, sha256: Optional[str] = None) -> bool:
    """Moves a file to the quarantine directory (renamed to its hash, mode 0600). Never raises."""
    try:
        d = quarantine_dir()
        _makedirs(d, mode=0o700, exist_ok=True)
        target = os.path.join(d, f"{sha256 or 'upload-' + str(int(time.time() * 1000))}.quarantined")
        try:
            _rename(path, target)
        except OSError:
            _copyfile(path, target)
            _unlink(path)
        _chmod(target, 0o600)
        return True
    except Exception:  # pylint: disable=broad-exception-caught
        return False
