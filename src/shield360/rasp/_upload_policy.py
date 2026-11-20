"""Upload policy and deep scan settings (sdk/rasp/README.md "Uploads", "Upload
policy and deep scan"): the signed config's ``uploads`` block, else the local
options, and the policy that applies to a request's route."""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Mapping, Optional, Set

from shield360.rasp._upload_inspect import DEFAULT_SCAN_BYTES, KINDS, MAX_SCAN_BYTES, TYPES
from shield360.rasp._upload_signatures import Signature, compile_signatures

_MODES = ("off", "monitor", "block")
_SHA = re.compile(r"[0-9a-f]{64}")
_TEST_ID = re.compile(r"[A-Za-z0-9_-]{8,64}")
_ALLOWED = frozenset(KINDS) | frozenset(TYPES)
_TCP = re.compile(r"tcp:([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:.]{2,45}\]):(\d{1,5})")


@dataclass
class DeepScan:
    mode: str = "off"
    scan: str = "sync"
    timeout_ms: int = 5000
    fail_mode: str = "open"
    #: ("unix", path) or ("tcp", host, port); None: no ClamAV.
    clamav: Optional[tuple] = None
    reputation: bool = False
    test_id: Optional[str] = None


@dataclass
class UploadConfig:
    max_bytes: Optional[int] = None
    allow: List[str] = field(default_factory=list)
    served_dirs: List[str] = field(default_factory=list)
    trusted: Set[str] = field(default_factory=set)
    rules: List[Signature] = field(default_factory=list)
    deep_scan: DeepScan = field(default_factory=DeepScan)
    routes: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class EffectivePolicy:
    allow: List[str]
    max_bytes: Optional[int]
    mode: Optional[str]
    deep_scan: DeepScan


def _mode(v: Any) -> Optional[str]:
    return v if isinstance(v, str) and v in _MODES else None


def _pos_int(v: Any) -> Optional[int]:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 1 else None


def _timeout(v: Any) -> Optional[int]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
        return None
    return min(60000, max(100, int(v)))


def _strings(v: Any, cap: int, keep: Any) -> List[str]:
    return [x for x in v if isinstance(x, str) and keep(x)][:cap] if isinstance(v, list) else []


def parse_clam_address(v: Any) -> Optional[tuple]:
    s = v.get("address") if isinstance(v, Mapping) else v
    if not isinstance(s, str):
        return None
    if s.startswith("unix:"):
        p = s[5:]
        return ("unix", p) if p and os.path.isabs(p) else None
    m = _TCP.fullmatch(s)
    if not m:
        return None
    port = int(m.group(2))
    return ("tcp", m.group(1).strip("[]"), port) if 1 <= port <= 65535 else None


def _deep(v: Any) -> DeepScan:
    o = v if isinstance(v, Mapping) else {}
    tid = o.get("testId")
    return DeepScan(
        mode=_mode(o.get("mode")) or "off",
        scan="async" if o.get("scan") == "async" else "sync",
        timeout_ms=_timeout(o.get("timeoutMs")) or 5000,
        fail_mode="closed" if o.get("failMode") == "closed" else "open",
        clamav=parse_clam_address(o.get("clamav")),
        reputation=o.get("reputation") is True,
        test_id=tid if isinstance(tid, str) and _TEST_ID.fullmatch(tid) else None,
    )


def _routes(v: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for r in v if isinstance(v, list) else []:
        if len(out) >= 64:
            break
        if not isinstance(r, Mapping):
            continue
        route = r.get("route")
        if not isinstance(route, str) or not route.startswith("/") or len(route) > 256:
            continue
        p: Dict[str, Any] = {"route": route}
        if isinstance(r.get("allow"), list):
            p["allow"] = _strings(r["allow"], 64, lambda s: s in _ALLOWED)
        if _pos_int(r.get("maxBytes")):
            p["max_bytes"] = r["maxBytes"]
        if _mode(r.get("mode")):
            p["mode"] = r["mode"]
        if _mode(r.get("deepScan")):
            p["deep_scan"] = r["deepScan"]
        if r.get("scan") in ("sync", "async"):
            p["scan"] = r["scan"]
        if _timeout(r.get("timeoutMs")):
            p["timeout_ms"] = _timeout(r["timeoutMs"])
        if r.get("failMode") in ("open", "closed"):
            p["fail_mode"] = r["failMode"]
        out.append(p)
    return out


def parse_uploads_block(v: Any) -> Optional[UploadConfig]:
    """The signed config's ``uploads`` block; None when absent."""
    if not isinstance(v, Mapping):
        return None
    return UploadConfig(
        max_bytes=_pos_int(v.get("maxBytes")),
        allow=_strings(v.get("allow"), 64, lambda s: s in _ALLOWED),
        served_dirs=_strings(v.get("servedDirs"), 32, lambda s: os.path.isabs(s) and len(s) <= 512),
        trusted=set(_strings(v.get("trusted"), 1000, lambda s: _SHA.fullmatch(s) is not None)),
        rules=compile_signatures(v.get("rules"))[0],
        deep_scan=_deep(v.get("deepScan")),
        routes=_routes(v.get("routes")),
    )


def local_upload_config(o: Optional[Mapping[str, Any]]) -> UploadConfig:
    """``init(rasp={"uploads": {...}})`` in the same shape (snake or camel keys)."""
    o = o or {}

    def get(snake: str, camel: str) -> Any:
        return o.get(snake, o.get(camel))

    d = dict(get("deep_scan", "deepScan") or {})
    deep = {
        "mode": d.get("mode"),
        "scan": d.get("scan"),
        "timeoutMs": d.get("timeout_ms", d.get("timeoutMs")),
        "failMode": d.get("fail_mode", d.get("failMode")),
        "clamav": d.get("clamav"),
        "reputation": d.get("reputation"),
    }
    return parse_uploads_block({"maxBytes": get("max_bytes", "maxBytes"), "allow": o.get("allow"), "servedDirs": get("served_dirs", "servedDirs"), "deepScan": deep, "routes": o.get("routes")}) or UploadConfig()


class _State:  # pylint: disable=too-few-public-methods
    local = UploadConfig()
    remote: Optional[UploadConfig] = None
    scan_bytes = DEFAULT_SCAN_BYTES
    quarantine_dir = os.path.join(tempfile.gettempdir(), "shield360-quarantine")


def configure_uploads(o: Optional[Mapping[str, Any]]) -> None:
    _State.local = local_upload_config(o)
    _State.remote = None
    sb = (o or {}).get("scan_bytes", (o or {}).get("scanBytes"))
    _State.scan_bytes = min(sb, MAX_SCAN_BYTES) if isinstance(sb, int) and sb > 0 else DEFAULT_SCAN_BYTES
    q = (o or {}).get("quarantine_dir", (o or {}).get("quarantineDir"))
    _State.quarantine_dir = q if isinstance(q, str) and os.path.isabs(q) else os.path.join(tempfile.gettempdir(), "shield360-quarantine")


def set_remote_uploads(v: Any) -> None:
    _State.remote = parse_uploads_block(v)


def upload_config() -> UploadConfig:
    return _State.remote or _State.local


def scan_bytes() -> int:
    return _State.scan_bytes


def quarantine_dir() -> str:
    return _State.quarantine_dir


def route_policy(route: Optional[str], c: Optional[UploadConfig] = None) -> Optional[Dict[str, Any]]:
    c = c or upload_config()
    if not route:
        return None
    for r in c.routes:
        if (route.startswith(r["route"][:-1]) if r["route"].endswith("*") else route == r["route"]):
            return r
    return None


def effective_policy(route: Optional[str], c: Optional[UploadConfig] = None) -> EffectivePolicy:
    c = c or upload_config()
    r = route_policy(route, c) or {}
    deep = replace(
        c.deep_scan,
        mode=r.get("deep_scan", c.deep_scan.mode),
        scan=r.get("scan", c.deep_scan.scan),
        timeout_ms=r.get("timeout_ms", c.deep_scan.timeout_ms),
        fail_mode=r.get("fail_mode", c.deep_scan.fail_mode),
    )
    return EffectivePolicy(allow=r.get("allow", c.allow), max_bytes=r.get("max_bytes", c.max_bytes), mode=r.get("mode"), deep_scan=deep)


_SERVED = frozenset(("public", "static", "www", "wwwroot", "htdocs", "webroot", "public_html"))


def is_served(resolved: str, c: Optional[UploadConfig] = None) -> bool:
    c = c or upload_config()
    p = resolved.replace("\\", "/")
    if c.served_dirs:
        for d in c.served_dirs:
            root = d.replace("\\", "/").rstrip("/")
            if p == root or p.startswith(root + "/"):
                return True
        return False
    return any(s.lower() in _SERVED for s in p.split("/")[:-1])
