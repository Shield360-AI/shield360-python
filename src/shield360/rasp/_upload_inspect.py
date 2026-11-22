"""Upload inspection (sdk/rasp/README.md "Uploads"): what an uploaded file
really is, from its bytes, read in bounded pieces. Pure: no file system, no
network, no events (``_upload.py`` turns a verdict into findings). A port of
the TypeScript SDK's upload-inspect.ts; ``testdata/uploads.json`` holds both
to the same answers.

Memory stays bounded whatever the file's size: the first 64 KiB, the last
1 MiB, one piece of at most 1 MiB with a 2 KiB overlap, and a running hash."""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from shield360.rasp._detect import _SCRIPT_FILE
from shield360.rasp._upload_signatures import LIMITS, Signature, SignatureMatcher, ascii_lower, compile_signatures

KINDS = ("image", "document", "text", "archive", "media", "executable", "script", "html", "svg", "other")
RULE_ORDER = (
    "upload.eicar",
    "upload.malware",
    "upload.reputation",
    "upload.webshell",
    "upload.signature",
    "upload.executable",
    "upload.script",
    "upload.polyglot",
    "upload.active_content",
    "upload.server_config",
    "upload.double_extension",
    "upload.archive_traversal",
    "upload.archive_symlink",
    "upload.archive_bomb",
    "upload.archive_encrypted",
    "upload.office_macro",
    "upload.office_ole",
    "upload.archive_script",
    "upload.type_mismatch",
    "upload.type_not_allowed",
    "upload.too_large",
    "upload.scan_unavailable",
)
CAPPED = frozenset(("upload.office_ole", "upload.archive_script", "upload.type_mismatch"))
DEFAULT_SCAN_BYTES = 8 * 1024 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024
HEAD = 64 * 1024
TAIL = 1024 * 1024
PIECE = 1024 * 1024
MIB = 1024 * 1024

# The EICAR test string, in two halves so this source file is not itself the test file.
_EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

KIND_OF: Dict[str, str] = {
    **dict.fromkeys(("elf", "pe", "macho", "java_class", "wasm", "jar", "war"), "executable"),
    **dict.fromkeys(("jpeg", "png", "gif", "webp", "bmp", "ico", "tiff"), "image"),
    **dict.fromkeys(("pdf", "ole2", "docx", "xlsx", "pptx"), "document"),
    **dict.fromkeys(("zip", "gzip", "bzip2", "xz", "7z", "rar", "tar"), "archive"),
    **dict.fromkeys(("mp4", "webm", "mp3", "wav", "ogg"), "media"),
    **dict.fromkeys(("php", "jsp_asp", "shebang"), "script"),
    "svg": "svg",
    "html": "html",
    "text": "text",
    "unknown": "other",
}
TYPES = tuple(KIND_OF)


def kind_of(t: str) -> str:
    return KIND_OF.get(t, "other")


def _load_builtin() -> List[Signature]:
    data = json.loads(resources.files("shield360.rasp").joinpath("data", "upload-signatures.json").read_text(encoding="utf-8"))
    return compile_signatures(data["rules"])[0]


BUILT_IN_SIGNATURES = _load_builtin()


@dataclass
class UploadFinding:
    rule: str
    engine: str = "builtin"
    signature: Optional[str] = None
    capped: bool = False


@dataclass
class UploadVerdict:
    type: str
    kind: str
    size: int
    sha256: Optional[str] = None
    ext: Optional[str] = None
    findings: List[UploadFinding] = field(default_factory=list)


def rule_rank(rule: str) -> int:
    return RULE_ORDER.index(rule) if rule in RULE_ORDER else len(RULE_ORDER)


# ---- real type ------------------------------------------------------------------


def sniff_type(head: bytes) -> str:  # pylint: disable=too-many-return-statements,too-many-branches
    """The real type from the first bytes (README "Real type")."""
    h = head
    if h.startswith(b"\x7fELF"):
        return "elf"
    if h.startswith(b"MZ") and len(h) >= 0x40:
        off = struct.unpack_from("<i", h, 0x3C)[0]
        if off >= 0 and h[off : off + 4] == b"PE\x00\x00":
            return "pe"
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macho"
    if h.startswith(b"\xca\xfe\xba\xbe"):
        n = struct.unpack_from(">I", h, 4)[0] if len(h) >= 8 else 1 << 40
        return "macho" if n < 30 else "java_class"
    if h.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if h[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return "webp"
    if h[:2] == b"BM" and len(h) >= 26:
        return "bmp"
    if h.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if h.startswith(b"II*\x00") or h.startswith(b"MM\x00*"):
        return "tiff"
    if b"%PDF-" in h[:1024]:
        return "pdf"
    if h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole2"
    if h.startswith(b"PK\x03\x04") or h.startswith(b"PK\x05\x06"):
        return "zip"
    if h.startswith(b"\x1f\x8b"):
        return "gzip"
    if h.startswith(b"BZh"):
        return "bzip2"
    if h.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if h.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if h.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if h[257:262] == b"ustar":
        return "tar"
    if h[4:8] == b"ftyp":
        return "mp4"
    if h.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"
    if h.startswith(b"ID3") or h[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "mp3"
    if h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return "wav"
    if h.startswith(b"OggS"):
        return "ogg"
    if h.startswith(b"\x00asm"):
        return "wasm"
    i = 3 if h.startswith(b"\xef\xbb\xbf") else 0
    while i < len(h) and (h[i] == 0x20 or 0x09 <= h[i] <= 0x0D):
        i += 1
    lead = ascii_lower(h[i : i + 1024].decode("latin-1"))
    if lead.startswith("<?php") or lead.startswith("<?="):
        return "php"
    if lead.startswith("<%") or lead.startswith("<jsp:"):
        return "jsp_asp"
    if lead.startswith("#!/"):
        return "shebang"
    if any(lead.startswith(t) for t in ("<!doctype html", "<html", "<head", "<body", "<script", "<iframe")):
        return "html"
    if "<svg" in lead:
        return "svg"
    if b"\x00" not in h[:8192]:
        return "text"
    return "unknown"


# ---- names -------------------------------------------------------------------------

_SERVER_CONFIG = frozenset((".htaccess", ".htpasswd", ".user.ini", "web.config"))
_SCRIPT_EXT = re.compile(r"(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)", re.IGNORECASE)
_ARCHIVE_SCRIPT = re.compile(r"\.(aspx?|jspx?|php[3-7]?|phar|phtml|cgi|pl|sh)\Z", re.IGNORECASE)


def base_name(name: str) -> str:
    return re.split(r"[\\/]", name)[-1]


def ext_of(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    base = re.sub(r"[. ]+\Z", "", base_name(name))
    dot = base.rfind(".")
    if dot <= 0 and not base.startswith("."):
        return None
    ext = base[dot + 1 :].lower()
    return ext if re.fullmatch(r"[a-z0-9]{1,10}", ext) else None


def is_server_config_name(name: str) -> bool:
    return base_name(name).lower() in _SERVER_CONFIG


def has_double_extension(name: str) -> bool:
    base = base_name(name)
    if "\x00" in base or "%00" in base:
        return True
    if re.search(r"\.[^.]+[. ]+\Z", base):
        return True
    parts = base.split(".")
    if len(parts) < 3 and ";" not in base:
        return False
    for seg in parts[1:-1]:
        if _SCRIPT_EXT.fullmatch(seg.split(";")[0]):
            return True
    return re.search(r"\.(aspx?|jspx?|php[3-7]?|phtml|cgi|pl)\s*;", base, re.IGNORECASE) is not None


_EXT_TYPES: Dict[str, Sequence[str]] = {
    **{k: ("jpeg",) for k in ("jpg", "jpeg", "jpe")},
    "png": ("png",), "gif": ("gif",), "webp": ("webp",), "bmp": ("bmp",), "ico": ("ico",), "tif": ("tiff",), "tiff": ("tiff",),
    "pdf": ("pdf",), "docx": ("docx", "zip"), "xlsx": ("xlsx", "zip"), "pptx": ("pptx", "zip"),
    "doc": ("ole2",), "xls": ("ole2",), "ppt": ("ole2",),
    "zip": ("zip", "docx", "xlsx", "pptx", "jar", "war"), "gz": ("gzip",), "tgz": ("gzip",),
    "mp4": ("mp4",), "m4a": ("mp4",), "mov": ("mp4",), "mp3": ("mp3",),
    **{k: ("text",) for k in ("csv", "txt", "json", "md")},
}  # fmt: skip
_CT_TYPES: Dict[str, Sequence[str]] = {
    "image/jpeg": ("jpeg",), "image/png": ("png",), "image/gif": ("gif",), "image/webp": ("webp",), "image/bmp": ("bmp",),
    "image/x-icon": ("ico",), "image/vnd.microsoft.icon": ("ico",), "image/tiff": ("tiff",), "application/pdf": ("pdf",),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ("docx", "zip"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ("xlsx", "zip"),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ("pptx", "zip"),
    "application/msword": ("ole2",), "application/vnd.ms-excel": ("ole2",), "application/vnd.ms-powerpoint": ("ole2",),
    "application/zip": ("zip", "docx", "xlsx", "pptx", "jar", "war"), "application/gzip": ("gzip",),
    "video/mp4": ("mp4",), "audio/mp4": ("mp4",), "video/quicktime": ("mp4",), "audio/mpeg": ("mp3",),
    "text/csv": ("text",), "text/plain": ("text",), "application/json": ("text",),
}  # fmt: skip


def type_mismatch(t: str, name: Optional[str], content_type: Optional[str]) -> bool:
    if t == "unknown":
        return False
    ext = ext_of(name)
    ct = (content_type or "").split(";")[0].strip().lower()
    for expected in (_EXT_TYPES.get(ext) if ext else None, _CT_TYPES.get(ct)):
        if expected and t not in expected and kind_of(expected[0]) != kind_of(t):
            return True
    return False


def name_findings(name: str, t: Optional[str] = None, content_type: Optional[str] = None) -> List[UploadFinding]:
    out: List[UploadFinding] = []
    if name and is_server_config_name(name):
        out.append(UploadFinding("upload.server_config"))
    if name and has_double_extension(name):
        out.append(UploadFinding("upload.double_extension"))
    if t and type_mismatch(t, name, content_type):
        out.append(UploadFinding("upload.type_mismatch", capped=True))
    return out


# ---- archives ----------------------------------------------------------------------


@dataclass
class ArchiveEntry:
    name: str
    symlink: bool = False
    encrypted: bool = False
    compressed: int = 0
    size: int = 0


def zip_entries(tail: bytes) -> Optional[tuple]:  # pylint: disable=too-many-locals
    """Zip entries from the central directory in ``tail``; None without an end record."""
    eocd = tail.rfind(b"PK\x05\x06", max(0, len(tail) - 22 - 65535))
    if eocd < 0 or eocd + 22 > len(tail):
        return None
    total = struct.unpack_from("<H", tail, eocd + 10)[0]
    cd_size = struct.unpack_from("<I", tail, eocd + 12)[0]
    cd_end = eocd
    if total == 0xFFFF or cd_size == 0xFFFFFFFF:
        loc = eocd - 20
        if loc < 0 or tail[loc : loc + 4] != b"PK\x06\x07":
            return [], total
        z = loc - 56
        if z < 0 or tail[z : z + 4] != b"PK\x06\x06":
            return [], total
        total = struct.unpack_from("<Q", tail, z + 32)[0]
        cd_size = struct.unpack_from("<Q", tail, z + 40)[0]
        cd_end = z
    start = cd_end - cd_size
    if start < 0:
        return [], total
    entries: List[ArchiveEntry] = []
    p = start
    while p + 46 <= cd_end and tail[p : p + 4] == b"PK\x01\x02" and len(entries) < 10001:
        made_by = struct.unpack_from("<H", tail, p + 4)[0] >> 8
        flags = struct.unpack_from("<H", tail, p + 8)[0]
        compressed, size = struct.unpack_from("<II", tail, p + 20)
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", tail, p + 28)
        attr = struct.unpack_from("<I", tail, p + 38)[0]
        name = tail[p + 46 : p + 46 + name_len].decode("latin-1")
        e = p + 46 + name_len
        extra_end = e + extra_len
        while e + 4 <= extra_end:
            fid, ln = struct.unpack_from("<HH", tail, e)
            if fid == 1:
                q = e + 4
                if size == 0xFFFFFFFF and q + 8 <= e + 4 + ln:
                    size = struct.unpack_from("<Q", tail, q)[0]
                    q += 8
                if compressed == 0xFFFFFFFF and q + 8 <= e + 4 + ln:
                    compressed = struct.unpack_from("<Q", tail, q)[0]
            e += 4 + ln
        mode = (attr >> 16) & 0o170000
        entries.append(ArchiveEntry(name, made_by == 3 and mode == 0o120000, bool(flags & 1), compressed, size))
        p = extra_end + comment_len
    return entries, total


def entry_escapes(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or re.match(r"[A-Za-z]:", n) is not None or ".." in n.split("/")


class _TarReader:
    """Reads tar headers as the bytes pass (ustar name and prefix, GNU ``L``, pax ``path``)."""

    def __init__(self) -> None:
        self.entries: List[ArchiveEntry] = []
        self.next = 0
        self.header = bytearray()
        self.want: Optional[Dict[str, Any]] = None
        self.pending_name: Optional[str] = None
        self.done = False

    def feed(self, chunk: bytes, offset: int) -> None:  # pylint: disable=too-many-branches,too-many-statements
        i = 0
        while i < len(chunk) and not self.done and len(self.entries) <= 10000:
            pos = offset + i
            if self.want is not None:
                w = self.want
                take = min(len(chunk) - i, w["left"])
                room = (512 if w["kind"] == "L" else 4096) - len(w["bytes"])
                w["bytes"] += chunk[i : i + min(take, room)]
                w["left"] -= take
                i += take
                if w["left"] == 0:
                    text = bytes(w["bytes"]).decode("latin-1")
                    if w["kind"] == "L":
                        self.pending_name = text.split("\x00", maxsplit=1)[0]
                    else:
                        m = re.search(r"(?:^|\n)\d+ path=([^\n]*)\n", text)
                        if m:
                            self.pending_name = m.group(1)
                    self.next = offset + i + w["skip"]
                    self.want = None
                continue
            if pos < self.next:
                i += min(len(chunk) - i, self.next - pos)
                continue
            take = min(len(chunk) - i, 512 - len(self.header))
            self.header += chunk[i : i + take]
            i += take
            if len(self.header) < 512:
                continue
            h = bytes(self.header)
            self.header = bytearray()
            if not any(h):
                self.done = True
                break

            def field_(o: int, ln: int, hh: bytes = h) -> str:
                return hh[o : o + ln].decode("latin-1").split("\x00")[0]

            try:
                size = int(field_(124, 12).strip() or "0", 8)
            except ValueError:
                size = 0
            typ = chr(h[156] or 0x30)
            padded = -(-size // 512) * 512
            data_start = offset + i
            if typ in ("L", "x"):
                cap = 512 if typ == "L" else 4096
                self.next = data_start + padded
                if size:
                    self.want = {"kind": typ, "left": min(size, cap), "bytes": bytearray(), "skip": padded - min(size, cap)}
                continue
            if typ == "g":
                self.next = data_start + padded
                continue
            prefix, base = field_(345, 155), field_(0, 100)
            name = (
                self.pending_name
                if self.pending_name is not None
                else (f"{prefix}/{base}" if prefix and h[257:262] == b"ustar" else base)
            )
            self.pending_name = None
            self.entries.append(ArchiveEntry(name, typ in ("1", "2"), False, size, size))
            self.next = data_start + padded


# ---- scanner ----------------------------------------------------------------------

_POLYGLOT = ("<?php", "<script", "<jsp:", 'runat="server"')
_ACTIVE = ("<script", "javascript:", "<foreignobject", "<iframe", "<embed", "<object")
_EVENT_HANDLER = re.compile(r"[\t\n\f\r /]on[a-z]{3,20}\s*=")


def _utf16(s: str) -> str:
    return s.encode("utf-16-le").decode("latin-1")


_OLE_VBA = _utf16("_VBA_PROJECT")
_OLE_ENCRYPTED = _utf16("EncryptedPackage")
_OLE_NATIVE = _utf16("\x01Ole10Native")


class UploadScanner:  # pylint: disable=too-many-instance-attributes
    """Inspects a file fed in pieces: ``push`` as the bytes arrive, ``finish`` once."""

    def __init__(
        self,
        name: Optional[str] = None,
        content_type: Optional[str] = None,
        scan_bytes: Optional[int] = None,
        custom: Optional[List[Signature]] = None,
        trusted: Optional[Set[str]] = None,
    ):
        self.name, self.content_type = name, content_type
        self.scan_bytes = min(scan_bytes, MAX_SCAN_BYTES) if isinstance(scan_bytes, int) and scan_bytes > 0 else DEFAULT_SCAN_BYTES
        self.trusted = trusted or set()
        self.size = 0
        self.head = bytearray()
        self.tail = bytearray()
        self.carry = ""
        self.carry_folded = ""
        self.scanned = 0
        self.pending = bytearray()
        self.hash = hashlib.sha256()
        self.builtin = SignatureMatcher(BUILT_IN_SIGNATURES)
        self.custom = SignatureMatcher(custom) if custom else None
        self.markers: Set[str] = set()
        self.tar: Optional[_TarReader] = None
        self.tar_checked = False

    def push(self, data: bytes) -> None:
        if not data:
            return
        data = bytes(data)
        offset = self.size
        self.size += len(data)
        self.hash.update(data)
        if len(self.head) < HEAD:
            self.head += data[: HEAD - len(self.head)]
        self.tail += data
        if len(self.tail) > 2 * TAIL:
            del self.tail[: len(self.tail) - TAIL]
        if not self.tar_checked and len(self.head) >= 262:
            self.tar_checked = True
            if sniff_type(bytes(self.head)) == "tar":
                self.tar = _TarReader()
                fed = min(len(self.head), offset + len(data))
                self.tar.feed(bytes(self.head[:fed]), 0)
                if offset + len(data) > fed:
                    self.tar.feed(data[fed - offset :], fed)
        elif self.tar is not None:
            self.tar.feed(data, offset)
        if self.scanned < self.scan_bytes:
            part = data[: self.scan_bytes - self.scanned]
            self.scanned += len(part)
            self.pending += part
            if len(self.pending) >= PIECE:
                self._flush(False)

    def skip(self, n: int) -> None:
        """Counts ``n`` bytes the caller does not read (the middle of a large file)."""
        if n <= 0:
            return
        self._flush(False)
        self.carry = self.carry_folded = ""
        self.size += n
        self.scanned = self.scan_bytes
        if self.tar is not None:
            self.tar.done = True

    def _scan(self, text: str, folded: str, final: bool) -> None:
        self.builtin.feed(text, folded, final)
        if self.custom is not None:
            self.custom.feed(text, folded, final)
        for m in _POLYGLOT + _ACTIVE:
            if m in folded:
                self.markers.add(m)
        if _EVENT_HANDLER.search(folded):
            self.markers.add("on*=")
        for m in (_OLE_VBA, _OLE_ENCRYPTED, _OLE_NATIVE):
            if m in text:
                self.markers.add(m)

    def _flush(self, final: bool) -> None:
        if not self.pending and not final:
            return
        chunk = bytes(self.pending).decode("latin-1")
        self.pending = bytearray()
        text = self.carry + chunk
        folded = self.carry_folded + ascii_lower(chunk)
        self._scan(text, folded, final)
        self.carry = text[-LIMITS["overlap"] :]
        self.carry_folded = folded[-LIMITS["overlap"] :]

    def finish(self, complete: bool = True) -> UploadVerdict:  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
        self._flush(True)
        tail = bytes(self.tail[-TAIL:])
        if self.size > self.scanned:
            unseen = min(len(tail), self.size - self.scanned)
            extra = tail[len(tail) - unseen :].decode("latin-1")
            self._scan(extra, ascii_lower(extra), True)
        sha = self.hash.hexdigest() if complete else None
        t = sniff_type(bytes(self.head))
        entries: List[ArchiveEntry] = []
        total = 0
        if t == "zip":
            z = zip_entries(tail)
            if z is not None:
                entries, total = z
                names = [e.name.replace("\\", "/") for e in entries]
                if "[Content_Types].xml" in names:
                    if any(n.startswith("word/") for n in names):
                        t = "docx"
                    elif any(n.startswith("xl/") for n in names):
                        t = "xlsx"
                    elif any(n.startswith("ppt/") for n in names):
                        t = "pptx"
                if t == "zip" and any(n.startswith("WEB-INF/") for n in names):
                    t = "war"
                elif t == "zip" and "META-INF/MANIFEST.MF" in names:
                    t = "jar"
        elif self.tar is not None:
            entries = self.tar.entries
            total = len(entries)
        kind = kind_of(t)
        name = self.name or ""
        findings: List[UploadFinding] = []

        def add(rule: str, **kw: Any) -> None:
            findings.append(UploadFinding(rule, capped=rule in CAPPED, **kw))

        if not (sha is not None and sha in self.trusted):
            if self.size <= 256:
                text = bytes(self.head).decode("latin-1").rstrip()
                if len(text) <= 128 and text.startswith(_EICAR):
                    add("upload.eicar")
            web = self.builtin.matched()
            if web:
                add("upload.webshell", signature=web[0].id)
            own = self.custom.matched() if self.custom else []
            if own:
                add("upload.signature", engine="custom", signature=own[0].id)
            if kind == "executable":
                add("upload.executable")
            if kind == "script":
                add("upload.script")
            if kind in ("image", "document", "media", "archive") and any(m in self.markers for m in _POLYGLOT):
                add("upload.polyglot")
            if kind in ("html", "svg") and (any(m in self.markers for m in _ACTIVE) or "on*=" in self.markers):
                add("upload.active_content")
            for f in name_findings(name):
                add(f.rule)
            if any(entry_escapes(e.name) for e in entries):
                add("upload.archive_traversal")
            if any(e.symlink for e in entries):
                add("upload.archive_symlink")
            declared = sum(e.size for e in entries)
            bomb = (
                total > 10000
                or len(entries) > 10000
                or declared > 1024 * MIB
                or any(e.size > 10 * MIB and e.size > 1000 * max(1, e.compressed) for e in entries)
            )
            if t == "gzip" and len(tail) >= 4 and self.size > 18:
                isize = struct.unpack_from("<I", tail, len(tail) - 4)[0]
                bomb = bomb or (isize > 10 * MIB and isize > 1000 * self.size)
            if bomb:
                add("upload.archive_bomb")
            if any(e.encrypted for e in entries) or (t == "ole2" and _OLE_ENCRYPTED in self.markers):
                add("upload.archive_encrypted")

            def last(n: str) -> str:
                return n.replace("\\", "/").split("/")[-1]

            if any(last(e.name).lower() == "vbaproject.bin" for e in entries) or (t == "ole2" and _OLE_VBA in self.markers):
                add("upload.office_macro")
            if any(
                re.search(r"(^|/)embeddings/oleObject", e.name.replace("\\", "/"), re.I)
                or re.search(r"(^|/)activeX/", e.name.replace("\\", "/"), re.I)
                for e in entries
            ) or (t == "ole2" and _OLE_NATIVE in self.markers):
                add("upload.office_ole")
            if any(_ARCHIVE_SCRIPT.search(last(e.name)) for e in entries):
                add("upload.archive_script")
            if type_mismatch(t, name, self.content_type):
                add("upload.type_mismatch")
        findings.sort(key=lambda f: rule_rank(f.rule))
        return UploadVerdict(t, kind, self.size, sha, ext_of(name), findings)


def inspect_bytes(data: bytes, name: Optional[str] = None, content_type: Optional[str] = None, **opts: Any) -> UploadVerdict:
    s = UploadScanner(name, content_type, **opts)
    for i in range(0, len(data), PIECE):
        s.push(data[i : i + PIECE])
    return s.finish(True)


def inspect_chunks(
    chunks: Iterable[bytes], name: Optional[str] = None, content_type: Optional[str] = None, **opts: Any
) -> UploadVerdict:
    s = UploadScanner(name, content_type, **opts)
    for c in chunks:
        s.push(c)
    return s.finish(True)


def is_active_content(v: UploadVerdict) -> bool:
    return v.kind in ("script", "html", "svg", "executable") or any(
        not f.capped and f.rule not in ("upload.too_large", "upload.type_not_allowed") for f in v.findings
    )


def is_executable_name(path: str) -> bool:
    return _SCRIPT_FILE.search(base_name(path)) is not None or is_server_config_name(path)
