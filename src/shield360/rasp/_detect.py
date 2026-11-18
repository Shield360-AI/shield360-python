"""Pure structural detectors (README "Detection algorithms"). Each takes the
sink's argument and the inputs in scope and returns a Finding or None. No
I/O, no state: the engine decides what a finding does."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from importlib import resources
from typing import Any, Dict, List, Optional, Sequence

from shield360.rasp._iast_rules import (
    vuln_argv,
    vuln_code,
    vuln_data,
    vuln_include,
    vuln_path,
    vuln_shell,
    vuln_sql,
    vuln_ssrf,
)
from shield360.rasp._iast_scope import note_vulnerability
from shield360.rasp._lexers import SQL_KEYWORDS, Token, code_tokens, occurrences, overlapping, shell_tokens, sql_tokens
from shield360.rasp._types import Finding, RaspInput


def _load_data(name: str) -> Dict[str, Any]:
    return json.loads(resources.files("shield360.rasp").joinpath("data", name).read_text(encoding="utf-8"))


def _req_inputs(inputs: Sequence[RaspInput], minimum: int) -> List[RaspInput]:
    return [i for i in inputs if i.source == "request" and len(i.value) >= minimum]


def _model_inputs(inputs: Sequence[RaspInput], minimum: int) -> List[RaspInput]:
    return [i for i in inputs if i.source == "model_output" and len(i.value) >= minimum]


# ---- SQL ----------------------------------------------------------------

_ANTI_DETECT = SQL_KEYWORDS
_COMMA_LIST = re.compile(r"(, *)?(([a-zA-Z_]\w*|[0-9+\-x.]+) *, *)+([a-zA-Z_]\w*|[0-9+\-x.]+)", re.ASCII)
_WRITE_STATEMENTS = frozenset("insert update delete drop alter create truncate grant revoke merge replace".split())


def _is_comment(t: Token) -> bool:
    return t.kind in ("comment", "version_comment")


def _has_stacked_after(tokens: List[Token], over: List[Token]) -> bool:
    for t in over:
        if t.kind != "op" or t.text != ";":
            continue
        at = tokens.index(t)
        if any(not _is_comment(x) for x in tokens[at + 1 :]):
            return True
    return False


def _sql_whole_is_dangerous(tokens: List[Token]) -> bool:
    code = [t for t in tokens if not _is_comment(t)]
    if not code:
        return False
    if code[0].kind == "word" and code[0].text.lower() in _WRITE_STATEMENTS:
        return True
    return any(code[i].kind == "op" and code[i].text == ";" for i in range(len(code) - 1))


def detect_sql(query: str, inputs: Sequence[RaspInput], dialect: str = "generic") -> Optional[Finding]:
    if not query or not inputs:
        return None
    cache: List[List[Token]] = []
    lexer = dialect or "generic"

    def toks() -> List[Token]:
        if not cache:
            cache.append(sql_tokens(query, lexer))
        return cache[0]

    trimmed = query.strip()
    for inp in _req_inputs(inputs, 3):
        v = inp.value
        if v == query or v.strip() == trimmed:
            continue  # allow_full: a SQL console
        occ = occurrences(query, v)
        if not occ:
            continue
        comma_list = _COMMA_LIST.fullmatch(v) is not None
        for idx in occ:
            over = overlapping(toks(), idx, len(v))
            if not comma_list and len(over) >= 2:
                if len(over) >= 10:
                    return Finding("sql_injection", "sqli.userinput", inp, dialect=lexer)
                plain = [t for t in over if not (t.kind == "word" and t.text.lower() in _ANTI_DETECT)]
                if len(plain) >= 2:
                    return Finding("sql_injection", "sqli.userinput", inp, dialect=lexer)
            if _has_stacked_after(toks(), over):
                return Finding("sql_injection", "sqli.stacked", inp, dialect=lexer)
    for inp in _model_inputs(inputs, 3):
        if inp.value.strip() == trimmed:
            if _sql_whole_is_dangerous(toks()):
                return Finding("sql_injection", "sqli.model_output", inp, dialect=lexer)
            continue
        for idx in occurrences(query, inp.value):
            if len(overlapping(toks(), idx, len(inp.value))) >= 2:
                return Finding("sql_injection", "sqli.model_output", inp, dialect=lexer)
    note_vulnerability(lambda: vuln_sql(query, inputs, toks))  # passive IAST (_iast_rules.py)
    return None


# ---- NoSQL ----------------------------------------------------------------


def _entries(node: Any) -> List[Any]:
    if isinstance(node, dict):
        return list(node.items())
    if isinstance(node, (list, tuple)):
        return [(str(i), v) for i, v in enumerate(node)]
    return []


def _is_object(v: Any) -> bool:
    return isinstance(v, (dict, list, tuple))


def _deep_equal(a: Any, b: Any, depth: int = 0) -> bool:
    if a is b:
        return True
    if not _is_object(a) and not _is_object(b):
        # JSON scalars: 1 equals 1.0, but true is not 1.
        return isinstance(a, bool) == isinstance(b, bool) and a == b
    if not _is_object(a) or not _is_object(b) or depth > 32:
        return False
    if isinstance(a, dict) != isinstance(b, dict):
        return False
    ea = _entries(a)
    eb = dict(_entries(b))
    if len(ea) != len(eb):
        return False
    return all(k in eb and _deep_equal(v, eb[k], depth + 1) for k, v in ea)


def _tree_contains(tree: Any, obj: Any, depth: int = 0) -> bool:
    if not _is_object(tree) or depth > 32:
        return False
    if tree is obj or _deep_equal(tree, obj):
        return True
    return any(_tree_contains(v, obj, depth + 1) for _, v in _entries(tree))


def detect_nosql(doc: Any, trees: Sequence[Any], inputs: Sequence[RaspInput]) -> Optional[Finding]:
    found: List[Finding] = []

    def walk(node: Any, depth: int) -> None:
        if found or not _is_object(node) or depth > 32:
            return
        entries = _entries(node)
        if isinstance(node, dict) and any(isinstance(k, str) and k.startswith("$") for k, _ in entries):
            if any(_tree_contains(t, node) for t in trees):
                found.append(Finding("nosql_injection", "nosqli.operator"))
                return
        for k, v in entries:
            if k in ("$where", "$function") and not found:
                if isinstance(v, str):
                    code = v
                elif isinstance(v, dict) and isinstance(v.get("body"), str):
                    code = v["body"]
                else:
                    code = ""
                hit = detect_code(code, inputs) if code else None
                if hit:
                    found.append(Finding("nosql_injection", "nosqli.where", hit.input))
            walk(v, depth + 1)

    walk(doc, 0)
    return found[0] if found else None


# ---- Command ----------------------------------------------------------------

SHELLS = frozenset("sh bash zsh dash ksh fish csh tcsh cmd powershell pwsh".split())
DOWNLOADERS = frozenset(("curl", "wget"))
_MULTI_OPS = frozenset((";", "&&", "||", "|", "`", "$("))


def exe_name(p: str) -> str:
    base = p.replace("\\", "/").split("/")[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


_QUOTE_EDGES = re.compile(r"^['\"]|['\"]\Z")


def _unquote_word(w: str) -> str:
    return _QUOTE_EDGES.sub("", w)


def detect_command(command: str, inputs: Sequence[RaspInput]) -> Optional[Finding]:
    if not command or not inputs:
        return None
    tokens, in_single = shell_tokens(command)
    trimmed = command.strip()
    for inp in _req_inputs(inputs, 3):
        for idx in occurrences(command, inp.value):
            if len(overlapping(tokens, idx, len(inp.value))) >= 2:
                return Finding("command_injection", "cmdi.userinput", inp)
    for inp in _req_inputs(inputs, 3):
        v = inp.value
        if "${IFS}" in v or "$IFS" in v:
            if v in command:
                return Finding("command_injection", "cmdi.substitution", inp)
        if "`" in v or "$(" in v:
            for idx in occurrences(command, v):
                for k in range(idx, idx + len(v)):
                    sub = command[k] == "`" or (command[k] == "$" and command[k + 1 : k + 2] == "(")
                    if sub and not in_single[k]:
                        return Finding("command_injection", "cmdi.substitution", inp)
    for inp in _req_inputs(inputs, 1):
        if inp.value.strip() == trimmed:
            return Finding("command_injection", "cmdi.full", inp)
    for inp in _model_inputs(inputs, 3):
        if inp.value.strip() == trimmed:
            if any(t.kind == "op" and t.text in _MULTI_OPS for t in tokens):
                return Finding("command_injection", "cmdi.model_output", inp)
            continue
        for idx in occurrences(command, inp.value):
            if len(overlapping(tokens, idx, len(inp.value))) >= 2:
                return Finding("command_injection", "cmdi.model_output", inp)
    note_vulnerability(lambda: vuln_shell(command, inputs, tokens))  # passive IAST
    return None


def detect_argv(argv: Sequence[str], inputs: Sequence[RaspInput]) -> Optional[Finding]:
    """argv spawns: the executable equals an input."""
    if not argv:
        return None
    for inp in inputs:
        if len(inp.value) >= 1 and inp.value == argv[0]:
            return Finding("command_injection", "cmdi.executable", inp)
    # Passive IAST: a `sh -c <script>` spawn's script is checked as shell text instead.
    note_vulnerability(lambda: None if shell_script_of(argv) else vuln_argv(argv, inputs))
    return None


def detect_shell_spawn(
    argv0: Optional[str] = None, command: Optional[str] = None, in_request: bool = False, allow: Sequence[str] = ()
) -> Optional[Finding]:
    """shell_spawn: a shell or downloader started during a request, or curl|sh at any time."""
    allowed = {exe_name(a) for a in allow}
    if command:
        words, _ = shell_tokens(command)
        for i, w in enumerate(words):
            if w.kind != "word" or exe_name(_unquote_word(w.text)) not in DOWNLOADERS:
                continue
            for k in range(i + 1, len(words) - 1):
                nxt = words[k + 1]
                piped = words[k].kind == "op" and words[k].text == "|"
                if piped and nxt.kind == "word" and exe_name(_unquote_word(nxt.text)) in SHELLS:
                    return Finding("shell_spawn", "shell_spawn.download_exec")
    if not in_request:
        return None
    name = exe_name(argv0) if argv0 else ""
    if not name and command:
        first = next((t for t in shell_tokens(command)[0] if t.kind == "word"), None)
        name = exe_name(_unquote_word(first.text)) if first else ""
    if name and (name in SHELLS or name in DOWNLOADERS) and name not in allowed:
        return Finding("shell_spawn", "shell_spawn.shell", target=name)
    return None


def shell_script_of(argv: Sequence[str]) -> Optional[str]:
    """The script of ``sh -c <script>`` style argv, if any."""
    if len(argv) < 3 or exe_name(argv[0]) not in SHELLS:
        return None
    i = next((k for k, a in enumerate(argv) if k > 0 and (a == "-c" or a.lower() in ("/c", "-command"))), -1)
    return " ".join(argv[i + 1 :]) if 0 < i < len(argv) - 1 else None


# ---- Path ----------------------------------------------------------------

_SLASHES = re.compile(r"/{2,}")
_DRIVE = re.compile(r"[A-Za-z]:")
_DRIVE_ROOT = re.compile(r"[A-Za-z]:/")


def norm_path(p: str) -> str:
    s = p.replace("\\", "/")
    unc = s.startswith("//")
    while "/./" in s:
        s = s.replace("/./", "/", 1)
    s = _SLASHES.sub("/", s)
    return "/" + s if unc else s


def _normalize_abs(p: str) -> str:
    # posix.normalize for an absolute path: '.' and empty segments dropped, '..' climbs (not above the root).
    out: List[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return "/" + "/".join(out)


def resolve_path(p: str, cwd: Optional[str] = None) -> str:
    s = p.replace("\\", "/")
    if cwd is None:
        cwd = os.getcwd()
    absolute = s if (s.startswith("/") or _DRIVE_ROOT.match(s)) else f"{cwd.replace(chr(92), '/')}/{s}"
    drive = absolute[:2] if _DRIVE.match(absolute) else ""
    normalized = _normalize_abs("/" + absolute[len(drive) :])
    if normalized.endswith("/"):
        normalized = normalized[:-1]
    return (drive + normalized) or "/"


_SENSITIVE = frozenset(
    ("/etc/passwd", "/etc/shadow", "/proc/self/environ", "/root/.bash_history", "/var/run/secrets/kubernetes.io/serviceaccount/token")
)
_SCRIPT_FILE = re.compile(
    r"\.(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)\.?\Z",
    re.IGNORECASE,
)
_NTFS_STREAM = re.compile(r"::\$(DATA|INDEX)\Z", re.IGNORECASE)

FILE_OPS = ("read", "write", "append", "delete", "rename", "list", "open")


def target_directory(resolved: str) -> str:
    """path.outside_root's target: the directory of the resolved path (README "Allow-list targets")."""
    i = resolved.rfind("/")
    d = resolved[:i] if i >= 0 else ""
    if d == "":
        return "/"
    return d + "/" if _DRIVE.fullmatch(d) else d


def under_root(resolved: str, root: str) -> bool:
    r = resolve_path(root)
    return resolved == r or resolved.startswith(r if r.endswith("/") else r + "/")


def detect_path(
    path: str, op: str, inputs: Sequence[RaspInput], file_roots: Sequence[str] = (), in_request: bool = True
) -> Optional[Finding]:
    if not isinstance(path, str) or not path:
        return None
    np_ = norm_path(path)
    resolved = resolve_path(path)
    writes = op in ("write", "append", "rename", "open")
    if writes and _NTFS_STREAM.search(path):
        return Finding("file_write", "file_write.ntfs")
    cands = _req_inputs(inputs, 3) + _model_inputs(inputs, 3)
    for inp in cands:
        ni = norm_path(inp.value)
        if "../" in ni and (np_.endswith(ni) or ni in np_):
            return Finding("path_traversal", "path.traversal", inp)
        absolute = ni.startswith("/") or _DRIVE_ROOT.match(ni) is not None or inp.value.startswith("file://")
        if absolute:
            target = norm_path(inp.value[7:]) if inp.value.startswith("file://") else ni
            if np_ == target or np_.endswith(target):
                return Finding("path_traversal", "path.absolute", inp)
        nul = inp.value.find("\0")
        if nul > 0 and inp.value[:nul] in path:
            return Finding("path_traversal", "path.nullbyte", inp)
    contained = next((i for i in cands if i.value in path or norm_path(i.value) in np_), None)
    if contained and file_roots and not any(under_root(resolved, r) for r in file_roots):
        return Finding("path_traversal", "path.outside_root", contained, target=target_directory(resolved))
    if contained:
        home = os.path.expanduser("~").replace("\\", "/")
        if resolved in _SENSITIVE or resolved == f"{home}/.ssh/id_rsa" or resolved.endswith("/.ssh/id_rsa"):
            return Finding("path_traversal", "path.sensitive", contained)
    if writes and in_request and _SCRIPT_FILE.search(resolved.split("/")[-1]):
        if contained or any(under_root(resolved, r) for r in file_roots) or under_root(resolved, tempfile.gettempdir()):
            return Finding("file_write", "file_write.script", contained)
    note_vulnerability(lambda: vuln_path(np_, inputs, norm_path))  # passive IAST
    return None


# ---- SSRF ----------------------------------------------------------------

_SSRF_PROTOCOLS = frozenset("file gopher dict ftp jar netdoc ldap ldaps php phar expect tftp".split())
METADATA_HOSTS = (
    "169.254.169.254",
    "fd00:ec2::254",
    "100.100.100.200",
    "168.63.129.16",
    "169.254.170.2",
    "metadata.google.internal",
    "metadata",
)

_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*):")
_AUTH_END = re.compile(r"[/?#\\]")


def raw_url(url: str) -> Optional[Dict[str, str]]:
    """Scheme and raw host as written (a URL parser would rewrite numeric hosts)."""
    m = _SCHEME.match(url)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = url[m.end() :]
    if not rest.startswith("//"):
        return {"scheme": scheme, "host": ""}
    rest = rest[2:]
    end = _AUTH_END.search(rest)
    auth = rest if end is None else rest[: end.start()]
    at = auth.rfind("@")
    if at >= 0:
        auth = auth[at + 1 :]
    host = auth
    if host.startswith("["):
        close = host.find("]")
        host = host[1:] if close < 0 else host[1:close]
    elif ":" in host:
        host = host[: host.find(":")]
    return {"scheme": scheme, "host": host.lower()}


_V4_PART = re.compile(r"0|[1-9]\d{0,2}", re.ASCII)
_V6_WORD = re.compile(r"[0-9a-f]{1,4}", re.IGNORECASE)


def _parse_v4(s: str) -> Optional[List[int]]:
    p = s.split(".")
    if len(p) != 4 or not all(_V4_PART.fullmatch(x) for x in p):
        return None
    n = [int(x) for x in p]
    return n if all(0 <= x <= 255 for x in n) else None


def _parse_v6(s: str) -> Optional[List[int]]:
    """Returns 16 bytes, or None."""
    if ":" not in s:
        return None
    tail: List[int] = []
    text = s
    last_colon = text.rfind(":")
    v4 = _parse_v4(text[last_colon + 1 :])
    if v4:
        tail = v4
        text = text[:last_colon] + ":0:0"
    halves = text.split("::")
    if len(halves) > 2:
        return None

    def parse(h: str) -> Optional[List[int]]:
        if not h:
            return []
        out = []
        for x in h.split(":"):
            if not _V6_WORD.fullmatch(x):
                return None
            out.append(int(x, 16))
        return out

    a = parse(halves[0])
    b = parse(halves[1]) if len(halves) == 2 else []
    if a is None or b is None:
        return None
    fill = 8 - len(a) - len(b) if len(halves) == 2 else 0
    if fill < 0 or (len(halves) == 1 and len(a) != 8):
        return None
    words = a + [0] * fill + b
    out: List[int] = []
    for w in words:
        out.extend((w >> 8, w & 255))
    if tail:
        out[12:16] = tail
    return out


def _v4_private(b: Sequence[int]) -> bool:
    a, c = b[0], b[1]
    return (
        a in (0, 10, 127)
        or (a == 100 and 64 <= c < 128)
        or (a == 169 and c == 254)
        or (a == 172 and 16 <= c < 32)
        or (a == 192 and c == 168)
        or (a == 198 and c in (18, 19))
    )


_BRACKETS = re.compile(r"^\[|\]\Z")


def is_private_address(addr: str) -> bool:
    """Private, loopback, link-local or unique-local, IPv4-mapped/compatible decoded."""
    a = _BRACKETS.sub("", addr.lower()).split("%")[0]
    v4 = _parse_v4(a)
    if v4:
        return _v4_private(v4)
    v6 = _parse_v6(a)
    if not v6:
        return False
    zero10 = all(x == 0 for x in v6[:10])
    if zero10 and v6[10] == 0xFF and v6[11] == 0xFF:
        return _v4_private(v6[12:])
    zero12 = zero10 and v6[10] == 0 and v6[11] == 0
    loop_or_any = all(x == 0 for x in v6[12:15]) and v6[15] <= 1
    if zero12 and not loop_or_any:
        return _v4_private(v6[12:])
    if all(x == 0 for x in v6):
        return True
    if all(x == 0 for x in v6[:15]) and v6[15] == 1:
        return True
    if (v6[0] & 0xFE) == 0xFC:
        return True
    if v6[0] == 0xFE and (v6[1] & 0xC0) == 0x80:
        return True
    return False


def is_ip_literal(host: str) -> bool:
    return bool(_parse_v4(host) or _parse_v6(host))


_DIGITS = re.compile(r"\d+", re.ASCII)
_HEX_NUMBER = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)
_NUM_PART = re.compile(r"0x[0-9a-f]+|\d+", re.IGNORECASE | re.ASCII)
_LEADING_ZERO = re.compile(r"0\d", re.ASCII)


def _is_obfuscated_v4(host: str) -> bool:
    if not host or _parse_v4(host):
        return False
    if _DIGITS.fullmatch(host) or _HEX_NUMBER.fullmatch(host):
        return True
    parts = host.split(".")
    if len(parts) > 4 or len(parts) < 2:
        return False
    if not all(_NUM_PART.fullmatch(p) for p in parts):
        return False
    return len(parts) < 4 or any(_LEADING_ZERO.match(p) or p[:2].lower() == "0x" for p in parts)


_DNSLOG = _load_data("dnslog-domains.json")
DNSLOG_SUFFIXES: List[str] = list(_DNSLOG.get("domains", []))
DNSLOG_HOSTS = frozenset(_DNSLOG.get("hosts", []))


def host_matches(host: str, pattern: str) -> bool:
    p = pattern.lower()
    if p.startswith("*."):
        return host.endswith(p[1:]) and len(host) > len(p) - 1
    return host == p


def taint_of(url: str, host: str, inputs: Sequence[RaspInput]) -> Optional[RaspInput]:
    """Whether an input taints the URL's host."""
    cands = [i for i in inputs if len(i.value) >= 3]
    if host:
        host_end = url.lower().find(host) + len(host)
        return next((i for i in cands if host in i.value.lower() or (url.startswith(i.value) and len(i.value) >= host_end)), None)
    # No host (file:, gopher: without //): an input that is a prefix past the scheme.
    scheme_end = url.find(":") + 1
    return next((i for i in cands if url.startswith(i.value) and len(i.value) > scheme_end), None)


def detect_ssrf(url: str, inputs: Sequence[RaspInput], resolved: Sequence[str] = ()) -> Optional[Finding]:
    raw = raw_url(url)
    if not raw:
        return None
    host = raw["host"]
    inp = taint_of(url, host, inputs)
    if not inp:
        return None
    if raw["scheme"] in _SSRF_PROTOCOLS:
        return Finding("ssrf", "ssrf.protocol", inp)
    if host in METADATA_HOSTS or any(a.lower() in METADATA_HOSTS for a in resolved):
        return Finding("ssrf", "ssrf.metadata", inp)
    if _is_obfuscated_v4(host):
        return Finding("ssrf", "ssrf.obfuscated", inp)
    if (
        host == "localhost"
        or host.endswith(".localhost")
        or (is_ip_literal(host) and is_private_address(host))
        or any(is_private_address(a) for a in resolved)
    ):
        return Finding("ssrf", "ssrf.internal", inp)
    if host in DNSLOG_HOSTS or any(host.endswith(s) for s in DNSLOG_SUFFIXES):
        return Finding("ssrf", "ssrf.dnslog", inp)
    note_vulnerability(lambda: vuln_ssrf(url, raw, inputs))  # passive IAST
    return None


def detect_outbound(url: str, allow: Sequence[str], always_allowed: Sequence[str] = ()) -> Optional[Finding]:
    """outbound.not_allowed: host matches none of the allow-list (always-allowed hosts aside)."""
    if not allow:
        return None
    raw = raw_url(url)
    if not raw or not raw["host"]:
        return None
    host = raw["host"]
    if host in always_allowed or any(host_matches(host, p) for p in allow):
        return None
    return Finding("outbound", "outbound.not_allowed", target=host)


# ---- Deserialization, code, XML, XSS ------------------------------------------

_BASE64ISH = re.compile(r"[A-Za-z0-9+/=_\-]+")


def _b64_latin1(s: str) -> str:
    # Lenient, as Node's decoder: base64url letters accepted, decoding stops at padding, a dangling character dropped.
    t = s.replace("-", "+").replace("_", "/").split("=")[0]
    if len(t) % 4 == 1:
        t = t[:-1]
    try:
        return base64.b64decode(t + "=" * (-len(t) % 4)).decode("latin-1")
    except Exception:  # pylint: disable=broad-exception-caught
        return ""


def tainted_data(data: str, inputs: Sequence[RaspInput]) -> Optional[RaspInput]:
    """Data is tainted when equal to an input, contained in one, or containing one of length >= 8."""
    if not data:
        return None
    for i in inputs:
        if not i.value:
            continue
        if i.value == data or data in i.value or (len(i.value) >= 8 and i.value in data):
            return i
        if len(i.value) >= 8 and _BASE64ISH.fullmatch(i.value):
            dec = _b64_latin1(i.value)
            if dec and (dec == data or (len(dec) >= 8 and (data in dec or dec in data))):
                return i
    return None


DESER_FORMATS = (
    "pickle", "marshal", "yaml", "jsonpickle", "node_serialize", "funcster", "binaryformatter", "typename", "java", "snakeyaml",
)
_JSONPICKLE_MARKS = ('"py/reduce"', '"py/object"', '"py/type"', '"py/function"', '"py/repr"', '"py/newargs"')
# A SnakeYAML global tag naming a Java class (`!!` or `!<tag:yaml.org,2002:` and a
# dotted name). Standard tags such as `!!str` have no dot and never match.
_SNAKEYAML_CLASS_TAG = re.compile(r"(?:^|[\s\[{,])(?:!!|!<tag:yaml\.org,2002:)[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$]")


def detect_deserialization(fmt: str, data: str, inputs: Sequence[RaspInput]) -> Optional[Finding]:
    inp = tainted_data(data, inputs)
    if not inp:
        return None
    # Passive IAST: tainted data reaching an unsafe deserializer, whatever the format check says.
    note_vulnerability(lambda: vuln_data("vuln.deser_input", data, tainted_data(data, [i for i in inputs if i.source == "request"])))

    def hit(rule: str) -> Finding:
        return Finding("deserialization", rule, inp)

    if fmt == "pickle":
        return hit("deser.pickle")
    if fmt == "marshal":
        return hit("deser.marshal")
    if fmt == "binaryformatter":
        return hit("deser.binaryformatter")
    if fmt == "java":
        return hit("deser.java")
    if fmt == "snakeyaml":
        return hit("deser.yaml") if _SNAKEYAML_CLASS_TAG.search(data) else None
    if fmt == "yaml":
        return hit("deser.yaml") if ("!!python/" in data or "!!js/" in data) else None
    if fmt == "jsonpickle":
        return hit("deser.jsonpickle") if any(m in data for m in _JSONPICKLE_MARKS) else None
    if fmt == "node_serialize":
        return hit("deser.node_serialize") if "_$$ND_FUNC$$_" in data else None
    if fmt == "funcster":
        return hit("deser.funcster") if "__js_function" in data else None
    if fmt == "typename":
        return hit("deser.typename") if ('"$type"' in data or '"__type"' in data) else None
    return None


def detect_code(code: str, inputs: Sequence[RaspInput]) -> Optional[Finding]:
    if not code:
        return None
    tokens: Optional[List[Token]] = None
    for inp in inputs:
        if len(inp.value) < 3:
            continue
        if inp.value == code:
            return Finding("code_injection", "code.eval", inp)
        for idx in occurrences(code, inp.value):
            if tokens is None:
                tokens = code_tokens(code)
            if len(overlapping(tokens, idx, len(inp.value))) >= 2:
                return Finding("code_injection", "code.eval", inp)

    def code_toks() -> List[Token]:
        nonlocal tokens
        if tokens is None:
            tokens = code_tokens(code)
        return tokens

    note_vulnerability(lambda: vuln_code(code, inputs, code_toks))  # passive IAST
    return None


_INCLUDE_PATHLIKE = re.compile(r"[/\\]|\.\.")
_INCLUDE_ABSOLUTE = re.compile(r"(?:/|[A-Za-z]:[\\/]|\\\\|file:)", re.IGNORECASE)


def detect_include(specifier: str, inputs: Sequence[RaspInput]) -> Optional[Finding]:
    """code.include: the module specifier equals a tainted input, or contains
    one of length >= 3 that is an absolute path or holds ``/``, ``\\``, ``..``
    or a NUL. ``_hooks/include.py`` calls it for ``importlib.import_module``,
    explicit ``__import__`` calls and ``runpy``."""
    if not isinstance(specifier, str) or not specifier:
        return None
    for inp in inputs:
        if not inp.value:
            continue
        if inp.value == specifier:
            return Finding("code_injection", "code.include", inp)
        if len(inp.value) >= 3 and inp.value in specifier:
            if _INCLUDE_ABSOLUTE.match(inp.value) or _INCLUDE_PATHLIKE.search(inp.value) or "\0" in inp.value:
                return Finding("code_injection", "code.include", inp)
    note_vulnerability(lambda: vuln_include(specifier, inputs))  # passive IAST
    return None


_EXT_ID = re.compile(r"\s(SYSTEM|PUBLIC)\s")
_LITERALS = re.compile(r"\"[^\"]*\"|'[^']*'")
_ENTITY_BODY = re.compile(r"(%\s+)?(\S+)\s+(.*)\Z", re.DOTALL)
_EXTERNAL = re.compile(r"(SYSTEM|PUBLIC)\b", re.ASCII)


def parse_doctype(xml: str) -> Dict[str, Any]:
    """Reads the DOCTYPE: external DTD id and entity declarations."""
    at = xml.find("<!DOCTYPE")
    if at < 0:
        return {"has_doctype": False, "external_dtd": None, "entities": []}
    head = xml[at : at + 64 * 1024]
    bracket = head.find("[")
    close = head.find(">")
    # As String.slice: with no '>' at all the cut is -1 (all but the last character).
    decl = head[: bracket if 0 <= bracket < close else close]
    ext = _EXT_ID.search(decl)
    external_dtd = None
    if ext:
        lits = _LITERALS.findall(decl[ext.start() :])
        pick = lits[1] if ext.group(1) == "PUBLIC" and len(lits) > 1 else (lits[0] if lits else "")
        external_dtd = pick[1:-1]
    entities: List[Dict[str, Any]] = []
    start = 0
    while len(entities) < 1000:
        i = head.find("<!ENTITY", start)
        if i < 0:
            break
        end = head.find(">", i)
        body = (head[i + 8 :] if end < 0 else head[i + 8 : end]).strip()
        start = len(head) if end < 0 else end + 1
        m = _ENTITY_BODY.match(body)
        if not m:
            continue
        rest = m.group(3).strip()
        lits = _LITERALS.findall(rest)
        external = _EXTERNAL.match(rest) is not None
        uri = ""
        if external:
            k = 1 if rest.startswith("PUBLIC") else 0
            uri = lits[k][1:-1] if len(lits) > k else ""
        value = "" if external else (lits[0][1:-1] if lits else "")
        entities.append({"name": m.group(2), "external": external, "uri": uri, "value": value})
    return {"has_doctype": True, "external_dtd": external_dtd, "entities": entities}


_XXE_PROTOCOLS = frozenset("ftp dict gopher netdoc mailto jar php expect".split())
_URI_SCHEME = re.compile(r"([a-z][a-z0-9+.\-]*):", re.IGNORECASE)
_FILE_PREFIX = re.compile(r"^file:(//)?", re.IGNORECASE)
_SCHEMA_FILE = re.compile(r"\.(dtd|xsd|xml)\Z", re.IGNORECASE)
_ENTITY_REF = re.compile(r"[&%][^\s;]+;")


def detect_xml(xml: str, inputs: Sequence[RaspInput], resolves_external: bool) -> Optional[Finding]:
    # Passive IAST: request data parsed by a parser that resolves external entities, DOCTYPE or not.
    if xml and resolves_external:
        note_vulnerability(
            lambda: vuln_data("vuln.xml_external", xml, tainted_data(xml, [i for i in inputs if i.source == "request"]))
        )
    if not xml or "<!DOCTYPE" not in xml:
        return None
    inp = tainted_data(xml, inputs)
    if not inp:
        return None
    d = parse_doctype(xml)
    uris = [e["uri"] for e in d["entities"] if e["external"]]
    if d["external_dtd"] is not None:
        uris.append(d["external_dtd"])
    for u in uris:
        m = _URI_SCHEME.match(u)
        scheme = m.group(1).lower() if m else None
        if (scheme and scheme in _XXE_PROTOCOLS) or u.startswith("\\\\"):
            return Finding("xxe", "xxe.protocol", inp)
        if scheme == "file":
            p = _FILE_PREFIX.sub("", u, count=1)
            if (p.startswith("/") or _DRIVE.match(p) or "../" in p) and not _SCHEMA_FILE.search(p):
                return Finding("xxe", "xxe.file", inp)
    if uris:
        return Finding("xxe", "xxe.external_entity" if resolves_external else "xxe.doctype", inp)
    referencing = [e for e in d["entities"] if not e["external"] and _ENTITY_REF.search(e["value"])]
    if len(referencing) >= 3:
        return Finding("xxe", "xxe.billion_laughs", inp)
    return None


# The contract's tag pattern (OpenRASP xss_userinput) includes control characters on purpose.
_XSS_TAG = re.compile(r"<![\-\[A-Za-z]|<([A-Za-z]{1,12})[/>\x00-\x20]")
_XSS_HANDLER = re.compile(r"\bon[a-z]{3,}\s*=", re.IGNORECASE | re.ASCII)
MAX_XSS_BODY = 1024 * 1024


def detect_xss(content_type: Optional[str], body: str, inputs: Sequence[RaspInput]) -> Optional[Finding]:
    if not content_type or "html" not in content_type.lower() or not body or len(body) > MAX_XSS_BODY:
        return None
    for inp in inputs:
        v = inp.value
        if len(v) < 15:
            continue
        if not (_XSS_TAG.search(v) or "javascript:" in v.lower() or _XSS_HANDLER.search(v)):
            continue
        if v in body:
            return Finding("xss", "xss.reflected", inp)
    return None
