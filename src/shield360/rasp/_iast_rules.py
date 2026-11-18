"""Passive IAST rules (README "Passive IAST"). Pure: each takes what a
detector already computed (the sink text, its tokens, the inputs) and says
whether a request input reaches the sink verbatim in a place the app did not
parameterize, even though the value is harmless and the attack check found
nothing. The detectors call these through ``_iast_scope.py`` only when
passive IAST is armed for the current check, so the rules never run, and
never lex, when it is off. Mirrors the TypeScript SDK's ``iast-rules.ts``."""

from __future__ import annotations

import re
import unicodedata
from typing import Callable, List, NamedTuple, Optional, Sequence, Tuple

from shield360.rasp._lexers import SQL_KEYWORDS, Token, occurrences, overlapping
from shield360.rasp._types import RaspInput

VULN_RULES = (
    "vuln.sql_concat",
    "vuln.cmd_shell",
    "vuln.cmd_arg",
    "vuln.path_from_input",
    "vuln.ssrf_host",
    "vuln.code_eval",
    "vuln.include_from_input",
    "vuln.deser_input",
    "vuln.xml_external",
)


class Vuln(NamedTuple):
    """A vulnerability a rule found: the rule, the input, and where in the sink argument it sits."""

    rule: str
    input: RaspInput
    position: str


# Shortest input considered.
IAST_MIN_LENGTH = 3
# Letters-only inputs shorter than this are common words that also appear hard-coded ('active', 'name').
IAST_MIN_WORD_LENGTH = 8
# Digits-only inputs shorter than this are small numbers that also appear hard-coded (``LIMIT 100``).
IAST_MIN_NUMBER_LENGTH = 4

_BORING_WORDS = frozenset("true false null none nil undefined yes no on off asc desc".split())
_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_NUMBERISH = frozenset("0123456789.+-")


def qualifies(value: str) -> bool:
    """Whether an input value is specific enough that finding it verbatim in a
    sink means it came from the request, not a coincidence with a literal the
    app wrote itself. Conservative on purpose (README "Thresholds")."""
    v = value
    if len(v) < IAST_MIN_LENGTH:
        return False
    if v.lower() in _BORING_WORDS:
        return False
    if all(c in _ASCII_LETTERS for c in v) and len(v) < IAST_MIN_WORD_LENGTH:
        return False
    if all(c in _NUMBERISH for c in v) and len(v) < IAST_MIN_NUMBER_LENGTH:
        return False
    if all(c == v[0] for c in v):
        return False
    # Only spaces and punctuation: no Unicode letter (L*) or number (N*).
    return any(unicodedata.category(c)[0] in "LN" for c in v)


def _candidates(inputs: Sequence[RaspInput]) -> List[RaspInput]:
    return [i for i in inputs if i.source == "request" and qualifies(i.value)]


def _is_comment(t: Token) -> bool:
    return t.kind in ("comment", "version_comment")


# ---- SQL ----------------------------------------------------------------------


def vuln_sql(query: str, inputs: Sequence[RaspInput], tokens: Callable[[], List[Token]]) -> Optional[Vuln]:
    """vuln.sql_concat: an input sits in the query text inside a string literal,
    as a whole number literal, as a whole identifier (not a keyword), or as a
    run of whole tokens the attack check let through (a sort list such as
    ``created_at desc``). Never inside a comment (sqlcommenter tags), never
    when the input is the whole query (a SQL console)."""
    trimmed = query.strip()
    for inp in _candidates(inputs):
        v = inp.value
        if v == query or v.strip() == trimmed:
            continue
        for idx in occurrences(query, v):
            over = overlapping(tokens(), idx, len(v))
            if not over or any(_is_comment(t) for t in over):
                continue
            end = idx + len(v)
            if len(over) == 1:
                t = over[0]
                if t.kind == "string" and idx > t.s and end <= t.e:
                    return Vuln("vuln.sql_concat", inp, "string")
                whole = t.s == idx and t.e == end
                if whole and t.kind == "number":
                    return Vuln("vuln.sql_concat", inp, "number")
                if whole and t.kind == "name":
                    return Vuln("vuln.sql_concat", inp, "identifier")
                if whole and t.kind == "word" and t.text.lower() not in SQL_KEYWORDS:
                    return Vuln("vuln.sql_concat", inp, "identifier")
                continue
            if over[0].s == idx and over[-1].e == end:
                return Vuln("vuln.sql_concat", inp, "tokens")
    return None


# ---- Command ------------------------------------------------------------------


def vuln_shell(command: str, inputs: Sequence[RaspInput], tokens: List[Token]) -> Optional[Vuln]:
    """vuln.cmd_shell: an input sits inside one word of a shell-interpreted
    command (the attack check fires when it spans two or more tokens)."""
    trimmed = command.strip()
    for inp in _candidates(inputs):
        v = inp.value
        if v.strip() == trimmed:
            continue
        for idx in occurrences(command, v):
            over = overlapping(tokens, idx, len(v))
            if len(over) == 1 and over[0].kind == "word":
                return Vuln("vuln.cmd_shell", inp, "word")
    return None


def vuln_argv(argv: Sequence[str], inputs: Sequence[RaspInput]) -> Optional[Vuln]:
    """vuln.cmd_arg: an argument (not the executable) of an argv spawn without
    a shell equals or contains an input. The caller skips ``sh -c <script>``
    spawns, whose script is checked as shell text."""
    for inp in _candidates(inputs):
        for a in list(argv)[1:]:
            if isinstance(a, str) and inp.value in a:
                return Vuln("vuln.cmd_arg", inp, "argument")
    return None


# ---- Path ---------------------------------------------------------------------


def vuln_path(normalized_path: str, inputs: Sequence[RaspInput], norm: Callable[[str], str]) -> Optional[Vuln]:
    """vuln.path_from_input: an input (normalized like the path) forms whole
    path segments: it starts at the start of a segment and ends at the end of
    one, or right before a ``.`` in it (``/data/<input>.json``)."""
    np_ = normalized_path
    for inp in _candidates(inputs):
        ni = norm(inp.value)
        if not ni or ni == "/":
            continue
        for idx in occurrences(np_, ni):
            end = idx + len(ni)
            start_ok = idx == 0 or np_[idx - 1] == "/" or ni.startswith("/")
            end_ok = end == len(np_) or np_[end] in "/." or ni.endswith("/")
            if start_ok and end_ok:
                return Vuln("vuln.path_from_input", inp, "segment")
    return None


# ---- SSRF ---------------------------------------------------------------------

_SCHEME_AUTHORITY = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_AUTHORITY_END = re.compile(r"[/?#\\]")


def _authority_of(url: str, host: str) -> Optional[Tuple[str, int]]:
    """The ``host[:port]`` of a URL as written (lower-cased), and the offset
    just past the host itself (after any userinfo), or None without an authority."""
    m = _SCHEME_AUTHORITY.match(url)
    if not m:
        return None
    rest = url[m.end() :]
    e = _AUTHORITY_END.search(rest)
    auth = rest if e is None else rest[: e.start()]
    at = auth.rfind("@")
    host_start = m.end() + at + 1
    bracket = 2 if url[host_start : host_start + 1] == "[" else 0
    return auth[at + 1 :].lower(), host_start + len(host) + bracket


def vuln_ssrf(url: str, raw: dict, inputs: Sequence[RaspInput]) -> Optional[Vuln]:
    """vuln.ssrf_host: the URL's host is an input (equal to the host or to
    ``host:port``), or an input is a prefix of the URL that covers its scheme
    and host (a base URL or whole URL from the request). An input that merely
    mentions the host somewhere in longer text does not count."""
    host = raw.get("host") or ""
    auth = _authority_of(url, host) if host else None
    authority = auth[0] if auth else ""
    # The prefix must reach past the destination host itself, not a copy of it in the userinfo.
    if host:
        host_end = auth[1] if auth else len(url) + 1
    else:
        host_end = url.find(":") + 1
    for inp in _candidates(inputs):
        v = inp.value.lower()
        if host and v in (host, authority, f"[{host}]"):
            return Vuln("vuln.ssrf_host", inp, "host")
        if url.startswith(inp.value) and len(inp.value) >= host_end and (host or len(inp.value) > host_end):
            return Vuln("vuln.ssrf_host", inp, "url")
    return None


# ---- Code, include, deserialization, XML ----------------------------------------


def vuln_code(code: str, inputs: Sequence[RaspInput], tokens: Callable[[], List[Token]]) -> Optional[Vuln]:
    """vuln.code_eval: an input sits inside a string literal of evaluated code,
    or is a whole identifier or number in it (the attack check fires when it
    spans two or more tokens or is the whole code). Never inside a comment."""
    for inp in _candidates(inputs):
        v = inp.value
        if v == code:
            continue
        for idx in occurrences(code, v):
            over = overlapping(tokens(), idx, len(v))
            if len(over) != 1:
                continue
            t = over[0]
            end = idx + len(v)
            if t.kind == "string" and idx > t.s and end <= t.e:
                return Vuln("vuln.code_eval", inp, "string")
            if t.s == idx and t.e == end and t.kind in ("word", "number"):
                return Vuln("vuln.code_eval", inp, "identifier" if t.kind == "word" else "number")
    return None


def vuln_include(specifier: str, inputs: Sequence[RaspInput]) -> Optional[Vuln]:
    """vuln.include_from_input: a module specifier contains an input (the attack check covers equal and path-like inputs)."""
    for inp in _candidates(inputs):
        if inp.value != specifier and inp.value in specifier:
            return Vuln("vuln.include_from_input", inp, "specifier")
    return None


def vuln_data(rule: str, data: str, inp: Optional[RaspInput]) -> Optional[Vuln]:
    """vuln.deser_input / vuln.xml_external: the data handed to an unsafe
    deserializer, or to an XML parser that resolves external entities, is
    tainted (the caller decides with the contract's tainted_data), at least
    3 characters long, by an input that qualifies."""
    if inp is None or inp.source != "request" or len(data) < IAST_MIN_LENGTH or not qualifies(inp.value):
        return None
    return Vuln(rule, inp, "data")
