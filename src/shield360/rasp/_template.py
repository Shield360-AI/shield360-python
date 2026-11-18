"""Structural template-source check (sdk/rasp/README.md, "Template source").
Only template *source* is inspected; data arguments are deliberately never
read. Python port of sdk/typescript/src/rasp/template.ts."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from shield360.rasp._lexers import Token, code_tokens, occurrences, overlapping
from shield360.rasp._types import Finding, RaspInput


def _engine(**fields: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "pairs": [],
        "literal": [],
        "tags": [],
        "directives": [],
        "lineComment": [],
        "lineCode": [],
        "attrs": [],
        "escape": "",
        "spaceLiteral": False,
        "pug": False,
    }
    base.update(fields)
    return base


def _jinja() -> List[List[str]]:
    return [["{{", "}}", "quoted"], ["{%", "%}", "quoted"]]


# The contract table sdk/rasp/rules/template-engines.json, verbatim (a test compares).
# Order inside each list matters: the first match wins.
TEMPLATE_ENGINES: Dict[str, Dict[str, Any]] = {
    "handlebars": _engine(
        pairs=[["{{{", "}}}", "quoted"], ["{{", "}}", "quoted"]], literal=[["{{!--", "--}}"], ["{{!", "}}"]], escape="\\"
    ),
    "ejs": _engine(pairs=[["<%", "%>", "first"]], literal=[["<%#", "%>"]]),
    "lodash": _engine(pairs=[["<%", "%>", "first"], ["${", "}", "first"]], literal=[["<%#", "%>"]]),
    "pug": _engine(pairs=[["#{", "}", "bracket"], ["!{", "}", "bracket"]], pug=True),
    "nunjucks": _engine(pairs=_jinja(), literal=[["{#", "#}"], ["{% raw %}", "{% endraw %}"]]),
    "jinja2": _engine(pairs=_jinja(), literal=[["{#", "#}"], ["{% raw %}", "{% endraw %}"]]),
    "minijinja": _engine(pairs=_jinja(), literal=[["{#", "#}"], ["{% raw %}", "{% endraw %}"]]),
    "tera": _engine(pairs=_jinja(), literal=[["{#", "#}"], ["{% raw %}", "{% endraw %}"]]),
    "twig": _engine(pairs=_jinja(), literal=[["{#", "#}"], ["{% verbatim %}", "{% endverbatim %}"]]),
    "pebble": _engine(pairs=_jinja(), literal=[["{#", "#}"], ["{% verbatim %}", "{% endverbatim %}"]]),
    "django": _engine(
        pairs=[["{{", "}}", "first"], ["{%", "%}", "first"]],
        literal=[["{#", "#}"], ["{% comment %}", "{% endcomment %}"], ["{% verbatim %}", "{% endverbatim %}"]],
    ),
    "liquid": _engine(pairs=_jinja(), literal=[["{% comment %}", "{% endcomment %}"], ["{% raw %}", "{% endraw %}"]]),
    "scriban": _engine(pairs=[["{{", "}}", "quoted"]], literal=[["{%{", "}%}"]]),
    "gotemplate": _engine(pairs=[["{{", "}}", "quoted"]], literal=[["{{/*", "*/"], ["{{- /*", "*/"]]),
    "mako": _engine(
        pairs=[["${", "}", "bracket"], ["<%", "%>", "first"]],
        literal=[["<%doc>", "</%doc>"], ["<%text>", "</%text>"]],
        tags=[["<%", ">"], ["</%", ">"]],
        lineComment=["##"],
        lineCode=["%"],
    ),
    "freemarker": _engine(
        pairs=[["${", "}", "bracket"], ["#{", "}", "bracket"]],
        literal=[["<#--", "-->"], ["<#noparse>", "</#noparse>"]],
        tags=[["<#", ">"], ["</#", ">"], ["<@", ">"], ["</@", ">"]],
    ),
    "velocity": _engine(
        pairs=[["$!{", "}", "bracket"], ["${", "}", "bracket"]],
        literal=[["#*", "*#"], ["##", "\n"], ["#[[", "]]#"]],
        directives=["$!", "$", "#"],
        escape="\\",
    ),
    "thymeleaf": _engine(
        pairs=[["[[", "]]", "quoted"], ["[(", ")]", "quoted"]],
        literal=[["<!--/*", "*/-->"]],
        attrs=["th:", "data-th-"],
    ),
    "smarty": _engine(pairs=[["{", "}", "quoted"]], literal=[["{*", "*}"], ["{literal}", "{/literal}"]], spaceLiteral=True),
    "blade": _engine(
        pairs=[["{!!", "!!}", "first"], ["{{", "}}", "first"], ["@php", "@endphp", "first"]],
        literal=[["{{--", "--}}"], ["@verbatim", "@endverbatim"]],
        directives=["@"],
        escape="@",
    ),
}

_SPACE = frozenset(" \t\n\r\f\v")
_ID_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_WORD = _ID_START | frozenset("0123456789")
_ATTR = _WORD | {":", "-"}
# Pug line regexes with ASCII \w and \s (README: "Line regexes use ASCII \w").
_PUG_MARKER = re.compile(r"\s*(?:-\s*|(?:[\w.#-]+\s*)?!?=\s*)", re.ASCII)
_PUG_TAG = re.compile(r"\s*\+?[\w.#:-]+", re.ASCII)
_PUG_REST = re.compile(r"!?=\s*", re.ASCII)


def _ch(source: str, i: int) -> str:
    """The character at ``i``, or "" outside the source (never wraps around)."""
    return source[i] if 0 <= i < len(source) else ""


def _skip_quoted(source: str, i: int) -> int:
    """Index just past a quoted run starting at ``i`` (source[i] is the quote)."""
    quote = source[i]
    n = len(source)
    k = i + 1
    while k < n and source[k] != quote:
        k += 2 if source[k] == "\\" else 1
    return min(n, k + 1)


def _quoted_close(source: str, start: int, close: str) -> int:
    """First ``close`` outside quoted strings (engines that lex strings inside an expression)."""
    i = start
    n = len(source)
    while i < n:
        c = source[i]
        if c in ('"', "'"):
            i = _skip_quoted(source, i)
            continue
        if source.startswith(close, i):
            return i
        i += 1
    return -1


def _bracket_close(source: str, start: int) -> int:
    """The bracket closing depth zero, skipping quoted strings and nested brackets."""
    depth = 0
    i = start
    n = len(source)
    while i < n:
        c = source[i]
        if c in ('"', "'", "`"):
            i = _skip_quoted(source, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if not depth:
                return i
            depth -= 1
        i += 1
    return -1


_LITERAL_GAP = _SPACE | {"-", "+", "~"}


def _literal_at(source: str, i: int, pattern: str) -> int:
    """End of literal-block ``pattern`` matched at ``i``, or -1; a space matches
    any run (possibly empty) of whitespace, ``-``, ``+`` and ``~``."""
    k = i
    n = len(source)
    for c in pattern:
        if c == " ":
            while k < n and source[k] in _LITERAL_GAP:
                k += 1
        elif k < n and source[k] == c:
            k += 1
        else:
            return -1
    return k


def _region_code(body: str) -> List[Token]:
    """Code tokens of a region body. Template expressions have no ``//`` or
    ``/*`` comments: both are operators."""
    out: List[Token] = []
    pos = 0
    while pos < len(body):
        resume = -1
        for t in code_tokens(body[pos:]):
            start = pos + t.s
            if t.kind == "comment":
                out.append(Token(start, start + 1, "op", "/"))
                out.append(Token(start + 1, start + 2, "op", body[start + 1]))
                resume = start + 2
                break
            out.append(Token(start, pos + t.e, t.kind, t.text))
        if resume < 0:
            break
        pos = resume
    return out


def _merge_paths(tokens: List[Token]) -> List[Token]:
    """A dotted property path (``user.name``) is one reference, like a single variable name."""
    out: List[Token] = []
    i = 0
    n = len(tokens)
    while i < n:
        token = tokens[i]
        while (
            token.kind == "word"
            and i + 2 < n
            and tokens[i + 1].text == "."
            and tokens[i + 1].s == token.e
            and tokens[i + 2].kind == "word"
            and tokens[i + 2].s == tokens[i + 1].e
        ):
            token = Token(token.s, tokens[i + 2].e, token.kind, f"{token.text}.{tokens[i + 2].text}")
            i += 2
        out.append(token)
        i += 1
    return out


def _first(items: Sequence[Any], test: Any) -> Any:
    for item in items:
        if test(item):
            return item
    return None


def template_tokens(source: str, engine: str) -> List[Token]:  # pylint: disable=too-many-branches,too-many-statements,too-many-locals
    """Template tokens: boundary delimiters plus code tokens of each expression
    region; literal template text yields nothing. Unknown engine: no tokens."""
    s = TEMPLATE_ENGINES.get(engine)
    tokens: List[Token] = []
    if s is None:
        return tokens
    n = len(source)

    def region(start: int, open_len: int, end: int, close_len: int) -> None:
        tokens.append(Token(start, start + open_len, "delimiter", ""))
        base = start + open_len
        for t in _merge_paths(_region_code(source[base:end])):
            tokens.append(Token(t.s + base, t.e + base, t.kind, t.text))
        if close_len:
            tokens.append(Token(end, end + close_len, "delimiter", ""))

    def line_end_at(i: int) -> int:
        end = source.find("\n", i)
        return n if end < 0 else end

    i = 0
    while i < n:
        line_start = i == 0 or source[i - 1] == "\n"
        if s["pug"] and line_start:
            line_end = line_end_at(i)
            line = source[i:line_end]
            # Pug's line code and buffered expressions; ordinary tag/text lines stay literal.
            marker = _PUG_MARKER.match(line)
            if marker:
                region(i, len(marker.group(0)), line_end, 0)
                i = line_end
                continue
            # Tag or mixin attributes are JavaScript expressions: `a(href=url)`, `+card(item)`.
            tag_m = _PUG_TAG.match(line)
            if tag_m and _ch(source, i + len(tag_m.group(0))) == "(":
                open_at = i + len(tag_m.group(0))
                close = _bracket_close(source, open_at + 1)
                if close >= 0:
                    region(open_at, 1, close, 1)
                    i = close + 1
                    rest_end = line_end_at(i)
                    rest = _PUG_REST.match(source[i:rest_end])
                    if rest:
                        region(i, len(rest.group(0)), rest_end, 0)
                        i = rest_end
                    continue
        if line_start and (s["lineComment"] or s["lineCode"]):
            j = i
            while _ch(source, j) in (" ", "\t"):
                j += 1
            line_end = line_end_at(i)
            if any(source.startswith(p, j) for p in s["lineComment"]):
                i = line_end
                continue
            code = _first(s["lineCode"], lambda p, j=j: source.startswith(p, j) and not source.startswith(p, j + len(p)))
            if code is not None:
                region(i, j + len(code) - i, line_end, 0)
                i = line_end
                continue
        # First match wins: literal blocks, tags, attributes, pairs, directives.
        literal = _first(s["literal"], lambda p, i=i: _literal_at(source, i, p[0]) >= 0)
        tag = (
            None
            if literal
            else _first(s["tags"], lambda p, i=i: source.startswith(p[0], i) and _ch(source, i + len(p[0])) in _ID_START)
        )
        attr: Optional[str] = None
        quote = -1
        if not literal and not tag and (i == 0 or source[i - 1] in _SPACE):
            for p in s["attrs"]:
                if not source.startswith(p, i):
                    continue
                k = i + len(p)
                while _ch(source, k) in _ATTR:
                    k += 1
                if k == i + len(p):
                    continue
                while _ch(source, k) in _SPACE:
                    k += 1
                if _ch(source, k) != "=":
                    continue
                k += 1
                while _ch(source, k) in _SPACE:
                    k += 1
                if _ch(source, k) in ('"', "'"):
                    attr = p
                    quote = k
                    break
        pair = None if literal or tag or attr else _first(s["pairs"], lambda p, i=i: source.startswith(p[0], i))
        directive = (
            None
            if literal or tag or attr or pair
            else _first(
                s["directives"],
                lambda p, i=i: source.startswith(p, i)
                and _ch(source, i + len(p)) in _ID_START
                and _ch(source, i - 1) not in _WORD,
            )
        )
        opener = tag[0] if tag else attr if attr else pair[0] if pair else directive
        if not literal and opener is None:
            i += 1
            continue
        start = _literal_at(source, i, literal[0]) if literal else i + len(opener)
        # An escaped opener (`\{{`, `@{{`) is literal; a doubled escape (`\\{{`) leaves it live.
        esc = s["escape"]
        if esc and _ch(source, i - 1) == esc and _ch(source, i - 2) != esc:
            i = start
            continue
        if literal:
            i = n
            for j in range(start, n):
                end = _literal_at(source, j, literal[1])
                if end >= 0:
                    i = end
                    break
            continue
        if tag:
            end = _quoted_close(source, start, tag[1])
            if end < 0:
                i = start
                continue
            region(i, len(tag[0]), end, len(tag[1]))
            i = end + len(tag[1])
            continue
        if attr:
            end = source.find(source[quote], quote + 1)
            if end < 0:
                i = start
                continue
            region(quote, 1, end, 1)
            i = end + 1
            continue
        if directive is not None:
            tokens.append(Token(i, start, "delimiter", ""))
            k = start
            while _ch(source, k) in _WORD or _ch(source, k) == ".":
                k += 1
            while _ch(source, k - 1) == ".":
                k -= 1
            tokens.append(Token(start, k, "word", source[start:k]))
            i = k
            if _ch(source, k) == "(":
                close = _bracket_close(source, k + 1)
                if close >= 0:
                    region(k, 1, close, 1)
                    i = close + 1
            continue
        open_text, close_text, mode = pair
        if s["spaceLiteral"] and _ch(source, start) in _SPACE:
            i = start
            continue
        # Closing delimiters inside quotes end an expression only where the engine itself ignores quotes.
        if mode == "bracket":
            end = _bracket_close(source, start)
        elif mode == "quoted":
            end = _quoted_close(source, start, close_text)
        else:
            end = source.find(close_text, start)
        if end < 0:
            i = start
            continue
        region(i, len(open_text), end, len(close_text))
        i = end + len(close_text)
    return tokens


def detect_template(source: Any, inputs: Sequence[RaspInput], engine: str) -> Optional[Finding]:
    """Input must introduce a template boundary or span multiple expression
    tokens. An engine missing from the table is not checked."""
    if not isinstance(source, str) or not source or engine not in TEMPLATE_ENGINES:
        return None
    tokens: Optional[List[Token]] = None
    for inp in inputs:
        if len(inp.value) < 3:
            continue
        for idx in occurrences(source, inp.value):
            if tokens is None:
                tokens = template_tokens(source, engine)
            span = overlapping(tokens, idx, len(inp.value))
            if len(span) >= 2 or any(t.kind == "delimiter" for t in span):
                return Finding("code_injection", "code.template_injection", inp)
    return None
