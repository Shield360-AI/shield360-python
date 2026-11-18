"""One-pass lexers used by the structural checks: SQL, shell and a generic
C-like lexer for code. No regex backtracking; every loop advances."""

from __future__ import annotations

from typing import List, NamedTuple, Tuple


class Token(NamedTuple):
    s: int
    e: int
    kind: str
    text: str


SQL_DIALECTS = ("mysql", "postgres", "sqlite", "mssql", "oracle", "db2", "generic")

# SQL keywords that are not data: OpenRASP's anti-detect list (README "SQL",
# rule 1). sqli.userinput ignores them; passive IAST never takes one for an
# identifier from input.
SQL_KEYWORDS = frozenset(
    (
        "add all alter analyze and any as asc avg begin between by case create count delete desc do dumpfile else elseif end "
        "exists false file float flush follows from group having identified if in insert interval into join last like limit "
        "loop not null on or order procedure regexp return rlike select then true union update values xor"
    ).split()
)

_SPACE = frozenset(" \t\n\r\f\v")
_DIGIT = frozenset("0123456789")
_ID_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_ID_CHAR = _ID_START | _DIGIT | {"$"}
_HEX = _DIGIT | frozenset("abcdefABCDEF")
# Oracle and DB2 identifiers may contain '#' after the first character.
_ID_CHAR_HASH = _ID_CHAR | {"#"}
_ALT_QUOTE_CLOSE = {"[": "]", "{": "}", "(": ")", "<": ">"}

_SQL_OPS = ("->>", "<=", ">=", "<>", "!=", "||", "&&", "::", ":=", "->", "<<", ">>")


def sql_tokens(q: str, dialect: str = "generic") -> List[Token]:
    """Tokenizes SQL per the contract's lexer."""
    out: List[Token] = []
    n = len(q)
    hash_comment = dialect in ("mysql", "generic")
    bracket_ident = dialect in ("mssql", "generic")
    dollar_quote = dialect in ("postgres", "generic")
    oracle = dialect == "oracle"
    db2 = dialect == "db2"
    # E'' (backslash escapes) is not a prefix in Oracle or DB2.
    e_prefix = not oracle and not db2
    id_char = _ID_CHAR_HASH if oracle or db2 else _ID_CHAR

    def at(j: int) -> str:
        return q[j] if 0 <= j < n else ""

    def push(s: int, e: int, kind: str) -> None:
        out.append(Token(s, e, kind, q[s:e]))

    def quoted(start: int, close: str, backslash: bool) -> int:
        # Reads a quoted run starting at start (q[start] is the quote); returns the end index.
        j = start + 1
        while j < n:
            c = q[j]
            if backslash and c == "\\":
                j += 2
                continue
            if c == close:
                if at(j + 1) == close:
                    j += 2
                    continue
                return j + 1
            j += 1
        return n

    def name_part(j: int) -> int:
        # A name part: identifier or quoted identifier; returns its end or -1.
        c = at(j)
        if c in _ID_START and c:
            k = j + 1
            while k < n and q[k] in id_char:
                k += 1
            return k
        if c in ('"', "`"):
            return quoted(j, c, False)
        if c == "[" and bracket_ident:
            return quoted(j, "]", False)
        return -1

    def alt_quoted(j: int) -> int:
        # Oracle alternative quoting q'X…X' (also nq'…'), the quote at j; returns
        # its end or -1. The delimiter X is one character other than whitespace.
        d = at(j + 1)
        if not d or d in _SPACE:
            return -1
        close = _ALT_QUOTE_CLOSE.get(d, d) + "'"
        k = q.find(close, j + 2)
        return n if k < 0 else k + 2

    nested_comments = dialect in ("db2", "postgres", "mssql")

    def block_comment(i: int) -> int:
        # A block comment starting at i; nests in db2, postgres and mssql.
        if not nested_comments:
            k = q.find("*/", i + 2)
            return n if k < 0 else k + 2
        depth = 1
        k = i + 2
        while k < n:
            if q.startswith("/*", k):
                depth += 1
                k += 2
            elif q.startswith("*/", k):
                k += 2
                depth -= 1
                if depth == 0:
                    return k
            else:
                k += 1
        return n

    i = 0
    while i < n:
        c = q[i]
        if c in _SPACE:
            i += 1
            continue
        start = i
        # comments
        if c == "-" and at(i + 1) == "-":
            k = q.find("\n", i)
            i = n if k < 0 else k
            push(start, i, "comment")
            continue
        if c == "#" and hash_comment:
            k = q.find("\n", i)
            i = n if k < 0 else k
            push(start, i, "comment")
            continue
        if c == "/" and at(i + 1) == "*":
            i = block_comment(i)
            push(start, i, "version_comment" if at(start + 2) == "!" else "comment")
            continue
        # strings, with E'' / N'' prefixes
        if c == "'":
            i = quoted(i, "'", dialect == "mysql")
            push(start, i, "string")
            continue
        if oracle:
            # q'…' / nq'…' alternative quoting
            p = i + 1 if c in ("N", "n") else i
            if at(p) in ("q", "Q") and at(p + 1) == "'":
                k = alt_quoted(p + 1)
                if k > 0:
                    i = k
                    push(start, i, "string")
                    continue
        if db2:
            # X'' hex, G'' graphic, GX'' / UX'' / BX'' hex strings
            g = c in ("G", "g")
            p = i + 1 if (g or c in ("U", "u", "B", "b")) and at(i + 1) in ("X", "x") else i
            if (p > i or g or c in ("X", "x")) and at(p + 1) == "'":
                i = quoted(p + 1, "'", False)
                push(start, i, "string")
                continue
        if (c in ("N", "n") or (e_prefix and c in ("E", "e"))) and at(i + 1) == "'":
            i = quoted(i + 1, "'", dialect == "mysql" or c in "Ee")
            push(start, i, "string")
            continue
        # dollar quotes and $n placeholders
        if c == "$":
            if at(i + 1) in _DIGIT and at(i + 1):
                k = i + 1
                while k < n and q[k] in _DIGIT:
                    k += 1
                i = k
                push(start, i, "placeholder")
                continue
            if dollar_quote:
                k = i + 1
                while k < n and (q[k] in _ID_START or q[k] in _DIGIT):
                    k += 1
                if at(k) == "$":
                    tag = q[i : k + 1]
                    end = q.find(tag, k + 1)
                    i = n if end < 0 else end + len(tag)
                    push(start, i, "string")
                    continue
        # placeholders
        if c == "?":
            i += 1
            push(start, i, "placeholder")
            continue
        if c in ":@" and at(i + 1) in _ID_START and at(i + 1) and not (c == ":" and at(i - 1) == ":"):
            k = i + 1
            while k < n and q[k] in id_char:
                k += 1
            i = k
            push(start, i, "placeholder")
            continue
        if oracle and c == ":" and at(i + 1) in _DIGIT and at(i - 1) != ":":
            # Oracle positional bind :1
            k = i + 1
            while k < n and q[k] in _DIGIT:
                k += 1
            i = k
            push(start, i, "placeholder")
            continue
        if c == "@" and at(i + 1) == "@" and at(i + 2) in _ID_START and at(i + 2):
            k = i + 2
            while k < n and q[k] in _ID_CHAR:
                k += 1
            i = k
            push(start, i, "word")
            continue
        if c == "%" and at(i + 1) == "s":
            i += 2
            push(start, i, "placeholder")
            continue
        if c == "%" and at(i + 1) == "(":
            k = q.find(")", i + 2)
            if k > 0 and at(k + 1) == "s":
                i = k + 2
                push(start, i, "placeholder")
                continue
        # numbers
        if c in _DIGIT or (c == "." and at(i + 1) in _DIGIT and at(i + 1)):
            k = i
            if c == "0" and at(i + 1) in ("x", "X"):
                k = i + 2
                while k < n and q[k] in _HEX:
                    k += 1
            else:
                while k < n and q[k] in _DIGIT:
                    k += 1
                if at(k) == ".":
                    k += 1
                    while k < n and q[k] in _DIGIT:
                        k += 1
                # at() is "" past the end, and "" is not in _DIGIT, so the membership test alone decides.
                if at(k) in ("e", "E") and (at(k + 1) in _DIGIT or (at(k + 1) in ("+", "-") and at(k + 2) in _DIGIT)):
                    k += 2
                    while k < n and q[k] in _DIGIT:
                        k += 1
            i = k
            push(start, i, "number")
            continue
        # identifiers and qualified names (one token)
        first = name_part(i)
        if first > 0:
            k = first
            while at(k) == ".":
                nxt = name_part(k + 1)
                if nxt < 0:
                    break
                k = nxt
            i = k
            push(start, i, "word" if c in _ID_START and k == first else "name")
            continue
        # operators
        op = next((o for o in _SQL_OPS if q.startswith(o, i)), None)
        i += len(op) if op else 1
        push(start, i, "op")
    return out


_SHELL_OPS = ("&&", "||", ">>", "<<", "$(", ";", "&", "|", ">", "<", "(", ")", "`", "\n")


def shell_tokens(cmd: str) -> Tuple[List[Token], bytearray]:
    """Shell tokens; ``in_single[i]`` marks characters inside single quotes."""
    out: List[Token] = []
    n = len(cmd)
    in_single = bytearray(n)
    i = 0
    word_start = -1
    dq = False

    def end_word(e: int) -> None:
        nonlocal word_start
        if 0 <= word_start < e:
            out.append(Token(word_start, e, "word", cmd[word_start:e]))
        word_start = -1

    while i < n:
        c = cmd[i]
        if not dq:
            if c in (" ", "\t"):
                end_word(i)
                i += 1
                continue
            op = next((o for o in _SHELL_OPS if cmd.startswith(o, i)), None)
            if op:
                end_word(i)
                out.append(Token(i, i + len(op), "op", op))
                i += len(op)
                continue
            if word_start < 0:
                word_start = i
            if c == "\\":
                i += 2
                continue
            if c == "'":
                k = cmd.find("'", i + 1)
                end = n if k < 0 else k + 1
                in_single[i:end] = b"\x01" * (end - i)
                i = end
                continue
            if c == '"':
                dq = True
                i += 1
                continue
            i += 1
            continue
        # inside double quotes
        if c == "\\":
            if word_start < 0:
                word_start = i
            i += 2
            continue
        if c == '"':
            if word_start < 0:
                word_start = i
            dq = False
            i += 1
            continue
        if c == "`" or (c == "$" and i + 1 < n and cmd[i + 1] == "("):
            end_word(i)
            ln = 1 if c == "`" else 2
            out.append(Token(i, i + ln, "op", cmd[i : i + ln]))
            i += ln
            continue
        if word_start < 0:
            word_start = i
        i += 1
    end_word(n)
    return out, in_single


def code_tokens(src: str) -> List[Token]:
    """A generic C-like lexer: identifiers, numbers, quoted strings, comments, punctuation."""
    out: List[Token] = []
    n = len(src)
    i = 0
    while i < n:
        c = src[i]
        if c in _SPACE:
            i += 1
            continue
        s = i
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            k = src.find("\n", i)
            i = n if k < 0 else k
            out.append(Token(s, i, "comment", src[s:i]))
            continue
        if c == "/" and nxt == "*":
            k = src.find("*/", i + 2)
            i = n if k < 0 else k + 2
            out.append(Token(s, i, "comment", src[s:i]))
            continue
        if c in ('"', "'", "`"):
            k = i + 1
            while k < n and src[k] != c:
                k += 2 if src[k] == "\\" else 1
            i = min(n, k + 1)
            out.append(Token(s, i, "string", src[s:i]))
            continue
        if c in _DIGIT:
            k = i + 1
            while k < n and (src[k] in _ID_CHAR or src[k] == "."):
                k += 1
            i = k
            out.append(Token(s, i, "number", src[s:i]))
            continue
        if c in _ID_START or c == "$" or ord(c) > 127:
            k = i + 1
            while k < n and (src[k] in _ID_CHAR or ord(src[k]) > 127):
                k += 1
            i = k
            out.append(Token(s, i, "word", src[s:i]))
            continue
        i += 1
        out.append(Token(s, i, "op", c))
    return out


def overlapping(tokens: List[Token], idx: int, length: int) -> List[Token]:
    """Tokens overlapping [idx, idx+length)."""
    end = idx + length
    out: List[Token] = []
    for t in tokens:
        if t.s >= end:
            break
        if t.e > idx:
            out.append(t)
    return out


def occurrences(hay: str, needle: str, limit: int = 8) -> List[int]:
    """Start offsets of ``needle`` in ``hay``, at most ``limit``."""
    out: List[int] = []
    if not needle:
        return out
    start = 0
    while len(out) < limit:
        i = hay.find(needle, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out
