"""Custom RASP rule expressions (sdk/rasp/README.md "Custom rules").

A small, sandboxed, CEL-style expression language: a fixed set of fields,
string literals, comparison, ``in``, a handful of string methods, a safe
regular-expression subset matched in linear time, and CIDR matching, joined
by ``&&``, ``||`` and ``!``. No loops, no function definitions, no I/O,
nothing outside the fields. Expressions are parsed and type-checked once and
evaluated as data; nothing downloaded is ever run as code.

A port of the TypeScript SDK's ``rule-expr.ts`` (which the platform shares
byte for byte), with the same grammar, types and limits, so a rule the
platform accepts runs identically here. Rule regexes never touch Python's
``re`` (it backtracks): they run on the same Pike VM as TypeScript, whose work
is linear in the subject. Strings are read as code points.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field as dc_field
from types import MappingProxyType
from typing import Any, List, Mapping, Optional, Sequence, Tuple, Union

#: Hard limits, identical on the platform and in every SDK.
RULE_EXPR_LIMITS: Mapping[str, int] = MappingProxyType(
    {
        # UTF-8 bytes of the whole expression.
        "expressionBytes": 2048,
        # AST depth (a leaf is 1), and parenthesis nesting.
        "depth": 12,
        # AST nodes.
        "nodes": 128,
        # UTF-8 bytes of one string literal, after escapes.
        "stringBytes": 1024,
        # Items in one ``in [...]`` list.
        "listItems": 64,
        # ``matches`` calls in one expression.
        "regexes": 8,
        # UTF-8 bytes of one pattern.
        "regexBytes": 256,
        # Atoms of one pattern once counted repetitions are expanded.
        "regexAtoms": 256,
        # The largest bound in ``{n}``, ``{n,}``, ``{n,m}``.
        "regexRepeat": 100,
        # ``matches`` reads at most this many code points of its subject.
        "matchCodePoints": 4096,
    }
)

_EXPRESSION_BYTES = RULE_EXPR_LIMITS["expressionBytes"]
_DEPTH = RULE_EXPR_LIMITS["depth"]
_NODES = RULE_EXPR_LIMITS["nodes"]
_STRING_BYTES = RULE_EXPR_LIMITS["stringBytes"]
_LIST_ITEMS = RULE_EXPR_LIMITS["listItems"]
_REGEXES = RULE_EXPR_LIMITS["regexes"]
_REGEX_BYTES = RULE_EXPR_LIMITS["regexBytes"]
_REGEX_ATOMS = RULE_EXPR_LIMITS["regexAtoms"]
_REGEX_REPEAT = RULE_EXPR_LIMITS["regexRepeat"]
_MATCH_CODE_POINTS = RULE_EXPR_LIMITS["matchCodePoints"]

ERROR_CODES = (
    "empty",
    "too_long",
    "syntax",
    "depth",
    "nodes",
    "string_too_long",
    "list_too_long",
    "unknown_field",
    "unknown_method",
    "type",
    "regex",
    "too_many_regexes",
    "cidr",
)

#: The fields an expression may read (README "Custom rules: fields").
RULE_FIELDS: Mapping[str, str] = MappingProxyType(
    {
        "request.method": "string",
        "request.path": "string",
        "request.route": "string",
        "request.ip": "string",
        "request.headers": "map",
        "request.query": "map",
        "request.body": "map",
        "input.value": "string",
        "input.key": "string",
        "input.source": "string",
        "sink.name": "string",
        "attack.type": "string",
        "attack.rule": "string",
        "app.name": "string",
    }
)

#: Work left for one evaluation (regex VM steps), per request. Exhausting it
#: ends the evaluation as no match. The same default as TypeScript.
DEFAULT_RULE_BUDGET = 4_000_000


#: How often (in VM steps) the regex VM reads the clock for the time budget.
_CLOCK_EVERY = 1024


class RuleBudget:
    """Work left for one request's custom rules: regex VM steps (the contract's
    budget, as in TypeScript) and, optionally, wall-clock seconds (a Python
    safeguard: string work outside the VM is slower here). Exhausting either
    ends the evaluation as no match and marks the budget spent."""

    __slots__ = ("steps", "time_left", "deadline", "timed_out")

    def __init__(self, steps: int = DEFAULT_RULE_BUDGET, time_left: Optional[float] = None):
        self.steps = steps
        # Seconds left across every evaluation charged to this budget (None = no time cap).
        self.time_left = time_left
        # Set while an evaluation runs: the monotonic time it must stop by.
        self.deadline: Optional[float] = None
        self.timed_out = False


def _check_clock(budget: RuleBudget) -> None:
    """Ends the evaluation when the time budget is spent (and marks every budget left spent)."""
    if budget.deadline is not None and time.monotonic() > budget.deadline:
        budget.timed_out = True
        budget.steps = -1
        raise _BudgetExhausted()


@dataclass(frozen=True)
class RuleExprError:
    code: str
    pos: int


@dataclass
class CompiledRuleExpr:
    ast: Any
    # Field names read (without map keys), sorted.
    fields: List[str]
    # ``finding`` when the expression reads ``sink.*`` or ``attack.*``, else ``request``.
    phase: str
    # Reads ``input.*``: evaluated once per input, true when any input makes it true.
    uses_input: bool
    # Reads ``request.body[...]``.
    uses_body: bool


@dataclass
class RuleExprResult:
    ok: bool
    expr: Optional[CompiledRuleExpr] = None
    error: Optional[RuleExprError] = None


@dataclass
class RuleEvalResult:
    matched: bool
    # The input that matched (an expression reading ``input.*``), as given in the subject.
    input: Any = None
    exhausted: bool = False


class _ExprError(Exception):
    def __init__(self, code: str, pos: int):
        super().__init__(code)
        self.code = code
        self.pos = pos


class _BudgetExhausted(Exception):
    pass


class _RegexError(Exception):
    pass


def utf8_length(s: str) -> int:
    """UTF-8 length of a string (a lone surrogate counts 3, as its U+FFFD replacement)."""
    n = 0
    for ch in s:
        c = ord(ch)
        if c < 0x80:
            n += 1
        elif c < 0x800:
            n += 2
        elif c < 0x10000:
            n += 3
        else:
            n += 4
    return n


# JavaScript's String.prototype.trim set, so "only whitespace" means the same as on the platform.
_JS_SPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)


_ASCII_LOWER = str.maketrans({chr(c): chr(c + 32) for c in range(0x41, 0x5B)})


def _ascii_lower(s: str) -> str:
    return s.translate(_ASCII_LOWER)


# ---- AST ----------------------------------------------------------------------
#
# Nodes are tuples, tag first:
#   ("str", v) ("bool", v) ("null",) ("field", name, key|None) ("not", x)
#   ("and", [xs]) ("or", [xs]) ("cmp", op, l, r) ("in", l, items)
#   ("str_method", m, t, arg) ("lower", t) ("matches", t, prog) ("cidr", t, net)

# ---- lexer --------------------------------------------------------------------

_OPS2 = ("==", "!=", "<=", ">=", "&&", "||")
_OPS1 = "()[],.<>!"
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_DEC_DIGITS = frozenset("0123456789")


def _is_ident_start(c: str) -> bool:
    return ("a" <= c <= "z") or ("A" <= c <= "Z") or c == "_"


def _is_ident_part(c: str) -> bool:
    return _is_ident_start(c) or ("0" <= c <= "9")


# A token: (kind, value, pos); kind is "ident", "str", "op" or "eof".
_Tok = Tuple[str, str, int]


def _lex(src: str) -> List[_Tok]:  # pylint: disable=too-many-branches,too-many-statements
    toks: List[_Tok] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in " \t\n\r":
            i += 1
            continue
        start = i
        raw = c in "rR" and i + 1 < n and src[i + 1] in "\"'"
        if c in "\"'" or raw:
            if raw:
                i += 1
            quote = src[i]
            i += 1
            parts: List[str] = []
            while True:
                if i >= n:
                    raise _ExprError("syntax", start)
                d = src[i]
                if d == quote:
                    i += 1
                    break
                if ord(d) < 0x20:
                    raise _ExprError("syntax", i)
                if d == "\\" and not raw:
                    e = src[i + 1] if i + 1 < n else ""
                    if e in ("\\", '"', "'") and e:
                        parts.append(e)
                    elif e == "n":
                        parts.append("\n")
                    elif e == "r":
                        parts.append("\r")
                    elif e == "t":
                        parts.append("\t")
                    elif e == "u":
                        h = src[i + 2 : i + 6]
                        if len(h) != 4 or any(x not in _HEX_DIGITS for x in h):
                            raise _ExprError("syntax", i)
                        code = int(h, 16)
                        if 0xD800 <= code <= 0xDFFF:
                            raise _ExprError("syntax", i)
                        parts.append(chr(code))
                        i += 4
                    else:
                        raise _ExprError("syntax", i)
                    i += 2
                    continue
                parts.append(d)
                i += 1
            v = "".join(parts)
            if utf8_length(v) > _STRING_BYTES:
                raise _ExprError("string_too_long", start)
            toks.append(("str", v, start))
            continue
        if _is_ident_start(c):
            while i < n and _is_ident_part(src[i]):
                i += 1
            toks.append(("ident", src[start:i], start))
            continue
        two = src[i : i + 2]
        if two in _OPS2:
            toks.append(("op", two, start))
            i += 2
            continue
        if c in _OPS1:
            toks.append(("op", c, start))
            i += 1
            continue
        raise _ExprError("syntax", i)
    toks.append(("eof", "", n))
    return toks


# ---- parser -------------------------------------------------------------------

_KEYWORDS = frozenset(("true", "false", "null", "in"))
_STR_METHODS = frozenset(("startsWith", "endsWith", "contains"))
_METHODS = frozenset(("startsWith", "endsWith", "contains", "lowerAscii", "matches", "inCidr"))
_CMP_OPS = frozenset(("==", "!=", "<", "<=", ">", ">="))


class _Parser:
    def __init__(self, toks: List[_Tok]):
        self.toks = toks
        self.i = 0
        self.nodes = 0
        # Parenthesis nesting, and nested `!` (each adds AST depth): both bounded while parsing.
        self.parens = 0
        self.nots = 0
        self.regexes = 0

    def peek(self, o: int = 0) -> _Tok:
        return self.toks[min(self.i + o, len(self.toks) - 1)]

    def next(self) -> _Tok:
        t = self.peek()
        if self.i < len(self.toks) - 1:
            self.i += 1
        return t

    def is_op(self, v: str, o: int = 0) -> bool:
        t = self.peek(o)
        return t[0] == "op" and t[1] == v

    def expect_op(self, v: str) -> _Tok:
        t = self.next()
        if t[0] != "op" or t[1] != v:
            raise _ExprError("syntax", t[2])
        return t

    def count(self, n: int, pos: int) -> None:
        self.nodes += n
        if self.nodes > _NODES:
            raise _ExprError("nodes", pos)

    def parse(self) -> Any:
        node = self.or_()
        t = self.peek()
        if t[0] != "eof":
            raise _ExprError("syntax", t[2])
        return node

    def or_(self) -> Any:
        pos = self.peek()[2]
        xs = [self.and_()]
        while self.is_op("||"):
            self.next()
            xs.append(self.and_())
        if len(xs) == 1:
            return xs[0]
        self.count(1, pos)
        return ("or", xs)

    def and_(self) -> Any:
        pos = self.peek()[2]
        xs = [self.relation()]
        while self.is_op("&&"):
            self.next()
            xs.append(self.relation())
        if len(xs) == 1:
            return xs[0]
        self.count(1, pos)
        return ("and", xs)

    def relation(self) -> Any:
        left = self.unary()
        t = self.peek()
        if t[0] == "op" and t[1] in _CMP_OPS:
            self.next()
            right = self.unary()
            self.count(1, t[2])
            return ("cmp", t[1], left, right)
        if t[0] == "ident" and t[1] == "in":
            self.next()
            self.expect_op("[")
            items: List[str] = []
            while not self.is_op("]"):
                s = self.next()
                if s[0] != "str":
                    raise _ExprError("syntax", s[2])
                items.append(s[1])
                if len(items) > _LIST_ITEMS:
                    raise _ExprError("list_too_long", s[2])
                if self.is_op(","):
                    self.next()
                elif not self.is_op("]"):
                    raise _ExprError("syntax", self.peek()[2])
            self.next()
            self.count(2 + len(items), t[2])
            return ("in", left, items)
        return left

    def unary(self) -> Any:
        t = self.peek()
        if self.is_op("!"):
            self.next()
            self.nots += 1
            if self.nots > _DEPTH:
                raise _ExprError("depth", t[2])
            x = self.unary()
            self.nots -= 1
            self.count(1, t[2])
            return ("not", x)
        return self.member()

    def member(self) -> Any:
        node = self.primary()
        while self.is_op("."):
            self.next()
            name = self.next()
            if name[0] != "ident":
                raise _ExprError("syntax", name[2])
            if not self.is_op("("):
                raise _ExprError("syntax", self.peek()[2])
            self.next()
            arg: Optional[str] = None
            if self.peek()[0] == "str":
                arg = self.next()[1]
            self.expect_op(")")
            method = name[1]
            if method not in _METHODS:
                raise _ExprError("unknown_method", name[2])
            if method == "lowerAscii":
                if arg is not None:
                    raise _ExprError("type", name[2])
                self.count(1, name[2])
                node = ("lower", node)
                continue
            if arg is None:
                raise _ExprError("type", name[2])
            self.count(2, name[2])
            if method in _STR_METHODS:
                node = ("str_method", method, node, arg)
            elif method == "matches":
                self.regexes += 1
                if self.regexes > _REGEXES:
                    raise _ExprError("too_many_regexes", name[2])
                prog = compile_regex(arg)
                if prog is None:
                    raise _ExprError("regex", name[2])
                node = ("matches", node, prog)
            else:
                net = parse_cidr(arg)
                if net is None:
                    raise _ExprError("cidr", name[2])
                node = ("cidr", node, net)
        return node

    def primary(self) -> Any:  # pylint: disable=too-many-return-statements
        t = self.next()
        kind, v, pos = t
        if kind == "str":
            self.count(1, pos)
            return ("str", v)
        if kind == "op" and v == "(":
            self.parens += 1
            if self.parens > _DEPTH:
                raise _ExprError("depth", pos)
            node = self.or_()
            self.parens -= 1
            self.expect_op(")")
            return node
        if kind == "ident":
            if v in ("true", "false"):
                self.count(1, pos)
                return ("bool", v == "true")
            if v == "null":
                self.count(1, pos)
                return ("null",)
            if v in _KEYWORDS:
                raise _ExprError("syntax", pos)
            # A dotted field name; a segment followed by `(` is a method call.
            name = v
            while self.is_op(".") and self.peek(1)[0] == "ident" and not self.is_op("(", 2):
                self.next()
                name += "." + self.next()[1]
            ftype = RULE_FIELDS.get(name)
            if ftype is None:
                raise _ExprError("unknown_field", pos)
            key: Optional[str] = None
            if self.is_op("["):
                opened = self.next()
                s = self.next()
                if s[0] != "str":
                    raise _ExprError("syntax", s[2])
                self.expect_op("]")
                if ftype != "map":
                    raise _ExprError("type", opened[2])
                # Header names are case-insensitive: ASCII lower-cased here, as the SDKs record them.
                key = _ascii_lower(s[1]) if name == "request.headers" else s[1]
            elif ftype == "map":
                raise _ExprError("type", pos)
            self.count(1, pos)
            return ("field", name, key)
        raise _ExprError("syntax", pos)


# ---- types --------------------------------------------------------------------


def _type_of(n: Any) -> str:  # pylint: disable=too-many-return-statements,too-many-branches
    k = n[0]
    if k == "str":
        return "string"
    if k == "bool":
        return "bool"
    if k == "null":
        return "null"
    if k == "field":
        return "string"
    if k == "not":
        if _type_of(n[1]) != "bool":
            raise _ExprError("type", 0)
        return "bool"
    if k in ("and", "or"):
        for x in n[1]:
            if _type_of(x) != "bool":
                raise _ExprError("type", 0)
        return "bool"
    if k == "cmp":
        left = _type_of(n[2])
        right = _type_of(n[3])
        if n[1] in ("==", "!="):
            strish = left in ("string", "null") and right in ("string", "null")
            if not (strish or (left == "bool" and right == "bool")):
                raise _ExprError("type", 0)
        elif left != "string" or right != "string":
            raise _ExprError("type", 0)
        return "bool"
    if k in ("in", "str_method", "matches", "cidr"):
        target = n[1] if k == "in" else (n[2] if k == "str_method" else n[1])
        if _type_of(target) != "string":
            raise _ExprError("type", 0)
        return "bool"
    if k == "lower":
        if _type_of(n[1]) != "string":
            raise _ExprError("type", 0)
        return "string"
    raise _ExprError("syntax", 0)


def _depth_of(n: Any) -> int:
    k = n[0]
    if k == "not":
        return 1 + _depth_of(n[1])
    if k in ("and", "or"):
        return 1 + max(_depth_of(x) for x in n[1])
    if k == "cmp":
        return 1 + max(_depth_of(n[2]), _depth_of(n[3]))
    if k == "in":
        return 1 + max(_depth_of(n[1]), 2)
    if k == "str_method":
        return 1 + max(_depth_of(n[2]), 1)
    if k in ("matches", "cidr"):
        return 1 + max(_depth_of(n[1]), 1)
    if k == "lower":
        return 1 + _depth_of(n[1])
    return 1


def _collect_fields(n: Any, out: set) -> None:
    k = n[0]
    if k == "field":
        out.add(n[1])
    elif k == "not":
        _collect_fields(n[1], out)
    elif k in ("and", "or"):
        for x in n[1]:
            _collect_fields(x, out)
    elif k == "cmp":
        _collect_fields(n[2], out)
        _collect_fields(n[3], out)
    elif k == "str_method":
        _collect_fields(n[2], out)
    elif k in ("in", "matches", "cidr", "lower"):
        _collect_fields(n[1], out)


def compile_rule_expr(src: Any) -> RuleExprResult:
    """Parses and type-checks an expression. Every limit is checked here; an
    expression that compiles is safe to evaluate on any input. Never raises."""
    try:
        if not isinstance(src, str) or src.strip(_JS_SPACE) == "":
            return RuleExprResult(False, error=RuleExprError("empty", 0))
        if utf8_length(src) > _EXPRESSION_BYTES:
            return RuleExprResult(False, error=RuleExprError("too_long", 0))
        ast = _Parser(_lex(src)).parse()
        if _type_of(ast) != "bool":
            raise _ExprError("type", 0)
        if _depth_of(ast) > _DEPTH:
            raise _ExprError("depth", 0)
        found: set = set()
        _collect_fields(ast, found)
        fields = sorted(found)
        phase = "finding" if any(f.startswith(("sink.", "attack.")) for f in fields) else "request"
        return RuleExprResult(
            True,
            expr=CompiledRuleExpr(
                ast=ast,
                fields=fields,
                phase=phase,
                uses_input=any(f.startswith("input.") for f in fields),
                uses_body="request.body" in found,
            ),
        )
    except _ExprError as e:
        return RuleExprResult(False, error=RuleExprError(e.code, e.pos))
    except Exception:  # pylint: disable=broad-exception-caught
        return RuleExprResult(False, error=RuleExprError("syntax", 0))


# ---- evaluation ---------------------------------------------------------------


def _get(obj: Any, name: str) -> Any:
    """A member of a subject part: a dict key, or an attribute (``RaspInput``)."""
    if isinstance(obj, dict):
        return obj.get(name)
    if obj is None or isinstance(obj, (str, bytes, int, float, list)):
        return None
    return getattr(obj, name, None)


def _string(v: Any) -> Optional[str]:
    return v if isinstance(v, str) else None


def _own(m: Any, key: Optional[str]) -> Optional[str]:
    if not isinstance(m, dict) or key is None or key not in m:
        return None
    return _string(m[key])


def _field(n: Any, s: Any, inp: Any) -> Optional[str]:  # pylint: disable=too-many-return-statements
    name = n[1]
    if name.startswith("request."):
        r = _get(s, "request")
        if not isinstance(r, dict):
            return None
        part = name[8:]
        if part in ("headers", "query", "body"):
            return _own(r.get(part), n[2])
        return _string(r.get(part))
    if name.startswith("input."):
        return _string(_get(inp, name[6:])) if inp is not None else None
    if name == "sink.name":
        return _string(_get(s, "sink"))
    if name.startswith("attack."):
        a = _get(s, "attack")
        return _string(a.get(name[7:])) if isinstance(a, dict) else None
    if name == "app.name":
        return _string(_get(s, "app"))
    return None


def _ev(n: Any, s: Any, inp: Any, budget: RuleBudget) -> Union[str, bool, None]:  # pylint: disable=too-many-return-statements,too-many-branches
    k = n[0]
    if k in ("str", "bool"):
        return n[1]
    if k == "null":
        return None
    if k == "field":
        return _field(n, s, inp)
    if k == "not":
        return not _ev(n[1], s, inp, budget)
    if k == "and":
        for x in n[1]:
            if not _ev(x, s, inp, budget):
                return False
        return True
    if k == "or":
        for x in n[1]:
            if _ev(x, s, inp, budget):
                return True
        return False
    if k == "cmp":
        op = n[1]
        left = _ev(n[2], s, inp, budget)
        right = _ev(n[3], s, inp, budget)
        if op in ("==", "!="):
            same = type(left) is type(right) and left == right
            return same if op == "==" else not same
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        # Python orders str by code point, as the contract asks.
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        return left >= right
    if k == "in":
        left = _ev(n[1], s, inp, budget)
        return isinstance(left, str) and left in n[2]
    if k == "str_method":
        t = _ev(n[2], s, inp, budget)
        if not isinstance(t, str):
            return False
        m = n[1]
        if m == "startsWith":
            return t.startswith(n[3])
        if m == "endsWith":
            return t.endswith(n[3])
        return n[3] in t
    if k == "lower":
        t = _ev(n[1], s, inp, budget)
        _check_clock(budget)
        return _ascii_lower(t) if isinstance(t, str) else None
    if k == "matches":
        t = _ev(n[1], s, inp, budget)
        return isinstance(t, str) and _run_regex(n[2], t[:_MATCH_CODE_POINTS], budget)
    if k == "cidr":
        t = _ev(n[1], s, inp, budget)
        return isinstance(t, str) and _in_cidr(t, n[2])
    return False


def _is_input(v: Any) -> bool:
    return isinstance(v, dict) or (v is not None and hasattr(v, "value") and hasattr(v, "key"))


def evaluate_rule_expr(expr: CompiledRuleExpr, subject: Any, budget: Optional[RuleBudget] = None) -> RuleEvalResult:
    """Evaluates a compiled expression against a subject (a dict: ``app``,
    ``request`` {method, path, route, ip, headers, query, body}, ``inputs``,
    ``sink``, ``attack`` {type, rule}; missing parts read as null). An
    expression that reads ``input.*`` is evaluated once per input, in order,
    and matches when any input makes it true (with no inputs, once with the
    input fields null). Never raises: an evaluation that runs out of budget,
    or fails in any way, is no match."""
    b = budget if budget is not None else RuleBudget()
    started = time.monotonic()
    if b.time_left is not None:
        if b.time_left <= 0:
            b.timed_out = True
            b.steps = -1
            return RuleEvalResult(False, exhausted=True)
        b.deadline = started + b.time_left
    try:
        _check_clock(b)
        if not expr.uses_input:
            return RuleEvalResult(_ev(expr.ast, subject, None, b) is True)
        inputs = _get(subject, "inputs")
        if not isinstance(inputs, (list, tuple)):
            inputs = []
        if not inputs:
            return RuleEvalResult(_ev(expr.ast, subject, None, b) is True)
        for inp in inputs:
            _check_clock(b)
            if _is_input(inp) and _ev(expr.ast, subject, inp, b) is True:
                return RuleEvalResult(True, input=inp)
        return RuleEvalResult(False)
    except _BudgetExhausted:
        return RuleEvalResult(False, exhausted=True)
    except Exception:  # pylint: disable=broad-exception-caught
        return RuleEvalResult(False)
    finally:
        if b.time_left is not None:
            b.time_left -= time.monotonic() - started
            b.deadline = None


# ---- regular expressions --------------------------------------------------------
#
# Regex AST nodes (tuples): ("char", c) ("any",) ("class", ranges, neg) ("bol",)
# ("eol",) ("cat", [xs]) ("alt", [xs]) ("rep", x, min, max)  (max -1 = unbounded)

_MAX_CP = 0x10FFFF
_DIGIT_RANGES = (0x30, 0x39)
_WORD_RANGES = (0x30, 0x39, 0x41, 0x5A, 0x5F, 0x5F, 0x61, 0x7A)
_SPACE_RANGES = (0x09, 0x0D, 0x20, 0x20)
_META = frozenset("\\.^$|?*+()[]{}")
_ESCAPABLE = frozenset("\\.^$|?*+()[]{}/-")


def _complement(r: Sequence[int]) -> List[int]:
    pairs = sorted((r[i], r[i + 1]) for i in range(0, len(r), 2))
    out: List[int] = []
    nxt = 0
    for lo, hi in pairs:
        if lo > nxt:
            out.extend((nxt, lo - 1))
        nxt = max(nxt, hi + 1)
    if nxt <= _MAX_CP:
        out.extend((nxt, _MAX_CP))
    return out


class _RegexParser:
    def __init__(self, cp: List[int]):
        self.cp = cp
        self.i = 0

    def peek(self) -> Optional[int]:
        return self.cp[self.i] if self.i < len(self.cp) else None

    def ch(self, c: str) -> bool:
        return self.i < len(self.cp) and self.cp[self.i] == ord(c)

    def parse(self) -> Any:
        n = self.alt()
        if self.i < len(self.cp):
            raise _RegexError()
        return n

    def alt(self) -> Any:
        xs = [self.cat()]
        while self.ch("|"):
            self.i += 1
            xs.append(self.cat())
        return xs[0] if len(xs) == 1 else ("alt", xs)

    def cat(self) -> Any:
        xs = []
        while self.i < len(self.cp) and not self.ch("|") and not self.ch(")"):
            xs.append(self.piece())
        return xs[0] if len(xs) == 1 else ("cat", xs)

    def piece(self) -> Any:
        atom = self.atom()
        q = self.quant()
        if q is None:
            return atom
        if atom[0] in ("bol", "eol"):
            raise _RegexError()
        if _has_rep(atom):
            raise _RegexError()  # nested quantifier
        if _atoms_of(atom) == 0:
            raise _RegexError()  # nothing to repeat
        return ("rep", atom, q[0], q[1])

    def num(self) -> Optional[int]:
        s = ""
        while True:
            c = self.peek()
            if c is None or not 0x30 <= c <= 0x39:
                break
            s += chr(c)
            self.i += 1
            if len(s) > 3:
                raise _RegexError()
        return int(s) if s else None

    def quant(self) -> Optional[Tuple[int, int]]:
        q: Optional[Tuple[int, int]] = None
        if self.ch("*"):
            q = (0, -1)
        elif self.ch("+"):
            q = (1, -1)
        elif self.ch("?"):
            q = (0, 1)
        if q is not None:
            self.i += 1
        elif self.ch("{"):
            self.i += 1
            lo = self.num()
            if lo is None:
                raise _RegexError()
            hi = lo
            if self.ch(","):
                self.i += 1
                m = self.num()
                hi = -1 if m is None else m
            if not self.ch("}"):
                raise _RegexError()
            self.i += 1
            if lo > _REGEX_REPEAT or hi > _REGEX_REPEAT or (hi != -1 and hi < lo):
                raise _RegexError()
            q = (lo, hi)
        else:
            return None
        if self.ch("?"):
            self.i += 1  # lazy: the same language, so the same answer
        if self.ch("*") or self.ch("+") or self.ch("?") or self.ch("{"):
            raise _RegexError()
        return q

    def escape(self) -> Any:  # pylint: disable=too-many-return-statements
        self.i += 1  # the backslash
        c = self.peek()
        if c is None:
            raise _RegexError()
        self.i += 1
        # Only ASCII has meaning after a backslash.
        e = chr(c) if c < 0x80 else ""
        if e in ("d", "D"):
            return ("class", _DIGIT_RANGES, e == "D")
        if e in ("w", "W"):
            return ("class", _WORD_RANGES, e == "W")
        if e in ("s", "S"):
            return ("class", _SPACE_RANGES, e == "S")
        simple = {"n": 0x0A, "r": 0x0D, "t": 0x09, "f": 0x0C, "v": 0x0B}
        if e in simple:
            return ("char", simple[e])
        if e in ("x", "u"):
            n = 2 if e == "x" else 4
            digits = self.cp[self.i : self.i + n]
            if len(digits) != n or any(d >= 0x80 or chr(d) not in _HEX_DIGITS for d in digits):
                raise _RegexError()
            code = int("".join(chr(d) for d in digits), 16)
            if 0xD800 <= code <= 0xDFFF:
                raise _RegexError()
            self.i += n
            return ("char", code)
        if e and e in _ESCAPABLE:
            return ("char", c)
        raise _RegexError()

    def atom(self) -> Any:  # pylint: disable=too-many-return-statements
        c = self.cp[self.i]
        # Operators are ASCII; any other code point is a literal.
        s = chr(c) if c < 0x80 else ""
        if s == "(":
            self.i += 1
            if self.ch("?"):
                self.i += 1
                if not self.ch(":"):
                    raise _RegexError()  # lookaround, named groups, flags
                self.i += 1
            inner = self.alt()
            if not self.ch(")"):
                raise _RegexError()
            self.i += 1
            return inner
        if s == "[":
            return self.cls()
        if s == ".":
            self.i += 1
            return ("any",)
        if s == "^":
            self.i += 1
            return ("bol",)
        if s == "$":
            self.i += 1
            return ("eol",)
        if s == "\\":
            return self.escape()
        if s and s in _META:
            raise _RegexError()
        self.i += 1
        return ("char", c)

    def cls_item(self) -> Any:
        c = self.peek()
        if c is None:
            raise _RegexError()
        if c == 0x5C:
            return self.escape()
        if c == 0x5B:
            raise _RegexError()  # unescaped [ inside a class
        self.i += 1
        return ("char", c)

    def cls(self) -> Any:
        self.i += 1  # [
        neg = False
        if self.ch("^"):
            neg = True
            self.i += 1
        r: List[int] = []
        while not self.ch("]"):
            if self.i >= len(self.cp):
                raise _RegexError()
            a = self.cls_item()
            # `-` between two items is a range; at the start or right before `]` it is literal.
            nxt = self.cp[self.i + 1] if self.i + 1 < len(self.cp) else None
            if self.ch("-") and nxt is not None and nxt != 0x5D:
                self.i += 1  # -
                b = self.cls_item()
                if a[0] != "char" or b[0] != "char" or a[1] > b[1]:
                    raise _RegexError()
                r.extend((a[1], b[1]))
            elif a[0] == "char":
                r.extend((a[1], a[1]))
            elif a[0] == "class":
                r.extend(_complement(a[1]) if a[2] else a[1])
            else:
                raise _RegexError()
        self.i += 1  # ]
        if not r:
            raise _RegexError()
        return ("class", tuple(r), neg)


def _has_rep(n: Any) -> bool:
    if n[0] == "rep":
        return True
    if n[0] in ("cat", "alt"):
        return any(_has_rep(x) for x in n[1])
    return False


def _atoms_of(n: Any) -> int:
    """Atoms once counted repetitions are expanded (README "Regular expressions")."""
    k = n[0]
    if k in ("char", "any", "class"):
        return 1
    if k in ("bol", "eol"):
        return 0
    if k in ("cat", "alt"):
        return sum(_atoms_of(x) for x in n[1])
    # rep: the copies the program holds: min, then one loop (unbounded) or max - min optional ones.
    return _atoms_of(n[1]) * (n[2] + 1 if n[3] == -1 else n[3])


# Program instructions: [op, a, b].
_I_CHAR, _I_ANY, _I_CLASS, _I_SPLIT, _I_JMP, _I_BOL, _I_EOL, _I_MATCH = range(8)


def _emit(n: Any, prog: List[List[Any]]) -> None:
    k = n[0]
    if k == "char":
        prog.append([_I_CHAR, n[1], None])
    elif k == "any":
        prog.append([_I_ANY, None, None])
    elif k == "class":
        prog.append([_I_CLASS, n[1], n[2]])
    elif k == "bol":
        prog.append([_I_BOL, None, None])
    elif k == "eol":
        prog.append([_I_EOL, None, None])
    elif k == "cat":
        for x in n[1]:
            _emit(x, prog)
    elif k == "alt":
        # split L1, next; L1: x0; jmp end; next: split ... ; last
        jumps = []
        xs = n[1]
        for idx, x in enumerate(xs):
            if idx < len(xs) - 1:
                split = [_I_SPLIT, len(prog) + 1, -1]
                prog.append(split)
                _emit(x, prog)
                j = [_I_JMP, -1, None]
                prog.append(j)
                jumps.append(j)
                split[2] = len(prog)
            else:
                _emit(x, prog)
        for j in jumps:
            j[1] = len(prog)
    else:  # rep
        x, lo, hi = n[1], n[2], n[3]
        for _ in range(lo):
            _emit(x, prog)
        if hi == -1:
            # L: split body, end; body; jmp L
            top = len(prog)
            split = [_I_SPLIT, top + 1, -1]
            prog.append(split)
            _emit(x, prog)
            prog.append([_I_JMP, top, None])
            split[2] = len(prog)
        else:
            for _ in range(lo, hi):
                split = [_I_SPLIT, len(prog) + 1, -1]
                prog.append(split)
                _emit(x, prog)
                split[2] = len(prog)


class RegexProgram:
    """A compiled pattern: parallel instruction arrays for the Pike VM."""

    __slots__ = ("ops", "a", "b")

    def __init__(self, insts: List[List[Any]]):
        self.ops = [i[0] for i in insts]
        self.a = [i[1] for i in insts]
        self.b = [i[2] for i in insts]

    def __len__(self) -> int:
        return len(self.ops)


def compile_regex(pattern: Any) -> Optional[RegexProgram]:
    """Checks a pattern against the safe subset and compiles it; None when refused."""
    try:
        if not isinstance(pattern, str) or utf8_length(pattern) > _REGEX_BYTES:
            return None
        ast = _RegexParser([ord(c) for c in pattern]).parse()
        if _atoms_of(ast) > _REGEX_ATOMS:
            return None
        insts: List[List[Any]] = []
        _emit(ast, insts)
        insts.append([_I_MATCH, None, None])
        return RegexProgram(insts)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def is_safe_regex(pattern: Any) -> bool:
    """Whether a pattern is in the safe subset."""
    return compile_regex(pattern) is not None


def _run_regex(prog: RegexProgram, subject: str, budget: RuleBudget) -> bool:  # pylint: disable=too-many-locals,too-many-branches
    """Pike VM: every thread advances in lock step, one code point at a time, so
    the work is at most (subject length + 1) x (program size). True when some
    substring of the subject (respecting ``^`` and ``$``) is in the pattern's language."""
    ops, a_, b_ = prog.ops, prog.a, prog.b
    mark = [-1] * len(ops)
    gen = 0
    length = len(subject)
    clist: List[int] = []

    def add(lst: List[int], pc0: int, pos: int) -> bool:
        stack = [pc0]
        pop, push = stack.pop, stack.append
        while stack:
            pc = pop()
            if mark[pc] == gen:
                continue
            mark[pc] = gen
            budget.steps -= 1
            if budget.steps < 0:
                raise _BudgetExhausted()
            if not budget.steps % _CLOCK_EVERY:
                _check_clock(budget)
            op = ops[pc]
            if op == _I_JMP:
                push(a_[pc])
            elif op == _I_SPLIT:
                push(b_[pc])
                push(a_[pc])
            elif op == _I_BOL:
                if pos == 0:
                    push(pc + 1)
            elif op == _I_EOL:
                if pos == length:
                    push(pc + 1)
            elif op == _I_MATCH:
                return True
            else:
                lst.append(pc)
        return False

    pos = 0
    while True:
        # Threads already in clist were marked with this generation when added.
        if add(clist, 0, pos):
            return True
        if pos == length:
            return False
        c = ord(subject[pos])
        gen += 1
        nlist: List[int] = []
        for pc in clist:
            op = ops[pc]
            if op == _I_ANY:
                ok = True
            elif op == _I_CHAR:
                ok = a_[pc] == c
            else:
                r = a_[pc]
                hit = False
                for k in range(0, len(r), 2):
                    if r[k] <= c <= r[k + 1]:
                        hit = True
                        break
                ok = hit != b_[pc]
            if ok and add(nlist, pc + 1, pos + 1):
                return True
        clist = nlist
        pos += 1


# ---- CIDR ---------------------------------------------------------------------


@dataclass(frozen=True)
class Net:
    bytes: Tuple[int, ...] = dc_field(default=())
    prefix: int = 128


def _dec_part(p: str) -> bool:
    """``^(0|[1-9][0-9]{0,2})$``."""
    return 1 <= len(p) <= 3 and all(c in _DEC_DIGITS for c in p) and (p == "0" or p[0] != "0")


def _parse_v4(s: str) -> Optional[List[int]]:
    parts = s.split(".")
    if len(parts) != 4:
        return None
    out: List[int] = []
    for p in parts:
        if not _dec_part(p):
            return None
        n = int(p)
        if n > 255:
            return None
        out.append(n)
    return out


def _v6_groups(h: str) -> Optional[List[int]]:
    if h == "":
        return []
    out: List[int] = []
    parts = h.split(":")
    for k, p in enumerate(parts):
        if k == len(parts) - 1 and "." in p:
            t = _parse_v4(p)
            if t is None:
                return None
            out.extend(((t[0] << 8) | t[1], (t[2] << 8) | t[3]))
        else:
            if not 1 <= len(p) <= 4 or any(c not in _HEX_DIGITS for c in p):
                return None
            out.append(int(p, 16))
    return out


def parse_ip_bytes(s: Any) -> Optional[List[int]]:
    """An IPv4 or IPv6 address as 16 bytes (IPv4 as ``::ffff:a.b.c.d``); None when not an address."""
    if not isinstance(s, str) or len(s) > 64:
        return None
    v4 = _parse_v4(s)
    if v4 is not None:
        return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] + v4
    if ":" not in s:
        return None
    halves = s.split("::")
    if len(halves) > 2:
        return None
    head = _v6_groups(halves[0])
    tail = _v6_groups(halves[1]) if len(halves) == 2 else []
    if head is None or tail is None:
        return None
    if len(halves) == 2 and halves[0] != "" and "." in halves[0]:
        return None
    if len(halves) == 2:
        if len(head) + len(tail) > 7:
            return None
        words = head + [0] * (8 - len(head) - len(tail)) + tail
    else:
        if len(head) != 8:
            return None
        words = head
    out: List[int] = []
    for w in words:
        out.extend((w >> 8, w & 0xFF))
    return out


def parse_cidr(s: Any) -> Optional[Net]:
    """``a.b.c.d/n``, ``x:y::z/n``, or a bare address (all bits). None when malformed."""
    if not isinstance(s, str):
        return None
    slash = s.find("/")
    addr = s if slash == -1 else s[:slash]
    if "%" in addr:
        return None
    b = parse_ip_bytes(addr)
    if b is None:
        return None
    v4 = _parse_v4(addr) is not None
    prefix = 128
    if slash != -1:
        p = s[slash + 1 :]
        if not _dec_part(p):
            return None
        n = int(p)
        if n > (32 if v4 else 128):
            return None
        prefix = n + 96 if v4 else n
    return Net(tuple(b), prefix)


def _in_cidr(ip: str, net: Net) -> bool:
    pct = ip.find("%")
    b = parse_ip_bytes(ip if pct == -1 else ip[:pct])
    if b is None:
        return False
    bits = net.prefix
    k = 0
    while k < 16 and bits > 0:
        mask = 0xFF if bits >= 8 else (0xFF << (8 - bits)) & 0xFF
        if (b[k] & mask) != (net.bytes[k] & mask):
            return False
        k += 1
        bits -= 8
    return True


def in_cidr(ip: Any, net: Net) -> bool:
    """Whether ``ip`` is an address in ``net`` (a zone on the address is dropped)."""
    return isinstance(ip, str) and _in_cidr(ip, net)
