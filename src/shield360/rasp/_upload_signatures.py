"""Upload signatures (sdk/rasp/README.md "Uploads", "Signatures"): the small,
YARA-like rule format for web shells and the organization's own rules, as the
TypeScript SDK and the platform read it (upload-signatures.ts). Rules are data;
every string, rule count and regex step is bounded. Bytes are handled as
Latin-1 text (one character a byte), as the contract says."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from shield360.rasp._rule_expr import RuleBudget, _BudgetExhausted, _run_regex, compile_regex

LIMITS = {
    "rules": 64,
    "total_bytes": 65536,
    "strings_per_rule": 16,
    "min_bytes": 3,
    "max_bytes": 256,
    "anchor_max": 64,
    "condition_chars": 256,
    "condition_depth": 8,
    "title_chars": 120,
    "window_before": 256,
    "window_after": 1024,
    "anchors_per_piece": 8,
    "regex_steps": 1_000_000,
    "overlap": 2048,
}
#: A Python safeguard on top of the step budget: seconds of regex work a file may take.
REGEX_SECONDS = 0.25

_RULE_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,47}")
_STRING_ID = re.compile(r"[a-z][a-z0-9_]{0,15}")
_HEX = re.compile(r"[0-9a-fA-F]{2}( ?[0-9a-fA-F]{2})*")
_RESERVED = ("and", "or", "not", "any", "all")


class SignatureError(Exception):
    def __init__(self, code: str, string: Optional[str] = None):
        super().__init__(code)
        self.code = code
        self.string = string


def ascii_lower(s: str) -> str:
    """Folds ASCII letters only."""
    return re.sub(r"[A-Z]+", lambda m: m.group(0).lower(), s)


def utf8_latin1(s: str) -> str:
    return s.encode("utf-8").decode("latin-1")


class _String:  # pylint: disable=too-few-public-methods
    __slots__ = ("id", "kind", "bytes", "nocase", "prog")

    def __init__(self, sid: str, kind: str, data: str, nocase: bool, prog: Any = None):
        self.id, self.kind, self.bytes, self.nocase, self.prog = sid, kind, data, nocase, prog


class Signature:  # pylint: disable=too-few-public-methods
    __slots__ = ("id", "title", "strings", "cond")

    def __init__(self, sid: str, title: str, strings: List[_String], cond: Tuple[Any, ...]):
        self.id, self.title, self.strings, self.cond = sid, title, strings, cond


def _compile_string(raw: Any) -> _String:
    if not isinstance(raw, dict):
        raise SignatureError("string_kind")
    sid = raw.get("id")
    if not isinstance(sid, str) or not _STRING_ID.fullmatch(sid) or sid in _RESERVED:
        raise SignatureError("string_id", sid if isinstance(sid, str) else None)
    kinds = [k for k in ("text", "hex", "regex") if raw.get(k) is not None]
    if len(kinds) != 1:
        raise SignatureError("string_kind", sid)
    nocase = raw.get("nocase") is True
    lo, hi = LIMITS["min_bytes"], LIMITS["max_bytes"]
    if isinstance(raw.get("text"), str):
        b = utf8_latin1(raw["text"])
        if not lo <= len(b) <= hi:
            raise SignatureError("text", sid)
        return _String(sid, "text", ascii_lower(b) if nocase else b, nocase)
    if isinstance(raw.get("hex"), str):
        h = raw["hex"].strip()
        if not _HEX.fullmatch(h):
            raise SignatureError("hex", sid)
        b = bytes.fromhex(h.replace(" ", "")).decode("latin-1")
        if not lo <= len(b) <= hi:
            raise SignatureError("hex", sid)
        return _String(sid, "hex", b, False)
    if isinstance(raw.get("regex"), str):
        prog = compile_regex(raw["regex"])
        if prog is None:
            raise SignatureError("regex", sid)
        anchor = raw.get("anchor")
        if not isinstance(anchor, str):
            raise SignatureError("anchor", sid)
        a = utf8_latin1(anchor)
        if not lo <= len(a) <= LIMITS["anchor_max"]:
            raise SignatureError("anchor", sid)
        return _String(sid, "regex", a, False, prog)
    raise SignatureError("string_kind", sid)


def _parse_condition(src: str, ids: Dict[str, int]) -> Tuple[Any, ...]:  # pylint: disable=too-many-statements
    text = src.strip()
    if not text or len(text) > LIMITS["condition_chars"]:
        raise SignatureError("condition")
    if text == "any":
        return ("at_least", 1)
    if text == "all":
        return ("at_least", len(ids))
    if re.fullmatch(r"[0-9]{1,2}", text):
        n = int(text)
        if 1 <= n <= len(ids):
            return ("at_least", n)
        raise SignatureError("condition")
    toks = re.findall(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*|\S", text)
    pos = [0]
    depth = [0]

    def peek() -> Optional[str]:
        return toks[pos[0]] if pos[0] < len(toks) else None

    def p_or() -> Tuple[Any, ...]:
        xs = [p_and()]
        while peek() == "or":
            pos[0] += 1
            xs.append(p_and())
        return xs[0] if len(xs) == 1 else ("or", xs)

    def p_and() -> Tuple[Any, ...]:
        xs = [p_unary()]
        while peek() == "and":
            pos[0] += 1
            xs.append(p_unary())
        return xs[0] if len(xs) == 1 else ("and", xs)

    def p_unary() -> Tuple[Any, ...]:
        t = peek()
        if t in ("not", "("):
            pos[0] += 1
            depth[0] += 1
            if depth[0] > LIMITS["condition_depth"]:
                raise SignatureError("condition")
            if t == "not":
                x = p_unary()
                depth[0] -= 1
                return ("not", x)
            x = p_or()
            depth[0] -= 1
            if peek() != ")":
                raise SignatureError("condition")
            pos[0] += 1
            return x
        if t is not None and _STRING_ID.fullmatch(t) and t not in ("and", "or", "not"):
            pos[0] += 1
            if t not in ids:
                raise SignatureError("unknown_string")
            return ("id", ids[t])
        raise SignatureError("condition")

    cond = p_or()
    if pos[0] != len(toks):
        raise SignatureError("condition")
    return cond


def _holds(c: Tuple[Any, ...], found: List[bool]) -> bool:
    op = c[0]
    if op == "id":
        return found[c[1]]
    if op == "not":
        return not _holds(c[1], found)
    if op == "and":
        return all(_holds(x, found) for x in c[1])
    if op == "or":
        return any(_holds(x, found) for x in c[1])
    return sum(found) >= c[1]


def compile_signature(raw: Any) -> Signature:
    """Checks one rule and compiles it; raises SignatureError with the contract's code."""
    if not isinstance(raw, dict):
        raise SignatureError("shape")
    sid = raw.get("id")
    if not isinstance(sid, str) or not _RULE_ID.fullmatch(sid):
        raise SignatureError("id")
    title = raw.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > LIMITS["title_chars"]:
        raise SignatureError("title")
    strings = raw.get("strings")
    if not isinstance(strings, list) or not 1 <= len(strings) <= LIMITS["strings_per_rule"]:
        raise SignatureError("strings")
    out: List[_String] = []
    ids: Dict[str, int] = {}
    for s in strings:
        spec = _compile_string(s)
        if spec.id in ids:
            raise SignatureError("duplicate_string", spec.id)
        ids[spec.id] = len(out)
        out.append(spec)
    cond = raw.get("condition")
    if isinstance(cond, bool) or not isinstance(cond, (str, int)):
        raise SignatureError("condition")
    return Signature(sid, title.strip(), out, _parse_condition(str(cond), ids))


def compile_signatures(raw: Any) -> Tuple[List[Signature], List[str]]:
    """Every valid rule, in order, and the error codes of the others."""
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], ["shape"]
    if len(raw) > LIMITS["rules"]:
        return [], ["too_many"]
    try:
        size = len(json.dumps(raw, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError):
        return [], ["shape"]
    if size > LIMITS["total_bytes"]:
        return [], ["too_large"]
    sigs: List[Signature] = []
    errors: List[str] = []
    seen = set()
    for r in raw:
        try:
            s = compile_signature(r)
        except SignatureError as e:
            errors.append(e.code)
            continue
        if s.id in seen:
            errors.append("duplicate_id")
            continue
        seen.add(s.id)
        sigs.append(s)
    return sigs, errors


class SignatureMatcher:
    """Matches rules over a file read in overlapping pieces of Latin-1 text."""

    def __init__(self, signatures: List[Signature]):
        self.signatures = signatures
        self.found = [[False] * len(s.strings) for s in signatures]
        self.budget = RuleBudget(LIMITS["regex_steps"])
        self.seconds = REGEX_SECONDS

    def _regex(self, prog: Any, window: str) -> bool:
        if self.budget.steps < 0 or self.seconds <= 0:
            return False
        started = time.monotonic()
        self.budget.deadline = started + self.seconds
        try:
            return _run_regex(prog, window, self.budget)
        except _BudgetExhausted:
            self.budget.steps = -1
            return False
        finally:
            self.seconds -= time.monotonic() - started
            self.budget.deadline = None

    def feed(self, piece: str, folded: str, final: bool) -> None:
        before, after, per = LIMITS["window_before"], LIMITS["window_after"], LIMITS["anchors_per_piece"]
        for r, sig in enumerate(self.signatures):
            for i, s in enumerate(sig.strings):
                if self.found[r][i]:
                    continue
                if s.kind != "regex":
                    if s.bytes in (folded if s.nocase else piece):
                        self.found[r][i] = True
                    continue
                at = piece.find(s.bytes)
                n = 0
                while at >= 0 and n < per:
                    end = at + len(s.bytes) + after
                    if end > len(piece) and not final:
                        break
                    if self._regex(s.prog, piece[max(0, at - before) : min(len(piece), end)]):
                        self.found[r][i] = True
                        break
                    if self.budget.steps < 0:
                        break
                    at = piece.find(s.bytes, at + 1)
                    n += 1

    def matched(self) -> List[Signature]:
        return [s for r, s in enumerate(self.signatures) if _holds(s.cond, self.found[r])]


def match_sample(signatures: List[Signature], data: bytes) -> List[str]:
    """Runs rules over a whole sample: the ids that match."""
    m = SignatureMatcher(signatures)
    piece = 1024 * 1024
    start = 0
    while True:
        lo = max(0, start - LIMITS["overlap"])
        end = min(len(data), start + piece)
        text = data[lo:end].decode("latin-1")
        m.feed(text, ascii_lower(text), end >= len(data))
        if end >= len(data):
            break
        start += piece
    return [s.id for s in m.matched()]
