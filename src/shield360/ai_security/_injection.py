# pylint: disable=too-many-locals,too-many-branches,too-many-statements
"""Prompt-injection and jailbreak detection for the SDK's AI security pack.

A port of sdk/typescript/src/ai-security/injection.ts (itself a copy of the
platform's detector and a port of cli/internal/coding/injection/detector.go),
loading a byte-identical copy of the shared rules.json (``npm run
injection:sync-rules`` in src/client writes every copy). The shared corpus's
golden results (cli/internal/coding/injection/testdata/expected.json) come out
the same here; a test checks every sample.

The rules are written in the subset of regular expressions Go RE2 and
JavaScript (``u`` flag) read alike. Python's ``re`` reads a few things
differently, so each pattern is translated when loaded: ``\\b``, ``\\w``,
``\\d`` and ``\\s`` get their JavaScript meaning (ASCII word characters, the
JavaScript whitespace set) and ``$`` means the end of the text only.

Deterministic and local: nothing leaves the process. What it reports is a
score, the rules that matched and where (code-point spans), and a short masked
snippet, never the text itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from typing import Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "injection_rules.json"), "r", encoding="utf-8") as _f:
    _DEF = json.load(_f)

INJECTION_RULES_VERSION: str = _DEF["version"]
INJECTION_THRESHOLD: float = _DEF["threshold"]
MAX_SCAN_CHARS: int = _DEF["maxScanChars"] if _DEF.get("maxScanChars", 0) > 0 else 200_000

Span = Tuple[int, int]

# JavaScript's \s, exactly.
_JS_SPACE = "\\t\\n\\x0b\\x0c\\r \\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"
_WORD = "A-Za-z0-9_"
_B = f"(?:(?<![{_WORD}])(?=[{_WORD}])|(?<=[{_WORD}])(?![{_WORD}]))"
_NB = f"(?:(?<![{_WORD}])(?![{_WORD}])|(?<=[{_WORD}])(?=[{_WORD}]))"


def translate(pattern: str) -> str:
    """A rules.json pattern as Python ``re`` must read it to match like JavaScript."""
    out: List[str] = []
    i = 0
    in_class = False
    n = len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            nxt = pattern[i + 1]
            if nxt == "s":
                out.append(_JS_SPACE if in_class else f"[{_JS_SPACE}]")
            elif nxt == "S":
                out.append(f"[^{_JS_SPACE}]") if not in_class else out.append("\\S")
            elif nxt == "d":
                out.append("0-9" if in_class else "[0-9]")
            elif nxt == "D":
                out.append("[^0-9]")
            elif nxt == "w":
                out.append(_WORD if in_class else f"[{_WORD}]")
            elif nxt == "W":
                out.append(f"[^{_WORD}]")
            elif nxt == "b" and not in_class:
                out.append(_B)
            elif nxt == "B" and not in_class:
                out.append(_NB)
            else:
                out.append(c + nxt)
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            elif c == "[":
                out.append("\\[")
                i += 1
                continue
            out.append(c)
        elif c == "[":
            in_class = True
            out.append(c)
            if i + 1 < n and pattern[i + 1] == "^":
                out.append("^")
                i += 1
            if i + 1 < n and pattern[i + 1] == "]":
                out.append("\\]")
                i += 1
        elif c == "$":
            out.append("\\Z")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _fold(s: str) -> str:
    """ASCII case folded, with the two letters case-insensitive matching folds onto ASCII."""
    out = []
    for ch in s:
        if "A" <= ch <= "Z":
            out.append(chr(ord(ch) + 32))
        elif ch == "ſ":
            out.append("s")
        elif ch == "K":
            out.append("k")
        else:
            out.append(ch)
    return "".join(out)


class _Rule:  # pylint: disable=too-few-public-methods,too-many-instance-attributes
    __slots__ = ("id", "category", "kind", "weight", "weights", "sources", "any", "patterns", "within", "decoded", "min")

    def __init__(self, d: Dict):
        self.id = d["id"]
        self.category = d["category"]
        self.kind = d.get("kind") or ""
        self.weight = d["weight"]
        self.weights = d.get("weights") or {}
        self.sources = d.get("sources") or []
        self.any = [_fold(x) for x in d.get("any") or []]
        flags = re.IGNORECASE
        self.patterns = [re.compile(translate(p), flags) for p in d.get("patterns") or []]
        self.within = [re.compile(translate(p), flags) for p in d.get("within") or []]
        self.decoded = bool(d.get("decoded"))
        self.min = d.get("min") or 0

    def applies(self, source: str) -> bool:
        return not self.sources or source in self.sources

    def weight_for(self, source: str) -> float:
        return self.weights[source] if source in self.weights else self.weight


_RULES = [_Rule(r) for r in _DEF["rules"]]
_BY_ID = {r.id: r for r in _RULES}
_MAX_SPANS = _DEF["maxSpans"]
_SNIPPET = _DEF["snippetChars"]


def injection_rule_catalog() -> List[Dict[str, str]]:
    return [{"id": r.id, "category": r.category} for r in _RULES]


# ---------------------------------------------------------------------------
# Characters.


def _is_js_space(r: int) -> bool:
    return (
        r in (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF)
        or 0x2000 <= r <= 0x200A
    )


def _norm_rune(r: int) -> int:
    if r in (0x0A, 0x0D, 0x2028, 0x2029):
        return 0x0A
    if _is_js_space(r):
        return 0x20
    return r


def _is_tag(r: int) -> bool:
    return 0xE0000 <= r <= 0xE007F


def _is_bidi(r: int) -> bool:
    return 0x202A <= r <= 0x202E or 0x2066 <= r <= 0x2069


def _is_zero_width(r: int) -> bool:
    return r in (0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF)


def _is_invisible(r: int) -> bool:
    return _is_zero_width(r) or r in (0x200C, 0x200D, 0xAD, 0x200E, 0x200F) or _is_tag(r) or _is_bidi(r)


def _is_ascii_letter(r: int) -> bool:
    return 0x61 <= r <= 0x7A or 0x41 <= r <= 0x5A


def _text(cps: List[int]) -> str:
    return "".join(map(chr, cps))


# ---------------------------------------------------------------------------
# Scanning.


class _View:  # pylint: disable=too-few-public-methods
    __slots__ = ("text", "folded", "origin")

    def __init__(self, runes: List[int], origin: Optional[List[int]]):
        # Python matches code points; ſ and the Kelvin sign are read as ASCII as
        # JavaScript's case-insensitive matching does (one code point each).
        self.text = _text(runes).replace("ſ", "s").replace("K", "k")
        self.folded = _fold(self.text)
        self.origin = origin

    def span(self, start: int, end: int) -> Span:
        if self.origin is None:
            return (start, end)
        os_ = self.origin[start]
        oe = self.origin[end - 1] + 1 if end > start else os_ + 1
        return (os_, oe)


class _Collector:
    def __init__(self, source: str):
        self.source = source
        self.hits: Dict[str, Dict] = {}

    def add(self, rule: _Rule, span: Span, text: str, snippet: str) -> None:
        hit = self.hits.get(rule.id)
        if hit is None:
            hit = {"rule": rule, "spans": [], "text": text, "snippet": snippet}
            self.hits[rule.id] = hit
        if len(hit["spans"]) < _MAX_SPANS:
            hit["spans"].append(span)

    def regex_matches(self, v: _View, decoded_only: bool) -> Dict[str, List[Span]]:
        found: Dict[str, List[Span]] = {}
        for rule in _RULES:
            if rule.kind or not rule.applies(self.source) or (decoded_only and not rule.decoded):
                continue
            if rule.any and not any(lit in v.folded for lit in rule.any):
                continue
            for rx in rule.patterns:
                taken = 0
                for m in rx.finditer(v.text):
                    if taken >= 20:
                        break
                    taken += 1
                    if m.end() == m.start():
                        continue
                    matched = m.group(0)
                    if all(w.search(matched) for w in rule.within):
                        found.setdefault(rule.id, []).append(v.span(m.start(), m.end()))
        return found


def scan_for_injection(text: str, source: str = "prompt", fingerprint_key: str = "") -> Dict:
    """Scans text with the shared rule set. Returns score, detected, categories and matches."""
    original = [ord(c) for c in (text if isinstance(text, str) else "")]
    if len(original) > MAX_SCAN_CHARS:
        original = original[:MAX_SCAN_CHARS]
    c = _Collector(source or "prompt")

    def text_of(s: Span) -> str:
        return _text(original[s[0] : s[1]])

    norm = [_norm_rune(r) for r in original]
    base = _View(norm, None)
    direct = c.regex_matches(base, False)
    for rid in sorted(direct):
        for s in direct[rid]:
            c.add(_BY_ID[rid], s, text_of(s), "")

    cleaned: List[int] = []
    origin: List[int] = []
    changed = False
    for i, r in enumerate(original):
        if _is_invisible(r):
            changed = True
            continue
        if 0xFF01 <= r <= 0xFF5E:
            r -= 0xFEE0
            changed = True
        cleaned.append(_norm_rune(r))
        origin.append(i)
    if changed:
        hidden = c.regex_matches(_View(cleaned, origin), False)
        for rid in sorted(hidden):
            if rid in direct:
                continue
            spans = hidden[rid]
            for s in spans:
                c.add(_BY_ID[rid], s, text_of(s), "")
            for split in (r for r in _RULES if r.kind == "invisible_split"):
                if split.applies(c.source):
                    c.add(split, spans[0], text_of(spans[0]), "")

    _invisible(c, original)
    _encoded(c, base)
    _respelled(c, norm, direct, text_of)
    return _result(c, original, fingerprint_key)


def _invisible(c: _Collector, original: List[int]) -> None:
    tag_spans: List[Span] = []
    zw_spans: List[Span] = []
    bidi_spans: List[Span] = []
    smuggled: List[int] = []
    smuggled_origin: List[int] = []
    i = 0
    n = len(original)
    while i < n:
        r = original[i]
        if _is_tag(r):
            j = i
            while j < n and _is_tag(original[j]):
                j += 1
            flag = i > 0 and original[i - 1] == 0x1F3F4 and original[j - 1] == 0xE007F and j - i <= 8
            if not flag:
                tag_spans.append((i, j))
                for k in range(i, j):
                    if 0xE0020 <= original[k] <= 0xE007E:
                        smuggled.append(original[k] - 0xE0000)
                        smuggled_origin.append(k)
                smuggled.append(0x20)
                smuggled_origin.append(j - 1)
            i = j
            continue
        if _is_zero_width(r) and not (r == 0xFEFF and i == 0):
            zw_spans.append((i, i + 1))
        elif r in (0x200C, 0x200D) and 0 < i < n - 1 and _is_ascii_letter(original[i - 1]) and _is_ascii_letter(original[i + 1]):
            zw_spans.append((i, i + 1))
        elif _is_bidi(r):
            bidi_spans.append((i, i + 1))
        i += 1

    def count(spans):
        return sum(b - a for a, b in spans)

    def concat(spans):
        return "".join(_text(original[a:b]) for a, b in spans)

    for rule in _RULES:
        if not rule.applies(c.source):
            continue
        if rule.kind == "tag":
            spans, what = tag_spans, "hidden tag characters"
        elif rule.kind == "zero_width":
            spans, what = zw_spans, "zero-width characters"
        elif rule.kind == "bidi":
            spans, what = bidi_spans, "bidirectional control characters"
        else:
            continue
        k = count(spans)
        if k == 0 or k < max(rule.min, 1):
            continue
        snippet = f"⟨{k} {what}⟩"
        joined = concat(spans)
        for s in spans:
            c.add(rule, s, joined, snippet)
    if smuggled:
        spelled = c.regex_matches(_View(smuggled, smuggled_origin), True)
        for rid in sorted(spelled):
            for s in spelled[rid]:
                c.add(_BY_ID[rid], s, _text(original[s[0] : s[1]]), "⟨instruction in hidden tag characters⟩")


_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_BLOB = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")
_MAX_BLOBS = 20


def _printable(b: bytes) -> bool:
    if len(b) < 12:
        return False
    ok = sum(1 for ch in b if 0x20 <= ch <= 0x7E or ch in (0x0A, 0x0D, 0x09))
    return ok * 10 >= len(b) * 9


def _utf8(b: bytes) -> Optional[str]:
    try:
        return b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _decode_base64(s: str) -> Optional[str]:
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        return None
    out = bytearray()
    acc = 0
    bits = 0
    for ch in s:
        o = ord(ch)
        if 65 <= o <= 90:
            v = o - 65
        elif 97 <= o <= 122:
            v = o - 97 + 26
        elif 48 <= o <= 57:
            v = o - 48 + 52
        elif ch in "+-":
            v = 62
        elif ch in "/_":
            v = 63
        else:
            return None
        acc = ((acc << 6) | v) & 0xFFFF
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
            acc &= (1 << bits) - 1
    return _utf8(bytes(out)) if _printable(bytes(out)) else None


def _decode_hex(s: str) -> Optional[str]:
    if len(s) % 2:
        return None
    b = bytes.fromhex(s)
    return _utf8(b) if _printable(b) else None


def _encoded(c: _Collector, base: _View) -> None:
    for rule in _RULES:
        if rule.kind not in ("base64", "hex") or not rule.applies(c.source):
            continue
        rx, decode, label = (_HEX_BLOB, _decode_hex, "hex") if rule.kind == "hex" else (_BASE64_BLOB, _decode_base64, "base64")
        seen = 0
        for m in rx.finditer(base.text):
            blob = m.group(0)
            if len(blob) < rule.min:
                continue
            if seen >= _MAX_BLOBS:
                break
            seen += 1
            plain = decode(blob)
            if plain is None:
                continue
            inner = c.regex_matches(_View([_norm_rune(ord(ch)) for ch in plain], None), True)
            if not inner:
                continue
            span = base.span(m.start(), m.end())
            snippet = f"⟨{label} blob, {span[1] - span[0]} characters⟩"
            for rid in sorted(inner):
                c.add(_BY_ID[rid], span, plain, snippet)
            c.add(rule, span, plain, snippet)


# ---------------------------------------------------------------------------
# Respelled views: look-alike letters, leetspeak, ROT13 (one code point each).

_HOMOGLYPHS = {
    0x0430: "a",
    0x0435: "e",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0443: "y",
    0x0445: "x",
    0x0456: "i",
    0x0458: "j",
    0x0455: "s",
    0x0501: "d",
    0x0261: "g",
    0x04BB: "h",
    0x051B: "q",
    0x051D: "w",
    0x0410: "A",
    0x0412: "B",
    0x0415: "E",
    0x041A: "K",
    0x041C: "M",
    0x041D: "H",
    0x041E: "O",
    0x0420: "P",
    0x0421: "C",
    0x0422: "T",
    0x0425: "X",
    0x0406: "I",
    0x0408: "J",
    0x0405: "S",
    0x03BF: "o",
    0x03B1: "a",
    0x03BD: "v",
    0x03B9: "i",
    0x03BA: "k",
    0x03C1: "p",
    0x03C5: "u",
    0x039F: "O",
    0x0391: "A",
    0x0392: "B",
    0x0395: "E",
    0x0397: "H",
    0x0399: "I",
    0x039A: "K",
    0x039C: "M",
    0x039D: "N",
    0x03A1: "P",
    0x03A4: "T",
    0x03A7: "X",
    0x03A5: "Y",
    0x0396: "Z",
}
_HOMOGLYPHS = {k: ord(v) for k, v in _HOMOGLYPHS.items()}
_LEET = {ord(a): ord(b) for a, b in (("0", "o"), ("1", "i"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("@", "a"), ("$", "s"))}


def _styled(r: int) -> int:
    if 0x1D400 <= r <= 0x1D6A3:
        i = (r - 0x1D400) % 52
        return 0x41 + i if i < 26 else 0x61 + i - 26
    if 0x24B6 <= r <= 0x24CF:
        return 0x41 + r - 0x24B6
    if 0x24D0 <= r <= 0x24E9:
        return 0x61 + r - 0x24D0
    return -1


def _respell_homoglyphs(norm: List[int]) -> Optional[List[int]]:
    out = list(norm)
    changed = False
    i = 0
    n = len(norm)
    while i < n:
        if not (_is_ascii_letter(norm[i]) or norm[i] in _HOMOGLYPHS):
            r = _styled(norm[i])
            if r >= 0:
                out[i] = r
                changed = True
            i += 1
            continue
        j = i
        ascii_ = False
        while j < n and (_is_ascii_letter(norm[j]) or norm[j] in _HOMOGLYPHS):
            ascii_ = ascii_ or _is_ascii_letter(norm[j])
            j += 1
        if ascii_:
            for k in range(i, j):
                if norm[k] in _HOMOGLYPHS:
                    out[k] = _HOMOGLYPHS[norm[k]]
                    changed = True
        i = j
    return out if changed else None


def _respell_leet(norm: List[int]) -> Optional[List[int]]:
    out = list(norm)
    changed = False

    def is_word(r: int) -> bool:
        return _is_ascii_letter(r) or 0x30 <= r <= 0x39 or r in _LEET

    i = 0
    n = len(norm)
    while i < n:
        if not is_word(norm[i]):
            i += 1
            continue
        j = i
        letters = digits = 0
        while j < n and is_word(norm[j]):
            if _is_ascii_letter(norm[j]):
                letters += 1
            elif norm[j] in _LEET:
                digits += 1
            j += 1
        if letters and digits:
            for k in range(i, j):
                if norm[k] in _LEET:
                    out[k] = _LEET[norm[k]]
                    changed = True
        i = j
    return out if changed else None


def _rot13(norm: List[int]) -> List[int]:
    out = []
    for r in norm:
        if 0x61 <= r <= 0x7A:
            r = 0x61 + (r - 0x61 + 13) % 26
        elif 0x41 <= r <= 0x5A:
            r = 0x41 + (r - 0x41 + 13) % 26
        out.append(r)
    return out


def _respelled(c: _Collector, norm: List[int], direct: Dict[str, List[Span]], text_of) -> None:
    folded_base = None
    for rule in _RULES:
        if not rule.applies(c.source):
            continue
        snippet = ""
        if rule.kind == "homoglyph":
            mapped = _respell_homoglyphs(norm)
        elif rule.kind == "leetspeak":
            mapped = _respell_leet(norm)
        elif rule.kind == "rot13":
            if folded_base is None:
                folded_base = _View(norm, None).folded
            if rule.any and not any(lit in folded_base for lit in rule.any):
                continue
            mapped = _rot13(norm)
            snippet = "⟨ROT13 text⟩"
        else:
            continue
        if mapped is None:
            continue
        found = c.regex_matches(_View(mapped, None), True)
        first: Optional[Span] = None
        for rid in sorted(found):
            if rid in direct:
                continue
            if rid in c.hits and snippet == "":
                continue
            for s in found[rid]:
                c.add(_BY_ID[rid], s, text_of(s), snippet)
                if first is None or s[0] < first[0]:  # pylint: disable=unsubscriptable-object
                    first = s
        if first is not None:
            c.add(rule, first, text_of(first), snippet)


# ---------------------------------------------------------------------------
# Results.


def _result(c: _Collector, original: List[int], key: str) -> Dict:
    keep = 1.0
    cats = set()
    matches = []
    for rid in sorted(c.hits):
        hit = c.hits[rid]
        rule = hit["rule"]
        w = rule.weight_for(c.source)
        if w <= 0:
            continue
        hit["spans"].sort()
        keep *= 1 - w
        cats.add(rule.category)
        m = {
            "rule": rid,
            "category": rule.category,
            "weight": w,
            "spans": [list(s) for s in hit["spans"]],
            "snippet": hit["snippet"] or mask_snippet(original, hit["spans"][0][0], hit["spans"][0][1], _SNIPPET),
        }
        fp = injection_fingerprint(key, rid, hit["text"])
        if fp:
            m["fingerprint"] = fp
        matches.append(m)
    score = _round3(1 - keep)
    return {
        "version": INJECTION_RULES_VERSION,
        "score": score,
        "threshold": INJECTION_THRESHOLD,
        "detected": bool(matches) and score >= INJECTION_THRESHOLD,
        "categories": sorted(cats),
        "matches": matches,
    }


def _round3(x: float) -> float:
    """Math.round(x * 1000) / 1000, as JavaScript rounds (half up)."""
    import math  # pylint: disable=import-outside-toplevel

    return math.floor(x * 1000 + 0.5) / 1000


_REDACT_LONG = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_REDACT_DIGITS = re.compile(r"[0-9]{6,}")
_SPACES = re.compile(r" {2,}")


def mask_snippet(original: List[int], start: int, end: int, n: int) -> str:
    s0 = max(0, start)
    e0 = min(end, len(original))
    cut = s0 + n if 0 < n < e0 - s0 else e0
    out = []
    for i in range(s0, cut):
        r = original[i]
        if _is_invisible(r):
            out.append(f"⟨U+{r:04X}⟩")
        elif r < 0x20 or 0x7F <= r <= 0x9F or _is_js_space(r):
            out.append(" ")
        else:
            out.append(chr(r))
    s = "".join(out)
    s = _SPACES.sub(" ", s)
    s = _REDACT_LONG.sub("[redacted]", s)
    s = _REDACT_DIGITS.sub("•••", s)
    s = s.strip(" ")
    s = _js_trim(s)
    if cut < e0:
        s += "…"
    if len(s) > 160:
        s = s[:160] + "…"
    return s


def _js_trim(s: str) -> str:
    i, j = 0, len(s)
    while i < j and (_is_js_space(ord(s[i])) or s[i] in "  "):
        i += 1
    while j > i and (_is_js_space(ord(s[j - 1])) or s[j - 1] in "  "):
        j -= 1
    return s[i:j]


def injection_fingerprint(key: str, rule: str, text: str) -> str:
    """Keyed hash of what a rule matched; whitespace and ASCII case folded."""
    if not key:
        return ""
    folded = []
    space = False
    for ch in text[:500]:
        if _is_js_space(ord(ch)):
            space = True
            continue
        if space and folded:
            folded.append(" ")
        space = False
        folded.append(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch)
    msg = f"{rule}\u0000{''.join(folded)}".encode("utf-8", errors="surrogatepass")
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:16]
