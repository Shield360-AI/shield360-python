"""The organisation's own kinds of sensitive data, matched in model output.

Keywords and format masks, never free-form regular expressions. A copy of the
matching half of src/client/src/lib/platform/collector/custom-data-kinds.ts
(the reference; other copies: cli/internal/coding/guard/custom.go,
extension/src/shared/custom-kinds.ts, sdk/typescript/src/ai-security/custom-kinds.ts).
Masks: ``#`` digit, ``@`` letter, ``*`` letter or digit, ``\\x`` the character
x, anything else that character without regard to case. A match may not start
or end inside a longer word.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Optional

_cache: Dict[tuple, "re.Pattern[str]"] = {}


def _parse_mask(mask: str) -> Optional[List[tuple]]:
    tokens: List[tuple] = []
    i = 0
    while i < len(mask):
        c = mask[i]
        if c == "\\":
            if i + 1 >= len(mask):
                return None
            tokens.append(("literal", mask[i + 1]))
            i += 2
            continue
        tokens.append(({"#": "digit", "@": "letter", "*": "alnum"}.get(c, "literal"), c))
        i += 1
    placeholders = sum(1 for t in tokens if t[0] != "literal")
    if len(tokens) < 3 or len(tokens) > 64 or placeholders < 3:
        return None
    if placeholders == len(tokens) and len(tokens) < 6:
        return None
    return tokens


def _mask_source(tokens: List[tuple]) -> str:
    out = []
    for kind, ch in tokens:
        out.append({"digit": "[0-9]", "letter": "[A-Za-z]", "alnum": "[A-Za-z0-9]"}.get(kind) or re.escape(ch))
    return "".join(out)


def _pattern(kind: Dict) -> "re.Pattern[str]":
    m = kind["match"]
    key = (m["type"], tuple(m.get("keywords") or m.get("masks") or ()))
    rx = _cache.get(key)
    if rx is not None:
        return rx
    if m["type"] == "keywords":
        parts = [re.escape(" ".join(k.split())).replace("\\ ", r"\s+") for k in sorted(m["keywords"], key=len, reverse=True)]
    else:
        parts = [_mask_source(t) for t in (_parse_mask(x) for x in m["masks"]) if t]
    rx = re.compile("|".join(parts) if parts else r"(?!)", re.IGNORECASE)
    if len(_cache) > 512:
        _cache.clear()
    _cache[key] = rx
    return rx


def _is_word(ch: str) -> bool:
    if not ch:
        return False
    if ch == "_":
        return True
    cat = unicodedata.category(ch)
    return cat[0] in ("L", "N")


def _on_boundaries(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else ""
    at = text[start] if start < len(text) else ""
    if _is_word(at) and _is_word(before):
        return False
    last = text[end - 1] if end > 0 else ""
    after = text[end] if end < len(text) else ""
    if _is_word(last) and _is_word(after):
        return False
    return True


def find_custom_kinds(text: str, kinds: List[Dict]) -> List[Dict]:
    """Every custom kind found in text, by code-point span."""
    out: List[Dict] = []
    if not text:
        return out
    for kind in kinds:
        rx = _pattern(kind)
        pos = 0
        while True:
            m = rx.search(text, pos)
            if not m:
                break
            if m.end() == m.start():
                pos = m.start() + 1
                continue
            if _on_boundaries(text, m.start(), m.end()):
                out.append({"id": kind["id"], "name": kind.get("name", kind["id"]), "start": m.start(), "end": m.end()})
                pos = m.end()
            else:
                pos = m.start() + 1
    out.sort(key=lambda f: (f["start"], -f["end"]))
    return out
