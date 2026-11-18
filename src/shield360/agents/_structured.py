"""
The part of Structured Field Values (RFC 8941) that HTTP Message Signatures
(RFC 9421) needs: parsing a Dictionary whose members are Items or Inner Lists
with Parameters, and serialising an Inner List and an Item back, so a signature
base can be rebuilt byte for byte. Anything that is not valid RFC 8941 raises
StructuredError.

Must stay in sync with: sdk/typescript/src/agents/structured.ts
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, List, Union


class StructuredError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    value: str


Bare = Union[int, float, str, bool, Token, bytes]
Params = Dict[str, Bare]  # insertion-ordered


@dataclass
class Item:
    value: Bare
    params: Params = field(default_factory=dict)


@dataclass
class InnerList:
    items: List[Item]
    params: Params = field(default_factory=dict)


Member = Union[Item, InnerList]

_KEY_FIRST = re.compile(r"[a-z*]")
_KEY_CHAR = re.compile(r"[a-z0-9_\-.*]")
_TOKEN_FIRST = re.compile(r"[A-Za-z*]")
_TOKEN_CHAR = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z:/]")
_BASE64_CHAR = re.compile(r"[A-Za-z0-9+/=]")
_DIGIT = re.compile(r"[0-9]")


class _Reader:
    def __init__(self, s: str):
        self.s = s
        self.i = 0

    @property
    def done(self) -> bool:
        return self.i >= len(self.s)

    def peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def fail(self):
        raise StructuredError(f"invalid structured field at {self.i}")

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t") and self.peek():
            self.i += 1


def _match(pattern: "re.Pattern[str]", c: str) -> bool:
    return bool(c) and pattern.fullmatch(c) is not None


def _parse_key(r: _Reader) -> str:
    if not _match(_KEY_FIRST, r.peek()):
        r.fail()
    start = r.i
    while not r.done and _match(_KEY_CHAR, r.peek()):
        r.i += 1
    return r.s[start : r.i]


def _parse_number(r: _Reader) -> Union[int, float]:
    start = r.i
    if r.peek() == "-":
        r.i += 1
    if not _match(_DIGIT, r.peek()):
        r.fail()
    decimal = False
    while not r.done:
        c = r.peek()
        if _match(_DIGIT, c):
            r.i += 1
        elif c == "." and not decimal:
            decimal = True
            r.i += 1
        else:
            break
    text = r.s[start : r.i]
    digits = text.lstrip("-")
    if not decimal:
        if len(digits) > 15:
            r.fail()
        return int(text)
    whole, _, frac = digits.partition(".")
    if len(whole) > 12 or not frac or len(frac) > 3:
        r.fail()
    return float(text)


def _parse_string(r: _Reader) -> str:
    r.i += 1
    out = []
    while True:
        if r.done:
            r.fail()
        c = r.s[r.i]
        r.i += 1
        if c == "\\":
            nxt = r.s[r.i] if r.i < len(r.s) else ""
            r.i += 1
            if nxt not in ('"', "\\"):
                r.fail()
            out.append(nxt)
        elif c == '"':
            return "".join(out)
        else:
            if ord(c) < 0x20 or ord(c) > 0x7E:
                r.fail()
            out.append(c)


def _parse_token(r: _Reader) -> Token:
    start = r.i
    r.i += 1
    while not r.done and _match(_TOKEN_CHAR, r.peek()):
        r.i += 1
    return Token(r.s[start : r.i])


def _parse_bytes(r: _Reader) -> bytes:
    r.i += 1
    start = r.i
    while not r.done and r.peek() != ":":
        if not _match(_BASE64_CHAR, r.peek()):
            r.fail()
        r.i += 1
    if r.done:
        r.fail()
    b64 = r.s[start : r.i]
    r.i += 1
    try:
        return base64.b64decode(b64 + "=" * (-len(b64) % 4))
    except (binascii.Error, ValueError):
        r.fail()
    return b""


def _parse_bare(r: _Reader) -> Bare:
    c = r.peek()
    if c == "-" or _match(_DIGIT, c):
        return _parse_number(r)
    if c == '"':
        return _parse_string(r)
    if c == ":":
        return _parse_bytes(r)
    if c == "?":
        r.i += 1
        b = r.s[r.i] if r.i < len(r.s) else ""
        r.i += 1
        if b == "1":
            return True
        if b == "0":
            return False
        r.fail()
    if _match(_TOKEN_FIRST, c):
        return _parse_token(r)
    r.fail()
    return False


def _parse_params(r: _Reader) -> Params:
    params: Params = {}
    while r.peek() == ";":
        r.i += 1
        r.skip_sp()
        key = _parse_key(r)
        value: Bare = True
        if r.peek() == "=":
            r.i += 1
            value = _parse_bare(r)
        params.pop(key, None)
        params[key] = value
    return params


def _parse_item(r: _Reader) -> Item:
    value = _parse_bare(r)
    return Item(value, _parse_params(r))


def _parse_inner_list(r: _Reader) -> InnerList:
    r.i += 1
    items: List[Item] = []
    while True:
        r.skip_sp()
        if r.peek() == ")":
            r.i += 1
            return InnerList(items, _parse_params(r))
        items.append(_parse_item(r))
        if r.peek() not in (" ", ")") or not r.peek():
            r.fail()


def _parse_member(r: _Reader) -> Member:
    return _parse_inner_list(r) if r.peek() == "(" else _parse_item(r)


def parse_dictionary(value: str) -> Dict[str, Member]:
    """Parses a Dictionary field value (several field lines joined with ", "). Later duplicates win."""
    r = _Reader(value)
    out: Dict[str, Member] = {}
    r.skip_sp()
    if r.done:
        return out
    while True:
        key = _parse_key(r)
        if r.peek() == "=":
            r.i += 1
            member = _parse_member(r)
        else:
            member = Item(True, _parse_params(r))
        out.pop(key, None)
        out[key] = member
        r.skip_ows()
        if r.done:
            return out
        if r.peek() != ",":
            r.fail()
        r.i += 1
        r.skip_ows()
        if r.done:
            r.fail()


def parse_item_field(value: str) -> Item:
    """Parses an Item field value."""
    r = _Reader(value)
    r.skip_sp()
    item = _parse_item(r)
    r.skip_sp()
    if not r.done:
        r.fail()
    return item


def _serialize_bare(v: Bare) -> str:
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        text = f"{round(v, 3):.3f}".rstrip("0")
        return text + "0" if text.endswith(".") else text
    if isinstance(v, str):
        if re.search(r"[^\x20-\x7e]", v):
            raise StructuredError("string")
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, Token):
        return v.value
    if isinstance(v, (bytes, bytearray)):
        return ":" + base64.b64encode(bytes(v)).decode() + ":"
    raise StructuredError("value")


def serialize_params(params: Params) -> str:
    return "".join(f";{k}" if v is True else f";{k}={_serialize_bare(v)}" for k, v in params.items())


def serialize_item(item: Item) -> str:
    return _serialize_bare(item.value) + serialize_params(item.params)


def serialize_inner_list(lst: InnerList) -> str:
    return "(" + " ".join(serialize_item(i) for i in lst.items) + ")" + serialize_params(lst.params)


def serialize_member(m: Member) -> str:
    return serialize_inner_list(m) if isinstance(m, InnerList) else serialize_item(m)
