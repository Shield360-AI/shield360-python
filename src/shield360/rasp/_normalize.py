"""Input normalization: percent-decoded forms, JSON flattening and model-output
fragments (README "Sources of untrusted input" and "Implementation notes")."""

from __future__ import annotations

import json
from typing import Any, List, Tuple

from shield360.rasp._types import RaspInput

MAX_INPUTS = 256
MAX_VALUE = 4096
MAX_FRAGMENTS = 32
MAX_RAW_BODY = 8 * 1024
_MAX_DEPTH = 16

_HEX = frozenset(b"0123456789abcdefABCDEF")


def percent_decode(s: str) -> str:
    """Lenient percent decoding: %XX to bytes, other % kept, UTF-8 with U+FFFD."""
    if "%" not in s:
        return s
    enc = s.encode("utf-8", "surrogatepass")
    out = bytearray()
    i = 0
    n = len(enc)
    while i < n:
        b = enc[i]
        if b == 0x25 and i + 2 < n and enc[i + 1] in _HEX and enc[i + 2] in _HEX:
            out.append(int(enc[i + 1 : i + 3], 16))
            i += 3
            continue
        out.append(b)
        i += 1
    return out.decode("utf-8", "replace")


def add_input(items: List[RaspInput], value: Any, key: str, source: str = "request") -> None:
    """Adds an input, its decoded and double-decoded forms; caps count and length."""
    if not isinstance(value, str) or value == "" or len(items) >= MAX_INPUTS:
        return
    v = value[:MAX_VALUE]
    items.append(RaspInput(v, key, source))
    if source != "request" or "%" not in v:
        return
    once = percent_decode(v)
    if once != v and len(items) < MAX_INPUTS:
        items.append(RaspInput(once, key, source))
        twice = percent_decode(once)
        if twice != once and len(items) < MAX_INPUTS:
            items.append(RaspInput(twice, key, source))


def flatten(items: List[RaspInput], value: Any, key: str, depth: int = 0) -> None:
    """Flattens string leaves of a parsed body (``body.a.b``, lists by index)."""
    if len(items) >= MAX_INPUTS or depth > _MAX_DEPTH or value is None:
        return
    if isinstance(value, str):
        add_input(items, value, key)
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            flatten(items, v, f"{key}.{i}", depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            flatten(items, v, f"{key}.{k}", depth + 1)


def model_fragments(text: str) -> List[str]:
    """Splits model text into fragments: fenced code blocks, then lines."""
    out: List[str] = []
    seen = set()

    def push(f: str) -> None:
        t = f.strip()
        if not t or t in seen or len(out) >= MAX_FRAGMENTS:
            return
        seen.add(t)
        out.append(t[:MAX_VALUE])

    lines = text.split("\n")
    block = None
    for line in lines:
        if line.strip().startswith("```"):
            if block is not None:
                push("\n".join(block))
                block = None
            else:
                block = []
            continue
        if block is not None:
            block.append(line)
    if block is not None:
        push("\n".join(block))
    for line in lines:
        if not line.strip().startswith("```"):
            push(line)
    return out


def add_model_output(items: List[RaspInput], text: str, key: str = "model.completion") -> None:
    """Adds model text as model_output fragments."""
    for f in model_fragments(text):
        if len(items) >= MAX_INPUTS:
            return
        items.append(RaspInput(f, key, "model_output"))


def add_tool_arguments(items: List[RaspInput], args: Any, path: str = "model.tool") -> None:
    """Adds tool-call argument string leaves as model_output (``model.tool.<path>``)."""
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except Exception:  # pylint: disable=broad-exception-caught
            add_model_output(items, args, path)
            return
    tmp: List[RaspInput] = []
    flatten(tmp, args, path)
    for i in tmp:
        if len(items) < MAX_INPUTS:
            items.append(RaspInput(i.value, i.key, "model_output"))


def parse_cookies(header: str) -> List[Tuple[str, str]]:
    """Parses a Cookie header into name/value pairs."""
    if not header:
        return []
    out: List[Tuple[str, str]] = []
    for part in header.split(";"):
        i = part.find("=")
        if i <= 0:
            continue
        out.append((part[:i].strip(), part[i + 1 :].strip()))
    return out
