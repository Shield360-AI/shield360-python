"""
Credential masking shared by RASP snippets and application logs.

The contract is ``sdk/rasp/README.md`` ("Masking"), checked by
``sdk/rasp/testdata/masking.json``; every Shield360 SDK applies it the same
way. In short:

1. A credential pair (``password=x``, ``"api_key": "x"``, ``Authorization:
   Bearer x``) keeps its name and loses its value, quotes kept.
2. A ``Bearer <credential>`` keeps the word and loses the credential.
3. A run of 20 or more token characters (``A-Z a-z 0-9 _ - + / = .``) is
   masked when it is opaque: it holds ``+``, ends in ``=``, or one of its
   pieces (split on ``. / - _ =``) of 8 or more characters is not a readable
   word. Dotted, slashed and CamelCase identifiers (class names, package and
   file paths) survive; keys, hashes, base64, JWTs and UUIDs do not.

Masking runs over the value plus 1,024 characters of look-ahead before it is
cut, so a credential that crosses the cut is never left half visible.

An attribute whose name is a credential (``password``, ``x-api-key``,
``sessionId``...) is masked whole, whatever its value; lists and maps are
masked item by item.
"""

import re
from typing import Any, Optional

LOOKAHEAD = 1024
MASK = "***"

_KEY = (
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|client[_-]?secret|auth(?:orization)?|bearer|cookie|session(?:[_-]?id)?|credentials?)"
)
PAIR = re.compile(
    "(" + _KEY + r"[\"']?[ \t]*[=:][ \t]*)"
    r"(\"(?:[^\"\\]|\\.)*\"?|'(?:[^'\\]|\\.)*'?"
    r"|(?:(?:bearer|basic|digest|negotiate|token)[ \t]+)?[^ \t\r\n\f\x0B&;,'\"]+)",
    re.I | re.A,
)
BEARER = re.compile(r"(bearer[ \t]+)[A-Za-z0-9._~+/=-]+", re.I | re.A)
_RUN = re.compile(r"[A-Za-z0-9_\-+/=.]{20,}")
_PIECE_SPLIT = re.compile(r"[./\-_=]")
_READABLE = re.compile(r"[A-Za-z]+[0-9]{0,4}")
_VOWELS = frozenset("aeiouyAEIOUY")

_SENSITIVE_WORDS = frozenset(
    {
        "password", "passwd", "passphrase", "pwd", "secret", "token", "apikey",
        "authorization", "cookie", "credential", "credentials", "bearer", "otp",
        "signature", "privatekey", "sessionid", "jwt", "accesskey", "secretkey",
    }
)
_SENSITIVE_PAIRS = frozenset(
    {("api", "key"), ("private", "key"), ("access", "key"), ("secret", "key"), ("session", "id")}
)


def _readable(piece: str) -> bool:
    if not _READABLE.fullmatch(piece):
        return False
    letters = [c for c in piece if c.isalpha()]
    if sum(1 for c in letters if c in _VOWELS) * 5 < len(letters):
        return False
    upper_run = longest = transitions = 0
    previous = ""
    for c in letters:
        if "A" <= c <= "Z":
            upper_run += 1
            longest = max(longest, upper_run)
            if "a" <= previous <= "z":
                transitions += 1
        else:
            upper_run = 0
        previous = c
    return longest <= 6 and transitions * 3 <= len(letters)


def is_opaque(run: str) -> bool:
    """Whether a run of 20+ token characters reads as a secret rather than an identifier."""
    if "+" in run or run.endswith("="):
        return True
    return any(len(p) >= 8 and not _readable(p) for p in _PIECE_SPLIT.split(run))


def _pair(m: "re.Match[str]") -> str:
    value = m.group(2)
    if value.startswith('"'):
        return m.group(1) + '"' + MASK + '"'
    if value.startswith("'"):
        return m.group(1) + "'" + MASK + "'"
    return m.group(1) + MASK


def _mask_credentials(value: str) -> str:
    s = PAIR.sub(_pair, value)
    return BEARER.sub(lambda m: m.group(1) + MASK, s)


def mask_secrets(value: str) -> str:
    """``value`` with credentials and opaque tokens masked; nothing is cut."""
    return _RUN.sub(lambda m: MASK if is_opaque(m.group(0)) else m.group(0), _mask_credentials(value))


# Allow-list targets (README "Masking", "Targets"): the credential rules on the
# whole target, a ``/`` segment holding ``@`` masked whole, then the strict
# long-token rule piece by piece between ``/`` and ``.``.
_TARGET_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/]{20,}={0,2}")
_TARGET_SPLIT = re.compile(r"([/.])")
_SLASH_SPLIT = re.compile(r"(/)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_TARGET_LENGTH = 256


def mask_target(raw: Optional[str]) -> Optional[str]:
    """An allow-list target for ``shield360.rasp.target``, or None when it is
    empty, holds a control character or is longer than 256 characters after
    masking (never cut: a cut directory or host is a different one)."""
    if not isinstance(raw, str) or not raw:
        return None
    s = _mask_credentials(raw)
    s = "".join(MASK if "@" in p else p for p in _SLASH_SPLIT.split(s))
    out = "".join(p if p in ("/", ".") else _TARGET_LONG_TOKEN.sub(MASK, p) for p in _TARGET_SPLIT.split(s))
    if not out or len(out) > MAX_TARGET_LENGTH or _CONTROL.search(out):
        return None
    return out


def mask_text(value: str, limit: int) -> str:
    """At most ``limit`` characters of ``value``, masked before it is cut."""
    return mask_secrets(value[: limit + LOOKAHEAD])[:limit]


def _words(key: str):
    words = []
    for chunk in re.split(r"[^A-Za-z0-9]+", key):
        start = 0
        for i in range(1, len(chunk)):
            a, b = chunk[i - 1], chunk[i]
            nxt = chunk[i + 1] if i + 1 < len(chunk) else ""
            lower_to_upper = (a.islower() or a.isdigit()) and b.isupper()
            acronym_end = a.isupper() and b.isupper() and nxt.islower()
            if lower_to_upper or acronym_end:
                words.append(chunk[start:i])
                start = i
        if chunk:
            words.append(chunk[start:])
    return [w.lower() for w in words if w]


def is_sensitive_key(key: str) -> bool:
    """Whether an attribute name names a credential (``password``, ``x-api-key``, ``sessionId``)."""
    words = _words(key)
    if any(w in _SENSITIVE_WORDS for w in words):
        return True
    return any((a, b) in _SENSITIVE_PAIRS for a, b in zip(words, words[1:]))


def mask_value(key: str, value: Any, limit: int) -> Any:
    """An attribute value as it may leave the process (strings at most ``limit`` characters)."""
    if value is None:
        return None
    if is_sensitive_key(key):
        return MASK
    if isinstance(value, str):
        return mask_text(value, limit)
    if isinstance(value, (list, tuple)):
        return [mask_value(key, v, limit) for v in value]
    if isinstance(value, dict):
        return {k: mask_value(str(k), v, limit) for k, v in value.items()}
    return value
