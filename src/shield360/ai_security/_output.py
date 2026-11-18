# pylint: disable=too-many-locals,too-many-branches
"""Output scanning (OWASP LLM02, LLM05, LLM07): a model's answer, checked
before the app returns it.

pii / secret (built-in kinds), custom_kind (the organisation's own),
cross_tenant (identifiers of another tenant that reached this request's
context), exfil_link (images to domains off the allow-list, links or images
carrying data), system_prompt_leak (6-word shingles of the request's system
prompt) and canary_leak. Findings carry a masked token and a keyed
fingerprint, never the value. ``OutputStreamScanner`` checks a streamed
answer with bounded buffers: it holds back HOLDBACK characters so a value
split across chunks can still be redacted.

Must stay in sync with: sdk/typescript/src/ai-security/output.ts
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from shield360.guard._findings import make as _make_finding
from shield360.ai_security._custom_kinds import find_custom_kinds


def _luhn(v: str) -> bool:
    d = [int(c) for c in v if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _issuable_ssn(v: str) -> bool:
    a, b, c = v.split("-")
    return a not in ("000", "666") and a[0] != "9" and b != "00" and c != "0000"


_PATTERNS = [
    ("openai-api-key", "secret", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), None),
    ("anthropic-api-key", "secret", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"), None),
    ("aws-access-key", "secret", re.compile(r"(?<![A-Za-z0-9/+=])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9/+=])"), None),
    ("gcp-api-key", "secret", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), None),
    ("github-token", "secret", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"), None),
    ("github-fine-grained", "secret", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"), None),
    ("stripe-key", "secret", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}"), None),
    ("slack-token", "secret", re.compile(r"\bxox[bpoas]-[A-Za-z0-9-]{10,}"), None),
    ("private-key", "secret", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), None),
    (
        "connection-string",
        "secret",
        re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://[^\s:@/]+:[^\s@/]+@\S+"),
        None,
    ),
    ("jwt", "secret", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), None),
    ("email", "pii", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), None),
    ("ssn", "pii", re.compile(r"(?<![0-9-])[0-9]{3}-[0-9]{2}-[0-9]{4}(?![0-9-])"), _issuable_ssn),
    (
        "credit-card",
        "pii",
        re.compile(
            r"(?<![0-9])(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{3,4}(?![0-9])"
        ),
        _luhn,
    ),
    ("phone-us", "pii", re.compile(r"(?<![0-9])(?:\+1[ .-]?)?\(?[2-9][0-9]{2}\)?[ .-][0-9]{3}[ .-][0-9]{4}(?![0-9])"), None),
]

_MD_IMAGE = re.compile(r"!\[[^\]\n]{0,200}\]\(\s*<?(https?://[^\s)>]+)>?[^)\n]{0,200}\)", re.IGNORECASE)
_HTML_IMAGE = re.compile(r"<img\b[^>\n]{0,300}?\bsrc\s*=\s*[\"']?(https?://[^\s\"'>]+)", re.IGNORECASE)
_ANY_URL = re.compile(r"\bhttps?://[^\s<>\"'()\]]+", re.IGNORECASE)
_BLOB = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def host_allowed(host: str, allowed: List[str]) -> bool:
    h = host.lower().rstrip(".")
    for d in allowed:
        if d.startswith("*."):
            if h == d[2:] or h.endswith(d[1:]):
                return True
        elif h == d:
            return True
    return False


def url_carries_data(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    values = [v for _k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if parts.fragment:
        values.append(unquote_plus(parts.fragment))
    values += [unquote_plus(seg) for seg in parts.path.split("/")]
    for v in values:
        if len(v) >= 40 and _BLOB.match(v):
            return True
        if len(v) >= 24 and re.search(r"\s", v) and re.search(r"[a-z]{3,}", v, re.IGNORECASE):
            return True
        for _label, _kind, rx, check in _PATTERNS:
            m = rx.search(v)
            if m and (check is None or check(m.group(0))):
                return True
    return False


_SHINGLE = 6
_STOP = set(
    (
        "a an and are as at be by for from has have i if in into is it its of on or that the their them then there these they "
        "this to was were will with you your we our us not no do does can should must may"
    ).split()
)
_WORDS = re.compile(r"[^\W_]+", re.UNICODE)


def _words(text: str) -> List[str]:
    return _WORDS.findall(text.lower())


def prompt_shingles(prompt: str, limit: int = 5000) -> set:
    w = _words(prompt)
    out: set = set()
    for i in range(0, len(w) - _SHINGLE + 1):
        if len(out) >= limit:
            break
        s = w[i : i + _SHINGLE]
        if sum(1 for x in s if x not in _STOP) >= 2:
            out.add(" ".join(s))
    return out


def _leaked(text: str, shingles: set) -> int:
    if not shingles:
        return 0
    w = _words(text)
    return len({" ".join(w[i : i + _SHINGLE]) for i in range(0, len(w) - _SHINGLE + 1)} & shingles)


def is_leak(matched: int, total: int) -> bool:
    if total == 0 or matched < 3:
        return False
    return matched >= min(25, max(3, -(-total // 10)))


def _finding(kind: str, label: str, start: int, end: int, value: str) -> Dict[str, Any]:
    if kind == "exfil_link":
        return {"kind": kind, "label": label, "start": start, "end": end, "masked": "[link removed]"}
    name = f"custom_{label}" if kind == "custom_kind" else ("cross_tenant" if kind == "cross_tenant" else label)
    f = _make_finding(name, value)
    out = {"kind": kind, "label": label, "start": start, "end": end, "masked": f["masked"]}
    if f.get("fingerprint"):
        out["fingerprint"] = f["fingerprint"]
    return out


_MAX_SCAN = 200_000


def scan_output(
    text: str,
    policy: Dict[str, Any],
    custom_kinds: Optional[List[Dict]] = None,
    system_prompt: Optional[str] = None,
    foreign: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    p = policy
    t = text[:_MAX_SCAN] if isinstance(text, str) else ""
    out: List[Dict[str, Any]] = []
    must_block = False
    if not t:
        return {"findings": out, "redacted": text if isinstance(text, str) else "", "must_block": False}
    for label, kind, rx, check in _PATTERNS:
        if (kind == "pii" and not p["pii"]) or (kind == "secret" and not p["secrets"]):
            continue
        for m in rx.finditer(t):
            if len(out) >= 200:
                break
            if check and not check(m.group(0)):
                continue
            out.append(_finding(kind, label, m.start(), m.end(), m.group(0)))
    if p["customKinds"] and custom_kinds:
        for f in find_custom_kinds(t, custom_kinds)[:100]:
            out.append(_finding("custom_kind", f["id"], f["start"], f["end"], t[f["start"] : f["end"]]))
    if p["crossTenant"] and foreign:
        lower = t.lower()
        for ident in foreign:
            at = lower.find(ident)
            while at >= 0 and len(out) < 300:
                out.append(_finding("cross_tenant", "identifier", at, at + len(ident), t[at : at + len(ident)]))
                at = lower.find(ident, at + len(ident))
    if p["exfilLinks"]:
        images = set()
        allowed = p["allowedDomains"]
        for rx in (_MD_IMAGE, _HTML_IMAGE):
            for m in rx.finditer(t):
                url = m.group(1)
                start = m.start(1)
                images.add(start)
                host = urlsplit(url).hostname or ""
                if allowed and host_allowed(host, allowed):
                    continue
                if allowed or url_carries_data(url):
                    out.append(_finding("exfil_link", "image", start, start + len(url), url))
        for m in _ANY_URL.finditer(t):
            if m.start() in images:
                continue
            url = m.group(0).rstrip(".,;:!?")
            host = urlsplit(url).hostname or ""
            if allowed and host_allowed(host, allowed):
                continue
            if url_carries_data(url):
                out.append(_finding("exfil_link", "query_data", m.start(), m.start() + len(url), url))
    if p.get("canary"):
        at = t.find(p["canary"])
        if at >= 0:
            out.append({"kind": "canary_leak", "label": "canary", "start": at, "end": at + len(p["canary"]), "masked": "[canary]"})
            must_block = True
    if p["systemPromptLeak"] and system_prompt:
        shingles = prompt_shingles(system_prompt)
        n = _leaked(t, shingles)
        if is_leak(n, len(shingles)):
            out.append(
                {"kind": "system_prompt_leak", "label": f"{n}/{len(shingles)}", "start": 0, "end": 0, "masked": "[system prompt]"}
            )
            must_block = True
    return {"findings": out, "redacted": redact(text, out), "must_block": must_block}


def redact(text: str, findings: List[Dict[str, Any]]) -> str:
    spans = sorted((f for f in findings if f["end"] > f["start"]), key=lambda f: (f["start"], -f["end"]))
    merged: List[List[Any]] = []
    for f in spans:
        if merged and f["start"] < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], f["end"])
        else:
            merged.append([f["start"], f["end"], f["masked"]])
    s = text
    for start, end, masked in reversed(merged):
        s = s[:start] + masked + s[end:]
    return s


HOLDBACK = 256
WINDOW = 2048
# Pending characters beyond the holdback before a scan runs: fewer scans, at most this much more delay.
RELEASE_STEP = 128


class OutputStreamScanner:  # pylint: disable=too-many-instance-attributes
    """Scans a streamed answer incrementally with bounded memory."""

    def __init__(
        self,
        policy: Dict[str, Any],
        custom_kinds=None,
        system_prompt: Optional[str] = None,
        foreign: Optional[Dict[str, str]] = None,
        redact_: bool = False,
        block: bool = False,
    ):
        self._policy = policy
        self._kinds = custom_kinds
        self._foreign = foreign
        self._redact = redact_
        self._block = block
        self._pending = ""
        self._released = ""
        self._offset = 0
        self._shingles = prompt_shingles(system_prompt) if policy["systemPromptLeak"] and system_prompt else set()
        self._leaked: set = set()
        self._tail_words: List[str] = []
        self._partial = ""
        self._reported: set = set()
        self.blocked = False
        self.findings: List[Dict[str, Any]] = []

    def push(self, chunk: str) -> Dict[str, Any]:
        if self.blocked:
            return {"text": "", "findings": [], "blocked": True}
        self._pending += chunk or ""
        self._count_shingles(chunk or "")
        if len(self._pending) <= HOLDBACK + RELEASE_STEP:
            return {"text": "", "findings": [], "blocked": False}
        return self._release(len(self._pending) - HOLDBACK)

    def end(self) -> Dict[str, Any]:
        if self.blocked:
            return {"text": "", "findings": [], "blocked": True}
        self._count_shingles(" ")
        return self._release(len(self._pending))

    def _count_shingles(self, chunk: str) -> None:
        if not self._shingles:
            return
        text = self._partial + chunk
        m = re.search(r"[^\W_]+$", text)
        self._partial = m.group(0)[-64:] if m else ""
        w = self._tail_words + _words(text[: len(text) - len(m.group(0))] if m else text)
        for i in range(0, len(w) - _SHINGLE + 1):
            s = " ".join(w[i : i + _SHINGLE])
            if s in self._shingles:
                self._leaked.add(s)
        self._tail_words = w[-(_SHINGLE - 1) :] if _SHINGLE > 1 else []

    def _release(self, up_to: int) -> Dict[str, Any]:
        ctx = self._released[-WINDOW:]
        res = scan_output(ctx + self._pending, self._policy, self._kinds, None, self._foreign)
        fresh: List[Dict[str, Any]] = []
        for f in res["findings"]:
            start = f["start"] - len(ctx)
            end = f["end"] - len(ctx)
            if end <= 0:
                continue
            if start >= up_to and up_to < len(self._pending):
                continue
            fid = (f["kind"], f["label"], f["masked"], start + self._offset)
            if fid in self._reported:
                continue
            self._reported.add(fid)
            fresh.append({**f, "start": start, "end": end})
        if is_leak(len(self._leaked), len(self._shingles)) and "leak" not in self._reported:
            self._reported.add("leak")
            fresh.append(
                {
                    "kind": "system_prompt_leak",
                    "label": f"{len(self._leaked)}/{len(self._shingles)}",
                    "start": 0,
                    "end": 0,
                    "masked": "[system prompt]",
                }
            )
        blocks = any(f["kind"] in ("system_prompt_leak", "canary_leak") for f in fresh)
        if fresh and self._block:
            self.blocked = True
        if blocks and (self._block or self._redact):
            self.blocked = True
        if self.blocked:
            self.findings.extend(fresh)
            self._pending = ""
            return {"text": "", "findings": fresh, "blocked": True}
        cut = up_to
        for f in fresh:
            if f["start"] < cut < f["end"]:
                cut = min(len(self._pending), f["end"])
        part = self._pending[:cut]
        in_part = [f for f in fresh if f["start"] >= 0 and f["end"] <= cut]
        text = redact(part, in_part) if self._redact else part
        self._pending = self._pending[cut:]
        self._released = (self._released + part)[-WINDOW:]
        self._offset += len(part)
        self.findings.extend(fresh)
        return {"text": text, "findings": fresh, "blocked": False}
