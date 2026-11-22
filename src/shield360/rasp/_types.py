"""Shield360 RASP shared types. sdk/rasp/README.md is the contract."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

ATTACK_TYPES = (
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "shell_spawn",
    "path_traversal",
    "file_write",
    "ssrf",
    "outbound",
    "deserialization",
    "code_injection",
    "xxe",
    "xss",
    "virtual_patch",
    "custom_rule",
    "malicious_upload",
    "upload_backdoor",
    # SHIELD: AI attack agents (README "AI attack agents").
    "ai_attack_agent",
)

MODES = ("off", "monitor", "block")
INPUT_SOURCES = ("request", "model_output")


class RaspInput(NamedTuple):
    """One piece of untrusted input. ``key`` is a location name; the value never leaves the process."""

    value: str
    key: str
    source: str = "request"


@dataclass
class Finding:
    """What a detector found."""

    attack: str
    rule: str
    input: Optional[RaspInput] = None
    cve: Optional[str] = None
    # Virtual patches and sink rules: the most the rule does.
    action: Optional[str] = None
    # Allow-list rules: the raw destination the rule compared (README "Allow-list targets").
    target: Optional[str] = None
    # SQL findings: the dialect the lexer used.
    dialect: Optional[str] = None
    # Upload findings: the mode that decides instead of the attack type's (a route's policy, the deep scan).
    mode: Optional[str] = None
    # Upload findings: README "Upload event attributes" (type, kind, ext, size, sha256, signature, engine, dest, action).
    upload: Optional[Dict[str, Any]] = None


BLOCK_MESSAGE = "Request blocked by Shield360 runtime protection"


class RaspBlockedError(Exception):
    """Raised by a blocking check; framework middleware maps it to a 403.

    The contract's Python name. ``status`` and ``status_code`` are 403 for
    error handlers that read the status from the exception.
    """

    status = 403
    status_code = 403
    code = 403

    def __init__(self, attack: str, rule: str, event_id: str):
        super().__init__(f"{BLOCK_MESSAGE} ({attack}, {rule})")
        self.attack = attack
        self.rule = rule
        self.event_id = event_id


def block_body(e: RaspBlockedError) -> Dict[str, Any]:
    """The JSON body of the 403 (README "The block response")."""
    return {"error": BLOCK_MESSAGE, "attack": e.attack, "rule": e.rule, "event": e.event_id}


class RaspDeterredError(RaspBlockedError):
    """The deter answer (README "AI attack agents"): a marked attack agent in
    block mode gets 429 with Retry-After instead of the 403, so agents that
    honor rate limits give up. Middleware maps it like the block error."""

    status = 429
    status_code = 429
    code = 429

    def __init__(self, rule: str, event_id: str, retry_after: int):
        super().__init__("ai_attack_agent", rule, event_id)
        self.retry_after = retry_after


DETER_MESSAGE = "Too Many Requests"


def block_answer(e: RaspBlockedError) -> Tuple[int, str, List[Tuple[str, str]], bytes]:
    """The status, reason, headers and body a block (403) or deter (429) answers with."""
    headers = [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
    if isinstance(e, RaspDeterredError):
        body = json.dumps({"error": DETER_MESSAGE}, separators=(",", ":")).encode()
        return 429, "Too Many Requests", headers + [("Retry-After", str(e.retry_after))], body
    return 403, "Forbidden", headers, json.dumps(block_body(e), separators=(",", ":")).encode()
