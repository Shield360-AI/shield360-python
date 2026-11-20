"""
Agent passports: the types shared by the verifier, its policy and its reports.

The wire formats (passport claims, receiver policy, check result) are a contract
with the Shield360 app (issuer: /api/agent-passports/*, receiver:
/api/inbound-agents/*) and with the TypeScript verifier.

Must stay in sync with: sdk/typescript/src/agents/types.ts
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Protocol, runtime_checkable

AGENT_HEADER = "Shield360-Agent"
PASSPORT_TYP = "shield360-agent+jwt"
DEFAULT_ISSUERS = ("https://app.shield360.ai",)
DEFAULT_BASE_URL = "https://app.shield360.ai"
MAX_LIFETIME_SECONDS = 300
# The largest clock skew a verifier accepts; a larger clock_skew_seconds is lowered to it.
MAX_CLOCK_SKEW_SECONDS = 300

_MODES = ("observe", "enforce")
# How strongly a passport shows the agent acts for a person, strongest first.
ASSURANCE_LEVELS = ("delegated", "named", "unverified")
_MIN_ASSURANCE = ("none",) + ASSURANCE_LEVELS


def assurance_rank(value: Optional[str]) -> int:
    """Higher is stronger; "none" (or no act) is 0."""
    return {"delegated": 3, "named": 2, "unverified": 1}.get(value or "", 0)


def assurance_of(value: Any) -> str:
    """An act's assurance: absent means "named" (older passports); anything unknown counts as the weakest."""
    if value is None:
        return "named"
    return value if value in ASSURANCE_LEVELS else "unverified"

_MAX_OPERATORS = 1000

# Policy fields: wire (camelCase) name -> Python attribute.
_POLICY_FIELDS = {
    "mode": "mode",
    "requireAgent": "require_agent",
    "operators": "operators",
    "requireOnBehalfOf": "require_on_behalf_of",
    "online": "online",
    "minAssurance": "min_assurance",
}


@dataclass(frozen=True)
class AgentPolicy:
    """The receiver's policy: what to do with the agents that call it."""

    mode: str = "observe"  # observe: never block, report what enforce would do
    require_agent: bool = False  # a call without a passport is denied ("absent")
    operators: tuple = ()  # allowed operator ids or domains; empty = any verified operator
    require_on_behalf_of: bool = False  # the passport must carry act
    online: bool = False  # always ask the issuer too
    # weakest on-behalf-of assurance accepted: "none" | "unverified" | "named" | "delegated"
    min_assurance: str = "none"

    @staticmethod
    def sanitise(value: Any) -> Dict[str, Any]:
        """The well-typed fields of a policy-like value (snake_case or camelCase keys)."""
        if isinstance(value, AgentPolicy):
            return {attr: getattr(value, attr) for attr in _POLICY_FIELDS.values()}
        if not isinstance(value, Mapping):
            return {}
        out: Dict[str, Any] = {}
        for wire, attr in _POLICY_FIELDS.items():
            if wire in value:
                raw = value[wire]
            elif attr in value:
                raw = value[attr]
            else:
                continue
            if attr == "mode":
                if raw in _MODES:
                    out[attr] = raw
            elif attr == "min_assurance":
                if raw in _MIN_ASSURANCE:
                    out[attr] = raw
            elif attr == "operators":
                if isinstance(raw, (list, tuple)):
                    ops = [o.strip() for o in raw if isinstance(o, str) and o.strip() and len(o) <= 256]
                    out[attr] = tuple(ops[:_MAX_OPERATORS])
            elif isinstance(raw, bool):
                out[attr] = raw
        return out

    def to_dict(self) -> Dict[str, Any]:
        """The wire (camelCase) form."""
        out = {wire: getattr(self, attr) for wire, attr in _POLICY_FIELDS.items()}
        out["operators"] = list(self.operators)
        return out


DEFAULT_POLICY = AgentPolicy()


@dataclass(frozen=True)
class AgentOwner:
    domain: Optional[str]


@dataclass(frozen=True)
class AgentIdentity:
    id: str
    name: str
    purpose: Optional[str] = None
    status: Optional[str] = None  # "enrolled" | "not_enrolled"
    environment: Optional[str] = None
    risk: Optional[str] = None
    owner: Optional[AgentOwner] = None
    reviewed_at: Optional[str] = None  # ISO 8601
    enrolled_at: Optional[str] = None  # ISO 8601

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"id": self.id, "name": self.name}
        for wire, value in (
            ("purpose", self.purpose),
            ("status", self.status),
            ("environment", self.environment),
            ("risk", self.risk),
            ("reviewedAt", self.reviewed_at),
            ("enrolledAt", self.enrolled_at),
        ):
            if value:
                out[wire] = value
        if self.owner is not None:
            out["owner"] = {"domain": self.owner.domain}
        return out


@dataclass(frozen=True)
class AgentMandate:
    id: str
    expires_at: str  # ISO 8601


@dataclass(frozen=True)
class AgentOperator:
    id: str
    name: str
    domain: Optional[str]


@dataclass(frozen=True)
class AgentOnBehalfOf:
    id: str  # the pairwise person id (act.sub): stable per receiver, never the person's id or email
    domain: Optional[str]
    # "delegated" | "named" | "unverified"; "named" when the act carries none; lowered when the issuer says so online
    assurance: str = "named"
    mandate: Optional[AgentMandate] = None


@dataclass(frozen=True)
class SignatureInfo:
    """A verified Web Bot Auth signature: the signer's Signature-Agent URL and the key's JWK thumbprint."""

    agent: str
    key_id: str


@dataclass
class AgentCheck:
    """The result of one check. Never contains the passport itself."""

    status: str  # "verified" | "absent" | "invalid"
    decision: str  # "allow" | "deny"
    blocked: bool  # decision == "deny" and mode == "enforce"
    reason: Optional[str] = None
    # What identified the caller: its passport, or a Web Bot Auth signature (then agent and operator
    # are the signer's host and no person is named). None when the call carried neither.
    via: Optional[str] = None  # "passport" | "web-bot-auth"
    # The Web Bot Auth signature that verified: the signer's Signature-Agent URL and key thumbprint.
    signature: Optional[SignatureInfo] = None
    agent: Optional[AgentIdentity] = None
    operator: Optional[AgentOperator] = None
    on_behalf_of: Optional[AgentOnBehalfOf] = None
    scopes: List[str] = field(default_factory=list)
    issuer: Optional[str] = None
    passport_id: Optional[str] = None  # jti
    expires_at: Optional[str] = None  # ISO 8601

    def to_dict(self) -> Dict[str, Any]:
        """The wire (camelCase) form, the same as the TypeScript verifier's result."""
        out: Dict[str, Any] = {"status": self.status, "decision": self.decision, "blocked": self.blocked, "scopes": list(self.scopes)}
        if self.reason is not None:
            out["reason"] = self.reason
        if self.via is not None:
            out["via"] = self.via
        if self.signature is not None:
            out["signature"] = {"agent": self.signature.agent, "keyId": self.signature.key_id}
        if self.agent is not None:
            out["agent"] = self.agent.to_dict()
        if self.operator is not None:
            out["operator"] = {"id": self.operator.id, "name": self.operator.name, "domain": self.operator.domain}
        if self.on_behalf_of is not None:
            obo = self.on_behalf_of
            out["onBehalfOf"] = {"id": obo.id, "domain": obo.domain, "assurance": obo.assurance}
            if obo.mandate is not None:
                out["onBehalfOf"]["mandate"] = {"id": obo.mandate.id, "expiresAt": obo.mandate.expires_at}
        if self.issuer is not None:
            out["issuer"] = self.issuer
        if self.passport_id is not None:
            out["passportId"] = self.passport_id
        if self.expires_at is not None:
            out["expiresAt"] = self.expires_at
        return out


@runtime_checkable
class ReplayStore(Protocol):
    """Remembers passport ids so each is accepted once."""

    def seen(self, jti: str, expires_at: float) -> bool:
        """Record ``jti`` until ``expires_at`` (epoch seconds); return whether it had already been seen.

        Must be atomic for clustered receivers (e.g. Redis ``SET key 1 NX EXAT``).
        """
