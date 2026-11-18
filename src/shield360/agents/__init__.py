"""
shield360.agents: verify the agents that call your API or MCP server.

    from shield360.agents import AgentVerifier

    verifier = AgentVerifier(audience="api.example.com")
    result = verifier.check(request.headers)

A calling agent sends a Shield360 agent passport in the ``Shield360-Agent`` header, or signs the
request with Web Bot Auth (RFC 9421 HTTP Message Signatures, as Cloudflare's signed agents do).
Verifying it needs the ``cryptography`` package: ``pip install 'shield360[agents]'``.
"""

from shield360.agents._middleware import AgentVerifierASGIMiddleware, AgentVerifierWSGIMiddleware
from shield360.agents._types import (
    AGENT_HEADER,
    ASSURANCE_LEVELS,
    DEFAULT_ISSUERS,
    DEFAULT_POLICY,
    PASSPORT_TYP,
    AgentCheck,
    AgentIdentity,
    AgentMandate,
    AgentOnBehalfOf,
    AgentOperator,
    AgentOwner,
    AgentPolicy,
    ReplayStore,
    SignatureInfo,
    assurance_rank,
)
from shield360.agents._web_bot_auth import DIRECTORY_PATH, WEB_BOT_AUTH_TAG, jwk_thumbprint
from shield360.agents._verifier import AgentVerifier, MemoryReplayStore, read_passport


def check(
    verifier: AgentVerifier, headers_or_token=None, online: bool = False, route=None, method=None, *, query=None, scheme=None
) -> AgentCheck:
    """Function form of ``verifier.check``."""
    return verifier.check(headers_or_token, online=online, route=route, method=method, query=query, scheme=scheme)


__all__ = [
    "AGENT_HEADER",
    "DIRECTORY_PATH",
    "ASSURANCE_LEVELS",
    "DEFAULT_ISSUERS",
    "DEFAULT_POLICY",
    "PASSPORT_TYP",
    "AgentCheck",
    "AgentIdentity",
    "AgentMandate",
    "AgentOnBehalfOf",
    "AgentOperator",
    "AgentOwner",
    "AgentPolicy",
    "AgentVerifier",
    "AgentVerifierASGIMiddleware",
    "AgentVerifierWSGIMiddleware",
    "MemoryReplayStore",
    "ReplayStore",
    "SignatureInfo",
    "WEB_BOT_AUTH_TAG",
    "assurance_rank",
    "check",
    "jwk_thumbprint",
    "read_passport",
]
