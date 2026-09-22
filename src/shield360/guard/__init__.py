"""
shield360.guard -- Production-grade guardrails for LLM applications.

All guard classes are also re-exported at the ``shield360`` top level:

    import shield360
    shield360.init(guards=[shield360.PII(action="redact")])

Or with direct imports:

    from shield360 import PII, PromptInjection, Moderation
"""

from shield360.guard._base import (
    Guard,
    GuardAction,
    GuardConfigError,
    GuardDeniedError,
    GuardError,
    GuardPhase,
    GuardResult,
    GuardTimeoutError,
    PipelineResult,
)
from shield360.guard._pipeline import Pipeline
from shield360.guard.pii import PII
from shield360.guard.prompt_injection import PromptInjection
from shield360.guard.sensitive_topic import SensitiveTopic
from shield360.guard.topic_restriction import TopicRestriction
from shield360.guard.moderation import Moderation
from shield360.guard.schema import Schema
from shield360.guard.custom import Custom

__all__ = [
    # Guard classes
    "PII",
    "PromptInjection",
    "SensitiveTopic",
    "TopicRestriction",
    "Moderation",
    "Schema",
    "Custom",
    # Pipeline
    "Pipeline",
    # Base / types
    "Guard",
    "GuardAction",
    "GuardPhase",
    "GuardResult",
    "PipelineResult",
    # Errors
    "GuardError",
    "GuardDeniedError",
    "GuardTimeoutError",
    "GuardConfigError",
]
