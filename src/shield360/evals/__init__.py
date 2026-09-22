"""
shield360.evals

Server-side evaluation capabilities for AI-generated text.
Uses the Shield360 evaluation engine for hallucination, bias, toxicity,
and custom evaluation types.
"""

from shield360.evals.offline import run_eval, run_eval_batch, fetch_eval_types
from shield360.evals.offline_types import (
    OfflineEvaluation,
    OfflineEvalResult,
    BatchEvalResult,
    EvalType,
    ContextInfo,
)
