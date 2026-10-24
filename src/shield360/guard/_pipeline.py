"""
Guard Pipeline -- composes multiple guards into an ordered evaluation chain.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from shield360.guard._base import (
    Guard,
    GuardAction,
    GuardPhase,
    GuardResult,
    PipelineResult,
    _ACTION_SEVERITY,
)

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Evaluates an ordered list of guards and returns an aggregated result.

    * **fail_open** (default ``True``): if a guard raises, treat it as ``allow``.
    * **Deny short-circuits**: once a guard returns ``deny``, no further guards run.
    * **Redactions chain**: successive ``redact`` results operate on the already-redacted text.
    * **OTel metrics + events**: emitted for every individual guard evaluation.
    """

    def __init__(
        self,
        guards: Optional[List[Guard]] = None,
        fail_open: bool = True,
    ):
        self._guards: List[Guard] = list(guards or [])
        self._fail_open = fail_open

    @property
    def guards(self) -> List[Guard]:
        """Return a shallow copy of the configured guards in pipeline order."""
        return list(self._guards)

    def has_phase(self, phase: str) -> bool:
        """Whether any guard runs in ``phase``."""
        guard_phase = GuardPhase(phase)
        return any(g.supports_phase(guard_phase) for g in self._guards)

    def scan_bound(self) -> int:
        """The most characters every guard reads: the smallest positive ``max_scan_length``, or 0 for all of it.

        Text past it is scanned in part by at least one guard; Shield Protect's
        enforced mode refuses such text instead.
        """
        bounds = [g.max_scan_length for g in self._guards if g.max_scan_length > 0]
        return min(bounds) if bounds else 0

    def evaluate(self, text: str, phase: str = "preflight") -> PipelineResult:
        """Run every guard that supports ``phase`` and aggregate the results."""
        guard_phase = GuardPhase(phase)
        results: List[GuardResult] = []
        current_text = text
        worst_action = GuardAction.ALLOW

        for guard in self._guards:
            if not guard.supports_phase(guard_phase):
                continue

            try:
                result = guard.run(current_text, guard_phase)
            except Exception:
                if self._fail_open:
                    logger.warning(
                        "Guard '%s' raised during %s evaluation; fail-open -> allow",
                        guard.name,
                        phase,
                        exc_info=True,
                    )
                    result = GuardResult(guard_name=guard.name)
                else:
                    raise

            results.append(result)
            self._emit_otel(result, phase)

            if _ACTION_SEVERITY[result.action] > _ACTION_SEVERITY[worst_action]:
                worst_action = result.action

            if (
                result.action == GuardAction.REDACT
                and result.transformed_text is not None
            ):
                current_text = result.transformed_text

            if result.action == GuardAction.DENY:
                break

        transformed = current_text if current_text != text else None
        return PipelineResult(
            action=worst_action,
            results=results,
            transformed_text=transformed,
        )

    def redact(self, text: str, phase: str = "preflight") -> str:
        """Apply every redacting guard to ``text`` and return the result.

        Used after ``evaluate`` has already decided a call is redacted, to
        rewrite each message on its own. Emits nothing: the decision, and its
        telemetry, came from ``evaluate``.
        """
        guard_phase = GuardPhase(phase)
        current = text
        for guard in self._guards:
            if not guard.supports_phase(guard_phase):
                continue
            try:
                result = guard.run(current, guard_phase)
            except Exception:
                if self._fail_open:
                    continue
                raise
            if (
                result.action == GuardAction.REDACT
                and result.transformed_text is not None
            ):
                current = result.transformed_text
        return current

    # ------------------------------------------------------------------
    # OTel emission
    # ------------------------------------------------------------------

    @staticmethod
    def _emit_otel(result: GuardResult, phase: str) -> None:
        """Best-effort OTel metric + event emission."""
        try:
            from shield360._config import Shield360Config

            metrics = getattr(Shield360Config, "metrics_dict", None)
            if metrics and not getattr(Shield360Config, "disable_metrics", False):
                counter = metrics.get("guard_requests")
                if counter is not None:
                    counter.add(
                        1,
                        {
                            "guard.name": result.guard_name,
                            "guard.action": result.action.value,
                            "guard.score": result.score,
                            "guard.classification": result.classification,
                            "guard.phase": phase,
                        },
                    )
        except Exception:
            pass

        try:
            from shield360.guard import _report

            _report.report(
                result.guard_name,
                result.action.value,
                result.classification,
                phase,
                findings=list(result.findings),
            )
        except Exception:
            pass

        try:
            from opentelemetry import trace
            from opentelemetry.trace import Status, StatusCode

            attributes = {
                "guard.name": result.guard_name,
                "guard.phase": phase,
                "guard.action": result.action.value,
                "guard.score": result.score,
                "guard.classification": result.classification,
                "guard.explanation": result.explanation,
                "guard.latency_ms": result.latency_ms,
            }
            span = trace.get_current_span()
            if span and span.is_recording():
                span.add_event("guard.evaluation", attributes=attributes)
            elif result.action != GuardAction.ALLOW:
                # Guards run before the LLM call's span starts, and a denied
                # call never starts one. Record what the guard did on a span
                # of its own so a block or redaction is never invisible.
                # Only the kind of data found is recorded, never the text.
                tracer = trace.get_tracer("shield360.guard")
                with tracer.start_as_current_span("shield360.guard") as own:
                    own.set_attributes(attributes)
                    own.add_event("guard.evaluation", attributes=attributes)
                    if result.action == GuardAction.DENY:
                        own.set_status(Status(StatusCode.ERROR, "denied by guard"))
        except Exception:
            pass
