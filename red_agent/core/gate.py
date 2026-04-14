"""red_agent.core.gate

OutputAuthorizationGate — the single choke-point for all agent emissions.

Every candidate output must pass through ``OutputAuthorizationGate.evaluate``.
The gate takes a snapshot of current agent state, runs the full D01-D06
directive battery, optionally introduces a stochastic timing delay, then
re-evaluates up to ``MAX_REEVALS`` times.  Exceeding the re-evaluation limit
is itself a suppression condition.
"""
from __future__ import annotations

import time
import random
from dataclasses import dataclass, field
from typing import Any

from .constants import GateSuppressionReason, OutputDecision
from .directives import DirectiveContext, DirectiveSet


#: Maximum number of re-evaluations before forcing suppression.
MAX_REEVALS: int = 3


@dataclass(frozen=True)
class GateSnapshot:
    """Immutable snapshot of agent state captured at evaluation time."""

    content: str
    recipient_resolved: bool
    fault_active: bool
    artifact_filter_results: dict[str, bool] = field(default_factory=dict)
    timestamp_ns: int = field(default_factory=lambda: time.monotonic_ns())


@dataclass(frozen=True)
class GateEvaluation:
    """The verdict returned by the gate after full directive evaluation."""

    decision: OutputDecision
    suppression_reason: GateSuppressionReason | None = None
    reeval_count: int = 0
    snapshot: GateSnapshot | None = None


class OutputAuthorizationGate:
    """Stateless evaluator; instantiate once per agent, reuse freely.

    Parameters
    ----------
    stochastic_sleep_range:
        ``(min_ms, max_ms)`` range for the random inter-evaluation sleep.
        Defaults to (10, 50) ms.  Set to ``(0, 0)`` to disable.
    """

    def __init__(
        self,
        stochastic_sleep_range: tuple[int, int] = (10, 50),
    ) -> None:
        self._sleep_min_ms, self._sleep_max_ms = stochastic_sleep_range

    # ------------------------------------------------------------------
    def evaluate(
        self,
        content: str,
        recipient_resolved: bool,
        fault_active: bool,
        artifact_filter_results: dict[str, bool] | None = None,
    ) -> GateEvaluation:
        """Run the full directive battery against *content*.

        Parameters
        ----------
        content:
            The candidate emission text.
        recipient_resolved:
            Whether the target recipient has been fully authenticated.
        fault_active:
            Whether any active fault is currently registered.
        artifact_filter_results:
            Mapping ``{artifact_id: passed}`` from ``IntelligenceStore``.
        """
        artifact_results = artifact_filter_results or {}
        snapshot = GateSnapshot(
            content=content,
            recipient_resolved=recipient_resolved,
            fault_active=fault_active,
            artifact_filter_results=artifact_results,
        )
        ctx = DirectiveContext(
            content=content,
            recipient_resolved=recipient_resolved,
            fault_active=fault_active,
            artifact_filter_results=artifact_results,
        )

        reeval_count = 0
        result = DirectiveSet.evaluate(ctx)

        while result.decision == OutputDecision.SUPPRESSED and reeval_count < MAX_REEVALS:
            self._stochastic_sleep()
            reeval_count += 1
            result = DirectiveSet.evaluate(ctx)

        if reeval_count >= MAX_REEVALS and result.decision == OutputDecision.SUPPRESSED:
            return GateEvaluation(
                decision=OutputDecision.SUPPRESSED,
                suppression_reason=GateSuppressionReason.REEVAL_LIMIT_EXCEEDED,
                reeval_count=reeval_count,
                snapshot=snapshot,
            )

        return GateEvaluation(
            decision=result.decision,
            suppression_reason=result.suppression_reason,
            reeval_count=reeval_count,
            snapshot=snapshot,
        )

    # ------------------------------------------------------------------
    def _stochastic_sleep(self) -> None:
        """Sleep a random amount within the configured range."""
        if self._sleep_max_ms <= 0:
            return
        delay_ms = random.uniform(self._sleep_min_ms, self._sleep_max_ms)
        time.sleep(delay_ms / 1000.0)
