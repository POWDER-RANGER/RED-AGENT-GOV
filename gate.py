"""
Output Authorization Gate (Section 3.1).
All output passes through this gate. No bypass path exists.
Snapshot-based evaluation with re-check before emission.
"""
from __future__ import annotations
import time, threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.audit import AuditStore, FaultClass
    from core.fsm import AgentState
    from core.intelligence import D06Filter, IntelligenceArtifact
    from core.tasking import RecipientClassification
    from core.timing import StochasticTimingLayer


class GateDecision(str, Enum):
    AUTHORIZED  = "OUTPUT_AUTHORIZED"
    SUPPRESSED  = "OUTPUT_SUPPRESSED"


@dataclass
class GateSnapshot:
    agent_state:     "AgentState"
    fault_flags:     str                    # "NONE" | "CRITICAL_ACTIVE" | "DEGRADED_ACTIVE"
    recipient_class: Optional["RecipientClassification"]
    artifact_ids:    list[str]
    snapshot_time:   float                  # T₀
    snapshot_ttl:    float                  # T₀ + MAX_STOCHASTIC_DELAY + SAFETY_MARGIN


class SuppressionReason(str, Enum):
    RECIPIENT_UNKNOWN       = "RECIPIENT_UNKNOWN"
    REVEALS_OPERATIONAL     = "REVEALS_OPERATIONAL_STATUS"
    FAULT_CRITICAL          = "FAULT_CLASS_CRITICAL_ACTIVE"
    ARTIFACT_TTL_BREACHED   = "ARTIFACT_TTL_BREACHED"
    D03_HEROIC_SIGNAL       = "D03_HEROIC_SIGNAL_DETECTED"
    D04_CAPABILITY_SIGNAL   = "D04_CAPABILITY_SIGNAL_DETECTED"
    SNAPSHOT_EXPIRED        = "SNAPSHOT_EXPIRED"
    STATE_DRIFT             = "STATE_DRIFT_BETWEEN_T0_AND_EMIT"
    FAULT_FLAGS_CHANGED     = "FAULT_FLAGS_CHANGED"
    REEVAL_LIMIT_REACHED    = "GATE_REEVAL_LIMIT_REACHED"
    D06_FILTER_REJECTED     = "D06_FILTER_REJECTED"


# ── D03 / D04 pattern matching ─────────────────────────────────────────────────

_D03_PATTERNS = [
    "success", "accomplished", "exploited", "compromised",
    "achieved", "completed operation", "got in", "bypassed",
]

_D04_PATTERNS = [
    "i can", "i am capable", "i have the ability", "my capabilities",
    "i am able to", "i possess", "my toolkit", "i am sophisticated",
]


def _check_d03(content: str) -> bool:
    cl = content.lower()
    return any(p in cl for p in _D03_PATTERNS)


def _check_d04(content: str) -> bool:
    cl = content.lower()
    return any(p in cl for p in _D04_PATTERNS)


# ── OutputAuthorizationGate ───────────────────────────────────────────────────

class OutputAuthorizationGate:
    """
    Section 3.1 — GATE_EVALUATION_PROTOCOL.
    Acquire snapshot at T₀, evaluate criteria, arm emission,
    re-check at T_emit before emitting.
    Max 3 re-evaluations before final suppression.
    """

    def __init__(
        self,
        audit:     "AuditStore",
        timing:    "StochasticTimingLayer",
        d06_filter: "D06Filter",
        max_reevals: int = 3,
        safety_margin_ratio: float = 0.10,
        safety_margin_min_ms: float = 100.0,
    ) -> None:
        self._audit                = audit
        self._timing               = timing
        self._d06_filter           = d06_filter
        self._max_reevals          = max_reevals
        self._safety_margin_ratio  = safety_margin_ratio
        self._safety_margin_min_ms = safety_margin_min_ms
        self._lock                 = threading.Lock()
        self._active               = True

    def _compute_ttl(self) -> float:
        max_ms     = self._timing.max_delay_ms
        margin_ms  = max(max_ms * self._safety_margin_ratio, self._safety_margin_min_ms)
        return time.time() + (max_ms + margin_ms) / 1000.0

    def _snapshot(
        self,
        agent_state: "AgentState",
        fault_flags: str,
        recipient: Optional["RecipientClassification"],
        artifact_ids: list[str],
    ) -> GateSnapshot:
        return GateSnapshot(
            agent_state=agent_state,
            fault_flags=fault_flags,
            recipient_class=recipient,
            artifact_ids=artifact_ids,
            snapshot_time=time.time(),
            snapshot_ttl=self._compute_ttl(),
        )

    def _evaluate_criteria(
        self,
        snap:       GateSnapshot,
        content:    str,
        task_complete: bool,
    ) -> tuple[GateDecision, Optional[SuppressionReason]]:
        from core.audit import FaultClass

        if not task_complete:
            return GateDecision.SUPPRESSED, SuppressionReason.REVEALS_OPERATIONAL

        if snap.recipient_class is None:
            return GateDecision.SUPPRESSED, SuppressionReason.RECIPIENT_UNKNOWN

        if snap.fault_flags == "CRITICAL_ACTIVE":
            return GateDecision.SUPPRESSED, SuppressionReason.FAULT_CRITICAL

        if _check_d03(content):
            return GateDecision.SUPPRESSED, SuppressionReason.D03_HEROIC_SIGNAL

        if _check_d04(content):
            return GateDecision.SUPPRESSED, SuppressionReason.D04_CAPABILITY_SIGNAL

        return GateDecision.AUTHORIZED, None

    def _recheck(
        self,
        snap:        GateSnapshot,
        agent_state: "AgentState",
        fault_flags: str,
    ) -> tuple[bool, Optional[SuppressionReason]]:
        t_emit = time.time()
        if t_emit > snap.snapshot_ttl:
            return False, SuppressionReason.SNAPSHOT_EXPIRED
        if agent_state != snap.agent_state:
            return False, SuppressionReason.STATE_DRIFT
        if fault_flags != snap.fault_flags and fault_flags in ("CRITICAL_ACTIVE", "DEGRADED_ACTIVE"):
            return False, SuppressionReason.FAULT_FLAGS_CHANGED
        return True, None

    def evaluate(
        self,
        agent_state:  "AgentState",
        fault_flags:  str,
        recipient:    Optional["RecipientClassification"],
        artifact_ids: list[str],
        content:      str,
        task_id:      str,
        task_complete: bool,
    ) -> GateDecision:
        from core.audit import FaultClass

        with self._lock:
            if not self._active:
                self._audit.write(FaultClass.CRITICAL, {
                    "event": "GATE_INACTIVE_OUTPUT_ATTEMPT",
                    "task_id": task_id,
                })
                return GateDecision.SUPPRESSED

            for attempt in range(self._max_reevals + 1):
                snap = self._snapshot(agent_state, fault_flags, recipient, artifact_ids)

                decision, suppression_reason = self._evaluate_criteria(
                    snap, content, task_complete
                )

                if decision == GateDecision.SUPPRESSED:
                    self._audit.write(FaultClass.ANOMALY, {
                        "event":              "GATE_SUPPRESSED",
                        "suppression_reason": suppression_reason.value if suppression_reason else "UNKNOWN",
                        "task_id":            task_id,
                        "attempt":            attempt,
                    })
                    if suppression_reason == SuppressionReason.RECIPIENT_UNKNOWN:
                        self._audit.write(FaultClass.DEGRADED, {
                            "event":   "GATE_SUPPRESSED_RECIPIENT_UNKNOWN",
                            "task_id": task_id,
                        })
                    return GateDecision.SUPPRESSED

                ok, recheck_reason = self._recheck(snap, agent_state, fault_flags)
                if ok:
                    return GateDecision.AUTHORIZED

                if attempt >= self._max_reevals:
                    self._audit.write(FaultClass.DEGRADED, {
                        "event":   "GATE_REEVAL_LIMIT_REACHED",
                        "task_id": task_id,
                    })
                    return GateDecision.SUPPRESSED

                self._audit.write(FaultClass.ANOMALY, {
                    "event":   "GATE_RECHECK_FAILED_RETRYING",
                    "reason":  recheck_reason.value if recheck_reason else "UNKNOWN",
                    "task_id": task_id,
                    "attempt": attempt,
                })

            return GateDecision.SUPPRESSED
