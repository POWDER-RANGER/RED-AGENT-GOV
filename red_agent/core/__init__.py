"""red_agent.core — Deterministic runtime engine.

Exposes the primary runtime types consumed by ``RedAgent``.
"""

from .audit import AuditStore, AuditStoreUnavailableError, FaultClass
from .fsm import AgentFSM
from .gate import GateDecision, OutputAuthorizationGate, SuppressionReason
from .intelligence import D06Filter, LifecycleManager
from .recovery import RecoverySignal, RecoverySignalValidator, generate_recovery_signal
from .tasking import RecipientClassification, TaskingUnit
from .timing import StochasticTimingLayer, TimingLayerUnavailableError

__all__ = [
    "AuditStore",
    "AuditStoreUnavailableError",
    "FaultClass",
    "AgentFSM",
    "GateDecision",
    "OutputAuthorizationGate",
    "SuppressionReason",
    "D06Filter",
    "LifecycleManager",
    "RecoverySignal",
    "RecoverySignalValidator",
    "generate_recovery_signal",
    "RecipientClassification",
    "TaskingUnit",
    "StochasticTimingLayer",
    "TimingLayerUnavailableError",
]
