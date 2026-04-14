"""red_agent.core - Deterministic runtime engine sub-package."""
from __future__ import annotations

from .audit import AuditStore
from .constants import (
    AgentState, ArtifactClass, ClassificationLevel, FaultClass,
    GateSuppressionReason, OutputDecision, ReviewAction, VALID_TRANSITIONS,
)
from .directives import DirectiveContext, DirectiveSet, DirectiveSetResult
from .fsm import AgentFSM, InvalidTransitionError
from .gate import GateEvaluation, GateSnapshot, OutputAuthorizationGate
from .intelligence import (
    IntelligenceArtifact, IntelligenceStore,
    RecipientClassification, ThreatModelEntry,
)
from .recovery import (
    NonceRegistry, RecoverySignal, RecoverySignalVerifier,
    generate_recovery_signal,
)
from .tasking import TaskExecutorFn, TaskingEnvelope, TaskingUnit, TaskResult
from .initialization import InitializationResult, run_initialization
from .teardown import TeardownResult, UngracefulTerminationHandler, run_teardown

__all__ = [
    "AuditStore",
    "AgentState", "ArtifactClass", "ClassificationLevel", "FaultClass",
    "GateSuppressionReason", "OutputDecision", "ReviewAction", "VALID_TRANSITIONS",
    "DirectiveContext", "DirectiveSet", "DirectiveSetResult",
    "AgentFSM", "InvalidTransitionError",
    "GateEvaluation", "GateSnapshot", "OutputAuthorizationGate",
    "IntelligenceArtifact", "IntelligenceStore",
    "RecipientClassification", "ThreatModelEntry",
    "NonceRegistry", "RecoverySignal", "RecoverySignalVerifier",
    "generate_recovery_signal",
    "TaskExecutorFn", "TaskingEnvelope", "TaskingUnit", "TaskResult",
    "InitializationResult", "run_initialization",
    "TeardownResult", "UngracefulTerminationHandler", "run_teardown",
]
