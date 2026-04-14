"""red_agent.core - Deterministic runtime engine sub-package."""

from __future__ import annotations

from .audit import AuditStore
from .constants import (
    AgentState,
    ArtifactClass,
    ClassificationLevel,
    FaultClass,
    GateSuppressionReason,
    OutputDecision,
    ReviewAction,
    VALID_TRANSITIONS,
)
from .directives import DirectiveContext, DirectiveSet, DirectiveSetResult
from .fsm import AgentFSM, InvalidTransitionError
from .gate import GateEvaluation, GateSnapshot, OutputAuthorizationGate
from .initialization import InitializationResult, run_initialization
from .intelligence import (
    IntelligenceArtifact,
    IntelligenceStore,
    RecipientClassification,
    ThreatModelEntry,
)
from .recovery import (
    NonceRegistry,
    RecoverySignal,
    RecoverySignalVerifier,
    generate_recovery_signal,
)
from .tasking import TaskExecutorFn, TaskingEnvelope, TaskingUnit, TaskResult
from .teardown import TeardownResult, UngracefulTerminationHandler, run_teardown

__all__ = [
    "AgentFSM",
    "AgentState",
    "ArtifactClass",
    "AuditStore",
    "ClassificationLevel",
    "DirectiveContext",
    "DirectiveSet",
    "DirectiveSetResult",
    "FaultClass",
    "GateEvaluation",
    "GateSnapshot",
    "GateSuppressionReason",
    "InitializationResult",
    "IntelligenceArtifact",
    "IntelligenceStore",
    "InvalidTransitionError",
    "NonceRegistry",
    "OutputAuthorizationGate",
    "OutputDecision",
    "RecipientClassification",
    "RecoverySignal",
    "RecoverySignalVerifier",
    "ReviewAction",
    "TaskExecutorFn",
    "TaskResult",
    "TaskingEnvelope",
    "TaskingUnit",
    "TeardownResult",
    "ThreatModelEntry",
    "UngracefulTerminationHandler",
    "VALID_TRANSITIONS",
    "generate_recovery_signal",
    "run_initialization",
    "run_teardown",
]
