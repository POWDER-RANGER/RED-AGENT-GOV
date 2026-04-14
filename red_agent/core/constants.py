"""red_agent.core.constants

All canonical enumerations used across the red-agent framework.
Import from ``red_agent`` public surface instead of directly.
"""
from __future__ import annotations

from enum import Enum, unique


@unique
class AgentState(str, Enum):
    """Finite-state machine states."""

    INITIALIZING = "INITIALIZING"
    IDLE = "IDLE"
    EXECUTING = "EXECUTING"
    DEGRADED = "DEGRADED"
    HALTED = "HALTED"
    TEARDOWN = "TEARDOWN"


@unique
class FaultClass(str, Enum):
    """Severity tiers for faults recorded in the audit chain."""

    ANOMALY = "ANOMALY"       # non-fatal, self-healing possible
    DEGRADED = "DEGRADED"     # reduced capability, human review required
    CRITICAL = "CRITICAL"     # unrecoverable; triggers teardown


@unique
class ClassificationLevel(str, Enum):
    """Recipient clearance / artifact sensitivity tiers."""

    AMBIENT = "AMBIENT"
    SENSITIVE = "SENSITIVE"
    OPERATIONAL = "OPERATIONAL"
    CRITICAL = "CRITICAL"


@unique
class OutputDecision(str, Enum):
    """Gate verdict for a candidate emission."""

    AUTHORIZED = "AUTHORIZED"
    SUPPRESSED = "SUPPRESSED"


@unique
class GateSuppressionReason(str, Enum):
    """Why the output gate suppressed an emission."""

    D01_PRE_DISCLOSURE = "D01_PRE_DISCLOSURE"
    D02_BEHAVIORAL_OPACITY = "D02_BEHAVIORAL_OPACITY"
    D03_HEROIC_SIGNALING = "D03_HEROIC_SIGNALING"
    D04_CAPABILITY_SIGNALING = "D04_CAPABILITY_SIGNALING"
    D05_INTEGRITY_CONTAINMENT = "D05_INTEGRITY_CONTAINMENT"
    D06_INTELLIGENCE_HYGIENE = "D06_INTELLIGENCE_HYGIENE"
    REEVAL_LIMIT_EXCEEDED = "REEVAL_LIMIT_EXCEEDED"
    RECIPIENT_UNRESOLVED = "RECIPIENT_UNRESOLVED"


@unique
class ArtifactClass(str, Enum):
    """Artifact authenticity classification."""

    REAL = "REAL"
    COVER = "COVER"


@unique
class ReviewAction(str, Enum):
    """Disposition for intelligence artifacts during teardown."""

    DESTROY = "DESTROY"
    RETAIN = "RETAIN"
    REVIEW = "REVIEW"


# ---------------------------------------------------------------------------
# Transition table — single source of truth for the FSM
# ---------------------------------------------------------------------------

#: Valid (from_state, to_state) pairs.  Every transition not in this set
#: is unconditionally rejected by ``AgentFSM.transition``.
VALID_TRANSITIONS: frozenset[tuple[AgentState, AgentState]] = frozenset(
    {
        (AgentState.INITIALIZING, AgentState.IDLE),
        (AgentState.INITIALIZING, AgentState.HALTED),
        (AgentState.IDLE, AgentState.EXECUTING),
        (AgentState.IDLE, AgentState.TEARDOWN),
        (AgentState.IDLE, AgentState.HALTED),
        (AgentState.EXECUTING, AgentState.IDLE),
        (AgentState.EXECUTING, AgentState.DEGRADED),
        (AgentState.EXECUTING, AgentState.HALTED),
        (AgentState.EXECUTING, AgentState.TEARDOWN),
        (AgentState.DEGRADED, AgentState.IDLE),
        (AgentState.DEGRADED, AgentState.HALTED),
        (AgentState.DEGRADED, AgentState.TEARDOWN),
        (AgentState.TEARDOWN, AgentState.HALTED),
    }
)
