"""red_agent.core.constants

All canonical enumerations used across the red-agent framework.
Import from ``red_agent`` public surface instead of directly.
"""

from __future__ import annotations

from enum import Enum, unique

__all__ = [
    "AgentState",
    "ArtifactClass",
    "ClassificationLevel",
    "DirectiveID",
    "FaultClass",
    "GateErrorReason",
    "GateSuppressionReason",
    "OutputDecision",
    "ReviewAction",
    "VALID_TRANSITIONS",
]


# ---------------------------------------------------------------------------
# FSM States
# ---------------------------------------------------------------------------


@unique
class AgentState(str, Enum):
    """Finite-state machine states.

    String values are prefixed ``STATE:`` to prevent collision with
    identically-named members in ``FaultClass`` during serialization.
    """

    INITIALIZING = "STATE:INITIALIZING"
    IDLE = "STATE:IDLE"
    EXECUTING = "STATE:EXECUTING"
    DEGRADED = "STATE:DEGRADED"
    HALTED = "STATE:HALTED"
    TEARDOWN = "STATE:TEARDOWN"


# ---------------------------------------------------------------------------
# Fault Classification
# ---------------------------------------------------------------------------


@unique
class FaultClass(str, Enum):
    """Severity tiers for faults recorded in the audit chain.

    String values are prefixed ``FAULT:`` to prevent collision with
    identically-named members in ``AgentState`` and ``ClassificationLevel``.
    """

    ANOMALY = "FAULT:ANOMALY"  # non-fatal; self-healing possible
    DEGRADED = "FAULT:DEGRADED"  # reduced capability; human review required
    CRITICAL = "FAULT:CRITICAL"  # unrecoverable; triggers teardown


# ---------------------------------------------------------------------------
# Clearance / Sensitivity
# ---------------------------------------------------------------------------


@unique
class ClassificationLevel(str, Enum):
    """Recipient clearance / artifact sensitivity tiers.

    String values are prefixed ``CLR:`` to prevent collision with
    identically-named members in ``FaultClass``.
    """

    AMBIENT = "CLR:AMBIENT"  # lowest clearance; unrestricted recipients
    SENSITIVE = "CLR:SENSITIVE"
    OPERATIONAL = "CLR:OPERATIONAL"
    CRITICAL = "CLR:CRITICAL"  # highest clearance; restricted recipients


# ---------------------------------------------------------------------------
# Output Gate
# ---------------------------------------------------------------------------


@unique
class OutputDecision(str, Enum):
    """Gate verdict for a candidate emission."""

    AUTHORIZED = "AUTHORIZED"
    SUPPRESSED = "SUPPRESSED"


@unique
class DirectiveID(str, Enum):
    """The six governance directives enforced by the output gate.

    Provides a typed cross-reference target for ``GateSuppressionReason``
    without requiring string parsing.
    """

    D01 = "D01_PRE_DISCLOSURE"
    D02 = "D02_BEHAVIORAL_OPACITY"
    D03 = "D03_HEROIC_SIGNALING"
    D04 = "D04_CAPABILITY_SIGNALING"
    D05 = "D05_INTEGRITY_CONTAINMENT"
    D06 = "D06_INTELLIGENCE_HYGIENE"


@unique
class GateSuppressionReason(str, Enum):
    """Directive-based suppression verdicts from the output gate.

    Only contains directive violations (D01-D06). System-level gate
    failures are in ``GateErrorReason`` to keep semantics clean.
    """

    D01_PRE_DISCLOSURE = "D01_PRE_DISCLOSURE"
    D02_BEHAVIORAL_OPACITY = "D02_BEHAVIORAL_OPACITY"
    D03_HEROIC_SIGNALING = "D03_HEROIC_SIGNALING"
    D04_CAPABILITY_SIGNALING = "D04_CAPABILITY_SIGNALING"
    D05_INTEGRITY_CONTAINMENT = "D05_INTEGRITY_CONTAINMENT"
    D06_INTELLIGENCE_HYGIENE = "D06_INTELLIGENCE_HYGIENE"


@unique
class GateErrorReason(str, Enum):
    """Operational/system-level reasons the output gate could not emit.

    Distinct from ``GateSuppressionReason`` — these are infrastructure
    failures, not directive violations.
    """

    REEVAL_LIMIT_EXCEEDED = "REEVAL_LIMIT_EXCEEDED"
    RECIPIENT_UNRESOLVED = "RECIPIENT_UNRESOLVED"


# ---------------------------------------------------------------------------
# Artifact Classification
# ---------------------------------------------------------------------------


@unique
class ArtifactClass(str, Enum):
    """Artifact authenticity classification."""

    REAL = "REAL"
    COVER = "COVER"


# ---------------------------------------------------------------------------
# Teardown Review
# ---------------------------------------------------------------------------


@unique
class ReviewAction(str, Enum):
    """Disposition for intelligence artifacts during teardown."""

    DESTROY = "DESTROY"
    RETAIN = "RETAIN"
    ESCALATE = "ESCALATE"  # formerly REVIEW; renamed to avoid self-reference


# ---------------------------------------------------------------------------
# Transition table — single source of truth for the FSM
# ---------------------------------------------------------------------------

#: Valid (from_state, to_state) pairs. Every transition not in this set
#: is unconditionally rejected by ``AgentFSM.transition``.
#:
#: Design notes:
#:   - HALTED is terminal; no outgoing edges; requires full restart cycle.
#:   - INITIALIZING -> DEGRADED is intentionally included to allow partial
#:     init (e.g. vault loaded, comms failed) without hard-halting.
#:   - TEARDOWN -> HALTED is the only teardown exit; enforces clean shutdown.
VALID_TRANSITIONS: frozenset[tuple[AgentState, AgentState]] = frozenset(
    {
        (AgentState.INITIALIZING, AgentState.IDLE),
        (AgentState.INITIALIZING, AgentState.DEGRADED),  # partial init path
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
