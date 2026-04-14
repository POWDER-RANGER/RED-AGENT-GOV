"""Constants and Enumerations for RED AGENT

Defines all state enums, classification levels, fault classes, and other constants
used throughout the framework.
"""
from __future__ import annotations

from enum import Enum
from enum import auto


class AgentState(Enum):
    """FSM states for RedAgent"""

    INITIALIZING = auto()
    IDLE = auto()
    EXECUTING = auto()
    DEGRADED = auto()
    HALTED = auto()
    TEARDOWN = auto()


class FaultClass(Enum):
    """Fault severity classification"""

    ANOMALY = auto()    # Observable but non-critical
    DEGRADED = auto()   # Compromised functionality, partial operation
    CRITICAL = auto()   # Immediate halt required


class ClassificationLevel(Enum):
    """Intelligence artifact classification levels (ascending)"""

    AMBIENT = auto()     # Public/unclassified
    SENSITIVE = auto()   # Internal use
    OPERATIONAL = auto() # Operational security required
    CRITICAL = auto()    # Highest classification


class ArtifactClass(Enum):
    """Intelligence artifact types"""

    REAL = auto()  # Genuine intelligence
    COVER = auto() # Deception/cover artifact


class ReviewAction(Enum):
    """Post-operation artifact disposition"""

    DESTROY = auto()
    RETAIN = auto()
    REVIEW = auto()


class OutputDecision(Enum):
    """Output gate authorization result"""

    AUTHORIZED = auto()
    SUPPRESSED = auto()


class GateSuppressionReason(Enum):
    """Reasons for output suppression by gate"""

    TASK_INCOMPLETE = auto()
    RECIPIENT_UNKNOWN = auto()
    FAULT_CRITICAL = auto()
    D06_FILTER_REJECTED = auto()
    HEROIC_SIGNAL = auto()        # D03
    CAPABILITY_SIGNAL = auto()    # D04
    UNAUTHORIZED_OBSERVER = auto() # D01/D02
    REEVAL_LIMIT_REACHED = auto()


# Configuration constants
GATE_REEVAL_MAX = 3
PROBE_DETECTION_THRESHOLD = 5
