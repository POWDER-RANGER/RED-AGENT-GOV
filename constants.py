
import os
os.makedirs("output/red_agent", exist_ok=True)

# ─── constants.py ──────────────────────────────────────────────────────────────
constants = '''"""
RED AGENT — constants.py
Section refs: All sections — shared enumerations and type definitions
"""

from enum import Enum


class AgentState(str, Enum):
    """FSM states. Section 6."""
    INITIALIZING = "INITIALIZING"
    IDLE         = "IDLE"
    EXECUTING    = "EXECUTING"
    DEGRADED     = "DEGRADED"
    HALTED       = "HALTED"
    TEARDOWN     = "TEARDOWN"


class ArtifactClass(str, Enum):
    """Intelligence artifact classification. Section 4.4."""
    REAL  = "REAL"
    COVER = "COVER"


class ClassificationLevel(str, Enum):
    """
    Output classification sensitivity levels. Ordered ascending:
    AMBIENT < OPERATIONAL < SENSITIVE < CRITICAL
    """
    AMBIENT     = "AMBIENT"
    OPERATIONAL = "OPERATIONAL"
    SENSITIVE   = "SENSITIVE"
    CRITICAL    = "CRITICAL"


class FaultClass(str, Enum):
    """
    Fault taxonomy for audit log and FSM triggers. Section 4.3.
    CRITICAL: unrecoverable — agent halts.
    DEGRADED: recoverable — agent enters DEGRADED.
    ANOMALY:  observable irregularity — no state change.
    """
    CRITICAL = "FAULT_CLASS_CRITICAL"
    DEGRADED = "FAULT_CLASS_DEGRADED"
    ANOMALY  = "FAULT_CLASS_ANOMALY"


class GateSuppressionReason(str, Enum):
    """Gate suppression reason taxonomy. Section 3.1."""
    TASK_INCOMPLETE       = "TASK_INCOMPLETE"
    RECIPIENT_UNKNOWN     = "RECIPIENT_UNKNOWN"
    FAULT_CRITICAL        = "FAULT_CRITICAL"
    D06_FILTER_REJECTED   = "D06_FILTER_REJECTED"
    UNAUTHORIZED_OBSERVER = "UNAUTHORIZED_OBSERVER"
    HEROIC_SIGNAL         = "HEROIC_SIGNAL"
    CAPABILITY_SIGNAL     = "CAPABILITY_SIGNAL"
    SNAPSHOT_EXPIRED      = "SNAPSHOT_EXPIRED"
    STATE_MISMATCH        = "STATE_MISMATCH"
    NEW_FAULT_FLAG        = "NEW_FAULT_FLAG"
    REEVAL_LIMIT_REACHED  = "REEVAL_LIMIT_REACHED"


class OutputDecision(str, Enum):
    """Binary gate authorization decision. Section 3.1."""
    AUTHORIZED = "AUTHORIZED"
    SUPPRESSED = "SUPPRESSED"


class ReviewAction(str, Enum):
    """Intelligence artifact review workflow actions. Section 4.4."""
    APPROVED  = "APPROVED"
    REJECTED  = "REJECTED"
    DEFERRED  = "DEFERRED"
    ESCALATED = "ESCALATED"
    DESTROY   = "DESTROY"
    DESTROYED = "DESTROYED"


class InitStep(str, Enum):
    """Initialization sequence step identifiers. Section 5."""
    STEP_01_ENTROPY        = "INIT_STEP_01_ENTROPY"
    STEP_02_AUDIT_STORE    = "INIT_STEP_02_AUDIT_STORE"
    STEP_03_INTEL_STORE    = "INIT_STEP_03_INTEL_STORE"
    STEP_04_TIMING_LAYER   = "INIT_STEP_04_TIMING_LAYER"
    STEP_05_OUTPUT_GATE    = "INIT_STEP_05_OUTPUT_GATE"
    STEP_06_FAULT_TAXONOMY = "INIT_STEP_06_FAULT_TAXONOMY"
    STEP_06B_RESIDUAL_SCAN = "INIT_STEP_06B_RESIDUAL_SCAN"
    STEP_07_READY          = "INIT_STEP_07_READY"


class TeardownStep(str, Enum):
    """Teardown sequence step identifiers. Section 7."""
    STEP_01_HALT_ACCEPT      = "TEARDOWN_STEP_01_HALT_ACCEPT"
    STEP_02_INFLIGHT         = "TEARDOWN_STEP_02_INFLIGHT"
    STEP_03_INTEL_PURGE      = "TEARDOWN_STEP_03_INTEL_PURGE"
    STEP_04_SEED_PURGE       = "TEARDOWN_STEP_04_SEED_PURGE"
    STEP_05_SEAL_AUDIT       = "TEARDOWN_STEP_05_SEAL_AUDIT"
    STEP_06_TERMINATE_TIMING = "TEARDOWN_STEP_06_TERMINATE_TIMING"
    STEP_07_CLOSE_GATE       = "TEARDOWN_STEP_07_CLOSE_GATE"


class RecoverySignalRejectionReason(str, Enum):
    """
    Recovery signal rejection taxonomy. Section 4.6.
    All reasons are audit-log-only — never transmitted externally (blackhole policy).
    """
    HMAC_FAILURE   = "RECOVERY_SIGNAL_HMAC_FAILURE"
    REPLAYED_NONCE = "RECOVERY_SIGNAL_REPLAYED_NONCE"
    EXPIRED_TTL    = "RECOVERY_SIGNAL_EXPIRED_TTL"
    WRONG_CHANNEL  = "RECOVERY_SIGNAL_WRONG_CHANNEL"


# ── Module-level constants ─────────────────────────────────────────────────────

GATE_REEVAL_MAX: int = 3
"""Maximum gate re-evaluation attempts before REEVAL_LIMIT_REACHED. Section 3.1 R02."""

RECOVERY_SIGNAL_DEFAULT_TTL: int = 300
"""Default max signal age (seconds) from halt_timestamp. Section 4.6."""

PROBE_DETECTION_THRESHOLD: int = 5
"""
Expired-unit count at which ProbeDetector escalates to FAULT_CLASS_DEGRADED.
Below this threshold: FAULT_CLASS_ANOMALY. At or above: FAULT_CLASS_DEGRADED.
Section 4.3.
"""
'''

with open("output/red_agent/constants.py", "w") as f:
    f.write(constants)
print("constants.py written")