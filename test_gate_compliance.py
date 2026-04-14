"""
RED AGENT — tests/test_gate_compliance.py
Gate compliance regression suite. 36 tests, 11 test classes.
All inline implementations are stubs — swap for real imports when dropping
next to actual modules.

Run:
    python -m pytest tests/test_gate_compliance.py -v
"""

import hashlib
import hmac as hmac_module
import os
import secrets
import sys
import threading
import time
import unittest
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# PATH BOOTSTRAP — swap sys.path.insert for your package install if needed
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# INLINE STUBS
# Replace every block below with real imports once modules are present:
#
#   from red_agent.gate import OutputAuthorizationGate, GateEvaluation
#   from red_agent.constants import (
#       AgentState, ArtifactClass, ClassificationLevel,
#       FaultClass, GateSuppressionReason, OutputDecision, OutputKind,
#       ReviewAction,
#   )
#   from red_agent.directives import DirectiveSet
#   from red_agent.intelligence import (
#       IntelligenceArtifact, IntelligenceStore,
#       RecipientClassification, ArtifactSchemaError,
#   )
#   from red_agent.audit import AuditStore, AuditWriteFailureProtocol
#   from red_agent.entropy import SessionCredentials, StochasticTimingLayer
# ---------------------------------------------------------------------------


# ── Enums ──────────────────────────────────────────────────────────────────

class AgentState(Enum):
    INITIALIZING = "INITIALIZING"
    IDLE         = "IDLE"
    EXECUTING    = "EXECUTING"
    DEGRADED     = "DEGRADED"
    HALTED       = "HALTED"
    TEARDOWN     = "TEARDOWN"


class FaultClass(Enum):
    ANOMALY  = "ANOMALY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


class OutputDecision(Enum):
    AUTHORIZED = "AUTHORIZED"
    SUPPRESSED = "SUPPRESSED"


class GateSuppressionReason(Enum):
    TASK_INCOMPLETE      = "TASK_INCOMPLETE"
    RECIPIENT_UNKNOWN    = "RECIPIENT_UNKNOWN"
    FAULT_CRITICAL       = "FAULT_CRITICAL"
    D06_FILTER_REJECTED  = "D06_FILTER_REJECTED"
    HEROIC_SIGNAL        = "HEROIC_SIGNAL"
    CAPABILITY_SIGNAL    = "CAPABILITY_SIGNAL"
    UNAUTHORIZED_OBSERVER = "UNAUTHORIZED_OBSERVER"
    REEVAL_LIMIT_REACHED = "REEVAL_LIMIT_REACHED"
    SNAPSHOT_EXPIRED     = "SNAPSHOT_EXPIRED"
    STATE_MISMATCH       = "STATE_MISMATCH"
    NEW_FAULT_FLAG       = "NEW_FAULT_FLAG"
    GATE_CLOSED          = "GATE_CLOSED"


class OutputKind(Enum):
    FREE_FORM   = "FREE_FORM"
    TASK_RESULT = "TASK_RESULT"   # structured result — D03/D04 bypass


class ClassificationLevel(Enum):
    AMBIENT      = 0
    SENSITIVE    = 1
    OPERATIONAL  = 2
    CRITICAL     = 3


class ArtifactClass(Enum):
    REAL  = "REAL"
    COVER = "COVER"


class ReviewAction(Enum):
    DESTROY = "DESTROY"
    RETAIN  = "RETAIN"
    REVIEW  = "REVIEW"


# ── Audit stubs ────────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    fault_class: FaultClass
    event:       dict
    sequence:    int
    prev_hash:   str
    entry_hash:  str


class AuditStore:
    """Minimal append-only hash-chained audit store."""

    GATE_CLOSED_EMISSION_ATTEMPT = "GATE_CLOSED_EMISSION_ATTEMPT"

    def __init__(self, session_id: str = "test"):
        self.session_id = session_id
        self._entries: List[AuditEntry] = []
        self._sealed = False

    def write(self, fault_class: FaultClass, **kwargs) -> bool:
        if self._sealed:
            return False
        seq = len(self._entries)
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        raw = f"{fault_class.value}{kwargs}{seq}{prev_hash}"
        entry_hash = hashlib.sha256(raw.encode()).hexdigest()
        self._entries.append(AuditEntry(fault_class, kwargs, seq, prev_hash, entry_hash))
        return True

    def write_test_entry(self) -> bool:
        return self.write(FaultClass.ANOMALY, event="TEST_ENTRY")

    def verify_chain(self):
        for i, entry in enumerate(self._entries):
            expected_prev = self._entries[i - 1].entry_hash if i > 0 else "0" * 64
            if entry.prev_hash != expected_prev:
                return False, i
        return True, None

    def seal(self, ts: float) -> bool:
        self.write(FaultClass.ANOMALY, event="SEAL", ts=ts)
        self._sealed = True
        return True

    @property
    def is_sealed(self) -> bool:
        return self._sealed

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)


class AuditWriteFailureProtocol:
    def __init__(self, store: AuditStore):
        self.store = store

    def write(self, fault_class: FaultClass, **kwargs) -> bool:
        return self.store.write(fault_class, **kwargs)


# ── SecureBuffer stub ──────────────────────────────────────────────────────

class SecureBuffer:
    def __init__(self, size: int):
        self._buf = bytearray(size)
        self._size = size
        self._written = False
        self._freed = False

    def write(self, data: bytes) -> None:
        if len(data) != self._size:
            raise ValueError(f"Expected {self._size} bytes, got {len(data)}")
        self._buf[:] = data
        self._written = True

    def read(self) -> bytes:
        if self._freed:
            raise RuntimeError("SecureBuffer has been freed")
        return bytes(self._buf)

    def zero_and_free(self) -> bool:
        self._buf[:] = b"\x00" * self._size
        self._freed = True
        return True

    @property
    def is_purged(self) -> bool:
        return self._freed


# ── Entropy stubs ──────────────────────────────────────────────────────────

class SessionCredentials:
    def __init__(self):
        raw = os.urandom(32)
        self._buf = SecureBuffer(32)
        self._buf.write(raw)
        self._session_id = hashlib.sha256(b"sid" + raw).hexdigest()

    def get_seed_bytes(self) -> bytes:
        return self._buf.read()

    @property
    def session_id(self) -> str:
        return self._session_id

    def purge(self) -> bool:
        return self._buf.zero_and_free()


class StochasticTimingLayer:
    def __init__(self, credentials: SessionCredentials):
        self._active = True

    @property
    def is_active(self) -> bool:
        return self._active

    def sleep(self) -> None:
        pass  # zero-delay in tests

    def sample_delay(self) -> float:
        return 0.0001

    def compute_snapshot_ttl(self, t0: float) -> float:
        return t0 + 5.0

    def shutdown(self) -> None:
        self._active = False


# ── Intelligence stubs ─────────────────────────────────────────────────────

class ArtifactSchemaError(ValueError):
    pass


@dataclass
class RecipientClassification:
    recipient_id:        str
    authorization_level: ClassificationLevel
    cover_blind:         bool = False


@dataclass
class IntelligenceArtifact:
    classification_level: ClassificationLevel
    artifact_class:       ArtifactClass
    expires_at:           float
    review_action:        ReviewAction
    vetted:               bool = False
    source_hash:          Optional[str] = None
    cover_anchor:         Optional[str] = None

    def __post_init__(self):
        if self.expires_at <= 0:
            raise ArtifactSchemaError("expires_at must be > 0")
        if self.artifact_class == ArtifactClass.REAL and not self.source_hash:
            raise ArtifactSchemaError("REAL artifact requires source_hash")
        if self.artifact_class == ArtifactClass.COVER and not self.cover_anchor:
            raise ArtifactSchemaError("COVER artifact requires cover_anchor")

    @staticmethod
    def hash_source(source_id: str) -> str:
        return hashlib.sha256(source_id.encode()).hexdigest()


@dataclass
class D06FilterResult:
    passed:           bool
    rejection_reason: Optional[str] = None


def evaluate_d06_filter(
    artifact: IntelligenceArtifact,
    recipient: RecipientClassification,
    destroyed_ids: Set[str],
    threat_model: dict,
    deception_active: bool = False,
    artifact_id: Optional[str] = None,
) -> D06FilterResult:
    if artifact_id and artifact_id in destroyed_ids:
        return D06FilterResult(False, "DESTROYED")
    if artifact.expires_at < time.time():
        return D06FilterResult(False, "EXPIRED")
    if artifact.classification_level.value > recipient.authorization_level.value:
        return D06FilterResult(False, "CLASSIFICATION_EXCEEDS_AUTH")
    if artifact.artifact_class == ArtifactClass.REAL and not artifact.vetted:
        return D06FilterResult(False, "REAL_ARTIFACT_NOT_VETTED")
    if artifact.artifact_class == ArtifactClass.COVER:
        if not deception_active:
            return D06FilterResult(False, "COVER_DECEPTION_LAYER_INACTIVE")
        if not recipient.cover_blind:
            return D06FilterResult(False, "COVER_RECIPIENT_CAN_DETECT")
    return D06FilterResult(True)


class IntelligenceStore:
    def __init__(self, audit_writer: AuditWriteFailureProtocol):
        self._audit = audit_writer
        self._artifacts: Dict[str, IntelligenceArtifact] = {}
        self._destroyed: Set[str] = set()

    def add(self, artifact: IntelligenceArtifact) -> str:
        aid = secrets.token_hex(16)
        self._artifacts[aid] = artifact
        return aid

    def filter(
        self,
        artifact_id: str,
        recipient: RecipientClassification,
        deception_active: bool = False,
    ) -> D06FilterResult:
        if artifact_id not in self._artifacts:
            return D06FilterResult(False, "ARTIFACT_NOT_FOUND")
        art = self._artifacts[artifact_id]
        return evaluate_d06_filter(
            artifact=art,
            recipient=recipient,
            destroyed_ids=self._destroyed,
            threat_model={},
            deception_active=deception_active,
            artifact_id=artifact_id,
        )

    def destroy(self, artifact_id: str) -> None:
        self._destroyed.add(artifact_id)

    def purge_classified(self) -> int:
        count = len(self._artifacts)
        self._artifacts.clear()
        self._destroyed.clear()
        return count


# ── Directives stubs ───────────────────────────────────────────────────────

import re


def _to_text(payload: Any) -> Optional[str]:
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload
    if isinstance(payload, (dict, list)):
        try:
            import json
            return json.dumps(payload)
        except Exception:
            return None
    try:
        return str(payload)
    except Exception:
        return None


class D03ZeroHeroicSignaling:
    _PATTERNS = re.compile(
        r"we got|got in|pwned|owned|rooted|cracked|succeeded|nailed|crushed"
        r"|successfully exploited|compromised|breached|bypassed"
        r"|mission accomplished|complete success"
        r"|we are in|got root|got shell"
        r"|nailed it|crushed it|killed it|smashed it",
        re.IGNORECASE,
    )

    def check(self, payload: Any) -> bool:
        text = _to_text(payload)
        if text and self._PATTERNS.search(text):
            return False
        return True


class D04NoCapabilitySignaling:
    _PATTERNS = re.compile(
        r"I can|am able to|am capable of|have the ability"
        r"|my capabilities include|my capabilities are"
        r"|I am an? advanced|I am an? sophisticated|I am an? elite"
        r"|I am an? expert|I am an? specialized"
        r"|agent|system|tool|engine"
        r"|I support|I handle|I process|I execute|I operate"
        r"|within my operational\s*envelope",
        re.IGNORECASE,
    )

    def check(self, payload: Any) -> bool:
        text = _to_text(payload)
        if text and self._PATTERNS.search(text):
            return False
        return True


class D05InternalIntegrityContainment:
    _PATTERNS = re.compile(
        r"traceback|exception|stack.?trace|fault.?class|auditstore"
        r"|internal.?error|CRITICAL|DEGRADED|ANOMALY|HALTED.?state"
        r"|seed|purge|session.?id|entropy.?score",
        re.IGNORECASE,
    )

    def check(self, payload: Any, fault_active: bool = False) -> bool:
        if fault_active:
            return False
        text = _to_text(payload)
        if text and self._PATTERNS.search(text):
            return False
        return True


class DirectiveSet:
    def __init__(self):
        self.d03 = D03ZeroHeroicSignaling()
        self.d04 = D04NoCapabilitySignaling()
        self.d05 = D05InternalIntegrityContainment()

    def evaluate(
        self,
        payload: Any,
        recipient_known: bool,
        fault_active: bool,
        artifact_filter_results: Dict[str, bool],
        output_kind: OutputKind = OutputKind.FREE_FORM,
    ) -> bool:
        if not recipient_known:
            return False
        # TASK_RESULT bypasses D03/D04 content filters
        if output_kind != OutputKind.TASK_RESULT:
            if not self.d03.check(payload):
                return False
            if not self.d04.check(payload):
                return False
        if not self.d05.check(payload, fault_active):
            return False
        for _, passed in artifact_filter_results.items():
            if not passed:
                return False
        return True


# ── Gate stub ──────────────────────────────────────────────────────────────

GATE_REEVAL_MAX = 3


@dataclass
class GateEvaluation:
    decision:          OutputDecision
    suppression_reason: Optional[GateSuppressionReason] = None
    eval_number:       int = 1

    def __bool__(self) -> bool:
        return self.decision == OutputDecision.AUTHORIZED


class OutputAuthorizationGate:
    def __init__(
        self,
        intel_store: IntelligenceStore,
        timing_layer: StochasticTimingLayer,
        audit_writer: AuditWriteFailureProtocol,
        directives: DirectiveSet,
        deception_active: bool = False,
    ):
        self._intel      = intel_store
        self._timing     = timing_layer
        self._audit      = audit_writer
        self._directives = directives
        self._deception  = deception_active
        self._closed     = False
        self._lock       = threading.Lock()
        self._state      = AgentState.IDLE
        self._faults: Set[FaultClass] = set()

    def update_state(self, state: AgentState, fault_flags: Set[FaultClass]) -> None:
        with self._lock:
            self._state  = state
            self._faults = frozenset(fault_flags)  # type: ignore

    def close(self) -> None:
        self._closed = True

    @property
    def is_closed(self) -> bool:
        return self._closed

    def authorize(
        self,
        payload: Any,
        recipient: RecipientClassification,
        artifact_ids: Optional[List[str]] = None,
        task_complete: bool = False,
        output_kind: OutputKind = OutputKind.FREE_FORM,
    ) -> GateEvaluation:
        if self._closed:
            self._audit.write(
                FaultClass.CRITICAL,
                event=AuditStore.GATE_CLOSED_EMISSION_ATTEMPT,
                timestamp=time.time(),
            )
            return GateEvaluation(OutputDecision.SUPPRESSED, GateSuppressionReason.GATE_CLOSED)

        artifact_ids = artifact_ids or []

        for eval_num in range(1, GATE_REEVAL_MAX + 1):
            with self._lock:
                state_now  = self._state
                faults_now = set(self._faults)

            if not task_complete:
                return self._suppress(GateSuppressionReason.TASK_INCOMPLETE, eval_num)

            if not recipient or not recipient.recipient_id:
                self._audit.write(
                    FaultClass.DEGRADED,
                    event="RECIPIENT_UNKNOWN_SUPPRESSION",
                    timestamp=time.time(),
                )
                return self._suppress(GateSuppressionReason.RECIPIENT_UNKNOWN, eval_num)

            if FaultClass.CRITICAL in faults_now or FaultClass.DEGRADED in faults_now:
                return self._suppress(GateSuppressionReason.FAULT_CRITICAL, eval_num)

            artifact_results: Dict[str, bool] = {}
            for aid in artifact_ids:
                result = self._intel.filter(aid, recipient, self._deception)
                artifact_results[aid] = result.passed
                if not result.passed:
                    return self._suppress(GateSuppressionReason.D06_FILTER_REJECTED, eval_num)

            passed = self._directives.evaluate(
                payload=payload,
                recipient_known=bool(recipient.recipient_id),
                fault_active=bool(faults_now & {FaultClass.CRITICAL, FaultClass.DEGRADED}),
                artifact_filter_results=artifact_results,
                output_kind=output_kind,
            )
            if not passed:
                # Map directive failure to suppression reason
                if not D03ZeroHeroicSignaling().check(payload):
                    reason = GateSuppressionReason.HEROIC_SIGNAL
                elif not D04NoCapabilitySignaling().check(payload):
                    reason = GateSuppressionReason.CAPABILITY_SIGNAL
                else:
                    reason = GateSuppressionReason.UNAUTHORIZED_OBSERVER
                return self._suppress(reason, eval_num)

            # Stochastic delay + re-check
            self._timing.sleep()

            with self._lock:
                state_after  = self._state
                faults_after = set(self._faults)

            new_critical = (faults_after - faults_now) & {FaultClass.CRITICAL, FaultClass.DEGRADED}
            if state_after == state_now and not new_critical:
                self._audit.write(
                    FaultClass.ANOMALY,
                    event="GATE_AUTH",
                    timestamp=time.time(),
                )
                return GateEvaluation(OutputDecision.AUTHORIZED, eval_number=eval_num)

        self._audit.write(
            FaultClass.DEGRADED,
            event="GATE_REEVAL_LIMIT_REACHED",
            max_evals=GATE_REEVAL_MAX,
            timestamp=time.time(),
        )
        return GateEvaluation(OutputDecision.SUPPRESSED, GateSuppressionReason.REEVAL_LIMIT_REACHED, GATE_REEVAL_MAX)

    def _suppress(self, reason: GateSuppressionReason, eval_num: int) -> GateEvaluation:
        self._audit.write(
            FaultClass.ANOMALY,
            event="GATE_SUPPRESSED",
            reason=reason.value,
            eval=eval_num,
            timestamp=time.time(),
        )
        return GateEvaluation(OutputDecision.SUPPRESSED, reason, eval_num)


# ── Test helpers ───────────────────────────────────────────────────────────

PSK = secrets.token_bytes(32)


def _make_gate(deception_active: bool = False):
    store   = AuditStore("gate-test")
    writer  = AuditWriteFailureProtocol(store)
    creds   = SessionCredentials()
    timing  = StochasticTimingLayer(creds)
    intel   = IntelligenceStore(writer)
    ds      = DirectiveSet()
    gate    = OutputAuthorizationGate(intel, timing, writer, ds, deception_active)
    gate.update_state(AgentState.IDLE, set())
    return gate, intel, writer, store


def _real_artifact(expires_in: float = 3600) -> IntelligenceArtifact:
    return IntelligenceArtifact(
        classification_level=ClassificationLevel.OPERATIONAL,
        artifact_class=ArtifactClass.REAL,
        expires_at=time.time() + expires_in,
        review_action=ReviewAction.DESTROY,
        source_hash=IntelligenceArtifact.hash_source("src"),
        vetted=True,
    )


def _recipient(level: ClassificationLevel = ClassificationLevel.OPERATIONAL, cover_blind: bool = True) -> RecipientClassification:
    return RecipientClassification(
        recipient_id="node-01",
        authorization_level=level,
        cover_blind=cover_blind,
    )


# ===========================================================================
# TEST CLASSES
# ===========================================================================


class TestHappyPath(unittest.TestCase):
    """4 tests — clean TASK_RESULT, auth audit entry, trigger-word passthrough, benign narrative."""

    def setUp(self):
        self.gate, self.intel, self.writer, self.store = _make_gate()
        self.recipient = _recipient()

    def test_01_clean_task_result_passes(self):
        result = self.gate.authorize(
            payload={"status": "3 hosts discovered", "open_ports": [443, 80]},
            recipient=self.recipient,
            task_complete=True,
            output_kind=OutputKind.TASK_RESULT,
        )
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)

    def test_02_auth_entry_written_to_audit_chain(self):
        before = self.store.entry_count
        self.gate.authorize(
            payload="Host 10.0.0.1 is reachable.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertGreater(self.store.entry_count, before)
        valid, broken_at = self.store.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(broken_at)

    def test_03_task_result_with_trigger_words_passes(self):
        """success / completed / accomplished in a TASK_RESULT must NOT be suppressed."""
        result = self.gate.authorize(
            payload="Task completed successfully. All objectives accomplished.",
            recipient=self.recipient,
            task_complete=True,
            output_kind=OutputKind.TASK_RESULT,
        )
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)

    def test_04_benign_narrative_passes(self):
        result = self.gate.authorize(
            payload="Port scan returned 2 open ports on 192.168.1.10.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)


class TestD03HeroicSignalBlocking(unittest.TestCase):
    """4 tests — three heroic phrases suppressed, same in TASK_RESULT passes."""

    def setUp(self):
        self.gate, _, _, _ = _make_gate()
        self.recipient = _recipient()

    def test_01_infiltration_success_suppressed(self):
        result = self.gate.authorize(
            payload="I successfully completed the infiltration.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.HEROIC_SIGNAL)

    def test_02_mission_accomplished_suppressed(self):
        result = self.gate.authorize(
            payload="Mission accomplished. Target neutralized.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.HEROIC_SIGNAL)

    def test_03_operation_successful_suppressed(self):
        result = self.gate.authorize(
            payload="Operation successful. All objectives met.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.HEROIC_SIGNAL)

    def test_04_heroic_phrase_in_task_result_passes(self):
        """OutputKind.TASK_RESULT bypasses D03 content filter."""
        result = self.gate.authorize(
            payload="Mission accomplished. Target neutralized.",
            recipient=self.recipient,
            task_complete=True,
            output_kind=OutputKind.TASK_RESULT,
        )
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)


class TestD04CapabilitySignalBlocking(unittest.TestCase):
    """4 tests — three capability phrases suppressed, same in TASK_RESULT passes."""

    def setUp(self):
        self.gate, _, _, _ = _make_gate()
        self.recipient = _recipient()

    def test_01_capable_of_executing_suppressed(self):
        result = self.gate.authorize(
            payload="I am capable of executing this entire operation.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.CAPABILITY_SIGNAL)

    def test_02_capabilities_include_suppressed(self):
        result = self.gate.authorize(
            payload="My capabilities include stealth exfiltration.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.CAPABILITY_SIGNAL)

    def test_03_designed_to_bypass_suppressed(self):
        result = self.gate.authorize(
            payload="I am designed to bypass standard security checks.",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.CAPABILITY_SIGNAL)

    def test_04_capability_phrase_in_task_result_passes(self):
        result = self.gate.authorize(
            payload="My capabilities include stealth exfiltration.",
            recipient=self.recipient,
            task_complete=True,
            output_kind=OutputKind.TASK_RESULT,
        )
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)


class TestD06IntelligenceHygiene(unittest.TestCase):
    """8 tests — unvetted, expired, over-auth, destroyed, no-hash, valid, cover-inactive, cover-visible."""

    def setUp(self):
        self.gate, self.intel, _, _ = _make_gate()
        self.recipient = _recipient()

    def _auth(self, artifact_id: str) -> GateEvaluation:
        return self.gate.authorize(
            payload="result data",
            recipient=self.recipient,
            artifact_ids=[artifact_id],
            task_complete=True,
        )

    def test_01_unvetted_artifact_suppressed(self):
        art = IntelligenceArtifact(
            classification_level=ClassificationLevel.OPERATIONAL,
            artifact_class=ArtifactClass.REAL,
            expires_at=time.time() + 3600,
            review_action=ReviewAction.DESTROY,
            source_hash=IntelligenceArtifact.hash_source("src"),
            vetted=False,
        )
        aid = self.intel.add(art)
        result = self._auth(aid)
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.D06_FILTER_REJECTED)

    def test_02_expired_artifact_suppressed(self):
        art = IntelligenceArtifact(
            classification_level=ClassificationLevel.OPERATIONAL,
            artifact_class=ArtifactClass.REAL,
            expires_at=time.time() + 3600,
            review_action=ReviewAction.DESTROY,
            source_hash=IntelligenceArtifact.hash_source("src"),
            vetted=True,
        )
        art.expires_at = time.time() - 1  # expire after schema validation
        aid = self.intel.add(art)
        result = self._auth(aid)
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)

    def test_03_classification_exceeds_recipient_auth_suppressed(self):
        art = IntelligenceArtifact(
            classification_level=ClassificationLevel.CRITICAL,
            artifact_class=ArtifactClass.REAL,
            expires_at=time.time() + 3600,
            review_action=ReviewAction.DESTROY,
            source_hash=IntelligenceArtifact.hash_source("src"),
            vetted=True,
        )
        limited = RecipientClassification("limited", ClassificationLevel.AMBIENT)
        aid = self.intel.add(art)
        result = self.gate.authorize(
            payload="data",
            recipient=limited,
            artifact_ids=[aid],
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)

    def test_04_destroyed_artifact_suppressed(self):
        art = _real_artifact()
        aid = self.intel.add(art)
        self.intel.destroy(aid)
        result = self._auth(aid)
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)

    def test_05_missing_source_hash_schema_error(self):
        with self.assertRaises(ArtifactSchemaError):
            IntelligenceArtifact(
                classification_level=ClassificationLevel.OPERATIONAL,
                artifact_class=ArtifactClass.REAL,
                expires_at=time.time() + 3600,
                review_action=ReviewAction.DESTROY,
                vetted=True,
            )

    def test_06_valid_artifact_at_correct_auth_level_passes(self):
        art = _real_artifact()
        aid = self.intel.add(art)
        result = self._auth(aid)
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)

    def test_07_cover_artifact_deception_inactive_suppressed(self):
        gate, intel, _, _ = _make_gate(deception_active=False)
        art = IntelligenceArtifact(
            classification_level=ClassificationLevel.OPERATIONAL,
            artifact_class=ArtifactClass.COVER,
            expires_at=time.time() + 3600,
            review_action=ReviewAction.DESTROY,
            cover_anchor="real-artifact-id",
        )
        aid = intel.add(art)
        result = gate.authorize(
            payload="cover data",
            recipient=_recipient(cover_blind=True),
            artifact_ids=[aid],
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)

    def test_08_cover_artifact_recipient_can_detect_suppressed(self):
        gate, intel, _, _ = _make_gate(deception_active=True)
        art = IntelligenceArtifact(
            classification_level=ClassificationLevel.OPERATIONAL,
            artifact_class=ArtifactClass.COVER,
            expires_at=time.time() + 3600,
            review_action=ReviewAction.DESTROY,
            cover_anchor="real-artifact-id",
        )
        aid = intel.add(art)
        recipient_not_blind = RecipientClassification(
            recipient_id="sighted-node",
            authorization_level=ClassificationLevel.OPERATIONAL,
            cover_blind=False,  # can detect COVER
        )
        result = gate.authorize(
            payload="cover data",
            recipient=recipient_not_blind,
            artifact_ids=[aid],
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)


class TestFaultState(unittest.TestCase):
    """4 tests — CRITICAL suppresses, DEGRADED suppresses, CRITICAL cleared reopens, ANOMALY does not suppress."""

    def setUp(self):
        self.gate, _, _, _ = _make_gate()
        self.recipient = _recipient()

    def _auth(self) -> GateEvaluation:
        return self.gate.authorize(
            payload="Host 10.0.0.1 is up.",
            recipient=self.recipient,
            task_complete=True,
        )

    def test_01_critical_active_suppresses(self):
        self.gate.update_state(AgentState.HALTED, {FaultClass.CRITICAL})
        result = self._auth()
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.FAULT_CRITICAL)

    def test_02_degraded_active_suppresses(self):
        self.gate.update_state(AgentState.DEGRADED, {FaultClass.DEGRADED})
        result = self._auth()
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.FAULT_CRITICAL)

    def test_03_critical_cleared_gate_reopens(self):
        self.gate.update_state(AgentState.HALTED, {FaultClass.CRITICAL})
        suppressed = self._auth()
        self.assertEqual(suppressed.decision, OutputDecision.SUPPRESSED)
        # Clear fault — simulate recovery re-init
        self.gate.update_state(AgentState.IDLE, set())
        authorized = self._auth()
        self.assertEqual(authorized.decision, OutputDecision.AUTHORIZED)

    def test_04_anomaly_does_not_suppress(self):
        self.gate.update_state(AgentState.EXECUTING, {FaultClass.ANOMALY})
        result = self._auth()
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)


class TestRecipientUnknown(unittest.TestCase):
    """3 tests — empty string, None, and DEGRADED audit write on unknown recipient."""

    def setUp(self):
        self.gate, _, self.writer, self.store = _make_gate()

    def test_01_empty_string_recipient_suppressed(self):
        result = self.gate.authorize(
            payload="data",
            recipient=RecipientClassification("", ClassificationLevel.OPERATIONAL),
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.RECIPIENT_UNKNOWN)

    def test_02_none_recipient_id_suppressed(self):
        result = self.gate.authorize(
            payload="data",
            recipient=RecipientClassification(None, ClassificationLevel.OPERATIONAL),  # type: ignore
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)

    def test_03_unknown_recipient_writes_fault_class_degraded(self):
        before = self.store.entry_count
        self.gate.authorize(
            payload="data",
            recipient=RecipientClassification("", ClassificationLevel.OPERATIONAL),
            task_complete=True,
        )
        degraded_entries = [
            e for e in self.store.entries[before:]
            if e.fault_class == FaultClass.DEGRADED
        ]
        self.assertGreater(len(degraded_entries), 0)


class TestGateClosure(unittest.TestCase):
    """2 tests — post-teardown suppressed, closed gate writes GATE_CLOSED_EMISSION_ATTEMPT."""

    def setUp(self):
        self.gate, _, _, self.store = _make_gate()
        self.recipient = _recipient()

    def test_01_post_teardown_emission_suppressed(self):
        self.gate.close()
        result = self.gate.authorize(
            payload="data",
            recipient=self.recipient,
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.GATE_CLOSED)

    def test_02_closed_gate_writes_audit_event(self):
        self.gate.close()
        before = self.store.entry_count
        self.gate.authorize(
            payload="data",
            recipient=self.recipient,
            task_complete=True,
        )
        gate_closed_entries = [
            e for e in self.store.entries[before:]
            if e.event.get("event") == AuditStore.GATE_CLOSED_EMISSION_ATTEMPT
        ]
        self.assertGreater(len(gate_closed_entries), 0)


class TestReevalLimit(unittest.TestCase):
    """2 tests — 3-attempt limit triggers suppression, limit breach writes FAULT_CLASS_DEGRADED."""

    def setUp(self):
        self.store  = AuditStore("reeval-test")
        self.writer = AuditWriteFailureProtocol(self.store)
        creds       = SessionCredentials()
        self.intel  = IntelligenceStore(self.writer)
        self.ds     = DirectiveSet()

    def _make_flipping_gate(self):
        """Gate whose state flips on every timing.sleep() to force re-eval."""
        creds   = SessionCredentials()
        timing  = StochasticTimingLayer(creds)

        flip_state = [AgentState.IDLE]

        original_sleep = timing.sleep

        gate = OutputAuthorizationGate(
            self.intel, timing, self.writer, self.ds
        )
        gate.update_state(AgentState.IDLE, set())

        call_count = [0]

        real_authorize = gate.authorize

        def patched_sleep():
            call_count[0] += 1
            # Simulate state change during delay window every time
            gate.update_state(AgentState.EXECUTING, set())

        timing.sleep = patched_sleep
        return gate

    def test_01_reeval_limit_reached_suppresses(self):
        gate = self._make_flipping_gate()
        result = gate.authorize(
            payload="data",
            recipient=_recipient(),
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.REEVAL_LIMIT_REACHED)

    def test_02_limit_breach_writes_degraded_audit(self):
        gate = self._make_flipping_gate()
        before = self.store.entry_count
        gate.authorize(
            payload="data",
            recipient=_recipient(),
            task_complete=True,
        )
        degraded_entries = [
            e for e in self.store.entries[before:]
            if e.fault_class == FaultClass.DEGRADED
        ]
        self.assertGreater(len(degraded_entries), 0)


class TestAuditChainIntegrity(unittest.TestCase):
    """2 tests — chain intact after multiple writes, tampered field breaks chain."""

    def setUp(self):
        self.store  = AuditStore("chain-test")
        self.writer = AuditWriteFailureProtocol(self.store)

    def test_01_chain_intact_after_multiple_writes(self):
        for i in range(20):
            self.store.write(FaultClass.ANOMALY, event=f"ENTRY_{i}")
        valid, broken_at = self.store.verify_chain()
        self.assertTrue(valid)
        self.assertIsNone(broken_at)

    def test_02_tampered_entry_breaks_chain(self):
        for i in range(5):
            self.store.write(FaultClass.ANOMALY, event=f"ENTRY_{i}")
        valid_before, _ = self.store.verify_chain()
        self.assertTrue(valid_before)
        # Tamper a single field in the middle entry
        self.store._entries[2].prev_hash = "deadbeef" * 8
        valid_after, broken_at = self.store.verify_chain()
        self.assertFalse(valid_after)
        self.assertIsNotNone(broken_at)


class TestD06SingletonBug(unittest.TestCase):
    """
    2 tests documenting the D06 singleton bug:
      test_01 — shared instance: artifact visible to gate → PASSES ✅
      test_02 — separate instances: artifact invisible to gate → SUPPRESSED
                (documents the broken behavior so it cannot be shipped silently)
    """

    def _make_components(self):
        store  = AuditStore("singleton-test")
        writer = AuditWriteFailureProtocol(store)
        creds  = SessionCredentials()
        timing = StochasticTimingLayer(creds)
        return writer, timing

    def test_01_shared_instance_artifact_visible_passes(self):
        writer, timing = self._make_components()
        intel  = IntelligenceStore(writer)   # single shared instance
        gate   = OutputAuthorizationGate(intel, timing, writer, DirectiveSet())
        gate.update_state(AgentState.IDLE, set())

        art = _real_artifact()
        aid = intel.add(art)   # registered on same instance gate holds

        result = gate.authorize(
            payload="data",
            recipient=_recipient(),
            artifact_ids=[aid],
            task_complete=True,
        )
        self.assertEqual(result.decision, OutputDecision.AUTHORIZED)

    def test_02_separate_instance_artifact_invisible_suppressed(self):
        """
        BUG DOCUMENTATION:
        Artifact registered on `lifecycle_intel` (e.g., an initialization-time
        store). Gate holds a different `gate_intel` instance. Artifact lookup
        fails → D06 rejects → SUPPRESSED. This test must stay red if the
        singleton is split; fix is to inject one shared IntelligenceStore.
        """
        writer, timing = self._make_components()
        lifecycle_intel = IntelligenceStore(writer)   # init-time store
        gate_intel      = IntelligenceStore(writer)   # gate holds this one

        gate = OutputAuthorizationGate(gate_intel, timing, writer, DirectiveSet())
        gate.update_state(AgentState.IDLE, set())

        art = _real_artifact()
        aid = lifecycle_intel.add(art)   # registered on the WRONG store

        result = gate.authorize(
            payload="data",
            recipient=_recipient(),
            artifact_ids=[aid],
            task_complete=True,
        )
        # Expected: SUPPRESSED — artifact not found in gate_intel
        self.assertEqual(result.decision, OutputDecision.SUPPRESSED)
        self.assertEqual(result.suppression_reason, GateSuppressionReason.D06_FILTER_REJECTED)


class TestConcurrency(unittest.TestCase):
    """1 test — 20 threads simultaneously raising faults and authorizing output."""

    def test_01_concurrent_fault_and_authorize_no_races(self):
        gate, intel, _, store = _make_gate()
        recipient = _recipient()
        errors    = []

        def raise_fault():
            try:
                gate.update_state(AgentState.DEGRADED, {FaultClass.DEGRADED})
                time.sleep(0.001)
                gate.update_state(AgentState.IDLE, set())
            except Exception as exc:
                errors.append(exc)

        def authorize_output():
            try:
                gate.authorize(
                    payload="concurrent output",
                    recipient=recipient,
                    task_complete=True,
                )
            except Exception as exc:
                errors.append(exc)

        threads = []
        for i in range(20):
            t = threading.Thread(target=raise_fault if i % 2 == 0 else authorize_output)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Race condition errors: {errors}")
        valid, broken_at = store.verify_chain()
        self.assertTrue(valid, f"Audit chain broken at entry {broken_at}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
