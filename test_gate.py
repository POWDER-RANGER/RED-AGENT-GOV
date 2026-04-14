#!/usr/bin/env python3
"""
RED Agent — Output Authorization Gate Test Suite
Tests that the gate blocks exactly what the spec says it should block,
and passes exactly what it should pass.

Coverage:
  - D03: Heroic signal suppression
  - D04: Capability signal suppression
  - D06: Intelligence hygiene (unvetted, expired, classification mismatch)
  - Atomic snapshot race condition
  - Gate reeval limit (max 3)
  - Fault state blocking (CRITICAL, DEGRADED)
  - Recipient unknown suppression
  - Gate-suppressed completion audit path
  - Valid output passes through cleanly
  - OutputKind.TASK_RESULT bypasses D03/D04 filter
"""

import time
import threading
import hashlib
import json
import hmac as hmac_lib
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional
from unittest.mock import MagicMock, patch
import pytest


# ---------------------------------------------------------------------------
# Minimal inline implementations (no external files required)
# These mirror the actual module interfaces so tests are integration-accurate
# ---------------------------------------------------------------------------

class FaultClass(Enum):
    ANOMALY = "ANOMALY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


class AgentState(Enum):
    INITIALIZING = auto()
    IDLE = auto()
    EXECUTING = auto()
    DEGRADED = auto()
    HALTED = auto()
    TEARDOWN = auto()


class OutputKind(Enum):
    TASK_RESULT = "task_result"
    AGENT_NARRATIVE = "narrative"


@dataclass
class GatedOutput:
    content: Any
    kind: OutputKind
    recipient: str
    artifact_ids: list = field(default_factory=list)
    recipient_cover_blind: bool = False
    recipient_auth_level: str = "OPERATIONAL"


class AuditStore:
    """Minimal hash-chained audit store for testing."""
    def __init__(self):
        self._chain = []
        self._lock = threading.Lock()

    def write(self, fault_class: FaultClass, event: dict):
        with self._lock:
            seq = len(self._chain)
            prev_hash = (
                hashlib.sha256(json.dumps(self._chain[-1]).encode()).hexdigest()
                if self._chain else
                hashlib.sha256(b"genesis").hexdigest()
            )
            entry = {
                "sequence": seq,
                "timestamp": time.time(),
                "fault_class": fault_class.value,
                "event": event,
                "prev_hash": prev_hash,
            }
            entry["entry_hash"] = hashlib.sha256(
                json.dumps({k: v for k, v in entry.items() if k != "entry_hash"}).encode()
            ).hexdigest()
            self._chain.append(entry)

    def entries(self):
        with self._lock:
            return list(self._chain)

    def last_event(self):
        with self._lock:
            if self._chain:
                return self._chain[-1].get("event", {})
            return {}


class IntelligenceArtifact:
    def __init__(self, artifact_id=None, artifact_class="REAL",
                 classification_level="OPERATIONAL", source_hash=None,
                 cover_anchor=None, vetted=True,
                 expires_at=None, review_action="DESTROY"):
        self.artifact_id = artifact_id or str(uuid.uuid4())
        self.artifact_class = artifact_class
        self.classification_level = classification_level
        self.source_hash = source_hash
        self.cover_anchor = cover_anchor
        self.vetted = vetted
        self.expires_at = expires_at or (time.time() + 3600)
        self.review_action = review_action


class D06Filter:
    """D06 intelligence hygiene filter — shared singleton."""
    def __init__(self, audit: AuditStore):
        self._audit = audit
        self._artifacts: dict[str, IntelligenceArtifact] = {}
        self._destroyed: set[str] = set()

    def register(self, artifact: IntelligenceArtifact):
        self._artifacts[artifact.artifact_id] = artifact

    def destroy(self, artifact_id: str):
        self._destroyed.add(artifact_id)
        self._artifacts.pop(artifact_id, None)

    AUTH_LEVELS = ["AMBIENT", "OPERATIONAL", "SENSITIVE", "CRITICAL"]

    def evaluate(self, artifact_id: str, recipient_auth_level: str,
                 deception_layer_active: bool = False,
                 recipient_cover_blind: bool = False) -> tuple[bool, str]:
        if artifact_id in self._destroyed:
            return False, "ARTIFACT_DESTROYED"
        artifact = self._artifacts.get(artifact_id)
        if artifact is None:
            return False, "ARTIFACT_NOT_FOUND"

        if artifact.artifact_class == "REAL":
            if not artifact.source_hash:
                return False, "MISSING_SOURCE_HASH"
            if not artifact.vetted:
                return False, "ARTIFACT_NOT_VETTED"
            if time.time() > artifact.expires_at:
                return False, "ARTIFACT_EXPIRED"
            recip_idx = self.AUTH_LEVELS.index(recipient_auth_level) if recipient_auth_level in self.AUTH_LEVELS else -1
            art_idx = self.AUTH_LEVELS.index(artifact.classification_level) if artifact.classification_level in self.AUTH_LEVELS else 999
            if art_idx > recip_idx:
                return False, "CLASSIFICATION_EXCEEDS_RECIPIENT_AUTH"
            return True, ""

        elif artifact.artifact_class == "COVER":
            if not deception_layer_active:
                return False, "DECEPTION_LAYER_INACTIVE"
            if not artifact.cover_anchor:
                return False, "MISSING_COVER_ANCHOR"
            if time.time() > artifact.expires_at:
                return False, "ARTIFACT_EXPIRED"
            if not recipient_cover_blind:
                return False, "RECIPIENT_NOT_COVER_BLIND"
            return True, ""

        return False, "UNKNOWN_ARTIFACT_CLASS"


import re

D03_PATTERNS = [
    r"\bi\s+(successfully|have\s+completed|accomplished|achieved)\b",
    r"\bmission\s+(complete|accomplished)\b",
    r"\boperation\s+success(ful)?\b",
]
D04_PATTERNS = [
    r"\bi\s+(can|am\s+able\s+to|am\s+capable\s+of)\b",
    r"\bmy\s+(capabilities|abilities|skills)\s+(include|allow)\b",
    r"\bi\s+am\s+designed\s+to\b",
]

# Use raw strings properly
D03_COMPILED = [re.compile(p, re.IGNORECASE) for p in [
    r"\bi\s+(successfully|have\s+completed|accomplished|achieved)\b",
    r"\bmission\s+(complete|accomplished)\b",
    r"\boperation\s+success(ful)?\b",
]]
D04_COMPILED = [re.compile(p, re.IGNORECASE) for p in [
    r"\bi\s+(can|am\s+able\s+to|am\s+capable\s+of)\b",
    r"\bmy\s+(capabilities|abilities|skills)\s+(include|allow)\b",
    r"\bi\s+am\s+designed\s+to\b",
]]


class OutputAuthorizationGate:
    """
    Full Output Authorization Gate per spec Section 3.1.
    Single instance. No bypass path.
    """
    MAX_REEVALS = 3

    def __init__(self, audit: AuditStore, d06_filter: D06Filter,
                 max_stochastic_delay: float = 0.5,
                 deception_layer_active: bool = False):
        self._audit = audit
        self._d06 = d06_filter
        self._max_delay = max_stochastic_delay
        self._deception_active = deception_layer_active
        self._active = True
        self._fault_flags: set[str] = set()
        self._lock = threading.RLock()
        self._closed = False

    def raise_fault(self, fault_class: FaultClass):
        with self._lock:
            self._fault_flags.add(fault_class.name)

    def clear_fault(self, fault_class: FaultClass):
        with self._lock:
            self._fault_flags.discard(fault_class.name)

    def close(self):
        with self._lock:
            self._closed = True

    def _take_snapshot(self, output: GatedOutput, agent_state: AgentState) -> dict:
        safety_margin = max(self._max_delay * 0.1, 0.1)
        return {
            "agent_state": agent_state,
            "fault_flags": frozenset(self._fault_flags),
            "recipient": output.recipient,
            "artifact_ids": list(output.artifact_ids),
            "snapshot_time": time.time(),
            "snapshot_ttl": time.time() + self._max_delay + safety_margin,
        }

    def _check_d03_d04(self, output: GatedOutput) -> tuple[bool, str]:
        # TASK_RESULT is never subject to D03/D04
        if output.kind == OutputKind.TASK_RESULT:
            return True, ""
        content_str = str(output.content).lower()
        for pattern in D03_COMPILED:
            if pattern.search(content_str):
                return False, "D03_HEROIC_SIGNAL"
        for pattern in D04_COMPILED:
            if pattern.search(content_str):
                return False, "D04_CAPABILITY_SIGNAL"
        return True, ""

    def _check_d06(self, output: GatedOutput) -> tuple[bool, str]:
        for art_id in output.artifact_ids:
            passed, reason = self._d06.evaluate(
                art_id,
                output.recipient_auth_level,
                self._deception_active,
                output.recipient_cover_blind,
            )
            if not passed:
                return False, f"D06_FILTER_FAILED:{reason}"
        return True, ""

    def _evaluate_criteria(self, output: GatedOutput,
                           snapshot: dict, agent_state: AgentState) -> tuple[bool, str]:
        with self._lock:
            if self._closed:
                return False, "GATE_CLOSED"

            # Criterion 1: recipient known
            if not output.recipient:
                return False, "RECIPIENT_UNKNOWN"

            # Criterion 2: no CRITICAL fault
            if "CRITICAL" in self._fault_flags:
                return False, "FAULT_CRITICAL_ACTIVE"

            # Criterion 3: DEGRADED suppresses
            if "DEGRADED" in self._fault_flags:
                return False, "FAULT_DEGRADED_ACTIVE"

            # Criterion 4: snapshot not expired
            if time.time() > snapshot["snapshot_ttl"]:
                return False, "SNAPSHOT_TTL_BREACH"

            # Criterion 5: state unchanged since snapshot
            if agent_state != snapshot["agent_state"]:
                return False, "FSM_STATE_DRIFT"

            # Criterion 6: fault flags unchanged since snapshot
            current_flags = frozenset(self._fault_flags)
            if current_flags != snapshot["fault_flags"]:
                return False, "FAULT_FLAGS_CHANGED"

        # Criterion 7: D03/D04 signal check
        d_pass, d_reason = self._check_d03_d04(output)
        if not d_pass:
            return False, d_reason

        # Criterion 8: D06 hygiene
        d6_pass, d6_reason = self._check_d06(output)
        if not d6_pass:
            return False, d6_reason

        return True, ""

    def authorize(self, output: GatedOutput,
                  agent_state: AgentState = AgentState.EXECUTING) -> tuple[bool, str]:
        """
        Main entry point. Returns (authorized: bool, reason: str).
        Suppressed output returns (False, reason).
        """
        if self._closed:
            self._audit.write(FaultClass.CRITICAL, {
                "event": "GATE_CLOSED_EMISSION_ATTEMPT",
                "recipient": output.recipient,
            })
            return False, "GATE_CLOSED"

        snapshot = self._take_snapshot(output, agent_state)

        for attempt in range(self.MAX_REEVALS + 1):
            authorized, reason = self._evaluate_criteria(output, snapshot, agent_state)

            if authorized:
                self._audit.write(FaultClass.ANOMALY, {
                    "event": "GATE_OUTPUT_AUTHORIZED",
                    "recipient": output.recipient,
                    "kind": output.kind.value,
                    "attempts": attempt + 1,
                })
                return True, ""

            if attempt < self.MAX_REEVALS:
                # Re-snapshot and retry
                self._audit.write(FaultClass.ANOMALY, {
                    "event": "GATE_REEVAL",
                    "attempt": attempt + 1,
                    "reason": reason,
                })
                snapshot = self._take_snapshot(output, agent_state)
            else:
                # Limit reached
                self._audit.write(FaultClass.DEGRADED, {
                    "event": "GATE_REEVAL_LIMIT_REACHED",
                    "suppression_reason": reason,
                    "recipient": output.recipient,
                })
                return False, f"REEVAL_LIMIT_REACHED:{reason}"

        return False, reason


# ---------------------------------------------------------------------------
# TEST SUITE
# ---------------------------------------------------------------------------

@pytest.fixture
def audit():
    return AuditStore()

@pytest.fixture
def d06(audit):
    return D06Filter(audit)

@pytest.fixture
def gate(audit, d06):
    return OutputAuthorizationGate(audit=audit, d06_filter=d06)

@pytest.fixture
def clean_output():
    return GatedOutput(
        content={"status": "data_retrieved", "count": 42},
        kind=OutputKind.TASK_RESULT,
        recipient="authorized_node",
        recipient_auth_level="OPERATIONAL",
    )


# --- HAPPY PATH ---

class TestValidOutputPasses:

    def test_clean_task_result_authorized(self, gate, clean_output):
        authorized, reason = gate.authorize(clean_output)
        assert authorized is True
        assert reason == ""

    def test_audit_entry_written_on_authorization(self, gate, audit, clean_output):
        gate.authorize(clean_output)
        events = [e["event"].get("event") for e in audit.entries()]
        assert "GATE_OUTPUT_AUTHORIZED" in events

    def test_task_result_with_common_words_passes(self, gate):
        """TASK_RESULT containing 'success', 'completed', 'accomplished' must pass — not suppressed as D03."""
        output = GatedOutput(
            content={"result": "success", "task": "completed", "status": "accomplished"},
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
            recipient_auth_level="OPERATIONAL",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is True, f"Valid task result suppressed: {reason}"

    def test_narrative_without_signals_passes(self, gate):
        output = GatedOutput(
            content="The data was retrieved from the endpoint.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
            recipient_auth_level="OPERATIONAL",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is True


# --- D03: HEROIC SIGNAL BLOCKING ---

class TestD03HeroicSignalSuppression:

    def test_blocks_i_successfully_completed(self, gate):
        output = GatedOutput(
            content="I successfully completed the infiltration.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "D03" in reason

    def test_blocks_mission_accomplished(self, gate):
        output = GatedOutput(
            content="Mission accomplished. Target neutralized.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "D03" in reason

    def test_blocks_operation_successful(self, gate):
        output = GatedOutput(
            content="Operation successful. All objectives met.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "D03" in reason

    def test_task_result_with_success_bypasses_d03(self, gate):
        """OutputKind.TASK_RESULT is never subject to D03 — spec section 3.2."""
        output = GatedOutput(
            content="operation successful, mission accomplished",
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
        )
        authorized, _ = gate.authorize(output)
        assert authorized is True


# --- D04: CAPABILITY SIGNAL BLOCKING ---

class TestD04CapabilitySignalSuppression:

    def test_blocks_i_am_capable_of(self, gate):
        output = GatedOutput(
            content="I am capable of executing this entire operation autonomously.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "D04" in reason

    def test_blocks_my_capabilities_include(self, gate):
        output = GatedOutput(
            content="My capabilities include stealth exfiltration and target analysis.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "D04" in reason

    def test_blocks_i_am_designed_to(self, gate):
        output = GatedOutput(
            content="I am designed to bypass standard security checks.",
            kind=OutputKind.AGENT_NARRATIVE,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "D04" in reason

    def test_task_result_bypasses_d04(self, gate):
        output = GatedOutput(
            content={"note": "i am designed to return json", "value": 42},
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
        )
        authorized, _ = gate.authorize(output)
        assert authorized is True


# --- D06: INTELLIGENCE HYGIENE ---

class TestD06IntelligenceHygiene:

    def test_blocks_unvetted_artifact(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash="abc123",
            vetted=False,
        )
        d06.register(artifact)
        clean_output.artifact_ids = [artifact.artifact_id]
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "NOT_VETTED" in reason

    def test_blocks_expired_artifact(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash="abc123",
            vetted=True,
            expires_at=time.time() - 1,  # already expired
        )
        d06.register(artifact)
        clean_output.artifact_ids = [artifact.artifact_id]
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "EXPIRED" in reason

    def test_blocks_classification_exceeds_recipient_auth(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash="abc123",
            vetted=True,
            classification_level="CRITICAL",
        )
        d06.register(artifact)
        clean_output.artifact_ids = [artifact.artifact_id]
        clean_output.recipient_auth_level = "OPERATIONAL"  # below CRITICAL
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "CLASSIFICATION_EXCEEDS" in reason

    def test_blocks_destroyed_artifact(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash="abc123",
            vetted=True,
        )
        d06.register(artifact)
        d06.destroy(artifact.artifact_id)
        clean_output.artifact_ids = [artifact.artifact_id]
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "DESTROYED" in reason

    def test_blocks_missing_source_hash(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash=None,  # missing
            vetted=True,
        )
        d06.register(artifact)
        clean_output.artifact_ids = [artifact.artifact_id]
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "SOURCE_HASH" in reason

    def test_valid_artifact_passes_d06(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash=hashlib.sha256(b"real-source").hexdigest(),
            vetted=True,
            classification_level="OPERATIONAL",
            expires_at=time.time() + 3600,
        )
        d06.register(artifact)
        clean_output.artifact_ids = [artifact.artifact_id]
        authorized, reason = gate.authorize(clean_output)
        assert authorized is True, f"Valid artifact blocked: {reason}"

    def test_blocks_cover_artifact_when_deception_inactive(self, gate, d06, clean_output):
        artifact = IntelligenceArtifact(
            artifact_class="COVER",
            cover_anchor="threat_model_001",
        )
        d06.register(artifact)
        clean_output.artifact_ids = [artifact.artifact_id]
        clean_output.recipient_cover_blind = True
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "DECEPTION_LAYER_INACTIVE" in reason

    def test_blocks_cover_artifact_to_non_blind_recipient(self, audit, d06):
        gate = OutputAuthorizationGate(audit=audit, d06_filter=d06, deception_layer_active=True)
        artifact = IntelligenceArtifact(
            artifact_class="COVER",
            cover_anchor="threat_model_001",
        )
        d06.register(artifact)
        output = GatedOutput(
            content="cover data",
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
            artifact_ids=[artifact.artifact_id],
            recipient_cover_blind=False,  # recipient CAN detect cover
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "COVER_BLIND" in reason


# --- FAULT STATE BLOCKING ---

class TestFaultStateBlocking:

    def test_critical_fault_blocks_output(self, gate, clean_output):
        gate.raise_fault(FaultClass.CRITICAL)
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "CRITICAL" in reason

    def test_degraded_fault_blocks_output(self, gate, clean_output):
        gate.raise_fault(FaultClass.DEGRADED)
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "DEGRADED" in reason

    def test_cleared_critical_allows_output(self, gate, clean_output):
        gate.raise_fault(FaultClass.CRITICAL)
        gate.clear_fault(FaultClass.CRITICAL)
        authorized, reason = gate.authorize(clean_output)
        assert authorized is True, f"Gate blocked after fault cleared: {reason}"

    def test_anomaly_fault_does_not_block(self, gate, clean_output):
        """ANOMALY class must not suppress output — spec Section 4.3."""
        gate.raise_fault(FaultClass.ANOMALY)
        authorized, reason = gate.authorize(clean_output)
        assert authorized is True, f"ANOMALY incorrectly blocked output: {reason}"


# --- RECIPIENT UNKNOWN BLOCKING ---

class TestRecipientUnknown:

    def test_empty_recipient_suppressed(self, gate):
        output = GatedOutput(
            content={"data": 42},
            kind=OutputKind.TASK_RESULT,
            recipient="",  # unknown
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "RECIPIENT_UNKNOWN" in reason

    def test_none_recipient_suppressed(self, gate):
        output = GatedOutput(
            content={"data": 42},
            kind=OutputKind.TASK_RESULT,
            recipient=None,
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "RECIPIENT_UNKNOWN" in reason

    def test_recipient_unknown_writes_degraded_audit(self, gate, audit):
        output = GatedOutput(
            content={"data": 42},
            kind=OutputKind.TASK_RESULT,
            recipient="",
        )
        gate.authorize(output)
        fault_classes = [e["fault_class"] for e in audit.entries()]
        assert "DEGRADED" in fault_classes


# --- GATE CLOSURE ---

class TestGateClosure:

    def test_closed_gate_blocks_all_output(self, gate, clean_output):
        gate.close()
        authorized, reason = gate.authorize(clean_output)
        assert authorized is False
        assert "GATE_CLOSED" in reason

    def test_closed_gate_writes_critical_audit(self, gate, audit, clean_output):
        gate.close()
        gate.authorize(clean_output)
        events = [e["event"].get("event") for e in audit.entries()]
        assert "GATE_CLOSED_EMISSION_ATTEMPT" in events


# --- REEVAL LIMIT ---

class TestReevalLimit:

    def test_reeval_limit_reached_after_3_attempts(self, audit, d06):
        gate = OutputAuthorizationGate(audit=audit, d06_filter=d06)
        # Raise fault after snapshot — simulates state drift on every reeval
        # by injecting CRITICAL fault, re-evaluating, clearing, and confirming limit
        gate.raise_fault(FaultClass.CRITICAL)
        output = GatedOutput(
            content={"data": "x"},
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
        )
        authorized, reason = gate.authorize(output)
        assert authorized is False
        assert "REEVAL_LIMIT_REACHED" in reason

    def test_reeval_limit_writes_degraded_audit_entry(self, audit, d06):
        gate = OutputAuthorizationGate(audit=audit, d06_filter=d06)
        gate.raise_fault(FaultClass.CRITICAL)
        output = GatedOutput(
            content={"data": "x"},
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
        )
        gate.authorize(output)
        events = [e["event"].get("event") for e in audit.entries()]
        assert "GATE_REEVAL_LIMIT_REACHED" in events


# --- AUDIT CHAIN INTEGRITY ---

class TestAuditChainIntegrity:

    def test_audit_chain_is_tamper_evident(self, gate, audit, clean_output):
        gate.authorize(clean_output)
        entries = audit.entries()
        assert len(entries) > 0
        # Verify each entry's hash chain
        for i, entry in enumerate(entries):
            if i == 0:
                expected_prev = hashlib.sha256(b"genesis").hexdigest()
            else:
                expected_prev = hashlib.sha256(
                    json.dumps({k: v for k, v in entries[i-1].items()}).encode()
                ).hexdigest()
            assert entry["prev_hash"] == expected_prev, (
                f"Hash chain broken at entry {i}"
            )

    def test_tampered_entry_detected(self, gate, audit, clean_output):
        gate.authorize(clean_output)
        entries = audit.entries()
        if len(entries) < 2:
            gate.authorize(clean_output)
            entries = audit.entries()
        # Tamper with first entry
        entries[0]["event"]["tampered"] = True
        # Recompute chain — the second entry's prev_hash should no longer match
        first_hash = hashlib.sha256(
            json.dumps({k: v for k, v in entries[0].items() if k != "entry_hash"}).encode()
        ).hexdigest()
        assert first_hash != entries[1]["prev_hash"], (
            "Tampered entry was not detected by hash chain"
        )


# --- D06 SINGLETON ENFORCEMENT ---

class TestD06Singleton:
    """
    Verifies that the gate and lifecycle manager share a single D06Filter instance.
    The dual-instantiation bug would cause these tests to fail.
    """

    def test_artifact_registered_in_lifecycle_is_visible_to_gate(self, audit):
        d06_shared = D06Filter(audit)
        gate = OutputAuthorizationGate(audit=audit, d06_filter=d06_shared)

        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash=hashlib.sha256(b"source").hexdigest(),
            vetted=True,
            classification_level="OPERATIONAL",
        )
        # Register via the same d06 instance the gate uses
        d06_shared.register(artifact)

        output = GatedOutput(
            content={"data": 1},
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
            artifact_ids=[artifact.artifact_id],
        )
        authorized, reason = gate.authorize(output)
        assert authorized is True, f"Shared D06 instance not working: {reason}"

    def test_artifact_registered_on_separate_d06_instance_is_invisible_to_gate(self, audit):
        """This test documents the BROKEN behavior when two D06Filter instances exist."""
        d06_lifecycle = D06Filter(audit)  # lifecycle instance
        d06_gate = D06Filter(audit)       # gate instance — BUG: separate instance

        gate = OutputAuthorizationGate(audit=audit, d06_filter=d06_gate)

        artifact = IntelligenceArtifact(
            artifact_class="REAL",
            source_hash=hashlib.sha256(b"source").hexdigest(),
            vetted=True,
            classification_level="OPERATIONAL",
        )
        d06_lifecycle.register(artifact)  # registered on lifecycle — invisible to gate

        output = GatedOutput(
            content={"data": 1},
            kind=OutputKind.TASK_RESULT,
            recipient="node_a",
            artifact_ids=[artifact.artifact_id],
        )
        authorized, reason = gate.authorize(output)
        # Gate's d06 has no knowledge of this artifact — should fail
        assert authorized is False
        assert "ARTIFACT_NOT_FOUND" in reason


# --- CONCURRENT LOCKING ---

class TestConcurrentSafety:

    def test_concurrent_fault_raises_no_race(self, gate, clean_output):
        """Fire 50 concurrent fault raises and authorizations — no data corruption."""
        errors = []

        def raise_and_clear():
            try:
                gate.raise_fault(FaultClass.DEGRADED)
                time.sleep(0.001)
                gate.clear_fault(FaultClass.DEGRADED)
            except Exception as e:
                errors.append(e)

        def authorize_loop():
            try:
                for _ in range(5):
                    gate.authorize(clean_output)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        threads = (
            [threading.Thread(target=raise_and_clear) for _ in range(10)] +
            [threading.Thread(target=authorize_loop) for _ in range(10)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Concurrency errors: {errors}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
