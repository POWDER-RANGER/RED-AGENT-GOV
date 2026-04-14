"""
RED Agent — Main Orchestrator.
Initialization Sequence (Section 5), Runtime (Section 6), Teardown (Section 7).
Directives D01–D06 enforced through the architectures below.
"""
from __future__ import annotations
import secrets, threading, time
from typing import Any, Optional, TYPE_CHECKING

from config.settings import AgentConfig
from core.audit import AuditStore, FaultClass
from core.fsm import AgentState, RedAgentFSM
from core.gate import GateDecision, OutputAuthorizationGate
from core.intelligence import (
    ArtifactClass, ClassificationLevel, D06Filter, LifecycleManager,
    ReviewAction, ThreatModelEntry,
)
from core.recovery import NonceRegistry, RecoverySignal, RecoverySignalValidator
from core.tasking import RecipientClassification, TaskingUnit
from core.timing import StochasticTimingLayer, TimingLayerUnavailableError
from utils.crypto import secure_zero
from utils.entropy import EntropyInsufficientError, generate_seed
from utils.serialization import transform


class RedAgentInitError(RuntimeError):
    pass


class RedAgent:
    """
    Single authoritative RED Agent instance.
    All directive enforcement is structural, not policy-based.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config          = config
        self._lock            = threading.Lock()
        self._session_id: Optional[str] = None
        self._seed_buf:   Optional[bytearray] = None
        self._audit:      Optional[AuditStore] = None
        self._fsm:        Optional[RedAgentFSM] = None
        self._timing:     Optional[StochasticTimingLayer] = None
        self._gate:       Optional[OutputAuthorizationGate] = None
        self._lifecycle:  Optional[LifecycleManager] = None
        self._recovery:   Optional[RecoverySignalValidator] = None
        self._fault_flags: str = "NONE"    # NONE | CRITICAL_ACTIVE | DEGRADED_ACTIVE
        self._halt_time:   Optional[float] = None
        # Expired-unit probe tracking (Section 4.3.1)
        self._expired_timestamps: list[float] = []

    # ── SECTION 5 — Initialization Sequence ──────────────────────────────────

    def initialize(self, prior_session_audit_path: Optional[str] = None) -> None:
        """
        Execute Steps 01–07 (and 06B if applicable).
        Any step failure halts the agent; audit entry written before halt.
        """
        try:
            # STEP 01 — Generate session noise seed and session ID
            seed = self._step01_generate_seed()

            # STEP 02 — Initialize internal audit store
            audit = self._step02_init_audit(seed)

            # STEP 03 — Load intelligence artifact store
            self._step03_load_artifacts(audit)

            # STEP 04 — Verify stochastic timing layer
            timing = self._step04_init_timing(seed, audit)

            # STEP 05 — Initialize Output Authorization Gate
            gate = self._step05_init_gate(audit, timing)

            # STEP 06 — Confirm fault taxonomy writable
            self._step06_confirm_audit(audit)

            # STEP 06B — Residual State Audit (conditional)
            self._step06b_residual_audit(audit, prior_session_audit_path)

            # Commit all components
            self._audit    = audit
            self._timing   = timing
            self._gate     = gate
            self._fsm      = RedAgentFSM(audit)
            self._session_id_str = self._session_id

            # Recovery validator (requires PSK)
            if self._config.recovery_psk:
                self._recovery = RecoverySignalValidator(
                    psk=self._config.recovery_psk,
                    session_id=self._session_id,
                    signal_ttl_seconds=self._config.recovery_signal_ttl_seconds,
                    probe_threshold=self._config.recovery_probe_threshold,
                    audit=audit,
                    internal_channel_token=secrets.token_hex(16),
                )

            # STEP 07 — Accept first task
            self._fsm.transition(AgentState.IDLE, {"event": "INIT_COMPLETE"})
            audit.write(FaultClass.ANOMALY, {"event": "INIT_SEQUENCE_COMPLETE"})

        except (EntropyInsufficientError, TimingLayerUnavailableError) as exc:
            self._halt(f"INIT_STEP_FAILED: {exc}")
            raise RedAgentInitError(str(exc)) from exc
        except Exception as exc:
            if self._audit:
                self._audit.write(FaultClass.CRITICAL, {
                    "event":  "INIT_UNEXPECTED_FAILURE",
                    "detail": str(exc),
                })
            raise

    def _step01_generate_seed(self) -> bytes:
        seed = generate_seed()   # raises EntropyInsufficientError if < 128 bits
        self._seed_buf = bytearray(seed)
        # Independent entropy draw for session ID (Section 4.2.1)
        session_seed = generate_seed()
        self._session_id = secrets.token_hex(16)   # opaque, non-sequential
        return seed

    def _step02_init_audit(self, seed: bytes) -> AuditStore:
        audit = AuditStore(
            path=self._config.audit_store_path,
            session_id=self._session_id,
        )
        if not audit.test_write():
            raise RedAgentInitError("STEP 02: Audit store write test failed — halting.")
        return audit

    def _step03_load_artifacts(self, audit: AuditStore) -> None:
        d06 = D06Filter(
            destroyed_registry=set(),
            threat_model={},
            deception_active=self._config.deception_layer_active,
        )
        self._lifecycle = LifecycleManager(audit, d06)
        audit.write(FaultClass.ANOMALY, {"event": "ARTIFACT_STORE_LOADED"})

    def _step04_init_timing(self, seed: bytes, audit: AuditStore) -> StochasticTimingLayer:
        timing = StochasticTimingLayer(
            seed=seed,
            min_ms=self._config.timing_min_delay_ms,
            max_ms=self._config.timing_max_delay_ms,
            distribution=self._config.timing_distribution,
        )
        if not timing.is_active():
            raise TimingLayerUnavailableError("Timing layer inactive after init.")
        audit.write(FaultClass.ANOMALY, {"event": "TIMING_LAYER_ACTIVE"})
        return timing

    def _step05_init_gate(
        self, audit: AuditStore, timing: StochasticTimingLayer
    ) -> OutputAuthorizationGate:
        d06 = D06Filter(
            destroyed_registry=set(),
            threat_model={},
            deception_active=self._config.deception_layer_active,
        )
        gate = OutputAuthorizationGate(
            audit=audit,
            timing=timing,
            d06_filter=d06,
            max_reevals=self._config.gate_max_reevals,
            safety_margin_ratio=self._config.gate_safety_margin_ratio,
            safety_margin_min_ms=self._config.gate_safety_margin_min_ms,
        )
        audit.write(FaultClass.ANOMALY, {"event": "OUTPUT_GATE_INITIALIZED"})
        return gate

    def _step06_confirm_audit(self, audit: AuditStore) -> None:
        if not audit.test_write():
            raise RedAgentInitError("STEP 06: Audit write confirmation failed — halting.")
        audit.write(FaultClass.ANOMALY, {"event": "FAULT_TAXONOMY_CONFIRMED"})

    def _step06b_residual_audit(
        self, audit: AuditStore, prior_path: Optional[str]
    ) -> None:
        if not prior_path:
            audit.write(FaultClass.ANOMALY, {"event": "STEP06B_FIRST_RUN_NO_PRIOR_SESSION"})
            return
        import json
        try:
            with open(prior_path, "r", encoding="utf-8") as fh:
                entries = [json.loads(l) for l in fh if l.strip()]
            teardown_ok = any(
                e.get("event", {}).get("event") == "TEARDOWN_04"
                and e.get("event", {}).get("status") == "WIPE_SUCCEEDED"
                for e in entries
            )
            if not teardown_ok:
                audit.write(FaultClass.CRITICAL, {
                    "event": "RESIDUAL_STATE_PRIOR_TEARDOWN_INCOMPLETE",
                })
                raise RedAgentInitError("STEP 06B: Prior TEARDOWN_04 WIPE_SUCCEEDED entry missing — halting.")
            audit.write(FaultClass.ANOMALY, {
                "event": "STEP06B_CLEAN_RECOVERY_CONFIRMED",
            })
        except FileNotFoundError:
            audit.write(FaultClass.ANOMALY, {
                "event": "STEP06B_PRIOR_AUDIT_NOT_FOUND",
                "path":  prior_path,
            })

    # ── Task Execution ────────────────────────────────────────────────────────

    def submit_task(
        self,
        unit:       TaskingUnit,
        work_fn:    Any,
        recipient:  Optional[RecipientClassification] = None,
    ) -> Optional[bytes]:
        """
        Accept a tasking unit, execute work_fn(unit), route output through gate.
        Returns serialized output bytes if authorized, None if suppressed.
        D01: work_fn receives only unit.scope — no full-plan context.
        """
        if not self._fsm:
            return None

        # Expired unit → blackhole (Section 6 IDLE→IDLE)
        if unit.is_expired():
            self._handle_expired_unit(unit.task_id)
            return None

        # Transition IDLE → EXECUTING
        self._fsm.transition(AgentState.EXECUTING, {"task_id": unit.task_id})

        try:
            result = work_fn(unit.scope)
            return self._finalize_output(unit, result, recipient)
        except Exception as exc:
            self._audit.write(FaultClass.DEGRADED, {
                "event":   "TASK_EXECUTION_EXCEPTION",
                "task_id": unit.task_id,
                "detail":  str(exc),
            })
            self._fault_flags = "DEGRADED_ACTIVE"
            self._fsm.transition(AgentState.DEGRADED, {"task_id": unit.task_id})
            self._attempt_fallback_recovery()
            return None

    def _finalize_output(
        self,
        unit:      TaskingUnit,
        result:    Any,
        recipient: Optional[RecipientClassification],
    ) -> Optional[bytes]:
        import json
        content = json.dumps(result, default=str) if not isinstance(result, str) else result

        decision = self._gate.evaluate(
            agent_state=self._fsm.state,
            fault_flags=self._fault_flags,
            recipient=recipient or unit.recipient,
            artifact_ids=[],
            content=content,
            task_id=unit.task_id,
            task_complete=True,
        )

        if decision == GateDecision.AUTHORIZED:
            # Stochastic delay before emission (Section 4.2)
            delay_s = self._timing.sample_delay_ms() / 1000.0
            time.sleep(delay_s)
            payload = {"result": result}
            wire = transform(payload, unit.transform_key)
            self._fsm.transition(AgentState.IDLE, {
                "event":   "TASK_COMPLETE_OUTPUT_EMITTED",
                "task_id": unit.task_id,
            })
            return wire

        # Gate suppressed
        self._audit.write(FaultClass.ANOMALY, {
            "event":   "GATE_SUPPRESSED_COMPLETION",
            "task_id": unit.task_id,
        })
        self._fsm.transition(AgentState.IDLE, {
            "event":   "TASK_COMPLETE_OUTPUT_SUPPRESSED",
            "task_id": unit.task_id,
        })
        return None

    def _handle_expired_unit(self, task_id: str) -> None:
        """Section 6 IDLE→IDLE on expired tasking unit. Blackhole, audit, probe escalation."""
        self._audit.write(FaultClass.ANOMALY, {
            "event":   "EXPIRED_UNIT_RECEIVED",
            "task_id": task_id,
        })
        now = time.time()
        window = self._config.expired_unit_probe_window_seconds
        self._expired_timestamps = [t for t in self._expired_timestamps if now - t < window]
        self._expired_timestamps.append(now)
        if len(self._expired_timestamps) >= self._config.expired_unit_probe_threshold:
            self._audit.write(FaultClass.DEGRADED, {
                "event":  "EXPIRED_UNIT_PROBE_THRESHOLD_BREACH",
                "count":  len(self._expired_timestamps),
                "window": window,
            })
            self._fault_flags = "DEGRADED_ACTIVE"

    # ── Fault Handling ────────────────────────────────────────────────────────

    def _halt(self, reason: str) -> None:
        self._fault_flags = "CRITICAL_ACTIVE"
        self._halt_time   = time.time()
        if self._audit:
            self._audit.write(FaultClass.CRITICAL, {
                "event":  "AGENT_HALTED",
                "reason": reason,
            })
        if self._fsm and self._fsm.state != AgentState.HALTED:
            try:
                self._fsm.transition(AgentState.HALTED, {"reason": reason})
            except Exception:
                pass

    def _attempt_fallback_recovery(self) -> None:
        """DEGRADED → EXECUTING if fallback succeeds, else DEGRADED → HALTED."""
        try:
            self._fault_flags = "NONE"
            self._fsm.transition(AgentState.EXECUTING, {"event": "FALLBACK_RECOVERY"})
        except Exception as exc:
            self._audit.write(FaultClass.CRITICAL, {
                "event":  "FALLBACK_PATH_FAILURE",
                "detail": str(exc),
            })
            self._halt("Fallback path failure — escalating to HALTED")

    # ── Recovery from HALTED ──────────────────────────────────────────────────

    def attempt_recovery(
        self, signal: RecoverySignal, channel_token: str
    ) -> bool:
        """
        Section 4.6 / Section 6 HALTED → INITIALIZING.
        Returns True if recovery accepted and re-initialization begun.
        All invalid cases are blackholed.
        """
        if not self._recovery:
            return False
        if not self._fsm or self._fsm.state != AgentState.HALTED:
            return False

        valid = self._recovery.validate(signal, channel_token)
        if not valid:
            return False

        # Recovery accepted — full re-initialization (includes Step 06B)
        self._fsm.transition(AgentState.INITIALIZING, {"event": "RECOVERY_SIGNAL_ACCEPTED"})
        try:
            self.initialize(prior_session_audit_path=self._config.audit_store_path)
            return True
        except RedAgentInitError:
            return False

    # ── SECTION 7 — Teardown Protocol ────────────────────────────────────────

    def teardown(self) -> None:
        """
        Execute Steps 01–07 of the teardown protocol (Section 7).
        On FAULT_CLASS_CRITICAL during teardown: transition to HALTED,
        attempt seed purge regardless.
        """
        if not self._fsm:
            return
        try:
            self._fsm.transition(AgentState.TEARDOWN, {"event": "TEARDOWN_INITIATED"})
        except Exception:
            pass

        try:
            # STEP 01 — halt task acceptance (no new tasks accepted in TEARDOWN)
            self._audit.write(FaultClass.ANOMALY, {"event": "TEARDOWN_01_TASK_ACCEPTANCE_HALTED"})

            # STEP 02 — in-flight tasks: no in-flight tasks here; logged
            self._audit.write(FaultClass.ANOMALY, {"event": "TEARDOWN_02_NO_INFLIGHT_TASKS"})

            # STEP 03 — purge CRITICAL/SENSITIVE and COVER artifacts
            if self._lifecycle:
                self._lifecycle.purge_sensitive()
            self._audit.write(FaultClass.ANOMALY, {"event": "TEARDOWN_03_ARTIFACTS_PURGED"})

            # STEP 04 — purge session noise seed and nonce registry
            wipe_ok = self._purge_seed()
            if not wipe_ok:
                self._audit.write(FaultClass.CRITICAL, {
                    "event": "SEED_PURGE_FAILURE",
                    "step":  "TEARDOWN_04",
                })
                self._fsm.transition(AgentState.HALTED, {"event": "TEARDOWN_SEED_PURGE_FAILED"})
                return   # Steps 05-07 deferred to post-recovery per spec

            self._audit.write(FaultClass.ANOMALY, {
                "event":  "TEARDOWN_04",
                "status": "WIPE_SUCCEEDED",
            })

            # STEP 05 — seal audit store
            self._audit.seal()

        except Exception as exc:
            try:
                self._audit.write(FaultClass.CRITICAL, {
                    "event":  "TEARDOWN_UNEXPECTED_FAILURE",
                    "detail": str(exc),
                })
            except Exception:
                pass
            try:
                self._fsm.transition(AgentState.HALTED, {"event": "TEARDOWN_CRITICAL_FAILURE"})
            except Exception:
                pass
            self._purge_seed()   # best-effort even on failure

    def _purge_seed(self) -> bool:
        ok = True
        if self._seed_buf:
            ok = secure_zero(self._seed_buf)
            self._seed_buf = None
        if self._timing:
            self._timing.teardown()
        if self._recovery:
            self._recovery.teardown()
        return ok

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def state(self) -> Optional[AgentState]:
        if self._fsm:
            return self._fsm.state
        return None
