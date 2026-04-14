"""red_agent.agent

RedAgent - top-level interface for the governance-enforced agent engine.

Typical usage::

    import secrets
    from red_agent import RedAgent, AgentConfig, ClassificationLevel

    PSK = secrets.token_bytes(32)
    agent = RedAgent(AgentConfig(pre_shared_key=PSK))
    agent.start()
    recipient = agent.create_recipient("node-01", ClassificationLevel.OPERATIONAL)
    result = agent.execute_task(
        scope={"host": "10.0.0.1", "port": 443},
        executor=lambda s: f"Port {s['port']} open on {s['host']}",
        recipient=recipient,
        need_to_know=["host", "port"],
    )
    print(result.output)  # None if suppressed
    agent.shutdown()
"""
from __future__ import annotations

import threading

from .config.settings import AgentConfig
from .core.audit import AuditStore
from .core.constants import AgentState
from .core.constants import ClassificationLevel
from .core.constants import OutputDecision
from .core.fsm import AgentFSM
from .core.gate import OutputAuthorizationGate
from .core.initialization import run_initialization
from .core.intelligence import IntelligenceStore
from .core.intelligence import RecipientClassification
from .core.recovery import RecoverySignal
from .core.recovery import RecoverySignalVerifier
from .core.recovery import generate_recovery_signal
from .core.tasking import TaskExecutorFn
from .core.tasking import TaskingEnvelope
from .core.tasking import TaskingUnit
from .core.tasking import TaskResult
from .core.teardown import TeardownResult
from .core.teardown import run_teardown


class RedAgentError(RuntimeError):
    """General-purpose error raised by the agent public API."""


class RedAgent:
    """Governance-enforced Python agent engine.

    Parameters
    ----------
    config: ``AgentConfig`` instance. Must include a ``pre_shared_key``.
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._started = False
        self._audit: AuditStore | None = None
        self._fsm: AgentFSM | None = None
        self._gate: OutputAuthorizationGate | None = None
        self._intelligence: IntelligenceStore | None = None
        self._verifier: RecoverySignalVerifier | None = None
        self._recipients: dict[str, RecipientClassification] = {}
        self._fault_active: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Run the 7-step initialization sequence; transition FSM to IDLE."""
        with self._lock:
            if self._started:
                raise RedAgentError("Agent is already running.")
            try:
                result = run_initialization(self._config)
            except Exception as exc:
                raise RedAgentError(f"Initialization failed: {exc}") from exc
            self._audit = result.audit
            self._gate = result.gate
            self._intelligence = result.intelligence
            self._fsm = AgentFSM(
                audit=result.audit,
                initial_state=AgentState.INITIALIZING,
            )
            self._fsm.transition(
                AgentState.IDLE, reason="initialization_complete"
            )
            self._verifier = RecoverySignalVerifier(
                pre_shared_key=self._config.pre_shared_key
            )
            self._started = True

    def shutdown(self) -> TeardownResult:
        """Execute the 7-step graceful teardown; return teardown summary."""
        with self._lock:
            self._require_started()
            self._fsm.transition(
                AgentState.TEARDOWN, reason="graceful_shutdown"
            )
            result = run_teardown(
                audit=self._audit,
                intelligence=self._intelligence,
                verifier=self._verifier,
            )
            self._fsm.transition(AgentState.HALTED, reason="teardown_complete")
            self._started = False
            return result

    # ------------------------------------------------------------------
    # Recipient management
    # ------------------------------------------------------------------

    def create_recipient(
        self,
        recipient_id: str,
        clearance_level: ClassificationLevel,
    ) -> RecipientClassification:
        """Register and return an authenticated recipient."""
        recipient = RecipientClassification(
            recipient_id=recipient_id,
            clearance_level=clearance_level,
            resolved=True,
        )
        with self._lock:
            self._recipients[recipient_id] = recipient
        return recipient

    # ------------------------------------------------------------------
    # Task execution
    # ------------------------------------------------------------------

    def execute_task(
        self,
        scope: dict[str, object],
        executor: TaskExecutorFn,
        recipient: RecipientClassification,
        need_to_know: list[str] | None = None,
    ) -> TaskResult:
        """Execute *executor* in a scoped task envelope and gate the output."""
        with self._lock:
            self._require_started()
        self._fsm.transition(AgentState.EXECUTING, reason="task_start")
        envelope = TaskingEnvelope(
            scope=scope,
            executor=executor,
            recipient_id=recipient.recipient_id,
            need_to_know=need_to_know or list(scope.keys()),
        )
        unit = TaskingUnit.from_envelope(envelope)
        try:
            raw_output = unit.execute()
        except Exception as exc:
            with self._lock:
                self._fault_active = True
            self._fsm.transition(AgentState.DEGRADED, reason=str(exc))
            return TaskResult(
                task_id=envelope.task_id, output=None, suppressed=True
            )
        evaluation = self._gate.evaluate(
            content=str(raw_output) if raw_output is not None else "",
            recipient_resolved=recipient.resolved,
            fault_active=self._fault_active,
            artifact_filter_results=self._intelligence.filter_results,
        )
        with self._lock:
            self._fsm.transition(AgentState.IDLE, reason="task_complete")
        if evaluation.decision == OutputDecision.AUTHORIZED:
            return TaskResult(
                task_id=envelope.task_id,
                output=raw_output,
                suppressed=False,
            )
        return TaskResult(
            task_id=envelope.task_id,
            output=None,
            suppressed=True,
            suppression_reason=evaluation.suppression_reason,
        )

    # ------------------------------------------------------------------
    # Recovery
    # ------------------------------------------------------------------

    def generate_recovery_signal(self) -> RecoverySignal:
        """Generate a signed recovery signal using the agent PSK."""
        return generate_recovery_signal(self._config.pre_shared_key)

    def apply_recovery_signal(self, signal: RecoverySignal) -> bool:
        """Verify and consume *signal*; transition FSM from DEGRADED to IDLE."""
        with self._lock:
            self._require_started()
            if not self._verifier.verify(signal):
                return False
            if self._fsm.state == AgentState.DEGRADED:
                self._fsm.transition(
                    AgentState.IDLE, reason="recovery_signal_accepted"
                )
            self._fault_active = False
            return True

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def state(self) -> AgentState:
        """Current FSM state."""
        self._require_started()
        return self._fsm.state

    def _require_started(self) -> None:
        if not self._started:
            raise RedAgentError(
                "Agent has not been started. Call start() first."
            )


__all__ = ["RedAgent", "RedAgentError"]
