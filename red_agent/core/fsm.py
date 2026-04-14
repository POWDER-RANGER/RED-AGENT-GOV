"""red_agent.core.fsm

AgentFSM - thread-safe deterministic finite state machine.

All valid (from, to) transitions are defined in constants.VALID_TRANSITIONS.
Every transition is written to the audit chain. Invalid transitions raise
InvalidTransitionError without modifying state.
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from .constants import AgentState, FaultClass, VALID_TRANSITIONS

if TYPE_CHECKING:
    from .audit import AuditStore


class InvalidTransitionError(ValueError):
    """Raised when a transition is not in the valid transition table."""


class AgentFSM:
    """Thread-safe finite state machine for the RedAgent lifecycle."""

    def __init__(
        self,
        audit: "AuditStore",
        initial_state: AgentState = AgentState.INITIALIZING,
    ) -> None:
        self._state = initial_state
        self._audit = audit
        self._lock = threading.Lock()

    @property
    def state(self) -> AgentState:
        """Current FSM state (thread-safe read)."""
        with self._lock:
            return self._state

    def transition(
        self,
        target: AgentState,
        reason: str | None = None,
    ) -> None:
        """Attempt to transition to *target* state.

        Raises
        ------
        InvalidTransitionError
            If (current, target) is not in VALID_TRANSITIONS.
        """
        with self._lock:
            current = self._state
            pair = (current, target)
            if pair not in VALID_TRANSITIONS:
                raise InvalidTransitionError(
                    f"Transition {current.value} to {target.value} is not permitted."
                )
            self._state = target
            self._audit.write(
                FaultClass.ANOMALY,
                {
                    "event": "STATE_TRANSITION",
                    "from": current.value,
                    "to": target.value,
                    "reason": reason or {},
                },
            )

    def is_halted(self) -> bool:
        """Return True when the FSM is in HALTED state."""
        return self.state == AgentState.HALTED

    def is_executing(self) -> bool:
        """Return True when the FSM is in EXECUTING state."""
        return self.state == AgentState.EXECUTING

    def is_idle(self) -> bool:
        """Return True when the FSM is in IDLE state."""
        return self.state == AgentState.IDLE

    def is_degraded(self) -> bool:
        """Return True when the FSM is in DEGRADED state."""
        return self.state == AgentState.DEGRADED


# Backward-compatible alias
RedAgentFSM = AgentFSM
