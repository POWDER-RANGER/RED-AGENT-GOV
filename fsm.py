"""
Runtime State Machine (Section 6).
States: INITIALIZING, IDLE, EXECUTING, DEGRADED, HALTED, TEARDOWN.
Every transition writes an audit entry.
"""
from __future__ import annotations
import threading
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.audit import AuditStore, FaultClass


class AgentState(str, Enum):
    INITIALIZING = "INITIALIZING"
    IDLE         = "IDLE"
    EXECUTING    = "EXECUTING"
    DEGRADED     = "DEGRADED"
    HALTED       = "HALTED"
    TEARDOWN     = "TEARDOWN"


class IllegalTransitionError(RuntimeError):
    pass


# Allowed (from, to) pairs per Section 6
_VALID_TRANSITIONS: set[tuple[AgentState, AgentState]] = {
    (AgentState.INITIALIZING, AgentState.IDLE),
    (AgentState.INITIALIZING, AgentState.HALTED),
    (AgentState.IDLE,         AgentState.EXECUTING),
    (AgentState.IDLE,         AgentState.IDLE),      # expired unit blackhole
    (AgentState.IDLE,         AgentState.HALTED),
    (AgentState.EXECUTING,    AgentState.IDLE),
    (AgentState.EXECUTING,    AgentState.DEGRADED),
    (AgentState.EXECUTING,    AgentState.HALTED),
    (AgentState.DEGRADED,     AgentState.EXECUTING),
    (AgentState.DEGRADED,     AgentState.HALTED),
    (AgentState.HALTED,       AgentState.INITIALIZING),
    (AgentState.TEARDOWN,     AgentState.HALTED),
    # ANY -> TEARDOWN handled explicitly
}


class RedAgentFSM:
    def __init__(self, audit: "AuditStore") -> None:
        self._state = AgentState.INITIALIZING
        self._audit = audit
        self._lock  = threading.Lock()

    @property
    def state(self) -> AgentState:
        with self._lock:
            return self._state

    def transition(self, target: AgentState, reason: dict | None = None) -> None:
        from core.audit import FaultClass
        with self._lock:
            current = self._state

            # ANY -> TEARDOWN is always legal
            if target != AgentState.TEARDOWN:
                if (current, target) not in _VALID_TRANSITIONS:
                    raise IllegalTransitionError(
                        f"Illegal transition {current} -> {target}"
                    )

            self._state = target
            self._audit.write(
                FaultClass.ANOMALY,
                {
                    "event":  "STATE_TRANSITION",
                    "from":   current.value,
                    "to":     target.value,
                    "reason": reason or {},
                },
            )

    def is_halted(self) -> bool:
        return self.state == AgentState.HALTED

    def is_executing(self) -> bool:
        return self.state == AgentState.EXECUTING
