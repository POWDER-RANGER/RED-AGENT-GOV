"""red_agent.core.tasking

Tasking subsystem: sealed-envelope task delivery with scoped data views.

The ``TaskingEnvelope`` carries the operator's signed task intent.  The
``TaskingUnit`` is the runtime execution context scoped to ``need_to_know``
fields only.  ``TaskResult`` captures the gate-evaluated output.
"""
from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .constants import OutputDecision, GateSuppressionReason


# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

#: A callable that receives the scoped task scope dict and returns output.
TaskExecutorFn = Callable[[dict[str, Any]], Any]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaskingEnvelope:
    """Immutable task container delivered by the operator.

    Parameters
    ----------
    task_id:
        Unique identifier for this task (auto-generated UUID4 if omitted).
    scope:
        Full task scope dict.  Only ``need_to_know`` keys will be exposed
        to the executor.
    executor:
        Callable that performs the task work.
    recipient_id:
        Target recipient identifier (must match a resolved ``RecipientClassification``).
    need_to_know:
        Keys from *scope* the executor is permitted to see.
    issued_at:
        Unix timestamp of envelope creation.
    """

    scope: dict[str, Any]
    executor: TaskExecutorFn
    recipient_id: str
    need_to_know: list[str] = field(default_factory=list)
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    issued_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class TaskingUnit:
    """Runtime execution context derived from a ``TaskingEnvelope``.

    Only the ``need_to_know`` subset of scope is included.
    """

    task_id: str
    scoped_view: dict[str, Any]
    executor: TaskExecutorFn
    recipient_id: str

    @classmethod
    def from_envelope(cls, envelope: TaskingEnvelope) -> "TaskingUnit":
        """Create a scoped unit from a full envelope."""
        scoped = {
            k: v
            for k, v in envelope.scope.items()
            if k in envelope.need_to_know
        }
        return cls(
            task_id=envelope.task_id,
            scoped_view=scoped,
            executor=envelope.executor,
            recipient_id=envelope.recipient_id,
        )

    def execute(self) -> Any:
        """Run the executor with the scoped view."""
        return self.executor(self.scoped_view)


@dataclass
class TaskResult:
    """The output of a completed tasking cycle."""

    task_id: str
    output: Any
    suppressed: bool
    suppression_reason: GateSuppressionReason | None = None
    completed_at: float = field(default_factory=time.time)

    @property
    def authorized(self) -> bool:
        """True when the output was passed through the gate."""
        return not self.suppressed
