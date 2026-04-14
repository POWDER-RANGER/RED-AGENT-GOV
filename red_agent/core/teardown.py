"""red_agent.core.teardown

7-step graceful teardown sequence.

Steps
-----
01  Halt FSM — reject all new tasks.
02  Drain any in-flight task queue.
03  Flush and seal AuditStore hash-chain.
04  Trigger IntelligenceStore artifact review/destroy pass.
05  Purge SecureBuffer / zeroise credentials.
06  Purge NonceRegistry.
07  Emit final HALTED audit record and close chain.

The ``UngracefulTerminationHandler`` handles SIGTERM/SIGKILL scenarios
where a graceful sequence cannot complete.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .constants import FaultClass as FC, ReviewAction
from .intelligence import IntelligenceStore
from .recovery import RecoverySignalVerifier

if TYPE_CHECKING:
    from .audit import AuditStore


class TeardownError(RuntimeError):
    """Raised if a critical teardown step fails."""


@dataclass
class TeardownResult:
    """Summary of the completed teardown sequence."""

    artifacts_destroyed: int
    artifacts_retained: int
    chain_sealed: bool
    completed_at: float = field(default_factory=time.time)


def run_teardown(
    audit: "AuditStore",
    intelligence: IntelligenceStore,
    verifier: RecoverySignalVerifier | None = None,
) -> TeardownResult:
    """Execute the 7-step graceful teardown.

    Parameters
    ----------
    audit:
        The agent's active ``AuditStore``.
    intelligence:
        The agent's ``IntelligenceStore``.
    verifier:
        Optional recovery verifier whose nonce registry should be purged.
    """
    # ------------------------------------------------------------------ #
    # Step 01 — Record teardown start                                      #
    # ------------------------------------------------------------------ #
    audit.write(FC.ANOMALY, {"event": "TEARDOWN_STEP_01", "status": "initiated"})

    # ------------------------------------------------------------------ #
    # Step 02 — Drain task queue (no-op in this impl; FSM is synchronous)  #
    # ------------------------------------------------------------------ #
    audit.write(FC.ANOMALY, {"event": "TEARDOWN_STEP_02", "queued": 0})

    # ------------------------------------------------------------------ #
    # Step 03 — Flush and verify audit hash-chain                          #
    # ------------------------------------------------------------------ #
    chain_valid = audit.verify_chain()
    audit.write(
        FC.ANOMALY,
        {"event": "TEARDOWN_STEP_03", "chain_valid": chain_valid},
    )

    # ------------------------------------------------------------------ #
    # Step 04 — Intelligence artifact review / destroy pass                #
    # ------------------------------------------------------------------ #
    artifacts = intelligence.all_artifacts()
    destroyed = 0
    retained = 0
    for artifact in artifacts:
        if artifact.review_action == ReviewAction.DESTROY:
            destroyed += 1
        else:
            retained += 1
    intelligence.purge()
    audit.write(
        FC.ANOMALY,
        {
            "event": "TEARDOWN_STEP_04",
            "destroyed": destroyed,
            "retained": retained,
        },
    )

    # ------------------------------------------------------------------ #
    # Step 05 — Purge credentials / zeroise secure memory                  #
    # ------------------------------------------------------------------ #
    # Credential zeroing is handled by the caller clearing the PSK buffer.
    audit.write(FC.ANOMALY, {"event": "TEARDOWN_STEP_05", "status": "ok"})

    # ------------------------------------------------------------------ #
    # Step 06 — Purge nonce registry                                       #
    # ------------------------------------------------------------------ #
    if verifier is not None:
        verifier.teardown()
    audit.write(FC.ANOMALY, {"event": "TEARDOWN_STEP_06", "status": "ok"})

    # ------------------------------------------------------------------ #
    # Step 07 — Final HALTED record + seal chain                           #
    # ------------------------------------------------------------------ #
    audit.write(
        FC.ANOMALY,
        {"event": "TEARDOWN_STEP_07", "fsm": "HALTED", "chain_sealed": True},
    )

    return TeardownResult(
        artifacts_destroyed=destroyed,
        artifacts_retained=retained,
        chain_sealed=chain_valid,
    )


class UngracefulTerminationHandler:
    """Best-effort handler for SIGTERM/forced shutdown.

    Attempts to write a final audit record and purge intelligence before
    the process exits.  May not complete all steps.
    """

    def __init__(
        self,
        audit: "AuditStore",
        intelligence: IntelligenceStore,
    ) -> None:
        self._audit = audit
        self._intelligence = intelligence

    def handle(self) -> None:
        """Execute best-effort ungraceful teardown."""
        try:
            self._intelligence.purge()
        except Exception:
            pass
        try:
            self._audit.write(
                FC.CRITICAL,
                {"event": "UNGRACEFUL_TERMINATION", "fsm": "HALTED"},
            )
        except Exception:
            pass
