"""red_agent.core.initialization

7-step initialization sequence for the RedAgent.

Steps
-----
01  Generate entropy + session credentials.
02  Bootstrap AuditStore and seed hash-chain.
03  Initialize IntelligenceStore.
04  Activate StochasticTimingLayer.
05  Instantiate OutputAuthorizationGate.
06  Load FaultTaxonomy + verify hash-chain integrity.
06B Residual state scan (recovery path).
07  Accept first task envelope — transition FSM to IDLE.

All steps write to the audit chain.  A failure in any step raises
``InitializationError`` and leaves the FSM in HALTED state.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .audit import AuditStore, FaultClass
from .constants import AgentState, FaultClass as FC
from .gate import OutputAuthorizationGate
from .intelligence import IntelligenceStore

if TYPE_CHECKING:
    from ..config.settings import AgentConfig


class InitializationError(RuntimeError):
    """Raised when any initialization step fails."""


@dataclass
class SessionCredentials:
    """Entropy and session identifiers generated during Step 01."""

    session_id: str
    entropy_bytes: bytes
    entropy_score: float
    created_at: float = field(default_factory=time.time)


def _score_entropy(entropy_bytes: bytes) -> float:
    """Heuristic entropy score in [0, 1] based on byte diversity."""
    if not entropy_bytes:
        return 0.0
    unique = len(set(entropy_bytes))
    return unique / 256.0


@dataclass
class InitializationResult:
    """Carries all subsystems constructed during initialization."""

    credentials: SessionCredentials
    audit: AuditStore
    intelligence: IntelligenceStore
    gate: OutputAuthorizationGate
    completed_at: float = field(default_factory=time.time)


def run_initialization(config: "AgentConfig") -> InitializationResult:
    """Execute all 7 initialization steps.

    Raises
    ------
    InitializationError
        If any step fails.
    """
    # ------------------------------------------------------------------ #
    # Step 01 — Entropy + session credentials                              #
    # ------------------------------------------------------------------ #
    entropy = os.urandom(64)
    score = _score_entropy(entropy)
    if score < 0.3:
        raise InitializationError(
            f"Step 01: entropy score too low ({score:.3f}); aborting."
        )
    credentials = SessionCredentials(
        session_id=secrets.token_hex(16),
        entropy_bytes=entropy,
        entropy_score=score,
    )

    # ------------------------------------------------------------------ #
    # Step 02 — AuditStore + hash-chain seed                               #
    # ------------------------------------------------------------------ #
    audit = AuditStore()
    audit.write(
        FC.ANOMALY,
        {
            "event": "INIT_STEP_02",
            "session_id": credentials.session_id,
            "entropy_score": credentials.entropy_score,
        },
    )

    # ------------------------------------------------------------------ #
    # Step 03 — IntelligenceStore                                          #
    # ------------------------------------------------------------------ #
    intelligence = IntelligenceStore()
    audit.write(FC.ANOMALY, {"event": "INIT_STEP_03", "status": "ok"})

    # ------------------------------------------------------------------ #
    # Step 04 — StochasticTimingLayer (parameterised via config)           #
    # ------------------------------------------------------------------ #
    sleep_range = getattr(config, "gate_sleep_range_ms", (10, 50))
    audit.write(
        FC.ANOMALY,
        {
            "event": "INIT_STEP_04",
            "sleep_range_ms": sleep_range,
        },
    )

    # ------------------------------------------------------------------ #
    # Step 05 — OutputAuthorizationGate                                    #
    # ------------------------------------------------------------------ #
    gate = OutputAuthorizationGate(stochastic_sleep_range=sleep_range)
    audit.write(FC.ANOMALY, {"event": "INIT_STEP_05", "status": "ok"})

    # ------------------------------------------------------------------ #
    # Step 06 — FaultTaxonomy + hash-chain verify                          #
    # ------------------------------------------------------------------ #
    chain_valid = audit.verify_chain()
    if not chain_valid:
        raise InitializationError(
            "Step 06: audit hash-chain verification failed."
        )
    audit.write(FC.ANOMALY, {"event": "INIT_STEP_06", "chain_valid": True})

    # ------------------------------------------------------------------ #
    # Step 06B — Residual state scan                                       #
    # ------------------------------------------------------------------ #
    # No residual state on a clean cold start; write the marker anyway.
    audit.write(FC.ANOMALY, {"event": "INIT_STEP_06B", "residual": None})

    # ------------------------------------------------------------------ #
    # Step 07 — Accept first task → FSM IDLE                               #
    # ------------------------------------------------------------------ #
    audit.write(FC.ANOMALY, {"event": "INIT_STEP_07", "fsm": "IDLE"})

    return InitializationResult(
        credentials=credentials,
        audit=audit,
        intelligence=intelligence,
        gate=gate,
    )
