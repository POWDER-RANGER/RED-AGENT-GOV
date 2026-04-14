"""Agent configuration dataclass.

All runtime-tunable parameters live here. Pass an ``AgentConfig`` instance
to ``RedAgent.__init__``; every field has a safe default.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AgentConfig:
    """Immutable configuration bag for a ``RedAgent`` instance."""

    # -- Entropy -------------------------------------------------------
    entropy_minimum_bits: int = 128

    # -- Stochastic timing (milliseconds) ------------------------------
    timing_min_delay_ms: float = 50.0
    timing_max_delay_ms: float = 2_000.0
    timing_distribution: str = "lognormal"  # lognormal | uniform | exponential

    # -- Output gate ---------------------------------------------------
    gate_max_reevals: int = 3
    gate_safety_margin_ratio: float = 0.10
    gate_safety_margin_min_ms: float = 100.0

    # -- Recovery signal -----------------------------------------------
    recovery_signal_ttl_seconds: int = 300
    recovery_probe_threshold: int = 5

    # -- Expired-unit escalation ---------------------------------------
    expired_unit_probe_window_seconds: int = 60
    expired_unit_probe_threshold: int = 3

    # -- Storage paths -------------------------------------------------
    audit_store_path: str = "red_agent_audit.jsonl"
    artifact_store_path: str = "red_agent_artifacts.json"

    # -- Recovery PSK (hex-encoded 32-byte secret) ---------------------
    recovery_psk_hex: str | None = None

    # -- Pre-shared key (raw bytes) ------------------------------------
    pre_shared_key: bytes | None = None

    # -- Deception layer -----------------------------------------------
    deception_layer_active: bool = False

    # -- Derived helpers -----------------------------------------------
    @property
    def recovery_psk(self) -> bytes | None:
        """Return the PSK as raw bytes, or *None* if not set."""
        if self.recovery_psk_hex:
            return bytes.fromhex(self.recovery_psk_hex)
        return None
