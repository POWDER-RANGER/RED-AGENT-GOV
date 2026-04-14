from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentConfig:
    # Entropy
    entropy_minimum_bits: int = 128

    # Stochastic timing (milliseconds)
    timing_min_delay_ms: float = 50.0
    timing_max_delay_ms: float = 2000.0
    timing_distribution: str = "lognormal"   # lognormal | uniform | exponential

    # Output gate
    gate_max_reevals: int = 3
    gate_safety_margin_ratio: float = 0.10
    gate_safety_margin_min_ms: float = 100.0

    # Recovery signal
    recovery_signal_ttl_seconds: int = 300
    recovery_probe_threshold: int = 5

    # Expired-unit escalation
    expired_unit_probe_window_seconds: int = 60
    expired_unit_probe_threshold: int = 3

    # Storage paths
    audit_store_path: str = "red_agent_audit.jsonl"
    artifact_store_path: str = "red_agent_artifacts.json"

    # Pre-shared key for recovery signals (hex-encoded, 32 bytes)
    recovery_psk_hex: Optional[str] = None

    # Deception layer (OPTIONAL)
    deception_layer_active: bool = False

    @property
    def recovery_psk(self) -> Optional[bytes]:
        if self.recovery_psk_hex:
            return bytes.fromhex(self.recovery_psk_hex)
        return None
