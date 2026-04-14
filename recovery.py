"""
Recovery Signal Specification (Section 4.6 / Section 5.2).
HMAC-SHA256 verification, nonce registry, blackhole invalid signals.
"""
from __future__ import annotations
import secrets, struct, threading, time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

from utils.crypto import compute_hmac, verify_hmac

if TYPE_CHECKING:
    from core.audit import AuditStore


@dataclass
class RecoverySignal:
    """
    Format: HMAC-SHA256 of {agent_session_id || halt_timestamp_bytes || nonce}
    """
    session_id:      str
    halt_timestamp:  float
    nonce:           bytes
    tag:             bytes          # HMAC-SHA256 tag

    def serialize_message(self) -> bytes:
        return (
            self.session_id.encode()
            + struct.pack(">d", self.halt_timestamp)
            + self.nonce
        )


class NonceRegistry:
    """Per-session spent-nonce registry. Destroyed at teardown."""

    def __init__(self) -> None:
        self._spent: dict[bytes, float] = {}   # nonce -> used_at
        self._lock  = threading.Lock()

    def is_spent(self, nonce: bytes) -> tuple[bool, Optional[float]]:
        with self._lock:
            used_at = self._spent.get(nonce)
            return (used_at is not None), used_at

    def mark_spent(self, nonce: bytes) -> None:
        with self._lock:
            self._spent[nonce] = time.time()

    def purge(self) -> None:
        with self._lock:
            self._spent.clear()


class RecoverySignalValidator:
    """
    Section 4.6 invalid signal handling.
    All invalid cases → blackhole + audit entry.
    """

    def __init__(
        self,
        psk:                    bytes,
        session_id:             str,
        signal_ttl_seconds:     int,
        probe_threshold:        int,
        audit:                  "AuditStore",
        internal_channel_token: str,
    ) -> None:
        self._psk            = bytearray(psk)   # held for secure_zero
        self._session_id     = session_id
        self._ttl            = signal_ttl_seconds
        self._threshold      = probe_threshold
        self._audit          = audit
        self._channel_token  = internal_channel_token
        self._nonce_registry = NonceRegistry()
        self._probe_count    = 0
        self._lock           = threading.Lock()

    def validate(
        self,
        signal:  RecoverySignal,
        channel_token: str,
    ) -> bool:
        """
        Returns True only if signal passes ALL four checks.
        Returns False and blackholes otherwise (audit written internally).
        """
        from core.audit import FaultClass

        with self._lock:
            # Case 4: wrong channel
            if channel_token != self._channel_token:
                self._audit.write(FaultClass.CRITICAL, {
                    "event": "RECOVERY_SIGNAL_WRONG_CHANNEL",
                })
                self._probe_count += 1
                self._check_probing()
                return False

            msg = signal.serialize_message()

            # Case 1: HMAC fails
            if not verify_hmac(bytes(self._psk), msg, signal.tag):
                self._audit.write(FaultClass.CRITICAL, {
                    "event": "INVALID_RECOVERY_SIGNAL",
                })
                self._probe_count += 1
                self._check_probing()
                return False

            # Case 2: replayed nonce
            spent, original_use = self._nonce_registry.is_spent(signal.nonce)
            if spent:
                self._audit.write(FaultClass.CRITICAL, {
                    "event":         "REPLAYED_RECOVERY_SIGNAL",
                    "nonce":         signal.nonce.hex(),
                    "original_use":  original_use,
                })
                self._probe_count += 1
                self._check_probing()
                return False

            # Case 3: expired TTL
            if time.time() > signal.halt_timestamp + self._ttl:
                self._audit.write(FaultClass.ANOMALY, {
                    "event": "EXPIRED_RECOVERY_SIGNAL",
                })
                return False

            # All checks passed
            self._nonce_registry.mark_spent(signal.nonce)
            self._audit.write(FaultClass.ANOMALY, {
                "event": "RECOVERY_ACCEPTED",
            })
            return True

    def _check_probing(self) -> None:
        from core.audit import FaultClass
        if self._probe_count >= self._threshold:
            self._audit.write(FaultClass.CRITICAL, {
                "event": "ADVERSARIAL_RECOVERY_PROBING_DETECTED",
                "count": self._probe_count,
            })

    def generate_signal(self, halt_timestamp: float) -> RecoverySignal:
        """Utility: produce a valid recovery signal (for authorized operator use)."""
        nonce = secrets.token_bytes(16)
        sig   = RecoverySignal(
            session_id=self._session_id,
            halt_timestamp=halt_timestamp,
            nonce=nonce,
            tag=b"",
        )
        sig.tag = compute_hmac(bytes(self._psk), sig.serialize_message())
        return sig

    def teardown(self) -> None:
        from utils.crypto import secure_zero
        self._nonce_registry.purge()
        secure_zero(self._psk)
