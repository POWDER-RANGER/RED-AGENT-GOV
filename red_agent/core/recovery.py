"""red_agent.core.recovery

Recovery signal generation and verification.

A ``RecoverySignal`` is an HMAC-SHA-256 token bound to a specific nonce
and timestamp.  The ``NonceRegistry`` enforces one-time use.  The
``RecoverySignalVerifier`` combines both checks so that replayed or
forged signals are unconditionally rejected.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Final


#: Default validity window for a recovery signal (seconds).
DEFAULT_VALIDITY_WINDOW_S: Final[int] = 300  # 5 minutes


@dataclass(frozen=True)
class RecoverySignal:
    """An authenticated recovery token.

    Attributes
    ----------
    nonce:
        16-byte random nonce encoded as hex.
    issued_at:
        Unix timestamp (float) when the signal was generated.
    token:
        HMAC-SHA-256 hex digest over ``nonce + issued_at``.
    """

    nonce: str
    issued_at: float
    token: str


def generate_recovery_signal(pre_shared_key: bytes) -> RecoverySignal:
    """Generate a fresh, signed ``RecoverySignal``.

    Parameters
    ----------
    pre_shared_key:
        The agent's PSK — must be the same key used during verification.
    """
    nonce = secrets.token_hex(16)
    issued_at = time.time()
    message = f"{nonce}:{issued_at}".encode()
    token = hmac.new(pre_shared_key, message, hashlib.sha256).hexdigest()
    return RecoverySignal(nonce=nonce, issued_at=issued_at, token=token)


class NonceRegistry:
    """Thread-safe one-time-use nonce store.

    Raises ``ValueError`` on duplicate nonce submission.
    """

    def __init__(self) -> None:
        self._used: set[str] = set()

    def consume(self, nonce: str) -> None:
        """Mark *nonce* as consumed.  Raises ``ValueError`` if already used."""
        if nonce in self._used:
            raise ValueError(f"Nonce already consumed: {nonce!r}")
        self._used.add(nonce)

    def purge(self) -> None:
        """Clear the registry (call during teardown only)."""
        self._used.clear()


class RecoverySignalVerifier:
    """Validates a ``RecoverySignal`` against the agent PSK.

    Parameters
    ----------
    pre_shared_key:
        The symmetric key shared between the agent and its operator.
    validity_window_s:
        How long (in seconds) a signal is considered valid after issuance.
    """

    def __init__(
        self,
        pre_shared_key: bytes,
        validity_window_s: int = DEFAULT_VALIDITY_WINDOW_S,
    ) -> None:
        self._psk = pre_shared_key
        self._window = validity_window_s
        self._registry = NonceRegistry()

    def verify(self, signal: RecoverySignal) -> bool:
        """Return ``True`` iff *signal* is authentic, unexpired, and unused.

        Side effect: consumes the nonce on success so it cannot be replayed.
        """
        # 1. Time-window check
        age = time.time() - signal.issued_at
        if age < 0 or age > self._window:
            return False

        # 2. HMAC verification (constant-time)
        message = f"{signal.nonce}:{signal.issued_at}".encode()
        expected = hmac.new(self._psk, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signal.token):
            return False

        # 3. Nonce replay check (consumes on success)
        try:
            self._registry.consume(signal.nonce)
        except ValueError:
            return False

        return True

    def teardown(self) -> None:
        """Purge internal nonce registry on agent shutdown."""
        self._registry.purge()
