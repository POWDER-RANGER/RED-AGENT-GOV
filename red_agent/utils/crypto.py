"""Cryptographic primitives used throughout red_agent.

Provides:
- ``sha256``      — deterministic hash for audit-chain entries  (Section 4.3.2)
- ``hmac_sha256`` — keyed MAC, returns hex string
- ``compute_hmac``— keyed MAC, returns raw bytes (for recovery signals)
- ``verify_hmac`` — constant-time comparison of expected vs received tag
- ``secure_zero`` — best-effort in-process memory zeroing for seed buffers
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
from typing import Optional


# ── SHA-256 ──────────────────────────────────────────────────────────────


def sha256(data: bytes) -> str:
    """Return the lowercase hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


# ── HMAC-SHA256 ───────────────────────────────────────────────────────


def hmac_sha256(key: bytes, msg: bytes) -> str:
    """Return the lowercase hex-encoded HMAC-SHA256 of *msg* under *key*."""
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def compute_hmac(key: bytes, msg: bytes) -> bytes:
    """Return the raw HMAC-SHA256 tag bytes of *msg* under *key*."""
    return hmac.new(key, msg, hashlib.sha256).digest()


def verify_hmac(key: bytes, msg: bytes, tag: bytes) -> bool:
    """Constant-time comparison: return True iff ``compute_hmac(key, msg) == tag``."""
    expected = compute_hmac(key, msg)
    return hmac.compare_digest(expected, tag)


# ── Secure memory zeroing ─────────────────────────────────────────────


def _zero_via_ctypes(buf: bytearray) -> bool:
    """Attempt to zero *buf* in-place using ctypes."""
    try:
        nbytes = len(buf)
        if nbytes == 0:
            return True
        ptr = (ctypes.c_char * nbytes).from_buffer(buf)
        ctypes.memset(ptr, 0, nbytes)
        return True
    except Exception:  # noqa: BLE001
        return False


def secure_zero(buf: bytearray) -> bool:
    """Best-effort zero-fill of a mutable *bytearray* seed buffer.

    Attempts ctypes-level zeroing to reduce the window in which plaintext
    seed material resides in process memory.  Falls back to a Python-level
    loop if ctypes is unavailable.  Always returns ``True`` on success,
    ``False`` if all strategies fail.

    .. warning::
        CPython does not guarantee that interpreter-level zeroing prevents
        residual copies in the garbage-collected heap.  This is a
        best-effort mitigation, not a security guarantee.
    """
    if _zero_via_ctypes(buf):
        return True
    # Python-level fallback — slower but always available
    try:
        for i in range(len(buf)):
            buf[i] = 0
        return True
    except Exception:  # noqa: BLE001
        return False
