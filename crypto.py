"""
Cryptographic primitives:
  - SHA-256 for hash-chain entries (Section 4.3.2)
  - HMAC-SHA256 for recovery signal verification (Section 4.6)
  - secure_zero: best-effort process-local memory zeroing
"""
from __future__ import annotations
import ctypes, hashlib, hmac, os, sys
from typing import Optional


# ── SHA-256 ───────────────────────────────────────────────────────────────────

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── HMAC-SHA256 ───────────────────────────────────────────────────────────────

def compute_hmac(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def verify_hmac(key: bytes, message: bytes, tag: bytes) -> bool:
    expected = compute_hmac(key, message)
    return hmac.compare_digest(expected, tag)


# ── secure_zero ───────────────────────────────────────────────────────────────

def secure_zero(buf: bytearray) -> bool:
    """
    Overwrite *buf* with zeros using ctypes memset, which the compiler
    cannot optimise away.  Returns True on success, False on failure.
    Simulates explicit_bzero / SecureZeroMemory semantics.
    """
    if not isinstance(buf, bytearray):
        return False
    try:
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        ctypes.memset(addr, 0, len(buf))
        return True
    except Exception:
        try:
            for i in range(len(buf)):
                buf[i] = 0
            return True
        except Exception:
            return False
