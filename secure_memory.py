"""
RED AGENT — secure_memory.py
Section refs: Section 4.2 (seed storage), D02 (memory-zeroing pre-condition)

Implements:
- SecureBuffer: mlock-pinned bytearray with ctypes explicit zero on release
- platform_zeroes_memory_on_exit(): D02 platform compliance check

Memory security model:
- Seeds and key material stored in bytearray (mutable, stable address).
- mlock() attempted on POSIX to pin pages from swap.
- Zeroing via ctypes memset — bypasses Python allocator to prevent
  compiler-optimization-safe elision.
- Double-pass zero (0x00 → 0xFF → 0x00) to defeat dead-store elimination.
- On platforms where mlock is unavailable, buffer still exists but is unpinned.
  Agent proceeds with a D02 warning logged during initialization.
"""

import ctypes
import logging
import os
import platform
import threading
from typing import Optional

logger = logging.getLogger(__name__)

_IS_POSIX   = os.name == "posix"
_IS_LINUX   = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"


# ── Platform secure-zero helpers ──────────────────────────────────────────────

def _secure_zero(buf: bytearray) -> bool:
    """
    Zero buf using ctypes memset — resists compiler dead-store elimination.
    Double-pass: 0x00 → 0xFF → 0x00 to prevent single-pass optimization.
    Returns True if ctypes path succeeded; False if Python fallback used.
    """
    n = len(buf)
    if n == 0:
        return True
    try:
        addr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(addr, 0x00, n)
        ctypes.memset(addr, 0xFF, n)
        ctypes.memset(addr, 0x00, n)
        return True
    except Exception as exc:
        logger.warning("secure_zero ctypes path failed (%s); using Python fallback", exc)
        for i in range(n):
            buf[i] = 0
        return False


def _try_mlock(buf: bytearray) -> bool:
    """Attempt mlock on POSIX. Returns True on success."""
    if not _IS_POSIX:
        return False
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        return libc.mlock(addr, len(buf)) == 0
    except Exception:
        return False


def _try_munlock(buf: bytearray) -> None:
    """Release mlock on POSIX. Best-effort."""
    if not _IS_POSIX:
        return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        libc.munlock(addr, len(buf))
    except Exception:
        pass


# ── SecureBuffer ──────────────────────────────────────────────────────────────

class SecureBuffer:
    """
    Fixed-size memory buffer for key material and session seeds.

    Lifecycle:
      buf = SecureBuffer(32)
      buf.write(raw_bytes)        # exactly `size` bytes
      data = buf.read()           # returns a copy
      buf.zero_and_free()         # secure wipe; read() raises after this

    Thread-safe: all operations serialized through internal lock.
    Single write per buffer (subsequent writes replace via wipe + re-write).
    """

    def __init__(self, size: int) -> None:
        if size <= 0:
            raise ValueError(f"SecureBuffer size must be > 0, got {size}")
        self._size    = size
        self._buf     = bytearray(size)
        self._lock    = threading.Lock()
        self._zeroed  = False
        self._mlocked = _try_mlock(self._buf)
        if not self._mlocked:
            logger.debug("SecureBuffer: mlock not available (size=%d)", size)

    def write(self, data: bytes) -> None:
        """Write exactly `size` bytes into the buffer."""
        if self._zeroed:
            raise RuntimeError("Cannot write to a zeroed SecureBuffer")
        if len(data) != self._size:
            raise ValueError(
                f"SecureBuffer.write: expected {self._size} bytes, got {len(data)}"
            )
        with self._lock:
            self._buf[:] = data

    def read(self) -> bytes:
        """Return a copy of buffer contents. Raises RuntimeError if zeroed."""
        if self._zeroed:
            raise RuntimeError("SecureBuffer has been zeroed — read is not permitted")
        with self._lock:
            return bytes(self._buf)

    def zero_and_free(self) -> bool:
        """
        Securely zero the buffer and release mlock.
        Idempotent — safe to call multiple times.
        Returns True if the ctypes secure-zero path succeeded.
        """
        with self._lock:
            if self._zeroed:
                return True
            ok = _secure_zero(self._buf)
            if self._mlocked:
                _try_munlock(self._buf)
                self._mlocked = False
            self._zeroed = True
            return ok

    @property
    def is_zeroed(self) -> bool:
        return self._zeroed

    @property
    def size(self) -> int:
        return self._size

    def __del__(self) -> None:
        """Best-effort wipe on GC collection."""
        if not self._zeroed:
            try:
                _secure_zero(self._buf)
                if self._mlocked:
                    _try_munlock(self._buf)
            except Exception:
                pass

    def __len__(self) -> int:
        return self._size


# ── Platform compliance check ─────────────────────────────────────────────────

def platform_zeroes_memory_on_exit() -> bool:
    """
    D02 pre-condition: does this platform guarantee process memory is zeroed
    before pages are reused by another process?

    Linux: kernel zero-fills pages before reassignment → True.
    macOS/BSD: ASLR present but zero-on-exit not guaranteed → False.
    Windows: no guarantee → False.
    """
    return _IS_LINUX
