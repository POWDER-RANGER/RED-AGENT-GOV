"""Entropy scoring and session-seed generation (Section 4.2 / Section 5 Step 01).

Minimum scored entropy: 128 bits.
Adversary-controllable sources contribute 0 credited bits.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time

try:
    import psutil

    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class EntropyInsufficientError(RuntimeError):
    """Raised when aggregated scored entropy falls below 128 bits."""


# ── Source collectors ──────────────────────────────────────────────────────────────────
def _os_entropy() -> tuple[bytes, int]:
    """256 bits from the OS CSPRNG; credited at the 128-bit threshold minimum."""
    return os.urandom(32), 128


def _wall_clock_jitter() -> tuple[bytes, int]:
    """8 high-resolution timing samples; credited at 16 bits."""
    samples: list[int] = []
    for _ in range(8):
        t1 = time.perf_counter_ns()
        time.sleep(0)
        t2 = time.perf_counter_ns()
        samples.append(t2 - t1)
    return struct.pack(">8Q", *samples), 16


def _memory_pressure() -> tuple[bytes, int]:
    """VM/swap pressure sample; credited at 8 bits when psutil is available."""
    if not _PSUTIL_AVAILABLE:
        return b"\x00" * 16, 0
    try:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        raw = struct.pack(">QQd", vm.available, vm.used, float(swap.percent))
        return raw, 8
    except Exception:
        return b"\x00" * 20, 0


# ── Public API ────────────────────────────────────────────────────────────────────────
def generate_seed(task_queue_depth: int = 0) -> bytes:
    """Aggregate ambient entropy and return a 32-byte conditioned seed.

    Raises ``EntropyInsufficientError`` if the total scored entropy falls
    below 128 bits. The result is Blake2b-conditioned over all sources.
    """
    sources: list[tuple[bytes, int]] = []
    for collector in (_os_entropy, _wall_clock_jitter, _memory_pressure):
        raw, bits = collector()
        sources.append((raw, bits))
    if task_queue_depth > 0:
        tq_raw = struct.pack(">I", task_queue_depth)
        tq_bits = min(task_queue_depth.bit_length(), 8)
        sources.append((tq_raw, tq_bits))
    total_bits = sum(b for _, b in sources)
    if total_bits < 128:
        raise EntropyInsufficientError(
            f"Scored entropy {total_bits} bits — minimum 128 required; halting."
        )
    combined = b"".join(raw for raw, _ in sources)
    return hashlib.blake2b(combined, digest_size=32).digest()
