"""
Entropy scoring and seed generation (Section 4.2 / Section 5 STEP 01).
Minimum threshold: 128 bits.
Adversary-controllable sources contribute 0 bits.
"""
from __future__ import annotations
import os, time, struct, hashlib
from typing import Tuple

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class EntropyInsufficientError(RuntimeError):
    """Raised when scored entropy total falls below 128-bit minimum."""


# ── source collectors ─────────────────────────────────────────────────────────

def _os_entropy() -> Tuple[bytes, int]:
    raw = os.urandom(32)      # 256 bits from OS CSPRNG
    return raw, 128           # credited at threshold minimum


def _wall_clock_jitter() -> Tuple[bytes, int]:
    samples: list[int] = []
    for _ in range(8):
        t1 = time.perf_counter_ns()
        time.sleep(0)
        t2 = time.perf_counter_ns()
        samples.append(t2 - t1)
    raw = struct.pack(">8Q", *samples)
    return raw, 16            # credited at 16 bits


def _memory_pressure() -> Tuple[bytes, int]:
    if not _PSUTIL_AVAILABLE:
        return b"\x00" * 16, 0
    try:
        vm   = psutil.virtual_memory()
        swap = psutil.swap_memory()
        raw  = struct.pack(">QQd", vm.available, vm.used, float(swap.percent))
        return raw, 8
    except Exception:
        return b"\x00" * 20, 0


# ── public API ────────────────────────────────────────────────────────────────

def generate_seed(task_queue_depth: int = 0) -> bytes:
    """
    Aggregate ambient entropy; hash-condition the result.
    Raises EntropyInsufficientError if total < 128 bits.
    Returns 32 bytes suitable for use as a noise seed.
    """
    sources: list[Tuple[bytes, int]] = []

    raw, bits = _os_entropy()
    sources.append((raw, bits))

    raw, bits = _wall_clock_jitter()
    sources.append((raw, bits))

    raw, bits = _memory_pressure()
    sources.append((raw, bits))

    if task_queue_depth > 0:
        tq_raw  = struct.pack(">I", task_queue_depth)
        tq_bits = min(task_queue_depth.bit_length(), 8)
        sources.append((tq_raw, tq_bits))

    total_bits = sum(b for _, b in sources)
    if total_bits < 128:
        raise EntropyInsufficientError(
            f"Scored entropy {total_bits} bits — minimum 128 required; halting."
        )

    combined = b"".join(raw for raw, _ in sources)
    seed = hashlib.blake2b(combined, digest_size=32).digest()
    return seed
