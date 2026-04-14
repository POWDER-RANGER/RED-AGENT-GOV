import os

dirs = [
    'red_agent', 'red_agent/config',
    'red_agent/core', 'red_agent/utils'
]
for d in dirs:
    os.makedirs(d, exist_ok=True)

# ── requirements.txt ─────────────────────────────────────────────────────────
with open('red_agent/requirements.txt', 'w') as f:
    f.write(
        "cryptography>=41.0.0\n"
        "psutil>=5.9.0\n"
    )

# ── config/__init__.py ────────────────────────────────────────────────────────
open('red_agent/config/__init__.py', 'w').close()

# ── config/settings.py ───────────────────────────────────────────────────────
with open('red_agent/config/settings.py', 'w') as f:
    f.write('''\
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
''')

# ── utils/__init__.py ─────────────────────────────────────────────────────────
open('red_agent/utils/__init__.py', 'w').close()

# ── utils/entropy.py ──────────────────────────────────────────────────────────
with open('red_agent/utils/entropy.py', 'w') as f:
    f.write('''\
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
        return b"\\x00" * 16, 0
    try:
        vm   = psutil.virtual_memory()
        swap = psutil.swap_memory()
        raw  = struct.pack(">QQd", vm.available, vm.used, float(swap.percent))
        return raw, 8
    except Exception:
        return b"\\x00" * 20, 0


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
''')

# ── utils/crypto.py ───────────────────────────────────────────────────────────
with open('red_agent/utils/crypto.py', 'w') as f:
    f.write('''\
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
''')

# ── utils/serialization.py ────────────────────────────────────────────────────
with open('red_agent/utils/serialization.py', 'w') as f:
    f.write('''\
"""
Serialization Boundary Protocol (Section 3.2).
- Randomize field ordering within each object.
- Stochastic padding on string fields (stripped by receiver).
- Variation driven by session entropy seed — not deterministic.
"""
from __future__ import annotations
import json, random, secrets
from typing import Any


_PAD_CHAR = "\\x00"    # stripped by receiver on deserialise


def _make_rng(seed: bytes) -> random.Random:
    rng = random.Random()
    rng.seed(seed)
    return rng


def _pad_string(value: str, rng: random.Random, max_pad: int = 32) -> str:
    n = rng.randint(0, max_pad)
    return value + (_PAD_CHAR * n)


def _shuffle_dict(d: dict, rng: random.Random) -> dict:
    keys = list(d.keys())
    rng.shuffle(keys)
    return {k: d[k] for k in keys}


def transform(payload: dict, seed: bytes) -> bytes:
    """
    Apply serialization boundary transformation driven by *seed*.
    Returns wire-format bytes.
    """
    rng = _make_rng(seed)

    def _transform_value(v: Any) -> Any:
        if isinstance(v, str):
            return _pad_string(v, rng)
        if isinstance(v, dict):
            return _shuffle_dict({k: _transform_value(vv) for k, vv in v.items()}, rng)
        if isinstance(v, list):
            return [_transform_value(i) for i in v]
        return v

    transformed = _transform_value(payload)
    if isinstance(transformed, dict):
        transformed = _shuffle_dict(transformed, rng)

    return json.dumps(transformed, separators=(",", ":")).encode()


def detransform(data: bytes) -> dict:
    """
    Strip padding and return canonical dict (field order is restored by receiver).
    """
    raw = json.loads(data.decode())

    def _strip(v: Any) -> Any:
        if isinstance(v, str):
            return v.rstrip(_PAD_CHAR)
        if isinstance(v, dict):
            return {k: _strip(vv) for k, vv in v.items()}
        if isinstance(v, list):
            return [_strip(i) for i in v]
        return v

    return _strip(raw)
''')

print("Batch 1 (config + utils) written successfully.")
