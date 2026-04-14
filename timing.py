"""
Stochastic Timing Layer (Section 4.2).
Entropy sources: OS + jitter + memory + per-session noise seed.
Never falls back to deterministic timing.
"""
from __future__ import annotations
import math, random, threading
from utils.entropy import EntropyInsufficientError


class TimingLayerUnavailableError(RuntimeError):
    pass


class StochasticTimingLayer:
    """
    Produces variable delays drawn from a statistical distribution
    seeded by session-local entropy.

    The seed is stored in a process-local bytearray and never persisted,
    never transmitted (secure_zero called at teardown).
    """

    DISTRIBUTIONS = {"lognormal", "uniform", "exponential"}

    def __init__(
        self,
        seed: bytes,
        min_ms: float = 50.0,
        max_ms: float = 2000.0,
        distribution: str = "lognormal",
    ) -> None:
        if distribution not in self.DISTRIBUTIONS:
            raise TimingLayerUnavailableError(
                f"Unknown distribution: {distribution}"
            )
        self._min_ms       = min_ms
        self._max_ms       = max_ms
        self._distribution = distribution
        self._rng          = random.Random()
        self._rng.seed(seed)
        self._seed_buf     = bytearray(seed)   # held for secure_zero on teardown
        self._lock         = threading.Lock()
        self._active       = True

    @property
    def max_delay_ms(self) -> float:
        return self._max_ms

    def sample_delay_ms(self) -> float:
        """Return a single stochastic delay in milliseconds."""
        with self._lock:
            if not self._active:
                raise TimingLayerUnavailableError(
                    "Timing layer deactivated; halting instead of falling back."
                )
            dist = self._distribution
            lo, hi = self._min_ms, self._max_ms

            if dist == "uniform":
                return self._rng.uniform(lo, hi)

            if dist == "lognormal":
                mu    = math.log((lo + hi) / 2)
                sigma = 0.6
                raw   = self._rng.lognormvariate(mu, sigma)
                return max(lo, min(hi, raw))

            if dist == "exponential":
                lam = 1.0 / ((lo + hi) / 2)
                raw = self._rng.expovariate(lam)
                return max(lo, min(hi, raw))

            raise TimingLayerUnavailableError(f"Unhandled distribution: {dist}")

    def is_active(self) -> bool:
        with self._lock:
            return self._active

    def teardown(self) -> None:
        """Wipe seed buffer and deactivate layer."""
        from utils.crypto import secure_zero
        with self._lock:
            secure_zero(self._seed_buf)
            self._active = False
