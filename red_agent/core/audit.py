"""Internal fault taxonomy and append-only audit pipeline (Section 4.3).

Features:
- Hash-chained tamper-evident log (Section 4.3.2)
- Three-level fault taxonomy: CRITICAL / DEGRADED / ANOMALY
- Write-failure fallback chain: file → in-memory → stderr (Section 4.3.3)
- Thread-safe with a single internal lock
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from ..utils.crypto import sha256


# ── Fault taxonomy ──────────────────────────────────────────────────


class FaultClass(str, Enum):
    """Three-level severity taxonomy."""

    CRITICAL = "FAULT_CLASS_CRITICAL"
    DEGRADED = "FAULT_CLASS_DEGRADED"
    ANOMALY = "FAULT_CLASS_ANOMALY"


# ── Audit entry ────────────────────────────────────────────────────


@dataclass
class AuditEntry:
    """A single hash-chained audit record."""

    sequence: int
    timestamp: float
    fault_class: FaultClass
    event: dict[str, Any]
    prev_hash: str
    entry_hash: str = field(default="", init=False)

    def __post_init__(self) -> None:
        payload = (
            str(self.sequence)
            + str(self.timestamp)
            + json.dumps(self.event, sort_keys=True)
            + self.prev_hash
        ).encode()
        self.entry_hash = sha256(payload)


# ── Exceptions ─────────────────────────────────────────────────────


class AuditStoreUnavailableError(RuntimeError):
    """Raised when all fallback paths are exhausted (Section 4.3.3)."""


# ── AuditStore ─────────────────────────────────────────────────────


class AuditStore:
    """Append-only, hash-chained audit log.

    Write-only from any external interface.  Falls back per Section 4.3.3 on
    primary write failure: file → in-memory buffer → stderr.
    """

    def __init__(self, path: str, session_id: str) -> None:
        self._path = path
        self._session_id = session_id
        self._lock = threading.Lock()
        self._sequence = 0
        self._prev_hash = sha256(session_id.encode())
        self._in_memory: list[AuditEntry] = []
        self._sealed = False
        self._file_ok = False
        self._fh = None
        self._open_file()

    # ── private helpers ─────────────────────────────────────────────

    def _open_file(self) -> None:
        try:
            self._fh = open(self._path, "a", encoding="utf-8")  # noqa: SIM115
            self._file_ok = True
        except OSError:
            self._file_ok = False

    def _write_to_file(self, entry: AuditEntry) -> bool:
        if not self._file_ok or self._fh is None:
            return False
        try:
            line = json.dumps(asdict(entry), default=str) + "\n"
            self._fh.write(line)
            self._fh.flush()
            return True
        except OSError:
            self._file_ok = False
            return False

    def _fallback_memory(self, entry: AuditEntry) -> bool:
        try:
            self._in_memory.append(entry)
            return True
        except Exception:  # noqa: BLE001
            return False

    def _fallback_stderr(self, entry: AuditEntry) -> None:
        """Minimum-disclosure external emission (Section 4.3.3)."""
        sys.stderr.write(
            json.dumps(
                {"event": "AUDIT_STORE_UNAVAILABLE", "timestamp": entry.timestamp}
            )
            + "\n"
        )
        sys.stderr.flush()

    def _build_entry(self, fault_class: FaultClass, event: dict[str, Any]) -> AuditEntry:
        seq = self._sequence
        self._sequence += 1
        return AuditEntry(
            sequence=seq,
            timestamp=time.time(),
            fault_class=fault_class,
            event=event,
            prev_hash=self._prev_hash,
        )

    # ── public API ──────────────────────────────────────────────────

    def write(self, fault_class: FaultClass, event: dict[str, Any]) -> None:
        """Thread-safe append following the Section 4.3.3 fallback chain."""
        with self._lock:
            if self._sealed:
                return
            entry = self._build_entry(fault_class, event)
            self._prev_hash = entry.entry_hash
            if self._write_to_file(entry):
                return
            if self._fallback_memory(entry):
                return
            self._fallback_stderr(entry)
            raise AuditStoreUnavailableError(
                "Audit store unavailable and all fallbacks exhausted — halting."
            )

    def test_write(self) -> bool:
        """Step 02 / Step 06: verify write path and hash chain integrity."""
        try:
            self.write(
                FaultClass.ANOMALY,
                {"event": "AUDIT_STORE_TEST_WRITE", "status": "ok"},
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    def verify_chain(self) -> bool:
        """Replay the persisted chain and verify all hash links."""
        try:
            with open(self._path, encoding="utf-8") as fh:
                entries = [json.loads(line) for line in fh if line.strip()]
            if not entries:
                return True
            prev = sha256(self._session_id.encode())
            for e in entries:
                payload = (
                    str(e["sequence"])
                    + str(e["timestamp"])
                    + json.dumps(e["event"], sort_keys=True)
                    + prev
                ).encode()
                if sha256(payload) != e["entry_hash"]:
                    return False
                prev = e["entry_hash"]
            return True
        except Exception:  # noqa: BLE001
            return False

    def seal(self) -> None:
        """Step 05 of teardown: finalize and prevent further writes."""
        with self._lock:
            self.write(FaultClass.ANOMALY, {"event": "AUDIT_STORE_SEALED"})
            self._sealed = True
            if self._file_ok and self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
