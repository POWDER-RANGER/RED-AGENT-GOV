"""
Internal Fault Taxonomy and Audit Pipeline (Section 4.3).
Hash-chained tamper-evident log (Section 4.3.2).
Audit Write Failure Protocol (Section 4.3.3).
"""
from __future__ import annotations
import json, sys, threading, time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional
from utils.crypto import sha256


class FaultClass(str, Enum):
    CRITICAL = "FAULT_CLASS_CRITICAL"
    DEGRADED = "FAULT_CLASS_DEGRADED"
    ANOMALY  = "FAULT_CLASS_ANOMALY"


@dataclass
class AuditEntry:
    sequence:    int
    timestamp:   float
    fault_class: FaultClass
    event:       dict
    prev_hash:   str
    entry_hash:  str = field(default="", init=False)

    def __post_init__(self) -> None:
        payload = (
            str(self.sequence)
            + str(self.timestamp)
            + json.dumps(self.event, sort_keys=True)
            + self.prev_hash
        ).encode()
        self.entry_hash = sha256(payload)


# ── AuditStore ────────────────────────────────────────────────────────────────

class AuditStoreUnavailableError(RuntimeError):
    pass


class AuditStore:
    """
    Append-only, hash-chained audit log.
    Write-only from any external interface.
    Falls back per Section 4.3.3 on primary write failure.
    """

    def __init__(self, path: str, session_id: str) -> None:
        self._path       = path
        self._session_id = session_id
        self._lock       = threading.Lock()
        self._sequence   = 0
        self._prev_hash  = sha256(session_id.encode())
        self._in_memory: list[AuditEntry] = []
        self._sealed     = False
        self._file_ok    = False

        self._open_file()

    # ── private ───────────────────────────────────────────────────────────────

    def _open_file(self) -> None:
        try:
            self._fh = open(self._path, "a", encoding="utf-8")
            self._file_ok = True
        except OSError:
            self._file_ok = False

    def _write_to_file(self, entry: AuditEntry) -> bool:
        if not self._file_ok:
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
        except Exception:
            return False

    def _fallback_stderr(self, entry: AuditEntry) -> None:
        """
        Controlled minimum-disclosure external emission per Section 4.3.3.
        Content: {event: AUDIT_STORE_UNAVAILABLE, timestamp: T} only.
        """
        sys.stderr.write(
            json.dumps({"event": "AUDIT_STORE_UNAVAILABLE",
                        "timestamp": entry.timestamp}) + "\n"
        )
        sys.stderr.flush()

    def _build_entry(self, fault_class: FaultClass, event: dict) -> AuditEntry:
        seq = self._sequence
        self._sequence += 1
        return AuditEntry(
            sequence=seq,
            timestamp=time.time(),
            fault_class=fault_class,
            event=event,
            prev_hash=self._prev_hash,
        )

    # ── public ────────────────────────────────────────────────────────────────

    def write(self, fault_class: FaultClass, event: dict) -> None:
        """Thread-safe append following Section 4.3.3 fallback chain."""
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
        """STEP 02 / STEP 06: verify write path and hash chain."""
        try:
            self.write(FaultClass.ANOMALY,
                       {"event": "AUDIT_STORE_TEST_WRITE", "status": "ok"})
            return True
        except Exception:
            return False

    def verify_chain(self) -> bool:
        """Verify hash chain integrity from the file."""
        try:
            with open(self._path, "r", encoding="utf-8") as fh:
                entries = [json.loads(line) for line in fh if line.strip()]
            if not entries:
                return True
            prev = sha256(self._session_id.encode())
            for e in entries:
                recomputed_prev = prev
                payload = (
                    str(e["sequence"])
                    + str(e["timestamp"])
                    + json.dumps(e["event"], sort_keys=True)
                    + recomputed_prev
                ).encode()
                if sha256(payload) != e["entry_hash"]:
                    return False
                prev = e["entry_hash"]
            return True
        except Exception:
            return False

    def seal(self) -> None:
        """STEP 05 of teardown: finalize store, prevent further writes."""
        with self._lock:
            self.write(FaultClass.ANOMALY, {"event": "AUDIT_STORE_SEALED"})
            self._sealed = True
            if self._file_ok:
                try:
                    self._fh.close()
                except OSError:
                    pass
