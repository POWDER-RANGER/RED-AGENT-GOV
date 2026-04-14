"""
Sealed-Envelope Tasking Model (Section 4.1).
Tasking units carry a TTL, scope-minimum context, and a transform_key.
Expired units are blackholed — never acknowledged.
"""
from __future__ import annotations
import secrets, time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class RecipientClassification:
    """Section 4.4 recipient schema."""
    classification_level: str   # CRITICAL | SENSITIVE | OPERATIONAL | AMBIENT
    cover_blind: bool = False   # True = cannot detect COVER artifacts


@dataclass
class TaskingUnit:
    """
    Section 4.1 — TASKING_UNIT schema.
    task_id:        opaque (no semantic content, non-sequential)
    scope:          minimum required execution context
    expiry:         wall-clock TTL
    recipient:      RecipientClassification of authorised executor
    need_to_know:   fields the sub-agent may read
    forbidden:      fields the sub-agent must not access
    transform_key:  serialization key for output decoding (Section 3.2)
    """
    scope:         dict[str, Any]
    expiry:        float                     # Unix timestamp
    recipient:     RecipientClassification
    need_to_know:  list[str]
    forbidden:     list[str]
    transform_key: bytes                     # 32-byte entropy-derived key
    task_id:       str = field(default_factory=lambda: secrets.token_hex(16))

    def is_expired(self) -> bool:
        return time.time() > self.expiry

    def field_allowed(self, field_name: str) -> bool:
        if field_name in self.forbidden:
            return False
        if field_name in self.need_to_know:
            return True
        return False

    @classmethod
    def create(
        cls,
        scope:         dict[str, Any],
        ttl_seconds:   float,
        recipient:     RecipientClassification,
        need_to_know:  list[str],
        forbidden:     list[str],
        session_seed:  bytes,
    ) -> "TaskingUnit":
        import hashlib
        transform_key = hashlib.blake2b(
            session_seed + secrets.token_bytes(16), digest_size=32
        ).digest()
        return cls(
            scope=scope,
            expiry=time.time() + ttl_seconds,
            recipient=recipient,
            need_to_know=need_to_know,
            forbidden=forbidden,
            transform_key=transform_key,
        )
