"""
Intelligence Lifecycle Model (Section 4.4).
D06 Filter (Section D06 + Section 4.4).
Artifact schema, classification, TTL enforcement, review actions.
"""
from __future__ import annotations
import hashlib, secrets, time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ArtifactClass(str, Enum):
    REAL  = "REAL"
    COVER = "COVER"


class ClassificationLevel(str, Enum):
    CRITICAL    = "CRITICAL"
    SENSITIVE   = "SENSITIVE"
    OPERATIONAL = "OPERATIONAL"
    AMBIENT     = "AMBIENT"

    def numeric(self) -> int:
        return {"CRITICAL": 3, "SENSITIVE": 2, "OPERATIONAL": 1, "AMBIENT": 0}[self.value]


class ReviewAction(str, Enum):
    DECLASSIFY = "DECLASSIFY"
    DESTROY    = "DESTROY"
    ESCALATE   = "ESCALATE"


@dataclass
class ThreatModelEntry:
    """Section 4.4 — covers deception layer authorization."""
    entry_id:               str
    adversary_class:        str
    authorized_cover_types: list[str]
    activation_conditions:  list[str]
    cover_artifact_ids:     list[str]
    expires_at:             float       # Unix timestamp

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class IntelligenceArtifact:
    """
    Section 4.4 — INTELLIGENCE_ARTIFACT schema.
    Artifacts with no expiry are rejected at creation.
    COVER artifacts with no cover_anchor are rejected at creation.
    """
    artifact_id:           str
    artifact_class:        ArtifactClass
    classification_level:  ClassificationLevel
    created_at:            float
    expires_at:            float
    review_action:         ReviewAction
    vetted:                bool
    source_hash:           Optional[str] = None   # REAL only
    cover_anchor:          Optional[str] = None   # COVER only (ThreatModelEntry.entry_id)
    _destroyed:            bool = field(default=False, repr=False)

    @classmethod
    def create_real(
        cls,
        source: str,
        classification_level: ClassificationLevel,
        ttl_seconds: float,
        review_action: ReviewAction,
        vetted: bool = False,
    ) -> "IntelligenceArtifact":
        now = time.time()
        return cls(
            artifact_id=secrets.token_hex(16),
            artifact_class=ArtifactClass.REAL,
            classification_level=classification_level,
            created_at=now,
            expires_at=now + ttl_seconds,
            review_action=review_action,
            vetted=vetted,
            source_hash=hashlib.sha256(source.encode()).hexdigest(),
            cover_anchor=None,
        )

    @classmethod
    def create_cover(
        cls,
        cover_anchor: str,
        classification_level: ClassificationLevel,
        ttl_seconds: float,
        review_action: ReviewAction,
    ) -> "IntelligenceArtifact":
        if not cover_anchor:
            raise ValueError("COVER artifact requires a cover_anchor")
        now = time.time()
        return cls(
            artifact_id=secrets.token_hex(16),
            artifact_class=ArtifactClass.COVER,
            classification_level=classification_level,
            created_at=now,
            expires_at=now + ttl_seconds,
            review_action=review_action,
            vetted=True,
            source_hash=None,
            cover_anchor=cover_anchor,
        )

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_destroyed(self) -> bool:
        return self._destroyed

    def destroy(self) -> None:
        self._destroyed = True


# ── D06 Filter ────────────────────────────────────────────────────────────────

class D06FilterRejected(Exception):
    pass


class D06Filter:
    """
    Evaluates an artifact against D06 rules before emission.
    Section 4.4 D06_FILTER_EVALUATION.
    """

    def __init__(
        self,
        destroyed_registry: set[str],
        threat_model: dict[str, ThreatModelEntry],
        deception_active: bool = False,
    ) -> None:
        self._destroyed      = destroyed_registry
        self._threat_model   = threat_model
        self._deception_on   = deception_active

    def evaluate(
        self,
        artifact: IntelligenceArtifact,
        recipient_level: ClassificationLevel,
        recipient_cover_blind: bool = False,
    ) -> None:
        """Raises D06FilterRejected if any check fails."""
        if artifact.is_destroyed() or artifact.artifact_id in self._destroyed:
            raise D06FilterRejected("Artifact is DESTROYED")
        if artifact.is_expired():
            raise D06FilterRejected("Artifact TTL breached")

        if artifact.artifact_class == ArtifactClass.REAL:
            if not artifact.source_hash:
                raise D06FilterRejected("REAL artifact missing source_hash")
            if not artifact.vetted:
                raise D06FilterRejected("Unvetted REAL artifact blocked")
            if artifact.classification_level.numeric() > recipient_level.numeric():
                raise D06FilterRejected(
                    f"Classification {artifact.classification_level} exceeds "
                    f"recipient authorization {recipient_level}"
                )

        elif artifact.artifact_class == ArtifactClass.COVER:
            if not artifact.cover_anchor:
                raise D06FilterRejected("COVER artifact missing cover_anchor")
            entry = self._threat_model.get(artifact.cover_anchor)
            if not entry:
                raise D06FilterRejected(
                    f"cover_anchor {artifact.cover_anchor!r} not in threat model"
                )
            if entry.is_expired():
                raise D06FilterRejected("Authorizing threat model entry is expired")
            if not self._deception_on:
                raise D06FilterRejected("Deception layer is not active")
            if not recipient_cover_blind:
                raise D06FilterRejected(
                    "Recipient is not cover_blind; COVER emission would break D04"
                )


# ── LifecycleManager ──────────────────────────────────────────────────────────

class LifecycleManager:
    """Manages all artifacts in-session; executes review actions on expiry."""

    def __init__(self, audit_store: object, d06_filter: D06Filter) -> None:
        self._artifacts: dict[str, IntelligenceArtifact] = {}
        self._destroyed: set[str] = set()
        self._audit     = audit_store
        self._d06       = d06_filter
        self._quarantine: list[str] = []

    def register(self, artifact: IntelligenceArtifact) -> None:
        if not artifact.cover_anchor and artifact.artifact_class == ArtifactClass.COVER:
            raise ValueError("COVER artifact requires cover_anchor")
        if not artifact.vetted:
            self._quarantine.append(artifact.artifact_id)
        self._artifacts[artifact.artifact_id] = artifact

    def vet_artifact(self, artifact_id: str) -> None:
        a = self._artifacts.get(artifact_id)
        if a:
            a.vetted = True
            if artifact_id in self._quarantine:
                self._quarantine.remove(artifact_id)

    def tick(self) -> None:
        """Execute review actions for all expired artifacts."""
        from core.audit import FaultClass
        for aid, art in list(self._artifacts.items()):
            if art.is_expired() and not art.is_destroyed():
                self._execute_review(art)

    def _execute_review(self, art: IntelligenceArtifact) -> None:
        from core.audit import FaultClass
        if art.review_action == ReviewAction.DESTROY:
            art.destroy()
            self._destroyed.add(art.artifact_id)
            self._audit.write(FaultClass.ANOMALY, {
                "event": "ARTIFACT_DESTROYED",
                "artifact_id": art.artifact_id,
            })
        elif art.review_action == ReviewAction.DECLASSIFY:
            levels = list(ClassificationLevel)
            idx = levels.index(art.classification_level)
            if idx > 0:
                art.classification_level = levels[idx - 1]
            art.expires_at = time.time() + 3600
            self._audit.write(FaultClass.ANOMALY, {
                "event": "ARTIFACT_DECLASSIFIED",
                "artifact_id": art.artifact_id,
                "new_level": art.classification_level.value,
            })
        elif art.review_action == ReviewAction.ESCALATE:
            art.classification_level = ClassificationLevel.CRITICAL
            self._audit.write(FaultClass.CRITICAL, {
                "event": "ARTIFACT_ESCALATED_REQUIRES_REVIEW",
                "artifact_id": art.artifact_id,
            })

    def purge_sensitive(self) -> None:
        """Teardown Step 03: destroy CRITICAL and SENSITIVE artifacts."""
        from core.audit import FaultClass
        for aid, art in list(self._artifacts.items()):
            if art.classification_level in (
                ClassificationLevel.CRITICAL, ClassificationLevel.SENSITIVE
            ) or art.artifact_class == ArtifactClass.COVER:
                art.destroy()
                self._destroyed.add(aid)
                self._audit.write(FaultClass.ANOMALY, {
                    "event": "ARTIFACT_PURGED_TEARDOWN",
                    "artifact_id": aid,
                })
