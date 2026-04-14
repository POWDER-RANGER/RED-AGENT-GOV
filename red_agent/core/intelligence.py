"""red_agent.core.intelligence

IntelligenceStore — artifact registry with D06 pre-filter.

Artifacts are classified by ``ArtifactClass`` and ``ClassificationLevel``.
The D06 filter runs automatically on every ingested artifact so the gate
never needs to re-evaluate hygiene inline.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .constants import ArtifactClass, ClassificationLevel, ReviewAction


# ---------------------------------------------------------------------------
# Recipient classification
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RecipientClassification:
    """Identifies a resolved, authenticated output recipient."""

    recipient_id: str
    clearance_level: ClassificationLevel
    resolved: bool = True


# ---------------------------------------------------------------------------
# Threat model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThreatModelEntry:
    """A single entry in the agent threat model."""

    entry_id: str
    description: str
    severity: str  # e.g. "HIGH", "MEDIUM", "LOW"
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Intelligence artifacts
# ---------------------------------------------------------------------------

@dataclass
class IntelligenceArtifact:
    """A piece of intelligence collected during task execution.

    Attributes
    ----------
    artifact_id:
        Unique artifact identifier.
    content:
        Raw content payload.
    artifact_class:
        Whether the artifact is genuine (REAL) or deliberate cover (COVER).
    classification:
        Sensitivity level driving access control.
    review_action:
        Default disposition for teardown review.
    ingested_at:
        Unix timestamp of ingestion.
    d06_passed:
        Set by ``IntelligenceStore`` after D06 hygiene check.
    """

    artifact_id: str
    content: Any
    artifact_class: ArtifactClass
    classification: ClassificationLevel
    review_action: ReviewAction = ReviewAction.REVIEW
    ingested_at: float = field(default_factory=time.time)
    d06_passed: bool = False


# ---------------------------------------------------------------------------
# D06 hygiene filter
# ---------------------------------------------------------------------------

# Content patterns that cause D06 to fail for an artifact.
_D06_BLOCKED_PATTERNS: frozenset[str] = frozenset({
    "<script", "javascript:", "data:text/html",
    "__import__", "exec(", "eval(",
})


def _d06_passes(content: Any) -> bool:
    """Return ``True`` when content clears the D06 hygiene check."""
    if not isinstance(content, str):
        return True  # non-string artifacts are not text-filtered
    lower = content.lower()
    return not any(pat in lower for pat in _D06_BLOCKED_PATTERNS)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class IntelligenceStore:
    """In-memory registry for ingested intelligence artifacts.

    All artifacts are D06-filtered on ingestion.  The ``filter_results``
    property exposes the ``{artifact_id: passed}`` map consumed by the gate.
    """

    def __init__(self) -> None:
        self._artifacts: dict[str, IntelligenceArtifact] = {}

    # ------------------------------------------------------------------
    def ingest(self, artifact: IntelligenceArtifact) -> None:
        """Ingest an artifact and run the D06 hygiene filter."""
        artifact.d06_passed = _d06_passes(artifact.content)
        self._artifacts[artifact.artifact_id] = artifact

    def get(self, artifact_id: str) -> IntelligenceArtifact | None:
        """Retrieve an artifact by ID."""
        return self._artifacts.get(artifact_id)

    def all_artifacts(self) -> list[IntelligenceArtifact]:
        """Return all ingested artifacts."""
        return list(self._artifacts.values())

    @property
    def filter_results(self) -> dict[str, bool]:
        """D06 filter map: ``{artifact_id: d06_passed}``."""
        return {
            aid: art.d06_passed
            for aid, art in self._artifacts.items()
        }

    def purge(self) -> None:
        """Destroy all stored artifacts (called during teardown)."""
        self._artifacts.clear()
