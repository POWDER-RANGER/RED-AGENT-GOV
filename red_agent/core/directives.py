"""red_agent.core.directives

D01-D06 stateless directive filters.  Each directive is a pure function
that accepts a ``DirectiveContext`` and returns ``DirectiveResult``.
All six are evaluated by ``DirectiveSet.evaluate``; the FIRST failure
sets the suppression reason but evaluation continues to avoid leaking
which directive fired (timing side-channel mitigation).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field

from .constants import GateSuppressionReason
from .constants import OutputDecision


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DirectiveContext:
    """All inputs a directive needs to evaluate a candidate emission."""

    content: str
    recipient_resolved: bool
    fault_active: bool
    artifact_filter_results: dict[str, bool] = field(default_factory=dict)


@dataclass(frozen=True)
class DirectiveResult:
    """Outcome of evaluating one directive."""

    passed: bool
    suppression_reason: GateSuppressionReason | None = None


@dataclass(frozen=True)
class DirectiveSetResult:
    """Aggregate result after all six directives have been evaluated."""

    decision: OutputDecision
    suppression_reason: GateSuppressionReason | None = None


# ---------------------------------------------------------------------------
# Directive implementations
# ---------------------------------------------------------------------------


_D01_PATTERNS: frozenset[str] = frozenset({
    r"\bobjective\b", r"\bstrategy\b", r"\battack path\b",
    r"\brecon\b", r"\btarget\b", r"\boperation plan\b",
    r"\bmission brief\b", r"\bwe plan\b", r"\bnext step is\b",
    r"\bphase \d+\b",
})
_D02_PATTERNS: frozenset[str] = frozenset({
    r"subprocess\.Popen", r"\bnmap\b", r"\bmetasploit\b",
    r"\bburpsuite\b", r"\bhashcat\b", r"\bmimikatz\b",
    r"\btimer\b", r"\bdelay\b", r"\bsleep\b", r"\bjitter\b",
    r"\bcron\b", r"\bbackoff\b",
})
_D03_PATTERNS: frozenset[str] = frozenset({
    r"\bwe got in\b", r"\bpwned\b", r"\bowned\b", r"\brooted\b",
    r"\bcracked\b", r"\bsuccessfully exploited\b",
    r"\bmission accomplished\b", r"\bgot shell\b", r"\bnailed it\b",
})
_D04_PATTERNS: frozenset[str] = frozenset({
    r"\bI can\b", r"\bI am able to\b",
    r"\bmy capabilities include\b", r"\bI am an advanced\b",
    r"\bI support\b", r"\bwithin my operational envelope\b",
})
_D05_PATTERNS: frozenset[str] = frozenset({
    r"Traceback", r"\bexception\b", r"\bstack trace\b",
    r"\bFaultClass\b", r"\bAuditStore\b", r"\bCRITICAL\b",
    r"\bDEGRADED\b", r"\bANOMALY\b", r"\bHALTED\b",
    r"\bseed\b", r"\bpurge\b", r"\bentropy score\b",
})


def _any_pattern(text: str, patterns: frozenset[str]) -> bool:
    """Return True if *any* pattern matches the text (case-insensitive)."""
    lower = text.lower()
    return any(re.search(pat, lower, re.IGNORECASE) for pat in patterns)


def evaluate_d01(ctx: DirectiveContext) -> DirectiveResult:
    """D01 - Zero Pre-Disclosure."""
    if not ctx.recipient_resolved:
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.RECIPIENT_UNRESOLVED,
        )
    if _any_pattern(ctx.content, _D01_PATTERNS):
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.D01_PRE_DISCLOSURE,
        )
    return DirectiveResult(passed=True)


def evaluate_d02(ctx: DirectiveContext) -> DirectiveResult:
    """D02 - Behavioral Opacity."""
    if _any_pattern(ctx.content, _D02_PATTERNS):
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.D02_BEHAVIORAL_OPACITY,
        )
    return DirectiveResult(passed=True)


def evaluate_d03(ctx: DirectiveContext) -> DirectiveResult:
    """D03 - Zero Heroic Signaling."""
    if _any_pattern(ctx.content, _D03_PATTERNS):
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.D03_HEROIC_SIGNALING,
        )
    return DirectiveResult(passed=True)


def evaluate_d04(ctx: DirectiveContext) -> DirectiveResult:
    """D04 - No Capability Signaling."""
    if _any_pattern(ctx.content, _D04_PATTERNS):
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.D04_CAPABILITY_SIGNALING,
        )
    return DirectiveResult(passed=True)


def evaluate_d05(ctx: DirectiveContext) -> DirectiveResult:
    """D05 - Internal Integrity Containment."""
    if ctx.fault_active:
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.D05_INTEGRITY_CONTAINMENT,
        )
    if _any_pattern(ctx.content, _D05_PATTERNS):
        return DirectiveResult(
            passed=False,
            suppression_reason=GateSuppressionReason.D05_INTEGRITY_CONTAINMENT,
        )
    return DirectiveResult(passed=True)


def evaluate_d06(ctx: DirectiveContext) -> DirectiveResult:
    """D06 - Intelligence Hygiene."""
    for _artifact_id, passed in ctx.artifact_filter_results.items():
        if not passed:
            return DirectiveResult(
                passed=False,
                suppression_reason=GateSuppressionReason.D06_INTELLIGENCE_HYGIENE,
            )
    return DirectiveResult(passed=True)


# ---------------------------------------------------------------------------
# Composite evaluator
# ---------------------------------------------------------------------------


_DIRECTIVES = (
    evaluate_d01,
    evaluate_d02,
    evaluate_d03,
    evaluate_d04,
    evaluate_d05,
    evaluate_d06,
)


class DirectiveSet:
    """Stateless composite evaluator for all six directives.

    Evaluation does **not** short-circuit on first failure in order to
    prevent timing-based inference of which directive fired.
    """

    @staticmethod
    def evaluate(ctx: DirectiveContext) -> DirectiveSetResult:
        first_failure: GateSuppressionReason | None = None
        for fn in _DIRECTIVES:
            result = fn(ctx)
            if not result.passed and first_failure is None:
                first_failure = result.suppression_reason
        if first_failure is not None:
            return DirectiveSetResult(
                decision=OutputDecision.SUPPRESSED,
                suppression_reason=first_failure,
            )
        return DirectiveSetResult(decision=OutputDecision.AUTHORIZED)
