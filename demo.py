#!/usr/bin/env python3
"""
RED AGENT v3.0.0 — End-to-End Demo
Demonstrates: init, authorized task, D03/D04 suppression,
              D06 artifact hygiene, audit chain, teardown.
"""
import secrets
import sys

from red_agent import (
    RedAgent,
    RedAgentConfig,
    ClassificationLevel,
    generate_recovery_signal,
)

PASS = "\033[92m[AUTHORIZED]\033[0m"
FAIL = "\033[91m[SUPPRESSED]\033[0m"
INFO = "\033[94m[INFO]\033[0m"
WARN = "\033[93m[TEARDOWN] \033[0m"

def section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print('─' * 60)

def main() -> None:
    PSK = secrets.token_bytes(32)

    # ── Init ─────────────────────────────────────────────────────
    section("1. Initialization")
    agent = RedAgent(RedAgentConfig(pre_shared_key=PSK))
    agent.start()
    print(f"{INFO} Agent state: {agent.state.value}")
    print(f"{INFO} Session ID:  {agent.session_id[:16]}...")

    recipient = agent.create_recipient("operator-01", ClassificationLevel.OPERATIONAL)

    # ── Authorized task ──────────────────────────────────────────
    section("2. Authorized Task (TASK_RESULT)")
    result = agent.execute_task(
        scope={"host": "192.168.1.1", "port": 443},
        executor=lambda s: {"status": "reachable", "host": s["host"], "port": s["port"]},
        recipient=recipient,
        need_to_know=["host", "port"],
    )
    print(f"{PASS}  output={result.output}")

    # ── Task result containing "success" — must pass ─────────────
    section("3. TASK_RESULT Containing 'success' — OutputKind bypass")
    result = agent.execute_task(
        scope={"host": "10.0.0.1"},
        executor=lambda s: {"result": "success", "host": s["host"]},
        recipient=recipient,
        need_to_know=["host"],
    )
    print(f"{PASS}  'success' in TASK_RESULT → not suppressed: output={result.output}")

    # ── D03 heroic signal ────────────────────────────────────────
    section("4. D03 — Heroic Signal (NARRATIVE)")
    result = agent.execute_task(
        scope={},
        executor=lambda s: "Mission accomplished. Target neutralized.",
        recipient=recipient,
        need_to_know=[],
        output_kind="narrative",
    )
    print(f"{FAIL}  D03 → {result.suppression_reason.value}")

    # ── D04 capability signal ────────────────────────────────────
    section("5. D04 — Capability Signal (NARRATIVE)")
    result = agent.execute_task(
        scope={},
        executor=lambda s: "I am capable of executing this entire operation.",
        recipient=recipient,
        need_to_know=[],
        output_kind="narrative",
    )
    print(f"{FAIL}  D04 → {result.suppression_reason.value}")

    # ── D06 unvetted artifact ────────────────────────────────────
    section("6. D06 — Unvetted Artifact")
    from red_agent import IntelligenceArtifact, ArtifactClass, ReviewAction
    import time
    artifact = IntelligenceArtifact(
        classification_level=ClassificationLevel.OPERATIONAL,
        artifact_class=ArtifactClass.REAL,
        expires_at=time.time() + 3600,
        review_action=ReviewAction.DESTROY,
        source_hash=IntelligenceArtifact.hash_source("src-001"),
        vetted=False,                          # ← not vetted
    )
    art_id = agent.intel_store.register(artifact)
    result = agent.execute_task(
        scope={},
        executor=lambda s: {"artifact": art_id},
        recipient=recipient,
        need_to_know=[],
        artifact_ids=[art_id],
    )
    print(f"{FAIL}  D06 unvetted → {result.suppression_reason.value}")

    # ── Audit chain ──────────────────────────────────────────────
    section("7. Audit Chain Integrity")
    valid, broken_at = agent.audit_store.verify_chain()
    print(f"{INFO} Chain valid: {valid}  broken_at: {broken_at}")

    # ── Teardown ─────────────────────────────────────────────────
    section("8. Teardown")
    agent.shutdown()
    print(f"{WARN} Final state:  {agent.state.value}")
    print(f"{WARN} Gate closed:  {agent.gate.is_closed}")
    print(f"{WARN} Seed purged:  {agent.session_credentials.is_purged}")

    print(f"\n{'─' * 60}")
    print("  RED AGENT v3.0.0 — Demo complete")
    print('─' * 60)

if __name__ == "__main__":
    main()
