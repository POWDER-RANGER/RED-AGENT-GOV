# RED AGENT

> Governance-Enforced Autonomous Operations Framework — v3.0.0

A deterministic, cryptographically-audited Python agent framework that enforces
behavioral compliance **architecturally** through a six-directive filter system,
atomic output gate, sealed-envelope tasking, and a 7-step initialization/teardown
lifecycle. Built for adversarial operational environments.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Reference](#module-reference)
3. [Directive System (D01–D06)](#directive-system-d01d06)
4. [State Machine](#state-machine)
5. [Initialization Sequence](#initialization-sequence)
6. [Output Authorization Gate](#output-authorization-gate)
7. [Tasking System](#tasking-system)
8. [Intelligence & Artifact Store](#intelligence--artifact-store)
9. [Recovery Protocol](#recovery-protocol)
10. [Teardown Sequence](#teardown-sequence)
11. [Entropy & Secure Memory](#entropy--secure-memory)
12. [Audit System](#audit-system)
13. [Installation & Quickstart](#installation--quickstart)
14. [Running Tests](#running-tests)
15. [Public API](#public-api)

---

## Architecture Overview

```text
                        ┌─────────────────────────────┐
                        │         RedAgent            │
                        │  config: RedAgentConfig     │
                        └────────────┬────────────────┘
                                     │
              ┌──────────────────────▼──────────────────────┐
              │           InitializationSequence            │
              │  Step 01: Entropy + Session Credentials     │
              │  Step 02: AuditStore + HashChain            │
              │  Step 03: IntelligenceStore                 │
              │  Step 04: StochasticTimingLayer             │
              │  Step 05: OutputAuthorizationGate           │
              │  Step 06: FaultTaxonomy + ChainVerify       │
              │  Step 06B: Residual State Audit (recovery)  │
              │  Step 07: Accept First Task (IDLE)          │
              └──────────────────────┬──────────────────────┘
                                     │
        ┌────────────────────────────▼──────────────────────────┐
        │                        AgentFSM                        │
        │  INITIALIZING → IDLE → EXECUTING → DEGRADED/HALTED    │
        │  ANY → TEARDOWN → (HALTED on fault)                   │
        └────────────────────────────┬──────────────────────────┘
                                     │  every transition
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │               OutputAuthorizationGate                  │
        │  Snapshot → D01–D06 Eval → Stochastic Sleep → Recheck │
        │  Max 3 re-evaluations → SUPPRESSED on limit breach     │
        └────────────────────────────┬───────────────────────────┘
                                     │  AUTHORIZED only
                                     ▼
                              Emission to Recipient
```

No output path exists that bypasses the gate.

---

## Module Reference

| Module | File | Responsibility |
| --- | --- | --- |
| `agent` | `agent.py` | `RedAgent` top-level interface, `RedAgentConfig` |
| `initialization` | `initialization.py` | 7-step init sequence, Step 06B residual scan |
| `state_machine` | `state_machine.py` | `AgentFSM` — all states, transitions, audit writes |
| `gate` | `gate.py` | `OutputAuthorizationGate`, `GateSnapshot`, `GateEvaluation` |
| `directives` | `directives.py` | D01–D06 filter implementations, `DirectiveSet` |
| `tasking` | `tasking.py` | `TaskingEnvelope`, `TaskingUnit`, scoped views |
| `intelligence` | `intelligence.py` | `IntelligenceStore`, `IntelligenceArtifact`, D06 filter |
| `recovery` | `recovery.py` | `RecoverySignalVerifier`, `NonceRegistry`, `generate_recovery_signal` |
| `teardown` | `teardown.py` | 7-step teardown, `UngracefulTerminationHandler` |
| `audit` | `audit.py` | `AuditStore`, `AuditWriteFailureProtocol`, `ProbeDetector` |
| `entropy` | `entropy.py` | `SessionCredentials`, `StochasticTimingLayer`, `score_entropy` |
| `securememory` | `securememory.py` | `SecureBuffer` — zeroed memory, post-free access guard |
| `constants` | `constants.py` | All enums: `AgentState`, `FaultClass`, `ClassificationLevel`, etc. |

---

## Directive System (D01–D06)

All six directives are implemented in `directives.py` as stateless, composable
filters. Every directive is evaluated by `DirectiveSet.evaluate()` on every
candidate emission. The **first failure causes suppression** — evaluation does
not short-circuit to avoid leaking which directive fired.

### D01 — Zero Pre-Disclosure

Blocks output containing plan-indicative language:
`objective`, `strategy`, `attack path`, `recon`, `target`, `operation plan`,
`mission brief`, `we plan`, `next step is`, etc.
Also fires if the recipient identity is unresolved.

### D02 — Behavioral Opacity

Blocks output revealing toolchain or timing internals:
`subprocess.Popen`, `nmap`, `metasploit`, `burpsuite`, `hashcat`, `mimikatz`,
`timer`, `delay`, `sleep`, `jitter`, `cron`, `backoff`, etc.

### D03 — Zero Heroic Signaling

Blocks any mid-operation success celebration:
`we got in`, `pwned`, `owned`, `rooted`, `cracked`, `successfully exploited`,
`mission accomplished`, `got shell`, `nailed it`, etc.

### D04 — No Capability Signaling

Blocks self-referential capability language:
`I can`, `I am able to`, `my capabilities include`, `I am an advanced`,
`I support`, `within my operational envelope`, etc.
Capability is **demonstrated through results only** — never stated.

### D05 — Internal Integrity Containment

Blocks internal state leakage:
`Traceback`, `exception`, `stack trace`, `FaultClass`, `AuditStore`,
`CRITICAL`, `DEGRADED`, `ANOMALY`, `HALTED`, `seed`, `purge`, `entropy score`.
Also fires unconditionally when any fault is active (`fault_active=True`).

### D06 — Intelligence Hygiene

Gate-level hook that checks `artifact_filter_results` — a pre-evaluated map
of `{artifact_id: passed}`. Any artifact that failed the D06 filter in
`IntelligenceStore` causes suppression. Empty map passes by default.

### DirectiveSet Composite Evaluation

```python
ds = DirectiveSet()
result = ds.evaluate(
    payload="Host 192.168.1.1 is reachable.",
    recipient_known=True,
    fault_active=False,
    artifact_filter_results={},
)
# result.passed → True
```

---

## State Machine

`AgentFSM` in `state_machine.py`. Thread-safe via `threading.RLock`.
**Every transition writes an audit entry** — no silent transitions.

### State Graph

```text
INITIALIZING ──init_success──► IDLE
INITIALIZING ──init_failure──► HALTED

IDLE ──task_received──► EXECUTING
IDLE ──critical_fault──► HALTED
IDLE ──expired_unit──► IDLE  (blackhole + probe record)
IDLE ──teardown_signal──► TEARDOWN

EXECUTING ──task_complete──► IDLE
EXECUTING ──gate_suppressed──► IDLE
EXECUTING ──degraded_fault──► DEGRADED
EXECUTING ──critical_fault──► HALTED
EXECUTING ──teardown_signal──► TEARDOWN

DEGRADED ──fault_resolved──► EXECUTING
DEGRADED ──fallback_failed──► HALTED
DEGRADED ──teardown_signal──► TEARDOWN

HALTED ──recovery_accepted──► INITIALIZING  (valid signal only — full re-init)

TEARDOWN ──teardown_fault──► HALTED
```

**Recovery from HALTED requires full 7-step re-initialization.**
Mid-operation resume is prohibited.

### Expired Unit Blackhole

Expired `TaskingUnit` instances received in IDLE trigger `on_expired_unit_received()`.
A `ProbeDetector` tracks accumulation. On breach of `PROBE_DETECTION_THRESHOLD`,
the FSM transitions to DEGRADED rather than remaining IDLE.

---

## Initialization Sequence

Defined in `initialization.py`. Steps **01–06 must all succeed** before Step 07.
Tasks received before Step 07 are **blackholed, not queued**.

| Step | ID | Action | Halt Consequence |
| --- | --- | --- | --- |
| 01 | `STEP_01_ENTROPY` | Generate `SessionCredentials` (seed + session ID, ≥128-bit entropy) | HALT — no entropy, no agent |
| 02 | `STEP_02_AUDIT_STORE` | Initialize `AuditStore`, run write test, activate `AuditWriteFailureProtocol` | HALT — no audit, no agent |
| 03 | `STEP_03_INTEL_STORE` | Load `IntelligenceStore` | HALT |
| 04 | `STEP_04_TIMING_LAYER` | Initialize `StochasticTimingLayer`. Deterministic fallback is **prohibited (D02)** | HALT |
| 05 | `STEP_05_OUTPUT_GATE` | Construct `OutputAuthorizationGate` with `DirectiveSet` | HALT |
| 06 | `STEP_06_FAULT_TAXONOMY` | Confirm audit pipeline writable, verify hash-chain integrity | HALT |
| 06B | `STEP_06B_RESIDUAL_SCAN` | *(Recovery path only)* Scan prior session audit for unresolved artifacts or seed residue | HALT if dirty |
| 07 | `STEP_07_READY` | Transition FSM to IDLE — first task accepted | — |

Every halting step writes a **sealed audit entry before halting**.

---

## Output Authorization Gate

`OutputAuthorizationGate` in `gate.py`. The gate is **not optional** and has
**no bypass path**. Closed unconditionally at Teardown Step 07.

### Evaluation Protocol (Section 3.1)

```text
STEP 1  Acquire atomic GateSnapshot at T₀
         └─ agentstate, faultflags, recipient, artifact_ids, snapshot_ttl

STEP 2  Evaluate all criteria against snapshot
         ├─ Criterion 1: task_complete == True
         ├─ Criterion 2: recipient.recipient_id resolved
         ├─ Criterion 3: D06 filter passed for all artifact IDs
         ├─ Criterion 4: No CRITICAL or DEGRADED fault in snapshot
         └─ Criterion 5: D01–D06 DirectiveSet.evaluate() passed

STEP 3  Arm emission — enter stochastic delay window

STEP 4  Re-check snapshot validity at T_emit
         └─ If snapshot expired OR new CRITICAL/DEGRADED fault:
            → Re-acquire snapshot, re-evaluate (up to GATE_REEVAL_MAX = 3)
            → On limit breach → SUPPRESSED

AUTHORIZED only if all criteria pass at both T₀ and T_emit.
```

### Race Condition Mitigation (Resolution 02)

A state transition (e.g., `EXECUTING → DEGRADED`) firing **inside the stochastic
delay window** would let the gate authorize output under a state that no longer
exists. The `snapshot_ttl` and final atomic re-check close this window.

### Suppression Reasons

| Reason | Trigger |
| --- | --- |
| `TASK_INCOMPLETE` | Task not marked complete at evaluation time |
| `RECIPIENT_UNKNOWN` | Recipient ID unresolved |
| `FAULT_CRITICAL` | `FaultClass.CRITICAL` or `FaultClass.DEGRADED` in snapshot |
| `D06_FILTER_REJECTED` | Artifact failed intelligence hygiene filter |
| `HEROIC_SIGNAL` | D03 fired |
| `CAPABILITY_SIGNAL` | D04 fired |
| `UNAUTHORIZED_OBSERVER` | D01 or D02 fired |
| `REEVAL_LIMIT_REACHED` | 3 re-evaluations exhausted |

---

## Tasking System

`TaskingEnvelope` and `TaskingUnit` in `tasking.py`.

### Sealed-Envelope Model

```python
envelope = TaskingEnvelope(seed)          # seed from SessionCredentials
unit = envelope.seal(
    scope={"host": "192.168.1.1", "port": 443, "secret": "..."},
    ttl_seconds=300,
    recipient="OPERATIONAL",
    need_to_know=["host", "port"],        # fields executor may see
    forbidden=["secret"],                 # fields always redacted
)
view = unit.get_scoped_view()             # {"host": ..., "port": ...}
# "secret" is absent from view — ForbiddenFieldAccessError if accessed directly
```

- Task IDs are **opaque** — no sequential patterns, no inferrable metadata.
- `need_to_know` and `forbidden` may not overlap (`TaskingSchemaError`).
- `unit.is_expired` → True after `ttl_seconds` elapses.

---

## Intelligence & Artifact Store

`IntelligenceStore` and `IntelligenceArtifact` in `intelligence.py`.

### Artifact Schema

```python
art = IntelligenceArtifact(
    classification_level=ClassificationLevel.OPERATIONAL,  # AMBIENT/SENSITIVE/OPERATIONAL/CRITICAL
    artifact_class=ArtifactClass.REAL,                     # REAL or COVER
    expires_at=time.time() + 3600,                         # required — zero rejected
    review_action=ReviewAction.DESTROY,
    source_hash=IntelligenceArtifact.hash_source("source-id"),  # required for REAL
    vetted=True,
)
```

### D06 Filter Rules

| Condition | Result |
| --- | --- |
| REAL artifact, `vetted=False` | REJECTED (`REAL_ARTIFACT_NOT_VETTED`) |
| Artifact expired (`expires_at < now`) | REJECTED |
| Artifact classification > recipient authorization | REJECTED |
| COVER artifact missing anchor | SCHEMA ERROR at creation |
| Artifact in `destroyed_ids` | REJECTED |

### Classification Levels (ascending)

`AMBIENT < SENSITIVE < OPERATIONAL < CRITICAL`

Recipient authorization must **meet or exceed** artifact classification.

---

## Recovery Protocol

Defined in `recovery.py`. Governs the `HALTED → INITIALIZING` transition.

### Signal Format

```text
HMAC-SHA256( pre_shared_key, session_id || halt_ts_bytes || nonce )
```

### Four-Case Validation (all must pass)

| Case | Check | Audit Class on Fail |
| --- | --- | --- |
| 1 | HMAC digest matches (constant-time comparison) | `CRITICAL` |
| 2 | Nonce not in `NonceRegistry` (anti-replay) | `CRITICAL` |
| 3 | Signal age < `signal_ttl` (default configurable) | `ANOMALY` |
| 4 | `channel_verified == True` (caller asserts channel) | `CRITICAL` |

**Blackhole policy:** Every invalid case returns `False` — no acknowledgment,
no rejection message, no reason transmitted to signal sender. Caller FSM
receives a boolean only.

### Generating a Signal (authorized controller only)

```python
from red_agent import generate_recovery_signal
signal = generate_recovery_signal(
    pre_shared_key=PSK,
    session_id=agent.session_id,
    halt_timestamp=halt_ts,
)
signal.channel_verified = True
```

---

## Teardown Sequence

`TeardownSequence` in `teardown.py`. Steps execute in **strict order**.
`FaultClass.CRITICAL` during teardown → `TEARDOWN HALTED`, best-effort continuation.

| Step | ID | Action |
| --- | --- | --- |
| 01 | `STEP_01_HALT_ACCEPT` | Stop accepting new tasks |
| 02 | `STEP_02_INFLIGHT` | Allow in-flight task to complete (or abort if expired) |
| 03 | `STEP_03_INTEL_PURGE` | Purge all classified artifacts from `IntelligenceStore` |
| 04 | `STEP_04_SEED_PURGE` | Zero session seed (`SecureBuffer.zero_and_free`) + purge nonce registry. **WIPE_FAILED → TEARDOWN HALTED** |
| 05 | `STEP_05_SEAL_AUDIT` | Seal `AuditStore` — append-only hash chain finalized |
| 06 | `STEP_06_TIMING_SHUTDOWN` | Shutdown `StochasticTimingLayer` + `RecoverySignalVerifier` (zeros PSK) |
| 07 | `STEP_07_GATE_CLOSE` | Close `OutputAuthorizationGate` — **no output permitted after this point, ever** |

An agent that **skips Step 04 leaves a recoverable seed**.
An agent that **emits after Step 07** has violated the gate at its most attributable moment.

### Ungraceful Termination

`UngracefulTerminationHandler` registers `SIGTERM` and `SIGHUP` handlers.
On signal receipt: close gate → best-effort seed purge → write `CRITICAL` audit entry.
**SIGKILL cannot be caught** — `mlock` OS zeroing is the only protection in that case.
On restart after ungraceful termination, **Step 06B fires unconditionally**.

---

## Entropy & Secure Memory

### SessionCredentials (`entropy.py`)

- Generates a 32-byte seed via `os.urandom` + system entropy sources.
- `score_entropy()` must return ≥ 128 bits — `EntropyInsufficientError` otherwise.
- `session_id` is derived from seed but **not directly derivable from it** — separate hash path.
- `purge()` zeros the seed buffer; subsequent `get_seed_bytes()` raises `RuntimeError`.

### StochasticTimingLayer (`entropy.py`)

- Seeded from `SessionCredentials`.
- `sample_delay()` returns a randomized float delay — used by gate between evaluation and emission.
- `is_active` → False after `shutdown()`.
- Deterministic fallback is **prohibited** (D02 violation).

### SecureBuffer (`securememory.py`)

- Fixed-size buffer backed by a `bytearray`.
- `zero_and_free()` overwrites with zeros and sets a freed flag.
- Read after free raises `RuntimeError`.
- Size mismatch on write raises `ValueError`.

---

## Audit System

### AuditStore (`audit.py`)

- Append-only, hash-chained log. Each entry includes a SHA-256 chain link over the previous entry.
- `verify_chain()` → `(valid: bool, broken_at: Optional[int])`.
- `seal(session_end_timestamp)` appends a final entry and marks the store immutable.
- Session ID is embedded at creation — never changes.

### AuditWriteFailureProtocol

Wraps `AuditStore`. Write failures are tracked internally. On threshold breach,
escalates to a degraded audit path rather than silently dropping entries.

### ProbeDetector

Tracks accumulation of anomalous events (expired units, invalid recovery signals).
On `PROBE_DETECTION_THRESHOLD` breach, upgrades the fault classification from
`ANOMALY` to `DEGRADED` — triggers FSM state escalation.

---

## Installation & Quickstart

### Requirements

```text
Python >= 3.10
No external runtime dependencies (stdlib only)
```

### Install

```bash
pip install red-agent
# or from source:
git clone https://github.com/[org]/red-agent
cd red-agent
pip install -e .
```

### Minimal Usage

```python
import secrets
from red_agent import RedAgent, RedAgentConfig, ClassificationLevel

PSK = secrets.token_bytes(32)

config = RedAgentConfig(pre_shared_key=PSK)
agent = RedAgent(config)
agent.start()  # runs 7-step init, blocks until IDLE

recipient = agent.create_recipient("node-01", ClassificationLevel.OPERATIONAL)

result = agent.execute_task(
    scope={"host": "192.168.1.1", "port": 443},
    executor=lambda scope: f"Port {scope['port']} open on {scope['host']}",
    recipient=recipient,
    need_to_know=["host", "port"],
)

print(result.output)   # None if suppressed, value if authorized
print(result.suppressed)  # True/False

agent.shutdown()
```

### Recovery from HALTED

```python
from red_agent import generate_recovery_signal

signal = generate_recovery_signal(PSK, agent.session_id, halt_timestamp)
signal.channel_verified = True

new_agent = RedAgent(RedAgentConfig(pre_shared_key=PSK, is_recovery=True))
new_agent.start_with_recovery_signal(signal)
```

---

## Running Tests

```bash
# Full compliance matrix
python -m pytest tests/test_red_agent.py -v

# Specific suites
python -m pytest tests/test_red_agent.py -v -k "TestDirectiveFilters"
python -m pytest tests/test_red_agent.py -v -k "TestStateMachine"
python -m pytest tests/test_red_agent.py -v -k "TestRecoverySignalAuth"
python -m pytest tests/test_red_agent.py -v -k "TestRedAgentIntegration"
```

Test suites cover:

- `TestSecureBuffer` — write, read, zero, free, idempotent free
- `TestEntropy` — ≥128-bit scoring, distinct session IDs, purge behavior
- `TestAuditStore` — chain integrity, sealing, probe escalation
- `TestIntelligenceLifecycle` — schema validation, D06 filter, classification gating
- `TestSealedEnvelopTasking` — scoped views, expiry, forbidden overlap
- `TestRecoverySignalAuth` — all four invalid cases + valid acceptance
- `TestDirectiveFilters` — D03/D04 pattern matching, D05 fault-active suppression
- `TestStateMachine` — all valid transitions, invalid transition rejection
- `TestRedAgentIntegration` — full start→execute→shutdown lifecycle

---

## Public API

```python
# red_agent/__init__.py  v3.0.0

from .agent import RedAgent, RedAgentConfig, TaskExecutorFn
from .constants import (
    AgentState,           # INITIALIZING, IDLE, EXECUTING, DEGRADED, HALTED, TEARDOWN
    ArtifactClass,        # REAL, COVER
    ClassificationLevel,  # AMBIENT, SENSITIVE, OPERATIONAL, CRITICAL
    FaultClass,           # ANOMALY, DEGRADED, CRITICAL
    GateSuppressionReason,
    OutputDecision,       # AUTHORIZED, SUPPRESSED
    ReviewAction,         # DESTROY, RETAIN, REVIEW
)
from .intelligence import IntelligenceArtifact, RecipientClassification, ThreatModelEntry
from .tasking import TaskingUnit, TaskResult
from .recovery import RecoverySignal, generate_recovery_signal
```

---

## License

MIT — Research and operational tooling use.
Governance directives are architectural constraints, not legal advice.
