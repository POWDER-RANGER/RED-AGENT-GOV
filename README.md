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
git clone https://github.com/POWDER-RANGER/red-agent
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

Copyright (c) 2026 Curtis Farrar  
All rights reserved.

This repository and its contents are proprietary and confidential.
Unauthorized copying, modification, distribution, or use of this code,
via any medium, is strictly prohibited without explicit written permission.
# red-agent
Governance-enforced Python agent engine for adversarial environments. Six-directive output gate, deterministic FSM, hash-chained audit, and cryptographic teardown. Compliance is architectural.
