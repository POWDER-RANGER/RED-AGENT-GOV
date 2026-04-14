#!/usr/bin/env python3
"""
RED AGENT — Entry point.
Usage:
  python main.py --run-demo
  python main.py --psk <32-byte-hex> --run-demo
  python main.py --psk <hex> --send-recovery --halt-ts <float> --nonce <hex> --tag <hex>
"""
import argparse, json, secrets, sys, time
sys.path.insert(0, ".")

from config.settings import AgentConfig
from core.agent import RedAgent, RedAgentInitError
from core.recovery import RecoverySignal
from core.tasking import RecipientClassification, TaskingUnit


# ── demo work function ────────────────────────────────────────────────────────

def demo_work(scope: dict) -> dict:
    """Minimal work stub: returns scoped result without leaking internal state."""
    return {"outcome": "task_processed", "scope_keys": list(scope.keys())}


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="RED AGENT — Deterministic Behavioral Security Engine"
    )
    p.add_argument("--psk",              type=str, default=None,
                   help="Pre-shared key (hex, 32 bytes) for recovery signals")
    p.add_argument("--audit-path",       type=str, default="red_agent_audit.jsonl")
    p.add_argument("--timing-min",       type=float, default=50.0)
    p.add_argument("--timing-max",       type=float, default=500.0)
    p.add_argument("--distribution",     type=str, default="lognormal",
                   choices=["lognormal", "uniform", "exponential"])
    p.add_argument("--deception",        action="store_true",
                   help="Activate optional deception layer (Section 4.5)")

    sub = p.add_subparsers(dest="command")

    sub.add_parser("run-demo",
        help="Initialize agent, submit one demo task, then teardown cleanly.")

    rec = sub.add_parser("send-recovery",
        help="Send a recovery signal to a HALTED agent instance.")
    rec.add_argument("--halt-ts",  type=float, required=True)
    rec.add_argument("--nonce",    type=str,   required=True, help="hex nonce")
    rec.add_argument("--tag",      type=str,   required=True, help="hex HMAC tag")

    sub.add_parser("gen-psk",
        help="Generate a fresh 32-byte PSK and print as hex.")

    return p


def cmd_run_demo(config: AgentConfig) -> None:
    print("[*] Initializing RED Agent...")
    agent = RedAgent(config)
    try:
        agent.initialize()
    except RedAgentInitError as exc:
        print(f"[!] Initialization failed: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Agent state: {agent.state.value}")

    # Build a sealed-envelope tasking unit
    from utils.entropy import generate_seed
    session_seed = generate_seed()
    recipient    = RecipientClassification(classification_level="OPERATIONAL")
    unit = TaskingUnit.create(
        scope={"target": "demo_endpoint", "depth": 1},
        ttl_seconds=60.0,
        recipient=recipient,
        need_to_know=["target", "depth"],
        forbidden=["internal_plan", "full_context"],
        session_seed=session_seed,
    )

    print("[*] Submitting task...")
    result = agent.submit_task(unit, demo_work, recipient)
    if result is not None:
        print(f"[+] Output emitted ({len(result)} bytes)")
    else:
        print("[~] Output suppressed by gate (expected in strict mode).")

    print(f"[*] Agent state: {agent.state.value}")
    print("[*] Executing teardown...")
    agent.teardown()
    print(f"[+] Teardown complete. Final state: {agent.state.value}")


def cmd_send_recovery(config: AgentConfig, args: argparse.Namespace) -> None:
    if not config.recovery_psk:
        print("[!] --psk required for recovery signal.", file=sys.stderr)
        sys.exit(1)

    agent = RedAgent(config)
    try:
        agent.initialize()
    except RedAgentInitError:
        pass   # agent may already be halted

    sig = RecoverySignal(
        session_id="",        # will be filled by validator
        halt_timestamp=args.halt_ts,
        nonce=bytes.fromhex(args.nonce),
        tag=bytes.fromhex(args.tag),
    )
    # internal channel token is session-scoped; in production this would be
    # passed via a secure out-of-band channel — here we demonstrate flow only
    print("[!] Recovery signal submission requires internal channel token.")
    print("    In production: obtain token from agent provisioning record.")


def cmd_gen_psk() -> None:
    psk = secrets.token_bytes(32)
    print(psk.hex())


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    config = AgentConfig(
        recovery_psk_hex=args.psk,
        audit_store_path=args.audit_path,
        timing_min_delay_ms=args.timing_min,
        timing_max_delay_ms=args.timing_max,
        timing_distribution=args.distribution,
        deception_layer_active=args.deception,
    )

    if args.command == "run-demo":
        cmd_run_demo(config)
    elif args.command == "send-recovery":
        cmd_send_recovery(config, args)
    elif args.command == "gen-psk":
        cmd_gen_psk()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
