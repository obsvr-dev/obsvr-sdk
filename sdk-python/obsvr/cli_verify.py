"""obsvr-verify: offline evidence verification for auditors, in Python.

    obsvr-verify <bundle.json> [--api-key <key>]

Behavioral twin of the TypeScript CLI (sdk/src/cli-verify.ts): same input
shapes, same two tiers, same exit codes, same verdicts. It exists so a
Python-only compliance team can check its own evidence without adopting a Node
toolchain - the verification claim is language-unqualified, and until now the
tooling was not. The GitHub Action keeps using the npm CLI.

Input: an exported obsvr evidence file - an incident evidence bundle
(obsvr-incident-evidence-v1, ``trace.steps``), a trace evidence bundle, or a
plain JSON array of audit events. Two verification tiers:

 - WITHOUT --api-key: structural chain verification. prev_sig linkage, seq_no
   continuity, session consistency, and timestamp monotonicity are checked from
   the events alone. Detects reordering, insertion, and deletion; cannot detect
   a re-signed forgery (that needs the key).
 - WITH --api-key: HMAC re-verification (verify_chain) - every signature is
   recomputed over the content + chain preimage, so any content tamper or
   reorder breaks. The client signature does NOT cover the decision/attribution
   fields (verdict, rule, tenant); those are sealed by the server
   countersignature at ingest, not by this offline check.

Exit code 0 = verified at the requested tier; 1 = broken; 2 = usage error.
Dependency-free and offline: an auditor must be able to verify obsvr's evidence
without trusting obsvr's servers or UI.
"""

import json
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .verify_chain import verify_chain

__all__ = ["main"]


def _fail(message: str, code: int = 1) -> "None":
    print(f"✗ {message}", file=sys.stderr)
    raise SystemExit(code)


def _extract_events(parsed: Any) -> List[Dict[str, Any]]:
    """The accepted bundle shapes, checked in the TS CLI's order."""
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        trace = parsed.get("trace")
        if isinstance(trace, dict) and isinstance(trace.get("steps"), list):
            return trace["steps"]
        if isinstance(parsed.get("steps"), list):
            return parsed["steps"]
        if isinstance(parsed.get("events"), list):
            return parsed["events"]
    _fail(
        "Unrecognized file shape: expected an event array, or a bundle with "
        "trace.steps / steps / events",
        2,
    )
    raise AssertionError("unreachable")  # pragma: no cover


def _seq(event: Dict[str, Any]) -> int:
    value = event.get("seq_no")
    return value if isinstance(value, int) else 0


def _ts(event: Dict[str, Any]) -> int:
    value = event.get("timestamp_sdk")
    return value if isinstance(value, (int, float)) else 0


def verify_structure(events: Sequence[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Keyless structural verification: linkage, continuity, monotonicity.

    Same checks in the same order as the TS CLI's verifyStructure, so the two
    reach the same verdict on the same file.
    """
    ordered = sorted(events, key=_seq)
    for i, event in enumerate(ordered):
        sig = event.get("sdk_sig")
        if not isinstance(sig, str) or len(sig) != 64:
            return False, "missing or malformed sdk_sig"
        if i == 0:
            continue
        prev = ordered[i - 1]
        if event.get("sdk_session_id") != prev.get("sdk_session_id"):
            continue  # chains are per-session
        if _seq(event) != _seq(prev) + 1:
            return False, f"seq_no gap: {prev.get('seq_no')} -> {event.get('seq_no')}"
        prev_sig = event.get("prev_sig")
        if prev_sig is not None and prev_sig != prev.get("sdk_sig"):
            return (
                False,
                "prev_sig does not link to the prior event's sdk_sig at seq "
                f"{event.get('seq_no')}",
            )
        if _ts(event) < _ts(prev):
            return False, f"timestamp regression at seq {event.get('seq_no')}"
    return True, None


def _parse_args(argv: Sequence[str]) -> Tuple[str, Optional[str]]:
    """Mirror the TS CLI's argument handling, including its tolerance: flags in
    any order, and the value after --api-key is never mistaken for the file."""
    args = list(argv)
    api_key: Optional[str] = None
    key_index = args.index("--api-key") if "--api-key" in args else -1
    if key_index >= 0 and key_index + 1 < len(args):
        api_key = args[key_index + 1]
    path: Optional[str] = None
    for i, arg in enumerate(args):
        if arg.startswith("--"):
            continue
        if key_index >= 0 and i == key_index + 1:
            continue
        path = arg
        break
    if not path:
        print("Usage: obsvr-verify <bundle.json> [--api-key <key>]", file=sys.stderr)
        raise SystemExit(2)
    return path, api_key


def main(argv: Optional[Sequence[str]] = None) -> int:
    path, api_key = _parse_args(sys.argv[1:] if argv is None else argv)

    try:
        with open(path, encoding="utf-8") as handle:
            parsed = json.load(handle)
    except Exception as err:
        _fail(f"Cannot read {path}: {err}", 2)

    events = _extract_events(parsed)
    print(f"Loaded {len(events)} event(s) from {path}")

    if api_key:
        # Group per session: the HMAC chain is per sdk_session_id.
        sessions: Dict[str, List[Dict[str, Any]]] = {}
        for event in events:
            sid = str(event.get("sdk_session_id", "unknown"))
            sessions.setdefault(sid, []).append(event)
        verified = 0
        for sid, session_events in sessions.items():
            result = verify_chain(sorted(session_events, key=_seq), api_key)
            if not result.valid:
                _fail(f"session {sid}: {result.reason} (event index {result.broken_at})")
            verified += result.events_verified
        print(
            f"✓ CONTENT + CHAIN verification passed: {verified} signature(s) "
            f"recomputed and chain-linked across {len(sessions)} session(s).\n"
            "  This attests prompt/response CONTENT integrity and event ORDER. The client\n"
            "  signature does NOT cover the decision/attribution fields (verdict, rule,\n"
            "  tenant) — those are sealed by the server countersignature at ingest."
        )
    else:
        valid, reason = verify_structure(events)
        if not valid:
            _fail(reason or "chain broken")
        print(
            "✓ STRUCTURAL verification passed: linkage, continuity, and "
            f"monotonicity hold for {len(events)} event(s).\n"
            "  Note: without --api-key, signatures were not recomputed - a holder of the\n"
            "  signing key could still have re-signed altered content. Pass --api-key for\n"
            "  full HMAC re-verification, and check the daily Merkle root (git anchor /\n"
            "  RFC 3161 token) for the no-insert/no-delete guarantee across days."
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
