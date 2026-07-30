"""obsvr-verify: offline evidence verification for auditors, in Python.

    obsvr-verify <bundle.json> [--api-key <key>] [--allow-gaps]

Behavioral twin of the TypeScript CLI (sdk-typescript/src/cli-verify.ts): same input
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

Either tier also reports GAP MARKERS: events the SDK signed to record that its
bounded queue dropped events it never got to chain. A chain carrying markers is
still valid - the marker is the SDK telling the truth about a loss - but it is
not complete, and the two must not be reported as the same thing. That
distinction has to survive into the exit code: ``obsvr-verify chain.json &&
deploy`` reads only the status, and a record missing most of its events must not
pass a gate that means "all clear".

Exit codes:
  0  verified at the requested tier, and the chain declares no loss
  1  broken - a signature, link, or continuity check failed
  2  usage error
  3  VALID BUT INCOMPLETE - every check passed and the chain itself declares
     events it dropped. Distinct from 1 because nothing is wrong with the
     evidence; distinct from 0 because it is not all of it.

``--allow-gaps`` maps 3 back to 0. It exists so that strict CAN be the default:
a team whose posture already accepts bounded-queue loss would otherwise pin an
old version or stop checking the exit code at all, and an explicit, greppable
flag in their CI config is a better record of that decision than either. It
suppresses only the STATUS - the declared loss is still printed, so the
disclosure survives the opt-out.

Dependency-free and offline: an auditor must be able to verify obsvr's evidence
without trusting obsvr's servers or UI.
"""

import json
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .audit_gap import read_audit_gap_claim
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


#: Valid, and short by however many events its markers declare.
EXIT_INCOMPLETE = 3


def _report_gaps(markers: int, lost: int, allow_gaps: bool) -> int:
    """Print the chain's own declaration of what is missing, and return the exit
    status it earns.

    Kept identical, word for word, to the TS CLI's reportGaps -
    scripts/check-cli-verify-parity.mjs compares stdout byte for byte, and an
    auditor comparing two runs should not have to wonder whether different
    wording means a different finding.
    """
    if markers == 0:
        return 0
    tail = (
        "  Exiting 0: --allow-gaps accepts declared loss as a pass."
        if allow_gaps
        else f"  Exiting {EXIT_INCOMPLETE} (valid but incomplete). "
        "--allow-gaps accepts it as a pass."
    )
    print(
        f"! {lost} event(s) declared LOST by {markers} gap marker(s) in this chain.\n"
        "  The chain is intact and these markers are signed: the SDK recorded that its\n"
        "  bounded queue dropped these events before they could be chained. What is here\n"
        "  is genuine and in order - it is not all of it.\n" + tail
    )
    return 0 if allow_gaps else EXIT_INCOMPLETE


def _parse_args(argv: Sequence[str]) -> Tuple[str, Optional[str], bool]:
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
        print(
            "Usage: obsvr-verify <bundle.json> [--api-key <key>] [--allow-gaps]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return path, api_key, "--allow-gaps" in args


def main(argv: Optional[Sequence[str]] = None) -> int:
    path, api_key, allow_gaps = _parse_args(sys.argv[1:] if argv is None else argv)

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
        gap_markers = 0
        events_lost = 0
        for sid, session_events in sessions.items():
            result = verify_chain(sorted(session_events, key=_seq), api_key)
            if not result.valid:
                _fail(f"session {sid}: {result.reason} (event index {result.broken_at})")
            verified += result.events_verified
            gap_markers += result.gap_markers
            events_lost += result.events_declared_lost
        print(
            f"✓ CONTENT + CHAIN verification passed: {verified} signature(s) "
            f"recomputed and chain-linked across {len(sessions)} session(s).\n"
            "  This attests prompt/response CONTENT integrity and event ORDER. The client\n"
            "  signature does NOT cover the decision/attribution fields (verdict, rule,\n"
            "  tenant) — those are sealed by the server countersignature at ingest."
        )
        return _report_gaps(gap_markers, events_lost, allow_gaps)
    else:
        valid, reason = verify_structure(events)
        if not valid:
            _fail(reason or "chain broken")
        # Keyless, the marker's count is read but not authenticated - same tier
        # as every other field at this level, and stated as such above.
        gap_markers = 0
        events_lost = 0
        for event in events:
            # Same discriminator as verify_chain: a marker is an event the
            # SDK emitted as one, not any event containing the string.
            gap = read_audit_gap_claim(event)
            if gap:
                gap_markers += 1
                events_lost += gap["dropped"]
        print(
            "✓ STRUCTURAL verification passed: linkage, continuity, and "
            f"monotonicity hold for {len(events)} event(s).\n"
            "  Note: without --api-key, signatures were not recomputed - a holder of the\n"
            "  signing key could still have re-signed altered content. Pass --api-key for\n"
            "  full HMAC re-verification, and check the daily Merkle root (git anchor /\n"
            "  RFC 3161 token) for the no-insert/no-delete guarantee across days."
        )
        return _report_gaps(gap_markers, events_lost, allow_gaps)


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
