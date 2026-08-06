"""obsvr-verify: offline evidence verification for auditors, in Python.

    obsvr-verify <bundle.json> [--api-key <key>] [--device-pubkey <key>]...
                 [--allow-gaps] [--json]

Behavioral twin of the TypeScript CLI (sdk-typescript/src/cli-verify.ts): same input
shapes, same two tiers, same exit codes, same verdicts. It exists so a
Python-only compliance team can check its own evidence without adopting a Node
toolchain - the verification claim is language-unqualified, and until now the
tooling was not. The GitHub Action keeps using the npm CLI.

Input: an exported obsvr evidence file - an incident evidence bundle
(obsvr-incident-evidence-v1, ``trace.steps``), a trace evidence bundle, or a
plain JSON array of audit events. Two verification tiers:

 - WITHOUT --api-key: structural chain verification. Events are grouped per
   sdk_session_id (a chain is per session) and each chain is checked for
   prev_sig linkage, seq_no continuity from 1, timestamp monotonicity and a
   constant chain_format, from the events alone; every event after the first
   must CARRY a prev_sig, or an unsigned insertion with a plausible seq_no and
   a well-formed sdk_sig would pass this tier by simply omitting the field.
   It reads NO content, decision or attribution field and recomputes no
   signature, so it detects reordering, and insertion into or deletion from the
   MIDDLE of a chain — and it does NOT detect an edit to any field (which needs
   no key at all), an event appended after the last, or the last one removed.
   Every claim about what an event SAYS comes from the --api-key tier.
 - WITH --api-key: HMAC re-verification (verify_chain) - every signature is
   recomputed over the content + chain preimage, so any content tamper or
   reorder breaks. Under chain format 3, the current signing format, the
   preimage also covers the decision/attribution fields (action_taken,
   action_reason, reason_code, rule_id, policy_version, model, provider,
   user_id); chains signed under formats 1 and 2 bind content and order only.
   The client signature does NOT cover tenant_id, token counts, metadata,
   operation, or content_provenance; those are sealed by the server
   countersignature at ingest, not by this offline check.
 - WITH --device-pubkey (repeatable; base64/hex raw key or a PEM path): the
   optional non-repudiation tier. Every event must carry a device_sig by a
   pinned key that verifies over the same payload the HMAC covers; an event
   signed by an unpinned key is reported as foreign, never trusted on first
   use, and a missing seal is a break - pinning asserts the expectation, so
   a stripped seal cannot read as clean. Works WITH --api-key (both seals
   checked) or ALONE (--device-pubkey without --api-key verifies content,
   order and the decision fields under the public key, no secret shared).
   The key id on an event is a selection hint only; trust comes from what
   you pinned. This CLI never generates or persists key material.

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

A broken keyed run reports EVERY break the verifier found, one line per break
(verify_chain re-anchors and keeps scanning), so an auditor triaging a
tampered export gets the full damage report from one run. ``--json`` replaces
the prose with one machine-readable document on stdout - same verdicts, same
exit codes, per-session break lists included. Usage and file-read errors
(exit 2) stay on stderr in either mode.

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


#: What the keyless tier examines, and what it does not. Emitted verbatim in
#: --json as `checked` / `notChecked`, so a machine consumer of `valid: true`
#: can see the scope of the claim instead of inferring one. Kept identical to
#: the TS CLI's STRUCTURAL_CHECKED / STRUCTURAL_NOT_CHECKED.
STRUCTURAL_CHECKED = (
    "sdk_sig_present",
    "seq_no_continuity",
    "chain_starts_at_one",
    "prev_sig_linkage",
    "timestamp_monotonicity",
    "chain_format_consistency",
)
STRUCTURAL_NOT_CHECKED = (
    "sdk_sig_recomputation",
    "prompt",
    "response",
    "action_taken",
    "action_reason",
    "reason_code",
    "rule_id",
    "policy_version",
    "model",
    "provider",
    "user_id",
    "append_after_last_event",
    "removal_of_last_event",
)


def verify_structure(events: Sequence[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    """Keyless structural verification: linkage, continuity, monotonicity.

    Same checks in the same order as the TS CLI's verifyStructure, so the two
    reach the same verdict on the same file.

    GROUPED PER SESSION, LIKE THE KEYED TIER. A chain is per ``sdk_session_id``,
    and this used to sort every event in the bundle by ``seq_no`` and then
    ``continue`` past any adjacent pair whose sessions differed. On a bundle
    with more than one session the global sort INTERLEAVES them — session A's
    seq 1, session B's seq 1, A's seq 2, B's seq 2 — so every adjacent pair was
    cross-session and not one linkage, continuity or monotonicity check ever
    ran. Measured on two three-event sessions with every ``prev_sig`` wrong and
    every timestamp regressing: the tier returned valid and the CLI printed
    "✓ STRUCTURAL verification passed". Multi-session bundles are the normal
    shape for a fleet, so the tier was closest to a no-op exactly where it was
    most likely to be used. The keyed path has always grouped first.
    """
    sessions: Dict[str, List[Dict[str, Any]]] = {}
    for event in events:
        sessions.setdefault(str(event.get("sdk_session_id", "unknown")), []).append(
            event
        )
    for sid, session_events in sessions.items():
        ok, reason = _verify_session_structure(session_events)
        if not ok:
            return False, (
                f"session {sid}: {reason}" if len(sessions) > 1 else reason
            )
    return True, None


def _verify_session_structure(
    events: Sequence[Dict[str, Any]],
) -> Tuple[bool, Optional[str]]:
    """The structural checks for ONE chain."""
    ordered = sorted(events, key=_seq)
    for i, event in enumerate(ordered):
        sig = event.get("sdk_sig")
        if not isinstance(sig, str) or len(sig) != 64:
            return False, "missing or malformed sdk_sig"
        if i == 0:
            # A chain starts at 1. Without this a bundle whose leading events
            # were deleted verifies clean, because every surviving pair still
            # links: the loss is only visible at the head. The keyed tier has
            # always checked the initial seq_no; this tier can check it too,
            # from the events alone.
            first = _seq(event)
            if first != 1:
                return (
                    False,
                    f"chain does not start at seq_no 1 (starts at {first}): "
                    "events before it are missing from this bundle",
                )
            continue
        prev = ordered[i - 1]
        if _seq(event) != _seq(prev) + 1:
            return False, f"seq_no gap: {prev.get('seq_no')} -> {event.get('seq_no')}"
        prev_sig = event.get("prev_sig")
        if prev_sig is None:
            # Linkage is required, not optional: an event that OMITS prev_sig
            # is not exempt from the check, or an unsigned insertion would
            # pass this tier by leaving the field out.
            return (
                False,
                "missing prev_sig at seq "
                f"{event.get('seq_no')}: every event after the first must "
                "link to its predecessor",
            )
        if prev_sig != prev.get("sdk_sig"):
            return (
                False,
                "prev_sig does not link to the prior event's sdk_sig at seq "
                f"{event.get('seq_no')}",
            )
        if _ts(event) < _ts(prev):
            return False, f"timestamp regression at seq {event.get('seq_no')}"
        if event.get("chain_format") != prev.get("chain_format"):
            # One chain is signed under one format. A format that changes
            # mid-chain is either a forgery or two chains spliced together, and
            # the keyed tier already refuses it.
            return (
                False,
                "chain_format changes mid-chain at seq "
                f"{event.get('seq_no')}: {prev.get('chain_format')} -> "
                f"{event.get('chain_format')}",
            )
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


def _parse_args(
    argv: Sequence[str],
) -> Tuple[str, Optional[str], List[str], bool, bool]:
    """Mirror the TS CLI's argument handling, including its tolerance: flags in
    any order, and a value that follows --api-key or --device-pubkey is never
    mistaken for the file."""
    args = list(argv)
    api_key: Optional[str] = None
    value_indices = set()
    key_index = args.index("--api-key") if "--api-key" in args else -1
    if key_index >= 0:
        # An explicitly passed --api-key must carry a usable key. Absent, the
        # CLI verifies structure only and says so; EMPTY, it used to do the
        # same thing silently and exit 0 - and `--api-key "$SECRET"` with the
        # secret unset is the ordinary CI shape that produces exactly that. A
        # tampered chain then passed. Refusing here keeps the distinction the
        # caller actually made: no flag means "structure only", and a flag
        # whose value did not arrive means the run cannot do what was asked.
        if key_index + 1 >= len(args) or args[key_index + 1] == "":
            print(
                "obsvr-verify: --api-key was passed with no key. Pass a key, or omit\n"
                "  the flag entirely for structural verification. An empty value is\n"
                "  refused rather than downgraded: in CI an unset secret expands to\n"
                "  one, and the downgrade is silent.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        api_key = args[key_index + 1]
        value_indices.add(key_index + 1)
    device_keys: List[str] = []
    for i, arg in enumerate(args):
        if arg == "--device-pubkey" and i + 1 < len(args):
            device_keys.append(args[i + 1])
            value_indices.add(i + 1)
    path: Optional[str] = None
    for i, arg in enumerate(args):
        if arg.startswith("--"):
            continue
        if i in value_indices:
            continue
        path = arg
        break
    if not path:
        print(
            "Usage: obsvr-verify <bundle.json> [--api-key <key>] "
            "[--device-pubkey <key>]... [--allow-gaps] [--json]",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return path, api_key, device_keys, "--allow-gaps" in args, "--json" in args


def _json_line(doc: Dict[str, Any]) -> str:
    """The --json document, serialized identically in both languages: compact
    separators and raw (unescaped) non-ASCII, which is what JSON.stringify
    emits - the parity harness compares the two byte for byte."""
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"))


def main(argv: Optional[Sequence[str]] = None) -> int:
    path, api_key, device_key_args, allow_gaps, as_json = _parse_args(
        sys.argv[1:] if argv is None else argv
    )

    device_keys: List[bytes] = []
    pinned_ids: List[str] = []
    if device_key_args:
        from .device_identity import (
            DeviceIdentityError,
            derive_device_key_id,
            load_device_public_key,
        )

        try:
            for value in device_key_args:
                raw = load_device_public_key(value)
                device_keys.append(raw)
                pinned_ids.append(derive_device_key_id(raw))
        except DeviceIdentityError as err:
            _fail(f"--device-pubkey: {err}", 2)
        from .policy_verify import _resolve_backend

        if _resolve_backend() is None:
            _fail(
                "--device-pubkey needs an Ed25519 backend; install one: "
                'pip install "obsvr-sdk[crypto]"',
                2,
            )

    try:
        with open(path, encoding="utf-8") as handle:
            parsed = json.load(handle)
    except Exception as err:
        _fail(f"Cannot read {path}: {err}", 2)

    events = _extract_events(parsed)
    if not as_json:
        print(f"Loaded {len(events)} event(s) from {path}")

    if api_key or device_keys:
        # Group per session: the HMAC chain is per sdk_session_id.
        sessions: Dict[str, List[Dict[str, Any]]] = {}
        for event in events:
            sid = str(event.get("sdk_session_id", "unknown"))
            sessions.setdefault(sid, []).append(event)
        reports = []
        any_invalid = False
        verified = 0
        gap_markers = 0
        events_lost = 0
        device_signed = 0
        for sid, session_events in sessions.items():
            result = verify_chain(
                sorted(session_events, key=_seq),
                api_key or None,
                device_public_keys=device_keys or None,
            )
            reports.append((sid, result))
            any_invalid = any_invalid or not result.valid
            verified += result.events_verified
            gap_markers += result.gap_markers
            events_lost += result.events_declared_lost
            device_signed += result.device_signed_events
        code = (
            1
            if any_invalid
            else (0 if gap_markers == 0 or allow_gaps else EXIT_INCOMPLETE)
        )
        mode = "content+chain" if api_key else "content+device"
        if as_json:
            doc: Dict[str, Any] = {
                "mode": mode,
                "valid": not any_invalid,
                "sessions": [
                    dict({"sessionId": sid}, **result.to_dict())
                    for sid, result in reports
                ],
                "eventsVerified": verified,
                "gapMarkers": gap_markers,
                "eventsDeclaredLost": events_lost,
                "deviceSignedEvents": device_signed,
                "deviceChecked": bool(device_keys),
                "allowGaps": allow_gaps,
                "exitCode": code,
            }
            print(_json_line(doc))
            return code
        if any_invalid:
            # Every break in every session, one line each - the full damage
            # report from one run, not one index per run.
            for sid, result in reports:
                for brk in result.breaks:
                    print(
                        f"✗ session {sid}: {brk['reason']} "
                        f"(event index {brk['index']})",
                        file=sys.stderr,
                    )
            return 1
        if api_key:
            print(
                f"✓ CONTENT + CHAIN verification passed: {verified} signature(s) "
                f"recomputed and chain-linked across {len(sessions)} session(s).\n"
                "  This attests prompt/response CONTENT integrity, event ORDER, and — under\n"
                "  chain format 3, the current signing format — the decision/attribution\n"
                "  fields: action_taken, action_reason, reason_code, rule_id, policy_version,\n"
                "  model, provider, user_id. Chains signed under formats 1 and 2 bind content\n"
                "  and order only. The client signature does NOT cover tenant_id, token\n"
                "  counts, metadata, operation, or content_provenance — those are sealed by\n"
                "  the server countersignature at ingest."
            )
        else:
            print(
                f"✓ CONTENT + DEVICE verification passed: {verified} device "
                f"signature(s) recomputed and chain-linked across {len(sessions)} session(s).\n"
                "  Each event's Ed25519 device seal was verified under the pinned public\n"
                "  key(s) over the same payload the HMAC covers — content, order, and (under\n"
                "  chain format 3) the decision/attribution fields — so this run needed no\n"
                "  API key and shared no secret. It does NOT check the HMAC chain: run with\n"
                "  --api-key as well to attest both seals."
            )
        if device_keys:
            print(
                f"✓ device signatures verified: {verified} event(s) under "
                f"pinned key(s) {', '.join(sorted(pinned_ids))}"
            )
        elif device_signed > 0:
            print(
                f"note: {device_signed} event(s) carry device signatures not "
                "verified in this run (no --device-pubkey supplied)"
            )
        return _report_gaps(gap_markers, events_lost, allow_gaps)
    else:
        valid, reason = verify_structure(events)
        # Keyless, the marker's count is read but not authenticated - same tier
        # as every other field at this level, and stated as such above.
        gap_markers = 0
        events_lost = 0
        if valid:
            for event in events:
                # Same discriminator as verify_chain: a marker is an event the
                # SDK emitted as one, not any event containing the string.
                gap = read_audit_gap_claim(event)
                if gap:
                    gap_markers += 1
                    events_lost += gap["dropped"]
        if as_json:
            code = (
                1
                if not valid
                else (0 if gap_markers == 0 or allow_gaps else EXIT_INCOMPLETE)
            )
            doc = {"mode": "structural", "valid": valid, "events": len(events)}
            if reason is not None:
                doc["reason"] = reason
            # What this verdict COVERS, in the machine-readable output, because
            # a script reads `valid` and cannot see the tier's footnote. A CI
            # job gating on `valid: true` from a keyless run is gating on
            # ordering alone, and nothing in the document used to say so.
            doc["checked"] = list(STRUCTURAL_CHECKED)
            doc["notChecked"] = list(STRUCTURAL_NOT_CHECKED)
            doc["gapMarkers"] = gap_markers
            doc["eventsDeclaredLost"] = events_lost
            doc["allowGaps"] = allow_gaps
            doc["exitCode"] = code
            print(_json_line(doc))
            return code
        if not valid:
            _fail(reason or "chain broken")
        print(
            "✓ STRUCTURAL verification passed: linkage, continuity, and "
            f"monotonicity hold for {len(events)} event(s).\n"
            "  This tier reads NO content, decision or attribution field, so it does not\n"
            "  check them. An edit to action_taken, reason_code, rule_id, prompt, response,\n"
            "  model, provider or user_id passes here, and needs no signing key: only the\n"
            "  ordering fields are examined. It also cannot detect an event appended after\n"
            "  the last one, or the last one removed.\n"
            "  Pass --api-key for full HMAC re-verification - that is the only tier that\n"
            "  says anything about what an event CONTAINS - and check the daily Merkle root\n"
            "  (git anchor / RFC 3161 token) for the no-insert/no-delete guarantee across days."
        )
        device_signed = sum(
            1 for event in events if isinstance(event.get("device_sig"), str)
        )
        if device_signed > 0:
            print(
                f"note: {device_signed} event(s) carry device signatures not "
                "verified in this run (no --device-pubkey supplied)"
            )
        return _report_gaps(gap_markers, events_lost, allow_gaps)


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    raise SystemExit(main())
