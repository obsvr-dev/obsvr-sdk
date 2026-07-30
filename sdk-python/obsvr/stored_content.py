"""The stored-content net for content the decision scan never reached.

Twin of ``sdk-typescript/src/policy/stored-content.ts`` — read that module's
header for the full reasoning; the short version is that SCAN SCOPE and
STORAGE SCOPE are different questions and this SDK answers them differently.

A policy decision is made on the last user turn only, deliberately, so a value
quoted three turns ago does not block today's call. But the event stores the
WHOLE concatenated prompt — system instructions, earlier user turns, assistant
replies, tool results — so every byte the decision pipeline never looked at
landed in the audit record verbatim.

The canary half of the net already lives in ``events.build_audit_event`` on
this side and always has; it is the PII half that was missing, and it was
missing in both languages. This module is that half.

What it deliberately does NOT do:

* It does not change the verdict. Widening enforcement to every role is a
  separate, breaking decision and is not smuggled in here.
* It does not fire for a ``detect_only``-only policy. That mode exists so an
  operator can baseline what actually flows before enforcing, and scrubbing
  the record would destroy the only thing it produces.
* It does not run when the stored text IS the scanned text. Single-turn calls
  — the common case — pay nothing.
* It records that it fired, and records that the OUTBOUND request was not
  modified. A redacted stored prompt beside ``action_taken: "allowed"`` would
  otherwise read as prevention, which is false.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


def redact_unscanned_for_storage(
    stored_text: str,
    scanned_text: str,
    config: Any,
) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Redact the stored prompt when it carries enforced PII the decision never saw.

    ``stored_text`` is what the event would otherwise persist (the full
    multi-role prompt); ``scanned_text`` is what the decision pipeline actually
    evaluated. Equal strings mean the decision already covered everything, and
    this is a no-op.

    Returns ``(stored_prompt, telemetry_or_None)``.
    """
    # Gated exactly the way the decision scan is gated, so "configured" means
    # the same thing in both places. An empty dict IS a configuration — it
    # selects the built-in severities, under which ``ssn`` and the other
    # credential types already resolve to block.
    pii_policy = getattr(config, "pii_policy", None)
    if pii_policy is None:
        return stored_text, None
    if not stored_text or stored_text == scanned_text:
        return stored_text, None

    from .deobfuscate import redact_for_storage, run_configured_pii_scan
    from .policy import (
        UNSCANNED_PLACEHOLDER,
        record_detector_failure,
        resolve_pii_policy,
    )

    # ONE span around every step that can raise, not just the scan. This runs
    # on the emit path of an already-decided call, so an exception escaping
    # here would reach the host from a function whose entire job is to build a
    # stored field — the failure mode the detector-guard contract exists to
    # forbid. The resolution is the stored-copy one and it fails CLOSED:
    # withhold the text rather than persist content nothing vetted.
    try:
        scan = run_configured_pii_scan(
            stored_text, getattr(config, "deobfuscation", None)
        )
        detected: List[str] = list(scan.get("detected_types") or [])  # type: ignore[union-attr]
        via = scan.get("via")  # type: ignore[union-attr]

        # Only the types the operator asked to be acted on, resolved by the
        # SDK's OWN resolver rather than by a second reading of the policy
        # dict. The order is rules[type] -> default -> built-in severity ->
        # detect_only, and getting it wrong here would either miss the common
        # configuration (``pii_policy={}``, which relies entirely on the
        # built-in severities) or scrub a detect_only record an operator is
        # deliberately baselining.
        resolved = resolve_pii_policy(detected, pii_policy)
        actionable = sorted(
            list(resolved.get("blocked_types") or [])
            + list(resolved.get("redacted_types") or [])
        )
        if not actionable:
            return stored_text, None

        telemetry: Dict[str, Any] = {
            # The stored copy was scrubbed; the request was not. Saying only
            # the first half would let a reader infer an enforcement that never
            # happened.
            "stored_redaction_scope": "unscanned_roles",
            "stored_redaction_types": actionable,
            "stored_redaction_outbound_unmodified": True,
        }
        if via is not None:
            telemetry["stored_redaction_via"] = via
        return redact_for_storage(stored_text, via), telemetry
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all
        record_detector_failure("builtin_pii_scan", exc, config)
        return UNSCANNED_PLACEHOLDER, {
            "stored_redaction_scan_failed": True,
            "stored_redaction_scope": "unscanned_roles",
        }
