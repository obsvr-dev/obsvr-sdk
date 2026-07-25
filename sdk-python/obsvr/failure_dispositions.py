"""Central failure-disposition registry (twin of sdk/src/policy/failure-dispositions.ts).

One question, answered in exactly one place: when a governance layer cannot
render a verdict - because it timed out, threw, or is running degraded - does
the call proceed or does it stop?

Answering that per code path is how enforcement products rot. The same detector
ends up fail-open on one surface and fail-closed on another, a reviewer reading
either one draws the wrong conclusion about the other, and nobody can state the
product's failure posture without reading every branch. So every layer declares
its disposition here, the declarations are pinned by
conformance/fixtures/fail_mode.json, and both SDKs are asserted against that one
file.

This registry DESCRIBES shipped behavior; it does not implement it. Nothing on
the call path reads it. Its jobs are (1) to make the posture reviewable in one
place, (2) to force any new detector to state its disposition before it can
land, and (3) to make a silent change of posture fail a test.

Reading the table honestly matters more than making it look tidy - which is why
``unguarded`` exists as a value. Several in-process detectors have no error
channel at all today: an unexpected exception inside them propagates out to the
host application. That is neither fail-open nor fail-closed, it is the absence
of a decision, and it is recorded as such (verified, not assumed: injecting a
throw into the builtin scanner surfaces the exception at the caller in both
languages). The MCP tool-call path, by contrast, does guard its policy
evaluation and resolves it by the configured fail mode. Same failure class, different answers,
one table that says so.

Vocabulary:
    open            the call proceeds; the failure is logged and counted, and
                    that layer's enforcement is lost for this call
    closed          the call is blocked
    fail_mode       resolved by the configured fail_mode: open by default,
                    closed when the operator opts in
    unguarded       no error channel: an exception propagates to the host
    not_applicable  the state cannot arise for this layer

Qualifiers narrow a value without multiplying it:
    shadow_exempt    closed, unless that unit is observe-only (shadow)
    warn_mode_flags  closed in block mode, flags in warn mode; never silent
"""

from typing import Dict, List, Optional

__all__ = [
    "FAILURE_STATES",
    "DISPOSITIONS",
    "FAILURE_DISPOSITIONS",
    "DECLARED_LAYER_IDS",
    "get_failure_disposition",
    "disposition_for",
    "unguarded_layer_ids",
]

FAILURE_STATES = ("timeout", "error", "degraded")

DISPOSITIONS = ("open", "closed", "fail_mode", "unguarded", "not_applicable")


def _s(disposition: str, qualifier: Optional[str] = None) -> Dict[str, str]:
    return {"disposition": disposition, "qualifier": qualifier} if qualifier else {
        "disposition": disposition
    }


#: The declarations. Ordered by pipeline position, then by tool-surface layers,
#: so the table reads in the order a call meets them. Module paths name the
#: Python owner; the TypeScript twin names its own, and the fixture carries
#: both so neither language's paths become the contract.
FAILURE_DISPOSITIONS: List[Dict[str, object]] = [
    {
        "id": "enforcement_integrity_gate",
        "module": "sdk-python/obsvr/remote.py",
        "timeout": _s("not_applicable"),
        "error": _s("open"),
        "degraded": _s("closed"),
        "hook_overridable": False,
        "notes": (
            "A failed policy poll does not block by itself; it counts toward staleness. "
            "Degraded state blocks: a revoked key or paused project always, and stale sync "
            "when the fail mode is closed. Not overridable by any means - the server has withdrawn "
            "authorization."
        ),
    },
    {
        "id": "policy_signature",
        "module": "sdk-python/obsvr/policy_verify.py",
        "timeout": _s("not_applicable"),
        "error": _s("open"),
        "degraded": _s("open"),
        "hook_overridable": False,
        "notes": (
            "Runs on the poll path, not the call path, so its failure is closed for the "
            "POLICY and open for the CALL: an unsigned, tampered, forged, or rolled-back "
            "payload is never applied and the last-good policy keeps governing, while "
            "in-flight calls proceed under it. Degraded means the signature could not be "
            "checked at all (Python without an Ed25519 backend); the policy is refused the "
            "same way and events carry policy_verification_unavailable. Either way the sync "
            "did not succeed, so staleness accrues and the integrity gate turns it into a "
            "block when the fail mode is closed."
        ),
    },
    {
        "id": "session_taint",
        "module": "sdk-python/obsvr/session_taint.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": "Guarded at the pre-call span in both languages and at the tool-execution path. An exception resolves by failMode: open loses this layer's escalation for the call, closed refuses it.",
    },
    {
        "id": "canary",
        "module": "sdk-python/obsvr/canary.py",
        "timeout": _s("not_applicable"),
        "error": _s("closed"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": "Floor class: resolves CLOSED regardless of failMode, because a layer that cannot run is the strongest form of 'cannot guarantee' and a canary block is unsuppressible by construction. The response phase is the exception - once an answer exists it is never withheld, so there the failure falls closed only on the stored copy.",
    },
    {
        "id": "builtin_pii_scan",
        "module": "sdk-python/obsvr/policy.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode", "redaction_application_closed"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": "Guarded at every pre-call span. Detection resolves by failMode; APPLYING a resolved redaction to outbound content resolves closed - see the redaction_application_closed qualifier.",
    },
    {
        "id": "presidio_merge",
        "module": "sdk-python/obsvr/presidio.py",
        "timeout": _s("open"),
        "error": _s("open"),
        "degraded": _s("open"),
        "hook_overridable": True,
        "notes": (
            "Out-of-process NER sidecar. Timeout or transport error yields no findings and the "
            "builtin regex tier still decides, so the layer degrades rather than disappears."
        ),
    },
    {
        "id": "deobfuscation_views",
        "module": "sdk-python/obsvr/deobfuscate.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode", "redaction_application_closed"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": "Guarded with the scan it feeds. Detection resolves by failMode; the stored-copy redactor fails closed to [UNSCANNED:detector_error] rather than persist text nothing vetted, and outbound application resolves closed - see the redaction_application_closed qualifier.",
    },
    {
        "id": "multi_turn_injection",
        "module": "sdk-python/obsvr/injection_session.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": "Guarded at the pre-call span in both languages. Resolves by failMode; a lost score costs this call's accumulated-probing signal only.",
    },
    {
        "id": "policy_floor",
        "module": "sdk-python/obsvr/rules.py",
        "timeout": _s("not_applicable"),
        "error": _s("closed"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": "Floor class: resolves CLOSED regardless of failMode. The non-overridable baseline that cannot run must not wave a call through ungoverned, exactly as a floor redact it cannot guarantee already fails closed to a block. The response phase never withholds the caller's value, so there it falls closed only on the stored copy.",
    },
    {
        "id": "policy_rules",
        "module": "sdk-python/obsvr/rules.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": "Guarded at every span that evaluates rules. Resolves by failMode. Two units of this layer are structurally always OPEN and cannot block whatever failMode says: shadow evaluation, which is defined as never decision-affecting, and the policy-version hash, which is provenance rather than a control.",
    },
    {
        "id": "customer_hook",
        "module": "sdk-python/obsvr/policy.py",
        "timeout": _s("fail_mode"),
        "error": _s("fail_mode"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": (
            "The one layer whose disposition the operator chooses: open by default, closed on "
            "opt-in. A timeout or error is recorded as its own hook disposition and can never "
            "un-block builtin enforcement - only an explicit allow verdict does that."
        ),
    },
    {
        "id": "external_backend",
        "module": "sdk-python/obsvr/external_backend.py",
        "timeout": _s("closed", "shadow_exempt"),
        "error": _s("closed", "shadow_exempt"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": (
            "An external decision point that cannot answer is a deny, because the operator asked "
            "for its verdict on every call. Observe-only (shadow) backends are exempt: they were "
            "never load-bearing."
        ),
    },
    {
        "id": "mcp_tool_policy",
        "module": "sdk-python/obsvr/integrations/mcp.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode"),
        "degraded": _s("closed"),
        "hook_overridable": False,
        "notes": (
            "The tool-call path guards its own policy evaluation and resolves failure by "
            "the configured fail mode - the posture the provider pipeline states but does not yet "
            "implement. "
            "Degraded enforcement blocks tool calls like any other governed call."
        ),
    },
    {
        "id": "tool_pinning",
        "module": "sdk-python/obsvr/tool_pinning.py",
        "timeout": _s("not_applicable"),
        "error": _s("closed", "warn_mode_flags"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": (
            "A descriptor that cannot be hashed is treated as a mismatch, never as a pass. "
            "Enforcement follows the configured pinning mode (block blocks, warn flags); neither "
            "is silent. Contained per tool so one unhashable entry cannot abort discovery."
        ),
    },
    {
        "id": "tool_result_scan",
        "module": "sdk-python/obsvr/response_scan.py",
        "timeout": _s("not_applicable"),
        "error": _s("fail_mode"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": "Guarded at its own call site, scan and sanitizer alike. Resolves by failMode with the default open even though it sees canary tokens, because the tool has ALREADY RUN: blocking cannot undo the side effect, it only withholds the result from the model.",
    },
]

#: Every declared layer id.
DECLARED_LAYER_IDS: List[str] = [entry["id"] for entry in FAILURE_DISPOSITIONS]  # type: ignore[misc]


def get_failure_disposition(layer_id: str) -> Optional[Dict[str, object]]:
    """Look up one layer's declaration."""
    for entry in FAILURE_DISPOSITIONS:
        if entry["id"] == layer_id:
            return entry
    return None


def disposition_for(layer_id: str, state: str) -> Optional[Dict[str, str]]:
    """The declared disposition of one layer in one failure state."""
    entry = get_failure_disposition(layer_id)
    if entry is None:
        return None
    return entry.get(state)  # type: ignore[return-value]


def unguarded_layer_ids() -> List[str]:
    """Layers whose failure currently escapes to the host rather than resolving
    to a decision. Exposed so the gap is countable and can be watched rather
    than rediscovered."""
    out: List[str] = []
    for entry in FAILURE_DISPOSITIONS:
        if any(
            entry[state]["disposition"] == "unguarded"  # type: ignore[index]
            for state in FAILURE_STATES
        ):
            out.append(entry["id"])  # type: ignore[arg-type]
    return out
