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
        "id": "session_taint",
        "module": "sdk-python/obsvr/session_taint.py",
        "timeout": _s("not_applicable"),
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": "Pure in-process latch over a bounded store. No timeout channel, no error channel.",
    },
    {
        "id": "canary",
        "module": "sdk-python/obsvr/canary.py",
        "timeout": _s("not_applicable"),
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": (
            "A canary leak is unsuppressible: the hook-override branch excludes it explicitly, "
            "because a leaked canary is proof of exfiltration in progress."
        ),
    },
    {
        "id": "builtin_pii_scan",
        "module": "sdk-python/obsvr/policy.py",
        "timeout": _s("not_applicable"),
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": (
            "Regex tier, bounded by the ReDoS-checked matcher rather than a timeout. An explicit "
            "hook allow can override its block; a hook timeout or error cannot."
        ),
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
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": (
            "Findings-only view producer; malformed encodings are handled internally (an "
            "undecodable view is simply not produced) rather than raised."
        ),
    },
    {
        "id": "multi_turn_injection",
        "module": "sdk-python/obsvr/injection_session.py",
        "timeout": _s("not_applicable"),
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": (
            "In-process accumulator over a bounded store; scoring is arithmetic with no failure "
            "channel."
        ),
    },
    {
        "id": "policy_floor",
        "module": "sdk-python/obsvr/rules.py",
        "timeout": _s("not_applicable"),
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": (
            "The non-overridable baseline. A floor redact the pipeline cannot guarantee fails "
            "CLOSED to a block rather than forward content under a false redacted record. Hook "
            "attempts to override are refused and recorded on the event."
        ),
    },
    {
        "id": "policy_rules",
        "module": "sdk-python/obsvr/rules.py",
        "timeout": _s("not_applicable"),
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": True,
        "notes": (
            "Deterministic rule evaluation; regex conditions are ReDoS-checked rather than timed "
            "out."
        ),
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
        "error": _s("unguarded"),
        "degraded": _s("not_applicable"),
        "hook_overridable": False,
        "notes": (
            "Response-side scan of tool results, the exfiltration channel. Runs outside the "
            "tool-call path's policy guard, so an exception here reaches the caller."
        ),
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
