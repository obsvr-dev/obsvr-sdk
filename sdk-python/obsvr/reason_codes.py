"""Closed registry of policy-verdict reason codes.

This is the SINGLE shared source of the reason-code vocabulary for the
Python SDK. Every policy verdict the engine emits carries a ``reason_code``
drawn from this enum PLUS an optional free-form ``reason`` detail (so no
information is lost). It mirrors the TypeScript twin
(sdk/src/governance/reason-codes.ts) byte for byte, and both are pinned to
the shared fixture ``conformance/fixtures/reason_codes.json``.

A CI staleness check (tests/test_reason_codes.py + the TS
tests/unit/reason-codes.test.ts) fails if the two SDKs diverge, if either
drifts from the fixture, or if the engine can emit a code that is not in
this registry.

Values are stable, screaming-snake-case wire strings: they appear on audit
events and in the deterministic response contract, so renaming an existing
value is a breaking change. New codes are additive.
"""
from enum import Enum
from typing import Dict


class ReasonCode(str, Enum):
    """Wire-string reason codes. ``str`` mixin so ``ReasonCode.X == "X"`` and
    the value serializes as the bare string in a decision dict (parity with
    the TS enum, whose members ARE the wire strings)."""

    PERMITTED = "PERMITTED"
    TRANSMISSION_BLOCKED = "TRANSMISSION_BLOCKED"
    DESTRUCTIVE_OPERATION_BLOCKED = "DESTRUCTIVE_OPERATION_BLOCKED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    PII_DETECTED = "PII_DETECTED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    NAMESPACE_VIOLATION = "NAMESPACE_VIOLATION"
    CROSS_TENANT_BLOCKED = "CROSS_TENANT_BLOCKED"
    ENVIRONMENT_BLOCKED = "ENVIRONMENT_BLOCKED"
    SOURCE_GROUNDING_FAILED = "SOURCE_GROUNDING_FAILED"
    TOPIC_BLOCKED = "TOPIC_BLOCKED"
    KEYWORD_BLOCKED = "KEYWORD_BLOCKED"
    REGEX_MATCHED = "REGEX_MATCHED"
    MODEL_GATE_BLOCKED = "MODEL_GATE_BLOCKED"
    HOOK_BLOCKED = "HOOK_BLOCKED"
    HOOK_TIMEOUT = "HOOK_TIMEOUT"
    TOOL_DENIED = "TOOL_DENIED"
    DELEGATION_BLOCKED = "DELEGATION_BLOCKED"
    LOOP_DETECTED = "LOOP_DETECTED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    SHADOW_WOULD_BLOCK = "SHADOW_WOULD_BLOCK"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    EXTERNAL_BACKEND_DENY = "EXTERNAL_BACKEND_DENY"
    MCP_TOOL_DENIED = "MCP_TOOL_DENIED"
    MCP_RESULT_BLOCKED = "MCP_RESULT_BLOCKED"
    UNKNOWN_BLOCKED = "UNKNOWN_BLOCKED"


# The full closed registry as a frozen, sorted tuple of wire strings. Runtime
# mirror of the enum for the CI staleness check and for callers that need to
# validate an inbound code against the vocabulary.
REASON_CODES = tuple(sorted(rc.value for rc in ReasonCode))


# Canonical PolicyRule-type -> ReasonCode mapping. Every enforceable rule type
# has an explicit entry; this is pinned in the shared fixture so TS and Python
# classify a fired rule identically. Adding a rule type without adding a
# mapping here (and in the TS twin + fixture) fails CI.
RULE_TYPE_TO_REASON_CODE: Dict[str, str] = {
    "keyword": ReasonCode.KEYWORD_BLOCKED.value,
    "regex": ReasonCode.REGEX_MATCHED.value,
    "topic_deny": ReasonCode.TOPIC_BLOCKED.value,
    "topic_allow": ReasonCode.PERMITTED.value,
    "pii": ReasonCode.PII_DETECTED.value,
    "action_gate": ReasonCode.POLICY_VIOLATION.value,
    "namespace_isolation": ReasonCode.NAMESPACE_VIOLATION.value,
    "cross_tenant_block": ReasonCode.CROSS_TENANT_BLOCKED.value,
    "destructive_op_gate": ReasonCode.DESTRUCTIVE_OPERATION_BLOCKED.value,
    "source_grounding": ReasonCode.SOURCE_GROUNDING_FAILED.value,
    "environment_gate": ReasonCode.ENVIRONMENT_BLOCKED.value,
    "quota": ReasonCode.QUOTA_EXCEEDED.value,
    "model_gate": ReasonCode.MODEL_GATE_BLOCKED.value,
}


def rule_type_to_reason_code(rule_type: str) -> str:
    """Map a PolicyRule type to its reason-code wire string (parity with the
    TS ruleTypeToReasonCode). Unknown types fall back to UNKNOWN_BLOCKED."""
    return RULE_TYPE_TO_REASON_CODE.get(rule_type, ReasonCode.UNKNOWN_BLOCKED.value)
