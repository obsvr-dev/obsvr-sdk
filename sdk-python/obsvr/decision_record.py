"""Canonical decision records (ADR-2 tier-1).

At decision time the enforcement pipeline builds a small canonical JSON
document -- the decision-input document, schema ``obsvr-decision-input-v1`` --
describing exactly what the rules engine evaluated: the canonical rules-set
hash, the enforcement-integrity (kill-switch/degraded) state, the evaluation
target, a digest of the evaluated text, the scope identifiers visible at the
boundary, and the customer-hook disposition. Its SHA-256
(``decision_input_hash``) plus ``engine_version`` are stamped on emitted audit
events as ADDITIVE fields (never part of the HMAC chain preimage), and the
ledger's v7 Merkle leaf seals them.

Canonicalization is RFC 8785-style: UTF-8, lexicographically sorted keys, no
insignificant whitespace, absent optionals OMITTED (never null). It reuses
``_canonical_json`` -- the same helper the cross-language rules hash is pinned
on -- so both SDKs produce byte-identical documents. Parity is pinned by
conformance/fixtures/decision_input.json (twin:
sdk/src/policy/decision-record.ts).
"""

import hashlib
from typing import Any, Dict, Optional

from .rules import _canonical_json

# Cross-language rules-engine semantics version. Bumped when -- and only
# when -- evaluation semantics change (a change that can produce a different
# decision for the same rules + input), in the same commit that updates
# conformance/fixtures/eval_semantics.json, in BOTH SDKs. Never bumped for
# additive fields or refactors.
RULES_ENGINE_SEMANTICS_VERSION = 1

# The engine_version string stamped on events: "obsvr-rules/<N>".
ENGINE_VERSION = f"obsvr-rules/{RULES_ENGINE_SEMANTICS_VERSION}"

# Schema tag of the canonical decision-input document.
DECISION_INPUT_SCHEMA = "obsvr-decision-input-v1"

# Customer-hook dispositions recorded in the decision-input document.
HOOK_DISPOSITIONS = (
    "not_configured",  # no customer hook registered
    "skipped",         # configured but not run (degraded gate / trigger unmet)
    "allow",
    "block",
    "redact",
    "timeout",
    "error",
)


def sha256_hex(text: str) -> str:
    """SHA-256 lowercase hex over the UTF-8 bytes of ``text``."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_decision_input(
    *,
    rules_hash: str,
    degraded: bool,
    degraded_reason: Optional[str] = None,
    target: str = "request",
    evaluated_text: str = "",
    user_id: Optional[str] = None,
    service_name: Optional[str] = None,
    tenant_id: Optional[str] = None,
    hook: str = "not_configured",
) -> Dict[str, Any]:
    """Build the canonical decision-input document (v1).

    ``evaluated_text`` is the exact text the decision pipeline evaluated
    (the scan text -- the last-user-message extraction -- captured BEFORE
    any redaction the pipeline applies); it is digested, never stored.
    Scope identifiers are included only when they are non-empty strings.
    All values are strings or booleans; optionals are omitted when absent
    -- a document never contains a JSON null.
    """
    doc: Dict[str, Any] = {
        "schema": DECISION_INPUT_SCHEMA,
        "engine_version": ENGINE_VERSION,
        "rules_hash": rules_hash,
        "degraded": bool(degraded),
        "target": target,
        "hook": hook,
    }
    if degraded and isinstance(degraded_reason, str) and degraded_reason:
        doc["degraded_reason"] = degraded_reason
    digest = sha256_hex(evaluated_text)
    if target == "request":
        doc["prompt_sha256"] = digest
    else:
        doc["response_sha256"] = digest
    if isinstance(user_id, str) and user_id:
        doc["user_id"] = user_id
    if isinstance(service_name, str) and service_name:
        doc["service_name"] = service_name
    if isinstance(tenant_id, str) and tenant_id:
        doc["tenant_id"] = tenant_id
    return doc


def canonicalize_decision_input(doc: Dict[str, Any]) -> str:
    """Canonical serialization: sorted keys, no insignificant whitespace,
    minimal escaping. Byte-for-byte identical to the TS SDK (pinned by
    conformance/fixtures/decision_input.json)."""
    return _canonical_json(doc)


def compute_decision_input_hash(doc: Dict[str, Any]) -> str:
    """SHA-256 lowercase hex of the canonical UTF-8 bytes of the document."""
    return sha256_hex(canonicalize_decision_input(doc))
