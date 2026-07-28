"""The canonical approval-action document (twin of the action half of
sdk-typescript/src/policy/approvals.ts).

A grant scoped only to a rule id answers "did someone approve something?". For
a product whose claim is that the record proves what was authorized, the
question has to be "was THIS call approved?" - otherwise one human approving a
$50 transfer leaves a live grant that satisfies a $5,000,000 one, because both
trip the same rule. The action hash is what makes the second question
answerable: a grant carrying one satisfies only a call whose action hashes the
same.

WHAT IT BINDS: the rule that demanded approval, that rule's definition, and the
structured facts the approvable rule types actually decide on - the action
name, the amount, the caller and target namespaces, and the subject.

WHAT IT DOES NOT BIND, deliberately: the prompt text. An approved request and
its retry differ in it more often than not - ids, timestamps, re-serialization
- and a grant that voided itself on a whitespace change would be turned off
within a week. The cost is stated rather than hidden: an attacker who can vary
the free text while holding every structured fact constant is inside the scope
one human approved, which is the scope the human was shown.

Absent and non-finite values are OMITTED rather than serialized as null - the
same convention as the canonical decision-input and rule projections, so "no
amount" and "amount: null" cannot hash differently.

Byte contract: conformance/fixtures/approvals.json.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, Optional

from .tool_pinning import _canonical_json_for_hash

__all__ = [
    "APPROVAL_ACTION_SCHEMA",
    "build_approval_action",
    "approval_action_hash",
    "safe_approval_action_hash",
]

#: Schema tag of the canonical approval-action document.
APPROVAL_ACTION_SCHEMA = "obsvr-action/1"


def _nonempty_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def build_approval_action(
    rule_id: str,
    rule_hash: str,
    action_name: Any = None,
    amount: Any = None,
    caller_namespace: Any = None,
    target_namespace: Any = None,
    user_id: Any = None,
) -> Dict[str, Any]:
    """The canonical action document. See the module docstring for what it
    binds and what it deliberately does not."""
    doc: Dict[str, Any] = {"schema": APPROVAL_ACTION_SCHEMA}
    name = _nonempty_str(action_name)
    if name is not None:
        doc["action_name"] = name
    if (
        isinstance(amount, (int, float))
        and not isinstance(amount, bool)
        and math.isfinite(amount)
    ):
        doc["amount"] = amount
    caller = _nonempty_str(caller_namespace)
    if caller is not None:
        doc["caller_namespace"] = caller
    doc["rule_hash"] = rule_hash
    doc["rule_id"] = rule_id
    target = _nonempty_str(target_namespace)
    if target is not None:
        doc["target_namespace"] = target
    subject = _nonempty_str(user_id)
    if subject is not None:
        doc["user_id"] = subject
    return doc


def approval_action_hash(**kwargs: Any) -> str:
    """SHA-256 (lowercase 64-hex) of the canonical action document.

    Uses the cross-SDK-stable canonicalizer rather than the rules-hash one: an
    ``amount`` reaches here from caller-supplied context, so it is
    attacker-shaped input, and the stable canonicalizer REFUSES values the two
    runtimes cannot render identically instead of normalizing them into
    agreement. A raise here means no action hash, which the caller resolves by
    refusing the grant - an approval that cannot be bound is not an approval.
    """
    return hashlib.sha256(
        _canonical_json_for_hash(build_approval_action(**kwargs)).encode("utf-8")
    ).hexdigest()


def safe_approval_action_hash(**kwargs: Any) -> Optional[str]:
    """:func:`approval_action_hash`, or None when the action carries a value the
    two runtimes cannot render identically. Callers treat None as "this call
    has no action hash", which under the matching rule means an unbound grant
    still satisfies and a bound one does not."""
    try:
        return approval_action_hash(**kwargs)
    except Exception:  # noqa: BLE001 - any canonicalization refusal
        return None
