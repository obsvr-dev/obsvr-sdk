"""The typed error a policy block raises (twin of sdk-typescript/src/policy/policy-error.ts).

A blocked call has to be distinguishable from a provider outage, a bad API key,
or a network failure - the caller's fallback behavior is different for each, and
"the request was refused on purpose" is the one case where retrying is
pointless. Until now the block raised a plain ``RuntimeError`` whose only
distinguishing feature was its message, so the de facto contract was string
matching on prose. That breaks the first time the wording improves.

::

    try:
        client.chat.completions.create(...)
    except ObsvrPolicyError as err:
        # refused by policy: err.reason_code, err.rule_id, err.decision
        ...
    except Exception:
        # provider or transport failure: retry, fall back, surface
        ...

Design rules this module exists to enforce:

- **One construction point.** Every block-raise site calls
  :func:`create_policy_error`. Classification never gets scattered across call
  sites, because that is how two call sites come to classify the same failure
  differently.
- **Explicit type strings.** ``type`` is a literal per class, never derived from
  the class name, so it survives refactoring and serializes stably.
- **A fallback class, never a bare raise.** A reason category this version does
  not know still produces a typed error (:class:`ObsvrUnknownPolicyError`)
  rather than degrading to a plain exception. Forward compatibility with a
  control plane that can introduce categories faster than SDKs ship.
- **The message is unchanged.** Existing code that string-matches the old
  message keeps working; this is additive.

``ObsvrPolicyError`` subclasses ``RuntimeError`` so callers that previously
caught ``RuntimeError`` around a governed call keep catching it.

Cross-language parity is asserted on the serialized fields, not the class
hierarchy, and pinned by conformance/fixtures/error_parity.json.
"""

from typing import Any, Dict, Optional

from .reason_codes import ReasonCode

__all__ = [
    "ObsvrPolicyError",
    "ObsvrUnknownPolicyError",
    "create_policy_error",
    "policy_block_message",
]

#: The block reason categories this version knows how to classify.
_KNOWN_REASONS = frozenset({"pii_detected", "policy_violation", "customer_override", "none"})


class ObsvrPolicyError(RuntimeError):
    """Raised when a call is refused by policy.

    Carries the same facts the audit event carries, so a caller can branch on
    the decision without parsing text.
    """

    #: Stable wire string, set explicitly per class.
    type: str = "obsvr_policy_error"

    def __init__(
        self,
        message: str,
        reason_code: str,
        decision: Dict[str, Any],
        rule_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        #: Reason code from the closed registry (conformance/fixtures/reason_codes.json).
        self.reason_code = reason_code
        #: The rule that decided, when a rule decided.
        self.rule_id = rule_id
        #: Decision metadata mirroring the emitted event.
        self.decision = decision

    def to_dict(self) -> Dict[str, Any]:
        """Serialized shape asserted for cross-language parity."""
        out: Dict[str, Any] = {"type": self.type, "reason_code": self.reason_code}
        if self.rule_id is not None:
            out["rule_id"] = self.rule_id
        out["decision"] = self.decision
        out["message"] = self.message
        return out


class ObsvrUnknownPolicyError(ObsvrPolicyError):
    """A block whose reason category this SDK version does not recognize - most
    likely a newer control plane. Still a policy error, still catchable the same
    way, still carrying whatever the server said; only the classification is
    unknown."""

    type: str = "obsvr_unknown_policy_error"


def policy_block_message(action_reason: Optional[str]) -> str:
    """The message a policy block has always produced.

    Preserved byte-for-byte (including for unknown categories, which fall to the
    "policy violation" wording exactly as the old conditional did) so existing
    string matches survive.
    """
    detail = "PII detected" if action_reason == "pii_detected" else "policy violation"
    return f"[obsvr] Request blocked by policy ({detail})"


def _resolve_reason_code(
    action_reason: Optional[str],
    action_source: Optional[str],
    reason_code: Optional[str],
) -> str:
    """An explicit code from the deciding layer always wins; otherwise it is
    derived from the reason and the deciding source."""
    if reason_code:
        return reason_code
    if action_reason == "pii_detected":
        return ReasonCode.PII_DETECTED.value
    if action_reason not in _KNOWN_REASONS:
        return ReasonCode.UNKNOWN_BLOCKED.value
    if action_source == "customer_hook":
        return ReasonCode.HOOK_BLOCKED.value
    if action_source == "external_backend":
        return ReasonCode.EXTERNAL_BACKEND_DENY.value
    return ReasonCode.POLICY_VIOLATION.value


def create_policy_error(compliance: Optional[Dict[str, Any]] = None, **overrides: Any) -> ObsvrPolicyError:
    """The single construction choke point.

    Every block-raise site in the SDK calls this; nothing else constructs a
    policy error. Accepts a compliance dict (what the pipeline already carries)
    with optional keyword overrides.
    """
    data: Dict[str, Any] = dict(compliance or {})
    data.update({k: v for k, v in overrides.items() if v is not None})

    action_reason = data.get("action_reason")
    action_source = data.get("action_source")

    decision: Dict[str, Any] = {
        "action_taken": data.get("action_taken") or "blocked",
        "action_reason": action_reason or "policy_violation",
        "action_source": action_source or "unknown",
    }
    if data.get("policy_version") is not None:
        decision["policy_version"] = data["policy_version"]
    if data.get("policy_reason") is not None:
        decision["policy_reason"] = data["policy_reason"]

    message = policy_block_message(action_reason)
    code = _resolve_reason_code(action_reason, action_source, data.get("reason_code"))
    cls = ObsvrPolicyError if action_reason in _KNOWN_REASONS else ObsvrUnknownPolicyError

    return cls(message, code, decision, data.get("rule_id"))
