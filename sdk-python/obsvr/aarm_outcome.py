"""Pure mapping onto Obsvr's AARM compatibility profile outcome vocabulary.

The shared fixture is Obsvr-authored. It is not an official conformance vector
and this module does not change the existing ``action_taken`` wire field.
"""

from typing import Final, Literal

AarmOutcome = Literal["ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER"]

AARM_OUTCOMES: Final = ("ALLOW", "DENY", "MODIFY", "STEP_UP", "DEFER")
AARM_COMPATIBILITY_PROFILE_VERSION: Final = "1.0"


class AarmOutcomeMappingError(ValueError):
    """An existing event has no single unambiguous compatibility outcome."""


def map_aarm_outcome(
    action_taken: str,
    *,
    approval_required: bool = False,
    deferred: bool = False,
) -> AarmOutcome:
    """Map an existing verdict onto compatibility profile 1.0.

    Hook failures and ``not_evaluated`` are evidence states rather than policy
    outcomes. Conflicting flags are rejected rather than resolved by precedence.
    """
    approval = approval_required is True
    is_deferred = deferred is True

    if approval and is_deferred:
        raise AarmOutcomeMappingError(
            "approval_required and deferred cannot both describe one outcome"
        )

    if action_taken in ("hook_error", "hook_timeout"):
        raise AarmOutcomeMappingError(
            f"{action_taken} records a hook failure, not a policy outcome"
        )
    if action_taken == "not_evaluated":
        raise AarmOutcomeMappingError(
            "not_evaluated records the absence of a policy outcome"
        )

    if (approval or is_deferred) and action_taken != "blocked":
        raise AarmOutcomeMappingError(
            "approval_required and deferred are valid only for a blocked action"
        )

    if is_deferred:
        return "DEFER"
    if approval:
        return "STEP_UP"
    if action_taken == "allowed":
        return "ALLOW"
    if action_taken == "blocked":
        return "DENY"
    if action_taken == "redacted":
        return "MODIFY"

    raise AarmOutcomeMappingError(f"unsupported action_taken: {action_taken}")
