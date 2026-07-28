"""An approval is re-checked after the layers that can delay a call, not only
when the rules engine first consults it. Twin:
sdk-typescript/tests/unit/approvals-revalidation.test.ts.

The window this closes is real rather than theoretical: the customer hook has a
two-second budget by default and an external policy backend has its own, so a
grant can be revoked or expire between "approved" and "sent". A revoking policy
poll during the hook is the deterministic way to stand that window up - and
revocation-mid-call is the case an operator actually cares about, since it is
what a human clicking "revoke" does.
"""

from datetime import datetime, timedelta, timezone

import obsvr
from obsvr import sender
from obsvr.config import _reset, get_config
from obsvr.policy import apply_pre_call_policy
from obsvr.remote import _reset_approvals, update_approvals
from obsvr.rules import PolicyRule, derive_rule_hash

RULE = PolicyRule(
    id="r-wire",
    name="Wire transfer needs approval",
    enabled=True,
    action="block",
    type="action_gate",
    conditions={"require_approval": True, "action_types": ["wire_transfer"]},
)

FUTURE = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def _live_grant():
    return [
        {
            "id": "g1",
            "rule_id": "r-wire",
            "expires_at": FUTURE,
            "rule_hash": derive_rule_hash(RULE),
        }
    ]


def _init(**extra):
    _reset()
    sender._reset_sender()
    _reset_approvals()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", policy_rules=[RULE], **extra)


def _pre(text):
    return apply_pre_call_policy(
        text,
        get_config(),
        provider="openai",
        operation="chat.completions.create",
        metadata={"action_name": "wire_transfer"},
        model="gpt-4",
    )


class TestApprovalRevalidation:
    def teardown_method(self):
        _reset()
        _reset_approvals()

    def test_a_grant_revoked_during_the_hook_does_not_authorize(self):
        def revoking_hook(_event):
            # Stands in for a /policies poll landing mid-call, or a human
            # clicking revoke: the grant is gone by the time the request would
            # be sent.
            update_approvals([])
            return {"decision": "allow"}

        _init(on_pre_call=revoking_hook)
        update_approvals(_live_grant())
        res = _pre("please wire_transfer the funds")
        assert res["decision"] == "block"
        assert res["compliance"]["rule_id"] == "r-wire"
        assert "approval_expired_before_execution" in res["compliance"]["policy_reason"]

    def test_a_grant_that_survives_the_hook_still_authorizes(self):
        _init(on_pre_call=lambda _e: {"decision": "allow"})
        update_approvals(_live_grant())
        assert _pre("please wire_transfer the funds")["decision"] == "allow"

    def test_an_expired_grant_never_authorizes_in_the_first_place(self):
        _init()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        update_approvals(
            [
                {
                    "id": "g1",
                    "rule_id": "r-wire",
                    "expires_at": past,
                    "rule_hash": derive_rule_hash(RULE),
                }
            ]
        )
        assert _pre("please wire_transfer the funds")["decision"] == "block"
