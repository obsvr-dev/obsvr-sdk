"""Cross-SDK approval-binding conformance (Python side). Twin:
sdk-typescript/tests/unit/approvals-conformance.test.ts.

A grant scoped only to a rule id says someone approved something. These cases
pin the stronger claim: that a grant names the call it was issued for and
cannot be spent on another one that happens to trip the same rule.
"""

import json
from pathlib import Path

import pytest

from obsvr.approval_action import approval_action_hash, build_approval_action
from obsvr.remote import _reset_approvals, has_approval, update_approvals

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/approvals.json")
    .resolve()
    .read_text(encoding="utf-8")
)

ACTION_CASES = FIXTURE["action_cases"]
MATCH_CASES = FIXTURE["match_cases"]


@pytest.mark.parametrize("case", ACTION_CASES, ids=[c["id"] for c in ACTION_CASES])
def test_canonical_action_document(case):
    action = case["action"]
    assert build_approval_action(**action) == case["expect"]["document"]
    assert approval_action_hash(**action) == case["expect"]["hash"]


def test_every_distinct_action_hashes_distinctly():
    # The whole point of the digest: two actions a human would describe
    # differently must not be interchangeable in a grant. Cases that declare
    # `same_as` are intentionally identical and are the only allowed
    # collisions, so an accidental one still fails here.
    by_hash = {}
    for case in ACTION_CASES:
        h = approval_action_hash(**case["action"])
        by_hash.setdefault(h, []).append(case["id"])
    declared = {c["id"]: c["same_as"] for c in ACTION_CASES if c.get("same_as")}
    unexpected = [
        ids
        for ids in by_hash.values()
        if len(ids) > 1
        and not all(i in declared or any(declared.get(o) == i for o in ids) for i in ids)
    ]
    assert unexpected == []

    # ...and every declared equivalence must actually hold.
    action_of = {c["id"]: c["action"] for c in ACTION_CASES}
    for cid, other in declared.items():
        assert approval_action_hash(**action_of[cid]) == approval_action_hash(
            **action_of[other]
        )


@pytest.mark.parametrize("case", MATCH_CASES, ids=[c["id"] for c in MATCH_CASES])
def test_grant_matching(case):
    _reset_approvals()
    try:
        update_approvals(case["grants"])
        claim = case["claim"]
        assert (
            has_approval(
                claim["rule_id"],
                claim.get("user_id"),
                claim.get("rule_hash"),
                claim.get("action_hash"),
            )
            is case["expect"]
        )
    finally:
        _reset_approvals()
