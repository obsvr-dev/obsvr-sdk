"""Python consumer of conformance/fixtures/tool_content_hash.json. Twin:
sdk/tests/unit/tool-content-hash-conformance.test.ts.

The fixture is the contract of record for obsvr-tool-content-v1, and this is
the half that proves the Python producer reproduces every byte of it. Literals
live in the fixture, never here, so the two languages cannot pass their own
suites while disagreeing with each other.
"""

import json
import re
from pathlib import Path

import pytest

from obsvr.tool_content_hash import (
    build_tool_content_document,
    canonicalize_tool_content,
    compute_tool_content_hash,
    tool_args_hash,
    tool_content_descriptor_hash,
)
from obsvr.tool_pinning import tool_descriptor_hash

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/tool_content_hash.json")
    .resolve()
    .read_text()
)

DOCUMENT_CASES = FIXTURE["document_cases"]
EQUIVALENCE_GROUPS = FIXTURE["equivalence_groups"]
UNSTABLE_CASES = FIXTURE["unstable_number_cases"]
DISTINCTION_CASES = FIXTURE["distinction_cases"]
_BY_ID = {c["id"]: c for c in DOCUMENT_CASES}


def _params(case):
    """Fixture descriptors use MCP wire names; this is the whole adaptation."""
    return {
        "tool_name": case["input"].get("tool_name"),
        "descriptor": case["input"].get("descriptor"),
        "args": case["input"].get("args"),
    }


def test_the_fixture_is_present_and_non_trivial():
    assert FIXTURE["name"] == "tool_content_hash"
    assert len(DOCUMENT_CASES) >= 16


@pytest.mark.parametrize("case", DOCUMENT_CASES, ids=[c["id"] for c in DOCUMENT_CASES])
def test_document_case(case):
    doc = build_tool_content_document(**_params(case))
    assert doc["descriptor_sha256"] == case["expect"]["descriptor_sha256"]
    assert doc["args_sha256"] == case["expect"]["args_sha256"]
    assert canonicalize_tool_content(doc) == case["expect"]["canonical"]
    assert compute_tool_content_hash(**_params(case)) == case["expect"]["hash"]
    # The pinned hash really is the digest of the pinned canonical bytes, so a
    # fixture whose two halves drifted apart cannot pass.
    assert re.fullmatch(r"[0-9a-f]{64}", case["expect"]["hash"])


def test_the_component_digests_are_computable_on_their_own():
    for case in DOCUMENT_CASES:
        assert tool_content_descriptor_hash(
            case["input"].get("descriptor")
        ) == case["expect"]["descriptor_sha256"]
        assert tool_args_hash(case["input"].get("args")) == case["expect"]["args_sha256"]


@pytest.mark.parametrize(
    "group", EQUIVALENCE_GROUPS, ids=[" == ".join(g["ids"]) for g in EQUIVALENCE_GROUPS]
)
def test_equivalence_group(group):
    hashes = {_BY_ID[i]["expect"]["hash"] for i in group["ids"]}
    assert len(hashes) == 1
    # Recomputed, not just compared as fixture literals.
    computed = {compute_tool_content_hash(**_params(_BY_ID[i])) for i in group["ids"]}
    assert len(computed) == 1
    assert computed == hashes


def test_cases_outside_a_group_are_genuinely_distinct():
    grouped = {i for g in EQUIVALENCE_GROUPS for i in g["ids"]}
    distinct = [c["expect"]["hash"] for c in DOCUMENT_CASES if c["id"] not in grouped]
    assert len(set(distinct)) == len(distinct)


def test_the_two_projections_give_different_digests_for_the_same_descriptor():
    c = next(
        x for x in DISTINCTION_CASES
        if x["id"] == "projections_differ_for_the_same_descriptor"
    )
    assert tool_descriptor_hash(c["descriptor"]) == c["expect"]["pinning_descriptor_hash"]
    assert (
        tool_content_descriptor_hash(c["descriptor"])
        == c["expect"]["content_descriptor_sha256"]
    )
    assert c["expect"]["pinning_descriptor_hash"] != c["expect"]["content_descriptor_sha256"]


def test_a_behavior_hint_change_moves_the_pin_and_not_the_content_hash():
    c = next(
        x for x in DISTINCTION_CASES
        if x["id"] == "behavior_hint_moves_the_pin_and_not_the_content_hash"
    )
    baseline = next(x for x in DISTINCTION_CASES if x["id"] == c["baseline_id"])

    assert tool_descriptor_hash(c["descriptor"]) == c["expect"]["pinning_descriptor_hash"]
    assert (
        tool_content_descriptor_hash(c["descriptor"])
        == c["expect"]["content_descriptor_sha256"]
    )

    # The pin catches the rug-pull...
    assert (
        c["expect"]["pinning_descriptor_hash"]
        != baseline["expect"]["pinning_descriptor_hash"]
    )
    # ...and the evidence contract does not, because annotations are outside
    # its projection. Substituting one hash for the other would silently change
    # which attack the field detects.
    assert (
        c["expect"]["content_descriptor_sha256"]
        == baseline["expect"]["content_descriptor_sha256"]
    )
    assert compute_tool_content_hash(
        tool_name="read_file", descriptor=c["descriptor"], args=c.get("args")
    ) == c["expect"]["content_hash"]
    assert c["expect"]["content_hash"] == c["expect"]["baseline_content_hash"]


@pytest.mark.parametrize("case", UNSTABLE_CASES, ids=[c["id"] for c in UNSTABLE_CASES])
def test_cross_sdk_unstable_number(case):
    if case["expect"]["throws"]:
        with pytest.raises(Exception):
            tool_args_hash(case["args"])
    else:
        assert tool_args_hash(case["args"]) == case["expect"]["args_sha256"]


def test_every_unstable_case_that_throws_also_throws_through_the_top_level_hash():
    for case in UNSTABLE_CASES:
        if case["expect"]["throws"]:
            with pytest.raises(Exception):
                compute_tool_content_hash(tool_name="t", args=case["args"])
