"""Twin tests for bounded strict identity evidence profile 2.1."""

from __future__ import annotations

import copy

import pytest

from obsvr.strict_identity_evidence_v2_1 import (
    STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
    STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
    StrictIdentityEvidenceV21ValidationError,
    build_strict_identity_evidence_v2_1,
    canonicalize_strict_identity_evidence_v2_1,
    create_strict_identity_evidence_v2_1_authority,
    strict_identity_evidence_v2_1_hash,
    trusted_strict_identity_evidence_v2_1_document,
)

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64
PINNED_HASH = "b756d7faa47c4a2a2dda6646168ca2771aed55fe8b6c1a2503decc8005a1e234"


def _delegated():
    return {
        "schema": STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
        "profile_version": STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
        "relationship": "delegated",
        "receipt_time_ms": 1_000,
        "requester": {
            "requester_ref_hash": A,
            "principal_type": "human",
            "role_ids": ["legal.reviewer", "admin", "admin"],
            "privilege_scopes": ["write", "admin", "read"],
        },
        "initiator": {
            "agent_ref_hash": C,
            "key_id": f"sha256:{D}",
            "role_ids": ["worker"],
            "privilege_scopes": ["read"],
        },
        "delegation_chain": [
            {
                "hop": 0,
                "delegation_id_hash": "1" * 64,
                "delegator_ref_hash": A,
                "delegatee_ref_hash": B,
                "granted_scopes": ["write", "read"],
                "issued_at_ms": 900,
                "expires_at_ms": 2_000,
            },
            {
                "hop": 1,
                "delegation_id_hash": "2" * 64,
                "delegator_ref_hash": B,
                "delegatee_ref_hash": C,
                "granted_scopes": ["read"],
                "issued_at_ms": 950,
                "expires_at_ms": 1_500,
            },
        ],
    }


def _direct():
    value = _delegated()
    value["relationship"] = "direct"
    value["requester"]["requester_ref_hash"] = C
    value["delegation_chain"] = []
    return value


def test_cross_language_canonical_sorting_and_domain_hash_are_pinned():
    document = build_strict_identity_evidence_v2_1(_delegated())
    assert document["requester"]["role_ids"] == ["admin", "legal.reviewer"]
    assert document["requester"]["privilege_scopes"] == ["admin", "read", "write"]
    assert document["delegation_chain"][0]["granted_scopes"] == ["read", "write"]
    assert canonicalize_strict_identity_evidence_v2_1(
        _delegated()
    ) == canonicalize_strict_identity_evidence_v2_1(document)
    assert strict_identity_evidence_v2_1_hash(_delegated()) == PINNED_HASH


def test_direct_identity_must_be_explicit_and_self_initiated():
    assert build_strict_identity_evidence_v2_1(_direct())["delegation_chain"] == []
    mismatch = _direct()
    mismatch["initiator"]["agent_ref_hash"] = B
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError,
        match="direct relationship requires requester and initiator to match",
    ):
        build_strict_identity_evidence_v2_1(mismatch)
    hidden = _direct()
    hidden["delegation_chain"] = _delegated()["delegation_chain"]
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError,
        match="direct relationship requires an empty delegation_chain",
    ):
        build_strict_identity_evidence_v2_1(hidden)


def test_chain_must_be_contiguous_from_requester_to_initiator():
    bad_hop = _delegated()
    bad_hop["delegation_chain"][1]["hop"] = 2
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError, match="hop must equal 1"
    ):
        build_strict_identity_evidence_v2_1(bad_hop)
    bad_start = _delegated()
    bad_start["delegation_chain"][0]["delegator_ref_hash"] = D
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError, match="start at requester"
    ):
        build_strict_identity_evidence_v2_1(bad_start)
    broken = _delegated()
    broken["delegation_chain"][1]["delegator_ref_hash"] = D
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError, match="does not continue"
    ):
        build_strict_identity_evidence_v2_1(broken)
    duplicate = _delegated()
    duplicate["delegation_chain"][1]["delegation_id_hash"] = duplicate[
        "delegation_chain"
    ][0]["delegation_id_hash"]
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="duplicate"):
        build_strict_identity_evidence_v2_1(duplicate)
    bad_end = _delegated()
    bad_end["delegation_chain"][1]["delegatee_ref_hash"] = D
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError, match="end at initiator"
    ):
        build_strict_identity_evidence_v2_1(bad_end)


def test_delegation_validity_uses_exact_receipt_time_boundaries():
    future = _delegated()
    future["delegation_chain"][0]["issued_at_ms"] = 1_001
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="not valid"):
        build_strict_identity_evidence_v2_1(future)
    exact_expiry = _delegated()
    exact_expiry["delegation_chain"][1]["expires_at_ms"] = 1_000
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="not valid"):
        build_strict_identity_evidence_v2_1(exact_expiry)
    exact_issue = _delegated()
    exact_issue["delegation_chain"][0]["issued_at_ms"] = 1_000
    build_strict_identity_evidence_v2_1(exact_issue)


def test_privileges_cannot_expand_across_delegation():
    first = _delegated()
    first["delegation_chain"][0]["granted_scopes"].append("root")
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError, match="outside requester"
    ):
        build_strict_identity_evidence_v2_1(first)
    child = _delegated()
    child["delegation_chain"][1]["granted_scopes"].append("admin")
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="expands"):
        build_strict_identity_evidence_v2_1(child)
    agent = _delegated()
    agent["initiator"]["privilege_scopes"].append("write")
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError, match="exceed delegated"
    ):
        build_strict_identity_evidence_v2_1(agent)


def test_raw_identity_email_controls_and_surrogates_are_rejected():
    for field in ("email", "name", "display_name", "principal"):
        raw = _delegated()
        raw["requester"][field] = "raw-identity"
        with pytest.raises(
            StrictIdentityEvidenceV21ValidationError,
            match=rf"requester contains unsupported field: {field}",
        ):
            build_strict_identity_evidence_v2_1(raw)
    raw_ref = _delegated()
    raw_ref["requester"]["requester_ref_hash"] = "person@example.com"
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="lowercase hex"):
        build_strict_identity_evidence_v2_1(raw_ref)
    for unsafe in ("person@example.com", "role\nadmin", "\ud800"):
        value = _delegated()
        value["requester"]["role_ids"] = [unsafe]
        with pytest.raises(
            StrictIdentityEvidenceV21ValidationError, match="safe ASCII"
        ):
            build_strict_identity_evidence_v2_1(value)


def test_identifier_set_and_delegation_caps():
    identifier = _delegated()
    identifier["requester"]["role_ids"] = ["a" + "x" * 128]
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="1-128 byte"):
        build_strict_identity_evidence_v2_1(identifier)
    oversized_set = _delegated()
    oversized_set["requester"]["role_ids"] = [f"r{index}" for index in range(65)]
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="exceeds 64"):
        build_strict_identity_evidence_v2_1(oversized_set)
    chain = _delegated()
    chain["delegation_chain"] = [
        {
            "hop": index,
            "delegation_id_hash": f"{index:064x}",
            "delegator_ref_hash": A,
            "delegatee_ref_hash": C,
            "granted_scopes": [],
            "issued_at_ms": 0,
            "expires_at_ms": 2_000,
        }
        for index in range(17)
    ]
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="exceeds 16"):
        build_strict_identity_evidence_v2_1(chain)

    scopes = [f"s{index:02d}" + "x" * 125 for index in range(64)]
    refs = [f"{index:064x}" for index in range(17)]
    canonical = _delegated()
    canonical["requester"]["requester_ref_hash"] = refs[0]
    canonical["requester"]["privilege_scopes"] = scopes
    canonical["initiator"]["agent_ref_hash"] = refs[16]
    canonical["initiator"]["privilege_scopes"] = scopes
    canonical["delegation_chain"] = [
        {
            "hop": index,
            "delegation_id_hash": f"{index + 32:064x}",
            "delegator_ref_hash": refs[index],
            "delegatee_ref_hash": refs[index + 1],
            "granted_scopes": scopes,
            "issued_at_ms": 0,
            "expires_at_ms": 2_000,
        }
        for index in range(16)
    ]
    with pytest.raises(
        StrictIdentityEvidenceV21ValidationError,
        match="canonical identity evidence exceeds 65536 UTF-8 bytes",
    ):
        build_strict_identity_evidence_v2_1(canonical)


def test_tampering_changes_hash_and_authority_returns_immutable_copies():
    role_tamper = _delegated()
    role_tamper["requester"]["role_ids"] = ["viewer"]
    assert strict_identity_evidence_v2_1_hash(role_tamper) != PINNED_HASH
    chain_tamper = _delegated()
    chain_tamper["delegation_chain"][0]["expires_at_ms"] = 1_999
    assert strict_identity_evidence_v2_1_hash(chain_tamper) != PINNED_HASH
    time_tamper = _delegated()
    time_tamper["receipt_time_ms"] = 999
    assert strict_identity_evidence_v2_1_hash(time_tamper) != PINNED_HASH

    authority = create_strict_identity_evidence_v2_1_authority()
    original = _delegated()
    trusted = authority.issue(original)
    original["requester"]["role_ids"] = ["tampered"]
    first = trusted_strict_identity_evidence_v2_1_document(trusted)
    assert first["requester"]["role_ids"] == ["admin", "legal.reviewer"]
    first["requester"]["role_ids"].append("tampered")
    assert trusted_strict_identity_evidence_v2_1_document(trusted)["requester"][
        "role_ids"
    ] == ["admin", "legal.reviewer"]
    with pytest.raises(StrictIdentityEvidenceV21ValidationError, match="not issued"):
        trusted_strict_identity_evidence_v2_1_document(copy.deepcopy(_delegated()))
