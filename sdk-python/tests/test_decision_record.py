"""Canonical decision records (ADR-2) — Python side. Twin:
sdk-typescript/tests/unit/decision-record.test.ts.

Two layers:
 1. Cross-SDK parity against conformance/fixtures/decision_input.json: both
    SDKs must build the SAME document from the same inputs, serialize it to
    the SAME canonical bytes, and derive the SAME sha256. A divergence is a
    release blocker, never a known-divergence.
 2. Wiring: apply_pre_call_policy stamps decision_input_hash + engine_version
    on the compliance context, build_audit_event carries them as ADDITIVE
    fields, and the HMAC chain preimage is provably unchanged.
"""

import hashlib
import hmac as hmac_mod
import json
from pathlib import Path

import pytest

from obsvr.decision_record import (
    DECISION_INPUT_SCHEMA,
    ENGINE_VERSION,
    RULES_ENGINE_SEMANTICS_VERSION,
    build_decision_input,
    canonicalize_decision_input,
    compute_decision_input_hash,
)
from obsvr.config import ResolvedConfig
from obsvr.events import build_audit_event
from obsvr.policy import apply_pre_call_policy

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/decision_input.json")
    .resolve()
    .read_text(encoding="utf-8")
)


def _cfg(**kw):
    defaults = dict(api_key="test", sample_rate=1)
    defaults.update(kw)
    return ResolvedConfig(**defaults)


# ── 1. Cross-SDK fixture parity ──────────────────────────────────────────────


def test_fixture_pins_the_engine_version_this_sdk_stamps():
    assert FIXTURE["engine_version"] == ENGINE_VERSION
    assert ENGINE_VERSION == f"obsvr-rules/{RULES_ENGINE_SEMANTICS_VERSION}"


def test_fixture_covers_both_targets_and_enough_cases():
    targets = {c["input"]["target"] for c in FIXTURE["cases"]}
    assert targets == {"request", "response"}
    assert len(FIXTURE["cases"]) >= 6


@pytest.mark.parametrize(
    "case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]]
)
def test_conformance_case(case):
    doc = build_decision_input(**case["input"])
    assert doc == case["doc"]
    assert canonicalize_decision_input(doc) == case["expected"]["canonical"]
    assert compute_decision_input_hash(doc) == case["expected"]["hash"]
    # The frozen doc in the fixture re-canonicalizes to the same bytes too.
    assert canonicalize_decision_input(case["doc"]) == case["expected"]["canonical"]


# ── 2. Document shape ────────────────────────────────────────────────────────


def test_absent_optionals_are_omitted_never_null():
    doc = build_decision_input(
        rules_hash="none",
        degraded=False,
        target="request",
        evaluated_text="",
        hook="not_configured",
    )
    assert sorted(doc.keys()) == [
        "degraded",
        "engine_version",
        "hook",
        "prompt_sha256",
        "rules_hash",
        "schema",
        "target",
    ]
    assert doc["schema"] == DECISION_INPUT_SCHEMA
    assert "null" not in canonicalize_decision_input(doc)


def test_degraded_reason_only_when_degraded():
    doc = build_decision_input(
        rules_hash="none",
        degraded=False,
        degraded_reason="policy_sync_stale",  # must be ignored
        target="request",
        evaluated_text="x",
        hook="skipped",
    )
    assert "degraded_reason" not in doc


def test_target_selects_the_digest_field():
    digest = hashlib.sha256("abc".encode("utf-8")).hexdigest()
    req = build_decision_input(
        rules_hash="none", degraded=False, target="request",
        evaluated_text="abc", hook="allow",
    )
    res = build_decision_input(
        rules_hash="none", degraded=False, target="response",
        evaluated_text="abc", hook="allow",
    )
    assert req["prompt_sha256"] == digest and "response_sha256" not in req
    assert res["response_sha256"] == digest and "prompt_sha256" not in res


# ── 3. Enforcement wiring ────────────────────────────────────────────────────


def test_apply_pre_call_policy_stamps_the_record():
    result = apply_pre_call_policy("hello world", _cfg(pii_policy={}))
    comp = result["compliance"]
    assert comp["engine_version"] == ENGINE_VERSION
    assert len(comp["decision_input_hash"]) == 64
    int(comp["decision_input_hash"], 16)  # valid hex
    # Replayable: the hash recomputes from the disclosed inputs.
    expected = compute_decision_input_hash(
        build_decision_input(
            rules_hash=comp["policy_version"],
            degraded=False,
            target="request",
            evaluated_text="hello world",
            hook="not_configured",
        )
    )
    assert comp["decision_input_hash"] == expected


def test_blocked_decision_carries_the_record():
    result = apply_pre_call_policy("my ssn is 123-45-6789", _cfg(pii_policy={}))
    assert result["decision"] == "block"
    comp = result["compliance"]
    assert comp["engine_version"] == ENGINE_VERSION
    assert len(comp["decision_input_hash"]) == 64


def test_hook_disposition_is_committed():
    no_hook = apply_pre_call_policy("same text", _cfg())
    with_hook = apply_pre_call_policy(
        "same text", _cfg(on_pre_call=lambda ev: "block")
    )
    assert (
        no_hook["compliance"]["decision_input_hash"]
        != with_hook["compliance"]["decision_input_hash"]
    )


def test_build_audit_event_carries_the_fields():
    cfg = _cfg()
    comp = apply_pre_call_policy("hello", cfg)["compliance"]
    event = build_audit_event(
        cfg,
        provider="openai",
        model="m",
        operation="test",
        source="test",
        prompt="hello",
        compliance=comp,
    )
    assert event["decision_input_hash"] == comp["decision_input_hash"]
    assert event["engine_version"] == ENGINE_VERSION


def test_events_without_a_decision_carry_no_record():
    event = build_audit_event(
        _cfg(),
        provider="openai",
        model="m",
        operation="test",
        source="test",
        prompt="hello",
    )
    assert "decision_input_hash" not in event
    assert "engine_version" not in event


# ── 4. Chain preimage untouched (signing_vectors stay green) ─────────────────


def test_decision_record_fields_are_outside_the_preimage_but_the_verdict_is_inside():
    """Which fields the chain signs, asserted from both directions.

    ``decision_input_hash`` and ``engine_version`` are diagnostic: they describe
    HOW a decision was reached, they are reproducible from the inputs, and they
    are deliberately not signed. The VERDICT is a different thing, and since
    format 3 it is inside the preimage — that is the whole point of the format.

    Both halves are asserted here because only the pair is meaningful. "Adding a
    field changes no signed byte" is a reassuring sentence about a diagnostic
    field and a catastrophic one about ``action_taken``, and this test used to
    make only the first claim while the second was silently also true.
    """
    from obsvr.chain_format import CHAIN_FORMAT_CURRENT, decision_fields_of, signature_payload

    key = hmac_mod.new(
        b"obsvr-sdk-signing-v1", b"test-api-key", hashlib.sha256
    ).digest()

    def sign(event, fmt=CHAIN_FORMAT_CURRENT):
        payload = signature_payload(
            fmt,
            event["sdk_session_id"],
            event["seq_no"],
            event["timestamp_sdk"],
            event.get("prompt") or "",
            event.get("response") or "",
            None,
            decision_fields_of(event, fmt),
        )
        return hmac_mod.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    base = {
        "sdk_session_id": "11111111-1111-1111-1111-111111111111",
        "seq_no": 1,
        "timestamp_sdk": 1700000000000,
        "prompt": "hello",
        "response": "world",
        "action_taken": "blocked",
        "rule_id": "rule-1",
    }

    # Diagnostic fields: outside the preimage, by design.
    with_record = dict(
        base, decision_input_hash="ab" * 32, engine_version=ENGINE_VERSION
    )
    assert sign(with_record) == sign(base)

    # The verdict and its attribution: INSIDE the preimage. Each of these was
    # freely rewritable under format 2 with the chain still verifying.
    assert sign(dict(base, action_taken="allowed")) != sign(base)
    assert sign(dict(base, rule_id="some-other-rule")) != sign(base)
    assert sign(dict(base, provider="anthropic")) != sign(base)

    # Absent and present-but-empty are different preimages, so a signed field
    # cannot be deleted into agreement either.
    without_rule = {k: v for k, v in base.items() if k != "rule_id"}
    assert sign(without_rule) != sign(dict(base, rule_id=""))

    # And the whole thing still matches the frozen cross-language vector.
    vectors = json.loads(
        (Path(__file__).parent / "../../conformance/fixtures/signing_vectors.json")
        .resolve()
        .read_text()
    )
    vector_event = dict(vectors["events"][0])
    vector_event["sdk_session_id"] = vectors["session_id"]
    assert sign(vector_event, vectors["chain_format"]) == vector_event["sdk_sig"]
