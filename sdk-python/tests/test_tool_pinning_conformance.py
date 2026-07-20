"""Cross-SDK tool-descriptor pinning conformance harness (Python side). Twin:
sdk/tests/unit/tool-pinning-conformance.test.ts. Runs every case in
conformance/fixtures/tool_pinning.json; a divergence from the fixture (or
from the TS harness) is a release blocker unless recorded in
conformance/known-divergences.md."""

import json
from pathlib import Path

import pytest

from obsvr.tool_pinning import (
    _canonical_json_for_hash,
    ToolPinStore,
    canonical_tool_descriptor,
    evaluate_tool_pin,
    tool_descriptor_hash,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/tool_pinning.json")
    .resolve()
    .read_text()
)


@pytest.mark.parametrize(
    "case", FIXTURE["hash_cases"], ids=[c["id"] for c in FIXTURE["hash_cases"]]
)
def test_descriptor_canonicalization_and_hash(case):
    assert _canonical_json_for_hash(canonical_tool_descriptor(case["descriptor"])) == (
        case["expect"]["canonical"]
    )
    assert tool_descriptor_hash(case["descriptor"]) == case["expect"]["hash"]


@pytest.mark.parametrize(
    "case", FIXTURE["hash_cases"], ids=[c["id"] + "-attr" for c in FIXTURE["hash_cases"]]
)
def test_attr_style_descriptor_hashes_identically(case):
    """mcp.types.Tool exposes fields as ATTRIBUTES; the projection must hash
    an attr-style object identically to the wire dict (dual-access parity)."""

    class AttrTool:
        pass

    t = AttrTool()
    for k, v in case["descriptor"].items():
        setattr(t, k, v)
    assert tool_descriptor_hash(t) == case["expect"]["hash"]


@pytest.mark.parametrize(
    "case",
    FIXTURE["hash_error_cases"],
    ids=[c["id"] for c in FIXTURE["hash_error_cases"]],
)
def test_cross_sdk_unstable_descriptor_fails_closed(case):
    with pytest.raises(Exception):
        tool_descriptor_hash(case["descriptor"])


@pytest.mark.parametrize(
    "case", FIXTURE["decision_cases"], ids=[c["id"] for c in FIXTURE["decision_cases"]]
)
def test_pin_decision(case):
    v = evaluate_tool_pin(
        config_pin=case["input"]["config_pin"],
        tofu_pin=case["input"]["tofu_pin"],
        observed_hash=case["input"]["observed_hash"],
        mode=case["input"]["mode"],
        require_pin=case["input"]["require_pin"],
    )
    assert v["status"] == case["expect"]["status"]
    assert v["enforcement"] == case["expect"]["enforcement"]
    assert v.get("expected") == case["expect"]["expected"]
    assert v.get("observed") == case["expect"]["observed"]
    assert v.get("source") == case["expect"]["source"]
    assert v.get("reason") == case["expect"]["reason"]


# ── Pin store invariants (not fixture-expressible: stateful) ─────────────────


def test_tofu_never_silently_repins():
    store = ToolPinStore()
    store.record_tofu_pin("t", "aaaa")
    store.record_tofu_pin("t", "bbbb")  # attacker swap trying to ratify itself
    assert store.get_tofu_pin("t") == "aaaa"


def test_verdicts_overwritable_latest_discovery_wins():
    store = ToolPinStore()
    store.set_verdict("t", {"status": "ok", "enforcement": "none"})
    store.set_verdict("t", {"status": "mismatch", "enforcement": "block"})
    assert store.get_verdict("t")["status"] == "mismatch"


def test_pinned_names_reflect_tofu_recordings():
    store = ToolPinStore()
    store.record_tofu_pin("a", "h1")
    store.record_tofu_pin("b", "h2")
    assert sorted(store.pinned_names()) == ["a", "b"]
    assert store.saturated() is False
