"""Descriptor content-scan conformance (Python side). Twin:
sdk-typescript/tests/unit/tool-poisoning.test.ts (the tool_descriptor_scan.json
describe). The fixture pins the exact reason arrays (order included) for
both SDKs: schema description/default surfaces, comment-concealment, bidi
presence, the opt-in decoding boundary, and the loud walk cap. A divergence
means one language's discovery scan sees hostile metadata the other misses.
"""
import json
from pathlib import Path

import pytest

from obsvr.integrations.mcp import scan_tool_description

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/tool_descriptor_scan.json")
    .resolve()
    .read_text()
)


@pytest.mark.parametrize(
    "case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]]
)
def test_descriptor_scan_matches_pinned_reasons(case):
    deob = {"enabled": True} if case.get("deobfuscation_enabled") else None
    assert scan_tool_description(case["tool"], deob) == case["expect_reasons"]
