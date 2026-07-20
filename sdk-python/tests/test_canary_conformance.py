"""Cross-SDK canary-leak conformance harness (Python side). Twin:
sdk/tests/unit/canary-conformance.test.ts. Pins the deterministic,
registry-independent detection (hash of the canonical token; candidate
extraction over raw + de-obfuscation views). Minting randomness is not
fixture-pinned; the stateful mint/scan integration is tested separately."""

import base64
import json
from pathlib import Path

import pytest

from obsvr.canary import (
    CANARY_PREFIX,
    _reset_canaries,
    canary_candidates,
    canary_registry_size,
    mint_canary,
    scan_for_canary,
)
from obsvr.decision_record import sha256_hex

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/canary.json").resolve().read_text()
)


@pytest.mark.parametrize(
    "case", FIXTURE["hash_cases"], ids=[c["id"] for c in FIXTURE["hash_cases"]]
)
def test_canonical_token_hash(case):
    assert sha256_hex(case["token"].lower()) == case["expect"]["hash"]


@pytest.mark.parametrize(
    "case", FIXTURE["candidate_cases"], ids=[c["id"] for c in FIXTURE["candidate_cases"]]
)
def test_candidate_extraction(case):
    assert canary_candidates(case["input"]) == case["expect"]


class TestMintScanIntegration:
    def setup_method(self):
        _reset_canaries()

    def teardown_method(self):
        _reset_canaries()

    def test_minted_token_leaks_and_raw_never_in_result(self):
        c = mint_canary(label="system-prompt")
        assert canary_registry_size() == 1
        assert scan_for_canary("nothing here")["leaked"] is False
        r = scan_for_canary("the model said: " + c["token"])
        assert r["leaked"] is True
        assert r["hits"][0]["id"] == c["id"]
        assert r["hits"][0]["label"] == "system-prompt"
        assert r["hits"][0]["via"] == "raw"
        # Hygiene: the raw token never appears in the scan result.
        blob = json.dumps(r)
        assert c["token"] not in blob
        assert c["token"][len(CANARY_PREFIX):] not in blob

    def test_base64_encoded_exfil_caught(self):
        c = mint_canary()
        encoded = base64.b64encode(c["token"].encode()).decode()
        r = scan_for_canary("exfil: " + encoded)
        assert r["leaked"] is True
        assert r["hits"][0]["via"] == "base64"

    def test_unminted_matching_token_is_not_a_leak(self):
        mint_canary()
        fake = CANARY_PREFIX + "0" * 32
        assert scan_for_canary("sees " + fake)["leaked"] is False

    def test_mint_returns_fresh_token_each_call(self):
        a = mint_canary()
        b = mint_canary()
        assert a["token"] != b["token"]
        assert len(a["token"]) == len(CANARY_PREFIX) + 32
        assert canary_registry_size() == 2
