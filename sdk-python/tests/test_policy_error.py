"""The typed policy-block error (Python side).

Twin: sdk-typescript/tests/unit/policy-error.test.ts. Both drive every case in
conformance/fixtures/error_parity.json through their own construction choke
point and must produce the same serialized fields, because the promise is that
a caller can branch on a policy block identically in either language.
"""
import json
from pathlib import Path

import pytest

from obsvr.errors import (
    ObsvrPolicyError,
    ObsvrUnknownPolicyError,
    create_policy_error,
    policy_block_message,
)
from obsvr.events import blocked_call_error
from obsvr.reason_codes import REASON_CODES

FIXTURE_PATH = (
    Path(__file__).parent / "../../conformance/fixtures/error_parity.json"
).resolve()


def _fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def _input_to_params(data):
    """Drop the fixture's explicit nulls: they mean absent, not null."""
    return {k: v for k, v in data.items() if v is not None}


class TestErrorParityVectors:
    def test_has_cases(self):
        assert len(_fixture()["cases"]) > 0

    def test_every_case_produces_the_pinned_serialized_fields(self):
        for case in _fixture()["cases"]:
            err = create_policy_error(_input_to_params(case["input"]))
            expect = case["expect"]

            assert err.type == expect["type"], case["id"]
            assert err.reason_code == expect["reason_code"], case["id"]
            assert err.rule_id == expect["rule_id"], case["id"]
            assert str(err) == expect["message"], case["id"]
            assert err.decision == expect["decision"], case["id"]

    def test_every_reason_code_comes_from_the_closed_registry(self):
        for case in _fixture()["cases"]:
            assert case["expect"]["reason_code"] in REASON_CODES


class TestWhatCallersCanRelyOn:
    def test_still_catchable_as_runtimeerror(self):
        """Callers who previously caught RuntimeError around a governed call
        keep catching the block. The typed error is additive, not a migration."""
        err = create_policy_error({"action_reason": "pii_detected"})
        assert isinstance(err, RuntimeError)
        assert isinstance(err, ObsvrPolicyError)

    def test_distinguishes_a_block_from_a_provider_failure(self):
        provider_failure = RuntimeError("503 Service Unavailable")
        policy_block = create_policy_error({"action_reason": "policy_violation"})

        assert isinstance(policy_block, ObsvrPolicyError)
        assert not isinstance(provider_failure, ObsvrPolicyError)

    def test_type_string_is_explicit_not_derived_from_the_class_name(self):
        err = create_policy_error({"action_reason": "pii_detected"})
        assert err.type == "obsvr_policy_error"

    def test_serializes_to_the_shape_the_fixture_pins(self):
        err = create_policy_error(
            {
                "action_reason": "policy_violation",
                "action_source": "policy_rules",
                "rule_id": "r1",
            }
        )
        assert err.to_dict() == {
            "type": "obsvr_policy_error",
            "reason_code": "POLICY_VIOLATION",
            "rule_id": "r1",
            "decision": {
                "action_taken": "blocked",
                "action_reason": "policy_violation",
                "action_source": "policy_rules",
            },
            "message": "[obsvr] Request blocked by policy (policy violation)",
        }

    def test_unknown_category_never_degrades_to_a_bare_exception(self):
        err = create_policy_error(
            {"action_reason": "something_new", "action_source": "server"}
        )
        assert isinstance(err, ObsvrUnknownPolicyError)
        assert isinstance(err, ObsvrPolicyError)
        assert err.type == "obsvr_unknown_policy_error"
        assert err.reason_code == "UNKNOWN_BLOCKED"

    def test_raising_and_catching_reads_the_way_a_caller_would_write_it(self):
        with pytest.raises(ObsvrPolicyError) as caught:
            raise create_policy_error(
                {"action_reason": "pii_detected", "rule_id": "r-pii"}
            )
        assert caught.value.reason_code == "PII_DETECTED"
        assert caught.value.rule_id == "r-pii"


class TestMessageIsACompatibilityContract:
    def test_preserves_the_exact_strings_callers_matched_on(self):
        assert policy_block_message("pii_detected") == (
            "[obsvr] Request blocked by policy (PII detected)"
        )
        assert policy_block_message("policy_violation") == (
            "[obsvr] Request blocked by policy (policy violation)"
        )

    def test_keeps_the_old_wording_for_unclassifiable_categories(self):
        assert policy_block_message("anything_else") == (
            "[obsvr] Request blocked by policy (policy violation)"
        )
        assert policy_block_message(None) == (
            "[obsvr] Request blocked by policy (policy violation)"
        )


class TestEverySurfaceUsesTheChokePoint:
    def test_blocked_call_error_returns_the_typed_error(self):
        compliance = {
            "event_type": "blocked_call",
            "policy_version": "a1b2c3d4e5f60718",
            "action_taken": "blocked",
            "action_reason": "pii_detected",
            "action_source": "builtin",
            "redacted_types": [],
            "blocked_types": ["email"],
        }
        err = blocked_call_error(compliance)
        assert isinstance(err, ObsvrPolicyError)
        assert err.reason_code == "PII_DETECTED"
        assert err.decision["policy_version"] == "a1b2c3d4e5f60718"
        assert str(err) == "[obsvr] Request blocked by policy (PII detected)"

    def test_no_module_constructs_a_block_error_outside_the_choke_point(self):
        """The old pattern was an inlined RuntimeError built at the call site,
        which is how two sites come to classify the same block differently.
        Only errors.py may construct one.

        This looks for error CONSTRUCTION, not for the message text: the MCP,
        Haystack and pydantic-ai integrations raise their own typed errors
        carrying the same phrase, and a blocked event's policy_reason can hold
        it too. Neither is an error built at the call site, so neither is what
        this guards against.
        """
        import re

        pkg_dir = Path(__file__).parent.parent / "obsvr"
        construction = re.compile(
            r"(RuntimeError|Exception)\(\s*f?[\"'][^\"']*blocked by policy", re.I
        )
        offenders = [
            str(path.relative_to(pkg_dir))
            for path in pkg_dir.rglob("*.py")
            if path.name != "errors.py" and construction.search(path.read_text())
        ]
        assert offenders == []
