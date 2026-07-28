"""Cross-SDK pre-call eval-context conformance (Python side). Twin:
sdk-typescript/tests/unit/eval-context-conformance.test.ts.

Each fixture case is one customer rule plus the four context values a gate
reads, and the verdict that rule must reach. Python has ONE shared pre-call
(``apply_pre_call_policy``) behind both ``wrap()`` and every framework
integration, so one assertion per case covers both of its doors; the
TypeScript twin has two separate doors and asserts each case through both.
``model_gate`` and ``environment_gate`` are the probe because they read this
context and nothing else, so a context that differs by entry point shows up
as those rules quietly never firing.
"""

import json
import os

import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset, get_config
from obsvr.policy import apply_pre_call_policy
from obsvr.rules import PolicyRule


def _fixture_path(rel: str) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        candidate = os.path.join(here, rel)
        if os.path.exists(candidate):
            return candidate
        here = os.path.dirname(here)
    raise AssertionError(f"fixture not found: {rel}")


with open(_fixture_path("conformance/fixtures/eval_context.json"), encoding="utf-8") as fh:
    FIXTURE = json.load(fh)

CASES = FIXTURE["precall_context_cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_precall_eval_context(case):
    if case["sdk_support"].get("py") == "skip":
        pytest.skip(f"{case['id']}: sdk_support py=skip")
    _reset()
    sender._reset_sender()
    obsvr.init(
        api_key="k",
        ingest_url="http://localhost:9",
        environment=case["environment"],
        policy_rules=[PolicyRule(**case["rule"])],
    )
    result = apply_pre_call_policy(
        case["prompt"],
        get_config(),
        provider=case["provider"],
        operation="test",
        model=case["model"],
    )
    assert result["decision"] == case["expect"]["decision"]
    if "rule_id" in case["expect"]:
        assert result["compliance"]["rule_id"] == case["expect"]["rule_id"]
