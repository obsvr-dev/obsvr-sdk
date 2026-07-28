"""Cross-SDK protocol-facet conformance (Python side). Twin:
sdk-typescript/tests/unit/protocol-facets-conformance.test.ts.

Two layers are pinned: the decomposition itself, and the rule semantics on top
of it - including the direction that matters most, which is that text the
decomposer cannot speak about MATCHES rather than passing.
"""

import json
from pathlib import Path

import pytest

from obsvr.protocol_facets import (
    MAX_FACET_INPUT,
    extract_sql_facets,
    strip_sql_comments,
)
from obsvr.rules import PolicyRule, evaluate_policy_rules

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/protocol_facets.json")
    .resolve()
    .read_text(encoding="utf-8")
)

FACET_CASES = FIXTURE["facet_cases"]
RULE_CASES = FIXTURE["rule_cases"]


@pytest.mark.parametrize("case", FACET_CASES, ids=[c["id"] for c in FACET_CASES])
def test_sql_facet_decomposition(case):
    assert extract_sql_facets(case["text"]) == case["expect"]


@pytest.mark.parametrize("case", RULE_CASES, ids=[c["id"] for c in RULE_CASES])
def test_protocol_facet_rule(case):
    result = evaluate_policy_rules([PolicyRule(**case["rule"])], case["text"])
    assert result.get("decision") == case["expect"]["decision"], case["id"]
    if "rule_id" in case["expect"]:
        assert result.get("rule_id") == case["expect"]["rule_id"], case["id"]
    if "reason_code" in case["expect"]:
        assert result.get("reason_code") == case["expect"]["reason_code"], case["id"]


class TestBoundsAndPurity:
    def test_refuses_input_past_the_length_bound(self):
        huge = "SELECT 1 FROM t WHERE x = " + "a" * MAX_FACET_INPUT
        facets = extract_sql_facets(huge)
        assert facets["parsed"] is False
        assert facets["reason"] == "input_too_long"

    def test_refuses_input_past_the_token_bound(self):
        # Comma-separated columns produce two tokens each, so this clears the
        # cap well inside the character bound.
        wide = "SELECT " + ",".join(f"c{i}" for i in range(1500)) + " FROM t"
        assert len(wide) <= MAX_FACET_INPUT
        facets = extract_sql_facets(wide)
        assert facets["parsed"] is False
        assert facets["reason"] == "too_many_tokens"

    def test_is_total_and_never_raises(self):
        for value in (
            None, 0, [], {}, "", "'", '"', "/*", "--", ";;;", "((((",
            "SELECT " + "(" * 500, " ", 'DROP TABLE "unterminated',
        ):
            result = extract_sql_facets(value)
            assert isinstance(result["parsed"], bool)

    def test_is_pure(self):
        q = "SELECT lower(a) FROM x JOIN y ON 1=1"
        assert extract_sql_facets(q) == extract_sql_facets(q)

    def test_comment_stripping_leaves_literals_intact(self):
        assert (
            strip_sql_comments("SELECT '/* not a comment */' FROM t")
            == "SELECT '/* not a comment */' FROM t"
        )
        assert strip_sql_comments("SELECT 1 /* gone */ FROM t") == "SELECT 1   FROM t"
