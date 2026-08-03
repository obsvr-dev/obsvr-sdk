"""The declared conflict-resolution mode, end to end.

``obsvr.init(rule_resolution="deny_wins")`` is the opt-in: the engine
evaluates order-insensitively with the strongest action prevailing, the
stamped ``policy_version`` commits to the declared semantics, decisions
carry engine version ``obsvr-rules/2``, and ``explain()`` predicts the mode
in force. Undeclared keeps the original first-match contract and the
original ``policy_version`` bytes; an unknown declaration is refused at
init. The engine-level semantics are pinned in test_rule_precedence.py —
this suite proves the declaration actually reaches them.
"""

import pytest

import obsvr
from obsvr import sender
from obsvr.config import ResolvedConfig, _reset
from obsvr.decision_record import engine_version_for
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.tools import govern_tool
from obsvr.policy import apply_pre_call_policy, explain
from obsvr.rules import PolicyRule, derive_policy_version

ALLOW_FIRST = [
    PolicyRule(
        id="allow-topic",
        name="allow the topic",
        enabled=True,
        action="flag",
        type="topic_allow",
        conditions={"topics": ["trigger"]},
    ),
    PolicyRule(
        id="block-keyword",
        name="block the keyword",
        enabled=True,
        action="block",
        type="keyword",
        conditions={"keywords": ["trigger"]},
    ),
]
BLOCK_FIRST = list(reversed(ALLOW_FIRST))


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())
    _reset()
    sender._reset_sender()
    yield
    _reset()


class TestDeclaredDenyWins:
    def test_the_declaration_reaches_the_pipeline_in_both_orders(self):
        for rules in (ALLOW_FIRST, BLOCK_FIRST):
            cfg = ResolvedConfig(
                api_key="k", policy_rules=rules, rule_resolution="deny_wins"
            )
            result = apply_pre_call_policy("a trigger word", cfg)
            assert result["decision"] == "block", (
                "deny_wins must block regardless of the allow rule's position"
            )
            compliance = result["compliance"]
            assert compliance["engine_version"] == engine_version_for("deny_wins")
            assert compliance["policy_version"] == derive_policy_version(
                rules, "deny_wins"
            )

    def test_undeclared_keeps_the_first_match_contract(self):
        cfg = ResolvedConfig(api_key="k", policy_rules=ALLOW_FIRST)
        result = apply_pre_call_policy("a trigger word", cfg)
        assert result["decision"] == "allow", (
            "undeclared stays first-match: the earlier topic_allow shields"
        )
        compliance = result["compliance"]
        assert compliance["engine_version"] == engine_version_for(None)
        assert compliance["policy_version"] == derive_policy_version(ALLOW_FIRST)

    def test_a_governed_tool_call_is_refused_under_the_declaration(self, monkeypatch):
        captured = []
        monkeypatch.setattr(
            sender, "send_audit_async", lambda config, event: captured.append(event)
        )
        obsvr.init(
            api_key="k",
            policy_rules=ALLOW_FIRST,
            pii_policy={},
            rule_resolution="deny_wins",
            policy_refresh_interval_s=0,
        )

        class _Tool:
            name = "helper"

            def __init__(self):
                self.calls = []

            def _run(self, note=""):
                self.calls.append(note)
                return "done"

        tool = _Tool()
        governed = govern_tool(tool)
        with pytest.raises(ObsvrPolicyError):
            governed._run(note="a trigger word")
        assert tool.calls == []
        blocked = [e for e in captured if e.get("action_taken") == "blocked"]
        assert blocked and blocked[0]["rule_id"] == "block-keyword"

    def test_explain_predicts_the_declared_mode(self):
        cfg = ResolvedConfig(
            api_key="k", policy_rules=ALLOW_FIRST, rule_resolution="deny_wins"
        )
        prediction = explain("a trigger word", config=cfg)
        assert prediction["decision"] == "block"
        assert prediction["rule_id"] == "block-keyword"

    def test_an_unknown_declaration_is_refused_at_init(self):
        with pytest.raises(ValueError, match="rule resolution"):
            obsvr.init(api_key="k", rule_resolution="deny-wins")
