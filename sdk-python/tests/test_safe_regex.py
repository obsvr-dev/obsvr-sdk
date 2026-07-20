"""Security regression tests: ReDoS guard for customer-supplied regex rules."""
import time

from obsvr.safe_regex import (
    compile_safe_regex,
    safe_regex_search,
    validate_regex_pattern,
)
from obsvr.rules import PolicyRule, evaluate_policy_rules


class TestValidateRegexPattern:
    def test_accepts_simple_safe_patterns(self):
        assert validate_regex_pattern(r"\bwire transfer\b")[0] is True
        assert validate_regex_pattern(r"^user_[0-9]{4}$")[0] is True
        assert validate_regex_pattern(r"credit\s?card")[0] is True

    def test_rejects_nested_quantifier(self):
        ok, reason = validate_regex_pattern(r"(a+)+$")
        assert ok is False
        assert reason == "nested_quantifier"

    def test_rejects_quantified_class_groups(self):
        assert validate_regex_pattern(r"(a*)*")[0] is False
        assert validate_regex_pattern(r"([a-z]+)+")[0] is False
        assert validate_regex_pattern(r"([0-9]*){2,}")[0] is False

    def test_rejects_brace_quantifier_nesting(self):
        # these passed the prior [+*]-only regex and could hang the
        # thread for minutes (Python re has no timeout; the 50 KB cap does not
        # tame super-linear backtracking).
        assert validate_regex_pattern(r"(a{2,})+$")[1] == "nested_quantifier"
        assert validate_regex_pattern(r"(\d{2,})+$")[1] == "nested_quantifier"
        assert validate_regex_pattern(r"([a-z]{3,})*$")[1] == "nested_quantifier"
        assert validate_regex_pattern(r"((a+)b?)+$")[1] == "nested_quantifier"  # nested deeper
        assert validate_regex_pattern(r"(?:a+)+")[1] == "nested_quantifier"

    def test_does_not_over_reject_fixed_or_unnested(self):
        assert validate_regex_pattern(r"(a{3})+")[0] is True  # fixed inner {n}
        assert validate_regex_pattern(r"(abc)+")[0] is True
        assert validate_regex_pattern(r"[+*]{1,5}")[0] is True  # + and * are literals
        assert validate_regex_pattern(r"\d{3}-\d{2}-\d{4}")[0] is True

    def test_polynomial_pattern_completes_bounded(self):
        # Deep nesting is now rejected; verify a rejected pattern is no-match and
        # a passing-but-suspicious one stays bounded under the input cap.
        assert compile_safe_regex(r"((a+)b?)+$") is None

    def test_rejects_quantified_alternation(self):
        ok, reason = validate_regex_pattern(r"(a|aa)+")
        assert ok is False
        assert reason == "quantified_alternation"

    def test_rejects_wrapped_quantified_alternation(self):
        # ((a|aa))+ hid the alternation one paren deeper, so the shallow
        # QUANTIFIED_ALTERNATION regex (which needs the quantifier right after
        # the alternation's ')') did not fire — yet it backtracks exponentially
        # like (a|aa)+. The structural scan now flags it via the group's
        # alternation flag.
        assert validate_regex_pattern(r"((a|aa))+$")[0] is False
        assert validate_regex_pattern(r"((a|aa))+$")[1] == "nested_quantifier"
        assert validate_regex_pattern(r"((x|xx|xxx))*")[0] is False
        assert validate_regex_pattern(r"(?:(a|ab))+")[0] is False
        assert validate_regex_pattern(r"(z(a|aa))+")[0] is False
        # Un-quantified alternation nesting is fine — no growth quantifier on it.
        assert validate_regex_pattern(r"((a|aa))")[0] is True
        assert validate_regex_pattern(r"(foo|bar|baz)")[0] is True

    def test_rejects_backreferences(self):
        ok, reason = validate_regex_pattern(r"(a)\1+")
        assert ok is False
        assert reason == "backreferences_not_allowed"

    def test_rejects_invalid_syntax(self):
        assert validate_regex_pattern(r"([unclosed")[0] is False

    def test_rejects_empty_and_oversized(self):
        assert validate_regex_pattern("")[0] is False
        assert validate_regex_pattern("a" * 600)[0] is False

    def test_rejects_too_many_quantifiers(self):
        pattern = "".join(f"a{i}+" for i in range(25))
        assert validate_regex_pattern(pattern)[0] is False


class TestCompileSafeRegex:
    def test_returns_pattern_for_safe(self):
        compiled = compile_safe_regex(r"hello\s+world")
        assert compiled is not None
        assert compiled.search("hello   world")

    def test_returns_none_for_dangerous(self):
        assert compile_safe_regex(r"(a+)+$") is None


class TestSafeRegexSearch:
    def test_matches_safe_patterns(self):
        assert safe_regex_search("secret", "this contains a secret word") is True
        assert safe_regex_search("secret", "nothing here") is False

    def test_rejected_patterns_are_no_match(self):
        assert safe_regex_search(r"(a+)+$", "a" * 30 + "!") is False

    def test_bounded_input_length(self):
        huge = "x" * 200_000 + "needle"
        start = time.time()
        assert safe_regex_search("needle", huge) is False
        assert time.time() - start < 1.0


class TestPolicyRulesWithGuard:
    def test_does_not_freeze_on_catastrophic_pattern(self):
        rule = PolicyRule(
            id="rule-redos", name="malicious", enabled=True,
            action="block", type="regex",
            conditions={"pattern": r"(a+)+$"},
        )
        evil = "a" * 40 + "!"
        start = time.time()
        result = evaluate_policy_rules([rule], evil, "prompt")
        assert time.time() - start < 1.0
        assert result["decision"] == "allow"

    def test_still_enforces_safe_regex_rules(self):
        rule = PolicyRule(
            id="rule-safe", name="wire transfer", enabled=True,
            action="block", type="regex",
            conditions={"pattern": r"wire\s+transfer"},
        )
        result = evaluate_policy_rules([rule], "please make a wire transfer now", "prompt")
        assert result["decision"] == "block"
        assert result["rule_id"] == "rule-safe"
