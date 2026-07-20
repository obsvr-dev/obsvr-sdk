"""PII policy parity tests — mirror the TS SDK hook.ts test vectors."""

import pytest

from obsvr.policy import (
    apply_observe_policy,
    apply_pre_call_policy,
    redact_builtin_pii,
    resolve_pii_policy,
    run_builtin_pii_scan,
)
from obsvr.config import ResolvedConfig


# ---------------------------------------------------------------------------
# run_builtin_pii_scan
# ---------------------------------------------------------------------------


def test_scan_email():
    r = run_builtin_pii_scan("contact john@example.com please")
    assert r["pii_detected"] is True
    assert "email" in r["detected_types"]


def test_scan_ssn():
    r = run_builtin_pii_scan("ssn 123-45-6789")
    assert r["pii_detected"] is True
    assert "ssn" in r["detected_types"]


def test_scan_ssn_dot():
    r = run_builtin_pii_scan("ssn 123.45.6789")
    assert r["pii_detected"] is True
    assert "ssn" in r["detected_types"]


def test_scan_credit_card():
    r = run_builtin_pii_scan("card 4111111111111111")
    assert r["pii_detected"] is True
    assert "credit_card" in r["detected_types"]


def test_scan_phone():
    r = run_builtin_pii_scan("call 555-867-5309")
    assert r["pii_detected"] is True
    assert "phone" in r["detected_types"]


def test_scan_api_key_sk():
    r = run_builtin_pii_scan("key sk-abcdefghij1234567890")
    assert r["pii_detected"] is True
    assert "api_key" in r["detected_types"]


def test_scan_api_key_akia():
    # Parity with TS: an AKIA key is labeled by the dedicated aws_access_key
    # pattern (severity block), not double-labeled api_key.
    r = run_builtin_pii_scan("aws AKIAIOSFODNN7EXAMPLE")
    assert r["pii_detected"] is True
    assert r["detected_types"] == ["aws_access_key"]


def test_scan_clean():
    r = run_builtin_pii_scan("hello world, no PII here!")
    assert r["pii_detected"] is False
    assert r["detected_types"] == []


# ---------------------------------------------------------------------------
# redact_builtin_pii
# ---------------------------------------------------------------------------


def test_redact_email():
    assert "[REDACTED_EMAIL]" in redact_builtin_pii("mail john@example.com please")
    assert "john@example.com" not in redact_builtin_pii("mail john@example.com please")


def test_redact_ssn():
    assert "[REDACTED_SSN]" in redact_builtin_pii("ssn 123-45-6789")


def test_redact_scrubs_zero_width_obfuscated_pii():
    # detection normalizes; redaction must de-obfuscate too, or a "redact"
    # verdict would forward the SSN intact.
    zwsp = "​"
    out = redact_builtin_pii(f"my ssn is 123-{zwsp}45-{zwsp}6789 ok")
    assert "[REDACTED_SSN]" in out
    assert "6789" not in out


def test_redact_scrubs_fullwidth_compatibility_pii():
    # matching on the NFKC-folded view scrubs PII written in fullwidth /
    # compatibility digits. The redacted string is what the provider receives,
    # so this closes the actual data path, not just the audit copy. (Python's
    # `\d` already matches fullwidth digits, but folding keeps the two SDKs
    # identical and covers forms `\d` misses.)
    fw_phone = redact_builtin_pii("call ５５５.１２３.４５６７ now")
    assert "[REDACTED_PHONE]" in fw_phone
    assert not any("０" <= c <= "９" for c in fw_phone)
    assert redact_builtin_pii("ssn ６５４-３２-１０９８ x") == "ssn [REDACTED_SSN] x"


def test_redact_preserves_non_pii_fullwidth_text():
    # Folding is LOCATE-only: only the matched PII span may change. Legit
    # fullwidth / CJK text with no PII passes through byte-for-byte, and in a
    # mixed prompt only the PII is replaced — the rest reaches the provider
    # exactly as written.
    no_pii = "ＨＥＬＬＯ ＷＯＲＬＤ 日本語 ①②③"
    assert redact_builtin_pii(no_pii) == no_pii
    assert redact_builtin_pii("ＨＥＬＬＯ call 555-123-4567") == "ＨＥＬＬＯ call [REDACTED_PHONE]"


def test_separatorless_ssn_gated_on_context():
    # separator-less SSN caught only with adjacent SSN context (no FP on a
    # bare 9-digit run).
    assert "ssn" in run_builtin_pii_scan("my ssn 123456789")["detected_types"]
    assert "[REDACTED_SSN]" in redact_builtin_pii("SSN: 123456789")
    assert "ssn" not in run_builtin_pii_scan("order 123456789 shipped")["detected_types"]


def test_ssn_context_pattern_bounded_on_whitespace_flood():
    # regression: the SSN-context pattern once used unbounded \s* around the
    # optional ':' / '#', which backtracks quadratically on a whitespace flood
    # ("ssn" + 40k spaces took ~17s). Bounded \s{0,8} keeps it near-instant.
    import time

    payload = "ssn" + (" " * 40000) + "x"
    start = time.time()
    redact_builtin_pii(payload)
    assert (time.time() - start) < 1.0


def test_redact_cc():
    assert "[REDACTED_CC]" in redact_builtin_pii("card 4111111111111111")


def test_redact_phone():
    assert "[REDACTED_PHONE]" in redact_builtin_pii("call 555-867-5309")


def test_redact_api_key():
    assert "[REDACTED_API_KEY]" in redact_builtin_pii("key sk-abcdefghij1234567890")


def test_redact_no_pii():
    text = "hello world"
    assert redact_builtin_pii(text) == text


# ---------------------------------------------------------------------------
# resolve_pii_policy
# ---------------------------------------------------------------------------


def test_resolve_ssn_default_blocks():
    r = resolve_pii_policy(["ssn"], {})
    assert r["action"] == "block"
    assert "ssn" in r["blocked_types"]


def test_resolve_email_default_redacts():
    r = resolve_pii_policy(["email"], {})
    assert r["action"] == "redact"
    assert "email" in r["redacted_types"]


def test_resolve_phone_default_redacts():
    r = resolve_pii_policy(["phone"], {})
    assert r["action"] == "redact"


def test_resolve_credit_card_blocks():
    r = resolve_pii_policy(["credit_card"], {})
    assert r["action"] == "block"


def test_resolve_api_key_blocks():
    r = resolve_pii_policy(["api_key"], {})
    assert r["action"] == "block"


def test_resolve_rule_override_to_redact():
    r = resolve_pii_policy(["ssn"], {"rules": {"ssn": "redact"}})
    assert r["action"] == "redact"
    assert "ssn" in r["redacted_types"]


def test_resolve_rule_override_to_detect_only():
    r = resolve_pii_policy(["email"], {"rules": {"email": "detect_only"}})
    assert r["action"] == "detect_only"


def test_resolve_default_policy_overrides_builtin():
    r = resolve_pii_policy(["email"], {"default": "block"})
    assert r["action"] == "block"


def test_resolve_block_wins_over_redact():
    r = resolve_pii_policy(["ssn", "email"], {})
    assert r["action"] == "block"


# ---------------------------------------------------------------------------
# apply_pre_call_policy
# ---------------------------------------------------------------------------


def _cfg(**kw):
    defaults = dict(api_key="test", sample_rate=1)
    defaults.update(kw)
    return ResolvedConfig(**defaults)


def test_pre_call_allows_clean():
    r = apply_pre_call_policy("hello world", _cfg(pii_policy={}))
    assert r["decision"] == "allow"
    assert r["compliance"]["action_taken"] == "allowed"


def test_pre_call_blocks_ssn():
    r = apply_pre_call_policy("ssn 123-45-6789", _cfg(pii_policy={}))
    assert r["decision"] == "block"
    assert r["compliance"]["event_type"] == "blocked_call"
    assert "[REDACTED_SSN]" in r["redacted_prompt"]


def test_pre_call_redacts_email():
    r = apply_pre_call_policy("mail john@example.com", _cfg(pii_policy={}))
    assert r["decision"] == "redact"
    assert r["compliance"]["action_taken"] == "redacted"


def test_pre_call_no_policy_allows_all():
    r = apply_pre_call_policy("ssn 123-45-6789", _cfg())
    assert r["decision"] == "allow"


def test_pre_call_hook_block_overrides_allow():
    cfg = _cfg(pii_policy={}, on_pre_call=lambda e: "block")
    r = apply_pre_call_policy("hello world", cfg)
    assert r["decision"] == "block"
    assert r["compliance"]["action_reason"] == "policy_violation"
    assert r["compliance"]["action_source"] == "customer_hook"


def test_pre_call_hook_allow_overrides_builtin_block():
    cfg = _cfg(pii_policy={}, on_pre_call=lambda e: "allow")
    r = apply_pre_call_policy("ssn 123-45-6789", cfg)
    assert r["decision"] == "allow"
    assert r["compliance"]["action_reason"] == "customer_override"
    assert r["compliance"]["action_source"] == "customer_hook"


# ---------------------------------------------------------------------------
# apply_observe_policy
# ---------------------------------------------------------------------------


def test_observe_policy_blocks_downgraded_to_redact():
    r = apply_observe_policy("ssn 123-45-6789", _cfg(pii_policy={}))
    assert r["should_redact_stored"] is True
    assert r["compliance"]["action_taken"] == "redacted"
    assert r["compliance"]["event_type"] == "llm_call"
    assert r["compliance"]["blocked_types"] == []
    assert "ssn" in r["compliance"]["redacted_types"]


def test_observe_policy_clean_no_redact():
    r = apply_observe_policy("hello world", _cfg(pii_policy={}))
    assert r["should_redact_stored"] is False
    assert r["compliance"]["action_taken"] == "allowed"


def test_observe_policy_no_policy():
    r = apply_observe_policy("ssn 123-45-6789", _cfg())
    assert r["should_redact_stored"] is False


# ── scan scope: DECISION scans scan_text (last user turn), storage keeps full ──
# Parity with the TS wrapper's extractLastUserMessageText (KD-1 resolved).

def test_scan_text_scopes_the_decision_not_storage():
    full = "SSN 123-45-6789 was in an earlier turn\nplease summarize"
    # PII only in the earlier turn -> last-turn scan does not see it -> allow.
    r = apply_pre_call_policy(
        full, _cfg(pii_policy={"ssn": "block"}),
        provider="openai", operation="chat", scan_text="please summarize",
    )
    assert r["decision"] == "allow"
    # ...but the FULL prompt is still what gets stored (redacted), not just the
    # last turn — storage and decision scope are decoupled.
    assert "please summarize" in r["redacted_prompt"]
    assert "earlier turn" in r["redacted_prompt"]


def test_scan_text_blocks_when_pii_in_last_turn():
    r = apply_pre_call_policy(
        "hello\nhere is my SSN 123-45-6789", _cfg(pii_policy={"ssn": "block"}),
        provider="openai", operation="chat", scan_text="here is my SSN 123-45-6789",
    )
    assert r["decision"] == "block"


def test_scan_text_defaults_to_full_prompt():
    # No scan_text -> scans the full prompt (back-compat for callers without
    # message structure, e.g. the autogen/mcp integrations).
    r = apply_pre_call_policy(
        "SSN 123-45-6789 anywhere", _cfg(pii_policy={"ssn": "block"}),
        provider="openai", operation="chat",
    )
    assert r["decision"] == "block"
