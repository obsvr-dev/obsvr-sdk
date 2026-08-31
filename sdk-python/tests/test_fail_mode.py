"""fail_mode ('open' | 'closed') parity tests for the Python SDK.

Mirrors sdk-typescript/tests/unit/fail-mode.test.ts. Default is 'open' (hook
timeout/error -> allow); 'closed' blocks on hook failure.
"""
import time

import obsvr
from obsvr.config import get_config
from obsvr.policy import apply_pre_call_policy


def _reset():
    obsvr._reset() if hasattr(obsvr, "_reset") else None
    from obsvr.config import _reset as cfg_reset
    cfg_reset()


class TestFailModeDefaultOpen:
    def test_defaults_to_open(self):
        _reset()
        obsvr.init(api_key="test")
        assert get_config().fail_mode == "open"

    def test_allows_on_hook_timeout(self):
        _reset()

        def slow_hook(_event):
            time.sleep(1.0)
            return "allow"

        obsvr.init(api_key="test", hook_timeout_ms=50, on_pre_call=slow_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "allow"

    def test_allows_on_hook_error(self):
        _reset()

        def bad_hook(_event):
            raise RuntimeError("hook exploded")

        obsvr.init(api_key="test", on_pre_call=bad_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "allow"
        assert result["compliance"]["action_taken"] == "hook_error"

    def test_hook_error_does_not_unblock_builtin_pii_block(self):
        # a broken hook must NOT downgrade a builtin PII block in fail-open.
        _reset()

        def bad_hook(_event):
            raise RuntimeError("hook exploded")

        obsvr.init(api_key="test", pii_policy={}, on_pre_call=bad_hook)  # ssn defaults to block
        result = apply_pre_call_policy(
            "my ssn is 123-45-6789", get_config(), provider="openai", operation="chat"
        )
        assert result["decision"] == "block"
        assert result["compliance"]["action_taken"] == "blocked"


class TestFailModeClosed:
    def test_carried_through_config(self):
        _reset()
        obsvr.init(api_key="test", fail_mode="closed")
        assert get_config().fail_mode == "closed"

    def test_blocks_on_hook_timeout(self):
        _reset()

        def slow_hook(_event):
            time.sleep(1.0)
            return "allow"

        obsvr.init(api_key="test", fail_mode="closed", hook_timeout_ms=50, on_pre_call=slow_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "block"

    def test_blocks_on_hook_error(self):
        _reset()

        def bad_hook(_event):
            raise RuntimeError("boom")

        obsvr.init(api_key="test", fail_mode="closed", on_pre_call=bad_hook)
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "block"

    def test_normal_verdict_unaffected(self):
        _reset()
        obsvr.init(api_key="test", fail_mode="closed", on_pre_call=lambda _e: "allow")
        result = apply_pre_call_policy("hello", get_config(), provider="openai", operation="chat")
        assert result["decision"] == "allow"


class TestKillSwitchNotHookOverridable:
    """EV-3: an enforcement-integrity gate block (paused project / revoked key /
    fail-closed staleness) must NOT be overridable by the customer hook. Mirrors
    the TS wrapper's `!degraded.degraded` guard. Regression test for the P0."""

    def test_allow_hook_cannot_override_kill_switch(self):
        from unittest.mock import patch

        _reset()
        obsvr.init(api_key="test", on_pre_call=lambda _e: "allow")
        with patch(
            "obsvr.remote.is_enforcement_degraded",
            return_value={"degraded": True, "reason": "project_paused_or_key_revoked"},
        ):
            result = apply_pre_call_policy(
                "hello", get_config(), provider="openai", operation="chat"
            )
        assert result["decision"] == "block"
        assert result["compliance"]["action_taken"] == "blocked"
        assert result["compliance"]["action_reason"] != "customer_override"
        # Gate blocks are labeled policy_rules (parity with both TS paths).
        assert result["compliance"]["action_source"] == "policy_rules"
        assert result["compliance"]["rule_id"] == "sdk:project_paused_or_key_revoked"

    def test_hook_still_runs_when_not_degraded(self):
        from unittest.mock import patch

        _reset()
        obsvr.init(api_key="test", on_pre_call=lambda _e: "block")
        with patch(
            "obsvr.remote.is_enforcement_degraded",
            return_value={"degraded": False, "reason": None},
        ):
            result = apply_pre_call_policy(
                "hello", get_config(), provider="openai", operation="chat"
            )
        assert result["decision"] == "block"
        assert result["compliance"]["action_source"] == "customer_hook"


# ── Central failure-disposition registry ─────────────────────────────────────
#
# The registry declares what every governance layer does when it cannot render
# a verdict. These tests assert three things: the Python registry matches the
# shared fixture (which the TypeScript twin also pins to, so this is the parity
# check), every detector module has a declaration (so a new detector cannot land
# without stating its posture), and the declarations match what the code
# actually does for every state a unit test can drive.

import json
from pathlib import Path

from obsvr.failure_dispositions import (
    DECLARED_LAYER_IDS,
    FAILURE_DISPOSITIONS,
    disposition_for,
    get_failure_disposition,
    unguarded_layer_ids,
)

FIXTURE_PATH = (
    Path(__file__).parent / "../../conformance/fixtures/fail_mode.json"
).resolve()


def _fixture():
    with open(FIXTURE_PATH) as f:
        return json.load(f)


class TestRegistryPinnedToFixture:
    def test_declares_exactly_the_pinned_layers_in_order(self):
        assert DECLARED_LAYER_IDS == [layer["id"] for layer in _fixture()["layers"]]

    def test_matches_the_fixture_on_every_field(self):
        for expected in _fixture()["layers"]:
            entry = get_failure_disposition(expected["id"])
            assert entry is not None, expected["id"]
            assert entry["module"] == expected["module_py"], expected["id"]
            assert entry["hook_overridable"] == expected["hook_overridable"], expected["id"]
            assert entry["notes"] == expected["notes"], expected["id"]
            for state in _fixture()["vocabulary"]["states"]:
                assert entry[state] == expected[state], f"{expected['id']}.{state}"

    def test_every_layer_declares_all_states_with_pinned_vocabulary(self):
        vocab = _fixture()["vocabulary"]
        for entry in FAILURE_DISPOSITIONS:
            for state in vocab["states"]:
                declared = entry[state]
                assert declared["disposition"] in vocab["dispositions"]
                if declared.get("qualifier"):
                    assert declared["qualifier"] in vocab["qualifiers"]

    def test_no_duplicate_layer_ids(self):
        assert len(set(DECLARED_LAYER_IDS)) == len(DECLARED_LAYER_IDS)


class TestRegistryGate:
    """Modules that are NOT governance layers and need no declaration. Adding a
    name here is a deliberate statement that it decides nothing; adding a
    detector without a declaration fails this gate."""

    NON_DETECTOR_MODULES = {
        "__init__.py",
        "_version.py",
        "agent_run.py",
        # Console entry point: validates startup configuration, installs
        # bindings, and transfers control to the target application. It runs
        # no detector and owns no per-call failure disposition.
        "auto_run.py",
        # Canonical document + hash for an approval action; decides nothing on
        # its own. The layer that DOES decide is policy_rules, which is
        # declared. Same exemption reason as decision_record.py in TS.
        "approval_action.py",
        # Strict-profile schemas, canonicalizers, evidence assemblers, receipt
        # builders/verifiers, strict transports, coordination, recovery, and
        # runtime orchestration. These are not detector layers: unavailable
        # required-detector evidence is encoded as a stricter outcome, invalid
        # inputs fail before admission, and uncertain admission freezes
        # execution rather than consulting the configurable detector fail mode.
        "aarm_outcome.py",
        "action_context.py",
        "action_context_v2.py",
        "intent_alignment.py",
        "intent_alignment_v2.py",
        "strict_admission.py",
        "strict_admission_v2.py",
        "strict_admission_v2_1.py",
        "strict_action_boundary_v2_1.py",
        "strict_canonical.py",
        "strict_evaluation_evidence_v2_1.py",
        "strict_evidence_bundle_v2_1.py",
        "strict_identity_evidence_v2_1.py",
        "strict_policy_continuity_v2_1.py",
        "strict_execution_outcome_v2_1.py",
        "strict_execution_outcome_transport_v2_1.py",
        "strict_receipt.py",
        "strict_receipt_coordinator.py",
        "strict_receipt_coordinator_support.py",
        "strict_receipt_coordinator_v2.py",
        "strict_receipt_coordinator_v2_1.py",
        "strict_receipt_coordinator_v2_1_approval.py",
        "strict_receipt_coordinator_v2_1_recovery.py",
        "strict_receipt_coordinator_v2_1_support.py",
        "strict_receipt_coordinator_v2_recovery.py",
        "strict_receipt_coordinator_v2_support.py",
        "strict_receipt_prepared_state.py",
        "strict_receipt_reconcile_v2.py",
        "strict_receipt_reconcile_v2_1.py",
        "strict_receipt_recovery_v2.py",
        "strict_receipt_recovery_v2_1.py",
        "strict_receipt_runtime.py",
        "strict_receipt_runtime_v2.py",
        "strict_receipt_runtime_v2_1.py",
        "strict_receipt_runtime_v2_1_execution.py",
        "strict_receipt_runtime_v2_1_outcomes.py",
        "strict_receipt_runtime_v2_1_support.py",
        "strict_runtime_recovery_v2_1.py",
        "strict_receipt_runtime_v2_bindings.py",
        "strict_receipt_runtime_v2_recovery_support.py",
        "strict_provider_boundary_v2_1.py",
        "strict_receipt_v2.py",
        "strict_receipt_v2_1.py",
        "strict_receipt_v2_1_verify.py",
        "strict_receipt_v2_verify.py",
        "strict_receipt_verify.py",
        "audit_gap.py",
        "auto.py",
        # Records why an optional integration failed to bind. Decides nothing:
        # it observes an import that already happened and stores the reason for
        # a human to read. Same exemption reason as cost.py.
        "binding_report.py",
        "chain_format.py",
        # Export serializer, decides nothing: it projects an audit event onto a
        # CloudEvents envelope. Same exemption reason as tool_content_hash.py.
        "cloudevents.py",
        "cli_verify.py",
        "config.py",
        # Layered cost resolution: arithmetic over numbers the caller already
        # holds, producing a record field. Decides nothing - a cost never
        # blocks a call on its own; a quota rule does. Same exemption reason as
        # tool_content_hash.py.
        "cost.py",
        "decision_record.py",
        # Remembers which calls have already been recorded so that registering
        # obsvr with a framework twice still yields one evidence record.
        # Decides nothing about a call: it answers "has this been emitted",
        # never "should this be allowed". Same exemption reason as cost.py.
        "dedupe.py",
        "errors.py",
        "escrow.py",
        "events.py",
        "failure_dispositions.py",
        "instance_guard.py",
        # Explicit ancestry/context carrier. It validates and hashes caller-
        # supplied source identity but does not make an allow/block decision.
        "source_lineage.py",
        # Post-call metering: arithmetic over counts the event already carries,
        # producing a record field and a quota increment. Decides nothing — a
        # cost never blocks a call on its own; the quota RULE does, and that is
        # declared. Same exemption reason as cost.py, whose two halves this
        # module now holds.
        "metering.py",
        # Reads one descriptor field under either of the two spellings the MCP
        # protocol types have carried. Decides nothing: it returns the value it
        # finds, or the caller's default. The layers that DO decide on what it
        # returns — tool_pinning, capability_hints, the MCP descriptor scan —
        # carry their own dispositions. It cannot fail open, because "not
        # present under either name" is a value it returns rather than an
        # exception it raises. Same exemption reason as tool_content_hash.py.
        "mcp_fields.py",
        "normalize.py",
        "otel_mirror.py",
        "pii_types.py",
        "policy_log.py",
        # Reads a client's base URL and names the destination for the record.
        # Decides nothing: no label it returns, or declines to return, blocks
        # anything — a provider rule does, and that is declared. It cannot fail
        # open, because "I cannot name this host" is a value it returns
        # (`unknown`, with the reason in `provider_attribution`) rather than an
        # exception it raises, and a raising property on the client is caught
        # and treated as a non-answer. Same exemption reason as token_usage.py
        # and tool_content_hash.py.
        "provider_attribution.py",
        "reason_codes.py",
        "register.py",
        "safe_regex.py",
        "sender.py",
        "span.py",
        "span_attributes.py",
        "ssrf.py",
        # Builds the STORED copy of content the decision scan never reached
        # (system prompts, earlier turns, assistant turns, tool results). It
        # decides nothing: the verdict is already final when it runs, and no
        # value it returns can block, allow, or change what went to the
        # provider. Its own failure resolution is a stored-copy one and is
        # already declared elsewhere - the scan it runs is `builtin_pii_scan`,
        # which is what it records a failure against, and the redactor it calls
        # is `deobfuscation_views`, whose declaration is the one that says a
        # stored copy fails CLOSED to [UNSCANNED:detector_error] rather than
        # persist text nothing vetted. Both of its call sites are on the emit
        # path, so the whole body is inside one guard: nothing raises into the
        # host. Same exemption reason as tool_content_hash.py, plus that
        # inherited disposition.
        "stored_content.py",
        # Ambient-subject scope (use_subject): a ContextVar carrier for the
        # caller principal, same class of module as span.py and agent_run.py.
        # Decides nothing: it supplies an identity that attribution and
        # bucket-scoping READ; the layers that enforce with it (rules quota,
        # session_taint) carry their own declarations. It runs no scan whose
        # failure could resolve open or closed — its only failure shape is an
        # unset scope, which resolves to the pre-existing behaviour (wrap-time
        # identity, or none).
        "subject.py",
        # An optional signing IDENTITY, not a detector: it loads an operator's
        # Ed25519 key and produces a second signature over the same preimage
        # the HMAC covers. It decides nothing about a call, so there is no
        # failure that could resolve open or closed — a key it cannot read
        # refuses loudly at init (a config error, before any call is
        # governed), and at verify time a missing or foreign seal is a chain
        # break the verifier reports, not a disposition this module holds.
        "device_identity.py",
        # Evidence producer, decides nothing: it hashes what a tool call saw
        # and its callers omit the field on failure. Matches the TS twin's
        # exemption for tool-content-hash.ts.
        "tool_content_hash.py",
        # Reads token counts out of a provider usage payload and produces a
        # record field. Decides nothing: no count it returns, or declines to
        # return, blocks anything on its own — a quota rule does, and that is
        # declared. Its whole contract is to be absent rather than wrong, and
        # it cannot fail open because "I could not read this" is a value it
        # returns rather than an exception it raises. Same exemption reason as
        # cost.py and tool_content_hash.py.
        "token_usage.py",
        # Signed coverage statement and verifier. It reports whether required
        # enforcement surfaces are present; it does not evaluate a live call.
        "coverage_attestation.py",
        # Audit delivery storage and deployment smoke assertion. Neither is a
        # detector layer: the outbox persists already-decided events, while the
        # smoke helper verifies that a caller-selected deny path stopped before
        # transport.
        "durable_outbox.py",
        "enforcement_smoke.py",
        # Public callable adapter over the existing tool-policy kernel. The
        # detector dispositions belong to that kernel, not this adapter.
        "govern_fn.py",
        # Closed remediation/retry document canonicalizer. It validates and
        # hashes evidence references but never decides whether an action runs.
        "remediation_v1.py",
        # Deployment/operator contracts. These validate, hash, sign, summarize,
        # or project already supplied records. They are not invoked as detector
        # layers on a governed call; signal failure disposition is data carried
        # to the deterministic kernel, not an exception policy owned here.
        "policy_lifecycle_v1.py",
        "workload_registry_v1.py",
        "policy_template_v1.py",
        "control_analytics_v1.py",
        "signal_interface_v1.py",
        "verify_chain.py",
        "wrap.py",
    }

    def test_every_detector_module_is_declared(self):
        pkg_dir = Path(__file__).parent.parent / "obsvr"
        declared = {Path(str(e["module"])).name for e in FAILURE_DISPOSITIONS}
        undeclared = sorted(
            p.name
            for p in pkg_dir.glob("*.py")
            if p.name not in self.NON_DETECTOR_MODULES and p.name not in declared
        )
        assert undeclared == [], (
            f"detector modules with no failure disposition declared: {undeclared}"
        )

    def test_no_layer_lets_its_failure_escape_to_the_host(self):
        """This list was the eight in-process layers with no error channel at
        all. Every one is now guarded, so the correct assertion is that the
        list is EMPTY - and it stays a tripwire in the other direction: a new
        detector that ships without an error channel, or a guard someone
        removes, turns this red rather than passing unnoticed."""
        assert unguarded_layer_ids() == []


class TestDeclarationsMatchObservedBehavior:
    def test_customer_hook_is_fail_mode_and_behaves_that_way(self):
        assert disposition_for("customer_hook", "timeout") == {"disposition": "fail_mode"}
        assert disposition_for("customer_hook", "error") == {"disposition": "fail_mode"}

        def boom(_event):
            raise RuntimeError("hook exploded")

        _reset()
        obsvr.init(api_key="test", on_pre_call=boom)
        assert apply_pre_call_policy(
            "hello", get_config(), provider="openai", operation="chat"
        )["decision"] == "allow"

        _reset()
        obsvr.init(api_key="test", fail_mode="closed", on_pre_call=boom)
        assert apply_pre_call_policy(
            "hello", get_config(), provider="openai", operation="chat"
        )["decision"] == "block"

    def test_external_backend_is_closed_with_a_shadow_exemption(self, monkeypatch):
        assert disposition_for("external_backend", "error") == {
            "disposition": "closed",
            "qualifier": "shadow_exempt",
        }
        from obsvr import external_backend as eb

        def boom(*_a):
            raise RuntimeError("ECONNREFUSED")

        backend = {"type": "opa", "url": "https://8.8.8.8/v1/data/obsvr/allow"}

        _reset()
        monkeypatch.setattr(eb, "_urllib_transport", boom)
        obsvr.init(api_key="t", external_policy_backend=dict(backend))
        assert apply_pre_call_policy(
            "hello world", get_config(), provider="openai", operation="chat.completions.create"
        )["decision"] == "block"

        _reset()
        obsvr.init(api_key="t", external_policy_backend={**backend, "shadow": True})
        assert apply_pre_call_policy(
            "hello world", get_config(), provider="openai", operation="chat.completions.create"
        )["decision"] == "allow"

    def test_integrity_gate_is_closed_when_degraded(self):
        from unittest.mock import patch

        assert disposition_for("enforcement_integrity_gate", "degraded") == {
            "disposition": "closed"
        }
        _reset()
        obsvr.init(api_key="test")
        with patch(
            "obsvr.remote.is_enforcement_degraded",
            return_value={"degraded": True, "reason": "project_paused_or_key_revoked"},
        ):
            assert apply_pre_call_policy(
                "hello", get_config(), provider="openai", operation="chat"
            )["decision"] == "block"

    def test_a_detector_defect_resolves_instead_of_reaching_the_caller(self, monkeypatch):
        """This test used to assert the opposite. The declaration said an
        exception escaped to the host, and its docstring said that the day
        someone added a guard, this test would tell them to update the table.
        That is what happened, so the assertion is inverted rather than
        deleted: the same injected defect must now resolve."""
        from obsvr import policy as policy_mod
        from obsvr.policy import get_detector_error_count

        assert disposition_for("builtin_pii_scan", "error") == {
            "disposition": "fail_mode",
            "qualifier": "redaction_application_closed",
        }

        def boom(*_a, **_k):
            raise RuntimeError("detector bug")

        _reset()
        obsvr.init(api_key="test", pii_policy={"action": "block", "types": ["email"]})
        monkeypatch.setattr(policy_mod, "run_builtin_pii_scan", boom)
        res = apply_pre_call_policy(
            "hello a@b.com", get_config(), provider="openai", operation="chat"
        )
        assert res["decision"] == "allow"
        assert res["compliance"]["rule_id"] == "sdk:detector_error"
        assert get_detector_error_count() == 1

        # And closed when the operator opted in.
        _reset()
        obsvr.init(api_key="test", fail_mode="closed",
                   pii_policy={"action": "block", "types": ["email"]})
        monkeypatch.setattr(policy_mod, "run_builtin_pii_scan", boom)
        assert apply_pre_call_policy(
            "hello a@b.com", get_config(), provider="openai", operation="chat"
        )["decision"] == "block"
