"""A detector defect must never surface as an unhandled error in the host app.

Eight in-process layers used to have no error channel at all: an exception
inside one propagated straight into the calling application. These tests drive
each of them through a real governed client and pin the resolution:

  - the six SCANNING layers resolve by fail_mode - the call proceeds under
    "open" with that layer's enforcement lost, and blocks under "closed";
  - the two FLOOR-CLASS layers (policy_floor, canary) block regardless of
    fail_mode, because a floor is by definition the thing fail_mode cannot
    move: a floor that cannot run must not wave the call through ungoverned.

Every case first asserts that governance is actually running on the client, so
a mock the wrapper does not recognize cannot pass through ungoverned and make a
broken guard look fixed.
"""

import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

import obsvr  # noqa: E402
from obsvr import policy as policy_mod  # noqa: E402
from obsvr import response_scan as response_scan_mod  # noqa: E402
from obsvr.config import _reset, get_config  # noqa: E402
from obsvr.policy import apply_pre_call_policy, get_detector_error_count  # noqa: E402
from obsvr.rules import PolicyRule  # noqa: E402

from test_wrap import FakeOpenAI  # noqa: E402

# The pre-call marker names the STEP a layer runs in. De-obfuscation views are
# produced INSIDE the builtin-scan step, so they resolve under that name rather
# than as a step of their own - asserted explicitly further down.
SCANNING_LAYERS = [
    "session_taint",
    "builtin_pii_scan",
    "multi_turn_injection",
    "policy_rules",
]
FLOOR_CLASS_LAYERS = ["policy_floor", "canary"]

#: The symbol each layer reaches through, so a throw lands INSIDE that layer.
#: Most are imported INSIDE apply_pre_call_policy, so the patch has to target
#: the source module - patching the policy module would silently not apply and
#: the test would prove nothing.
_INJECTION_POINT = {
    "session_taint": ("obsvr.session_taint", "evaluate_session_taint"),
    "canary": ("obsvr.canary", "scan_for_canary"),
    "builtin_pii_scan": ("obsvr.policy", "run_builtin_pii_scan"),
    "multi_turn_injection": ("obsvr.injection_session", "score_turn"),
    "policy_floor": ("obsvr.rules", "evaluate_floor"),
    # The floor shares this evaluator and runs FIRST, so a blanket throw would
    # land in the floor step (and correctly fail closed). Throw only for the
    # customer rule set, which is what isolates the policy_rules step.
    "policy_rules": ("obsvr.rules", "evaluate_policy_rules"),
}
_CUSTOMER_RULE_ID = "r1"


def _init(fail_mode="open", **kw):
    _reset()
    obsvr.init(
        api_key="k",
        ingest_url="https://ingest.test",
        policy_refresh_interval_s=0,
        pii_policy={"default": "block"},
        fail_mode=fail_mode,
        # Every layer armed so each injection point is actually reached.
        session_taint={"enabled": True, "action": "block"},
        multi_turn_injection={"enabled": True},
        deobfuscation={"enabled": True},
        policy_floor=[PolicyRule(id="f1", name="floor", enabled=True, action="block",
                                 type="keyword", conditions={"keywords": ["floortrip"]})],
        policy_rules=[PolicyRule(id="r1", name="rule", enabled=True, action="block",
                                 type="keyword", conditions={"keywords": ["ruletrip"]})],
        **kw,
    )
    return get_config()


def _arm_layer(monkeypatch, layer):
    """Make `layer` raise, and make sure it is reached at all."""
    if layer == "session_taint":
        from obsvr import session_taint as st
        st.mark_tainted("global", "prompt_injection", 0.0)
    if layer == "canary":
        obsvr.mint_canary("secret-token-value")
    mod_name, attr = _INJECTION_POINT[layer]
    module = importlib.import_module(mod_name)
    assert hasattr(module, attr), f"{mod_name}.{attr} does not exist - the patch would be a no-op"

    if layer == "policy_rules":
        original = getattr(module, attr)

        def boom(rules=None, *a, **k):
            first_id = getattr((rules or [None])[0], "id", None)
            if first_id == _CUSTOMER_RULE_ID:
                raise RuntimeError(f"detector bug in {layer}")
            return original(rules, *a, **k)
    else:

        def boom(*_a, **_k):
            raise RuntimeError(f"detector bug in {layer}")

    monkeypatch.setattr(module, attr, boom)


def _call(client):
    return client.chat.completions.create(
        model="gpt-4o", messages=[{"role": "user", "content": "hello there"}]
    )


# ── the control: governance really is running ───────────────────────────────


def test_governance_is_actually_running_on_this_client():
    """If this fails, every other test in the file is vacuous."""
    _init()
    client = obsvr.wrap(FakeOpenAI())
    with pytest.raises(Exception) as exc:
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "my ssn is 123-45-6789"}],
        )
    assert "ObsvrPolicyError" in type(exc.value).__name__
    _reset()


# ── the six scanning layers: resolve by fail_mode ───────────────────────────


@pytest.mark.parametrize("layer", SCANNING_LAYERS)
def test_scanning_layer_failure_does_not_reach_the_host_under_open(monkeypatch, layer):
    _init(fail_mode="open")
    client = obsvr.wrap(FakeOpenAI())
    assert _call(client).choices[0].message.content == "fake openai answer"  # healthy first

    _arm_layer(monkeypatch, layer)
    before = get_detector_error_count()
    result = _call(client)  # must NOT raise
    assert result.choices[0].message.content == "fake openai answer"
    assert get_detector_error_count() > before, "the failure must be counted"
    _reset()


def test_fail_open_detector_failure_bypasses_allowed_sampling(monkeypatch):
    """Control-loss evidence must survive even when clean allows are sampled out."""
    cfg = _init(fail_mode="open", sample_rate=0)
    sent = []
    wrap_mod = importlib.import_module("obsvr.wrap")
    monkeypatch.setattr(wrap_mod, "send_audit_async", lambda _cfg, event: sent.append(event))
    _arm_layer(monkeypatch, "policy_rules")

    assert _call(obsvr.wrap(FakeOpenAI())).choices[0].message.content
    assert len(sent) == 1
    failure = sent[0]["metadata"]["obsvr_telemetry"]["detector_failure"]
    assert failure["resolution"] == "open"
    assert cfg.sample_rate == 0
    _reset()


@pytest.mark.parametrize("layer", SCANNING_LAYERS)
def test_scanning_layer_failure_blocks_under_closed(monkeypatch, layer):
    _init(fail_mode="closed")
    client = obsvr.wrap(FakeOpenAI())
    _arm_layer(monkeypatch, layer)
    with pytest.raises(Exception) as exc:
        _call(client)
    # Blocked by policy, NOT the detector's own RuntimeError escaping.
    assert "detector bug" not in str(exc.value)
    assert "ObsvrPolicyError" in type(exc.value).__name__
    _reset()


# ── the floor class: closed regardless of fail_mode ─────────────────────────


@pytest.mark.parametrize("layer", FLOOR_CLASS_LAYERS)
def test_floor_class_failure_blocks_even_under_fail_mode_open(monkeypatch, layer):
    """The carve-out. fail_mode cannot move a floor, so a floor that cannot run
    blocks rather than letting the call through ungoverned."""
    _init(fail_mode="open")
    client = obsvr.wrap(FakeOpenAI())
    _arm_layer(monkeypatch, layer)
    with pytest.raises(Exception) as exc:
        _call(client)
    assert "detector bug" not in str(exc.value), "the raw exception must not reach the host"
    assert "ObsvrPolicyError" in type(exc.value).__name__
    _reset()


@pytest.mark.parametrize("layer", FLOOR_CLASS_LAYERS)
def test_floor_class_failure_also_blocks_under_closed(monkeypatch, layer):
    _init(fail_mode="closed")
    client = obsvr.wrap(FakeOpenAI())
    _arm_layer(monkeypatch, layer)
    with pytest.raises(Exception):
        _call(client)
    _reset()


# ── the record: what an operator sees ───────────────────────────────────────


def test_failure_is_recorded_on_the_call_s_own_event(monkeypatch):
    """No second event, no new action_taken value - the record rides the
    existing event in reserved telemetry."""
    cfg = _init(fail_mode="open")
    monkeypatch.setattr(policy_mod, "run_builtin_pii_scan",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("detector bug")))
    result = apply_pre_call_policy("hello", cfg, provider="openai", operation="chat")

    assert result["decision"] == "allow"
    comp = result["compliance"]
    assert comp["rule_id"] == "sdk:detector_error"
    assert comp["action_taken"] == "allowed"  # a legal wire-enum value
    failure = comp["detector_failure"]
    assert failure["layer"] == "builtin_pii_scan"
    assert failure["resolution"] == "open"
    assert failure["floor_class"] is False
    assert "RuntimeError" in failure["error"]
    _reset()


def test_failure_telemetry_reaches_the_emitted_event(monkeypatch):
    """The mirror into metadata.obsvr_telemetry, so it survives to the wire."""
    from obsvr.events import build_audit_event

    cfg = _init(fail_mode="open")
    import obsvr.rules
    monkeypatch.setattr(obsvr.rules, "evaluate_floor",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("floor bug")))
    result = apply_pre_call_policy("hello", cfg, provider="openai", operation="chat")
    assert result["decision"] == "block", "floor class fails closed"

    event = build_audit_event(
        cfg, provider="openai", model="gpt-4o", operation="chat",
        source="test", prompt="hello", compliance=result["compliance"],
    )
    failure = event["metadata"]["obsvr_telemetry"]["detector_failure"]
    assert failure["layer"] == "policy_floor"
    assert failure["resolution"] == "closed"
    assert failure["floor_class"] is True
    _reset()


def test_counter_is_reported_on_the_fleet_poll_header(monkeypatch):
    """Its own key, and never folded into the delivery drop aggregate."""
    from unittest.mock import MagicMock

    from obsvr import remote

    cfg = _init(fail_mode="open")
    monkeypatch.setattr(policy_mod, "run_builtin_pii_scan",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("detector bug")))
    apply_pre_call_policy("hello", cfg, provider="openai", operation="chat")
    apply_pre_call_policy("hello", cfg, provider="openai", operation="chat")

    captured = {}

    def fake_urlopen(req, timeout=None):
        captured.update(dict(req.headers))
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b'{"rules": []}'
        resp.__enter__ = lambda s: s
        resp.__exit__ = lambda s, *a: False
        return resp

    monkeypatch.setattr(remote, "urlopen", fake_urlopen)
    remote.poll_once(cfg)
    counters = next(v for k, v in captured.items() if k.lower() == "x-obsvr-counters")
    assert "detector_errors=2" in counters
    assert "dropped=0" in counters, "enforcement loss is not delivery loss"
    _reset()


# ── the response-side layer, guarded at its own call site ───────────────────


def test_tool_result_scan_failure_resolves_open_by_default():
    """The tool has already run, so blocking cannot undo the side effect - it
    would only withhold the result from the model."""
    cfg = _init(fail_mode="open")
    before = get_detector_error_count()
    out = response_scan_mod.resolve_response_scan_failure(RuntimeError("scan bug"), cfg)
    assert out["action"] == "allow"
    assert out["rule_id"] == "sdk:detector_error"
    assert get_detector_error_count() == before + 1
    _reset()


def test_tool_result_scan_failure_blocks_under_closed():
    cfg = _init(fail_mode="closed")
    out = response_scan_mod.resolve_response_scan_failure(RuntimeError("scan bug"), cfg)
    assert out["action"] == "block"
    assert out["action_taken"] == "blocked"
    _reset()


def test_guarded_result_shape_matches_the_real_scanner():
    """A guard that returns a differently-shaped dict breaks its caller, which
    would be the same outage by another route."""
    cfg = _init()
    real = response_scan_mod.scan_mcp_tool_result("nothing interesting", cfg)
    guarded = response_scan_mod.resolve_response_scan_failure(RuntimeError("x"), cfg)
    assert set(real).issubset(set(guarded)), set(real) - set(guarded)
    _reset()


def test_deobfuscation_view_failure_resolves_under_the_builtin_scan_step(monkeypatch):
    """The views are produced inside the builtin-scan step, so that is the step
    the guard names. Pinned so the nesting is a stated fact, not a surprise."""
    import obsvr.policy

    cfg = _init(fail_mode="open")
    monkeypatch.setattr(obsvr.policy, "run_configured_pii_scan",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("view bug")))
    result = apply_pre_call_policy("hello", cfg, provider="openai", operation="chat")
    assert result["decision"] == "allow"
    assert result["compliance"]["detector_failure"]["layer"] == "builtin_pii_scan"
    _reset()


def test_a_floor_that_cannot_evaluate_blocks_even_via_the_shared_evaluator(monkeypatch):
    """The floor and customer rules share one evaluator, and the floor runs
    first. If that evaluator breaks, the floor is what could not run - so the
    call blocks, under fail_mode open."""
    import obsvr.rules

    cfg = _init(fail_mode="open")
    monkeypatch.setattr(obsvr.rules, "evaluate_policy_rules",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("evaluator bug")))
    result = apply_pre_call_policy("hello", cfg, provider="openai", operation="chat")
    assert result["decision"] == "block"
    failure = result["compliance"]["detector_failure"]
    assert failure["layer"] == "policy_floor"
    assert failure["floor_class"] is True
    _reset()


# ── the response phase: never withhold, but never store the unvetted ───────


def test_post_call_failure_never_withholds_the_response(monkeypatch):
    """The provider already answered; blocking cannot undo that, and the
    published contract says the caller's value is never mutated."""
    import obsvr.rules

    cfg = _init(fail_mode="closed")  # even closed must not withhold
    client = obsvr.wrap(FakeOpenAI())
    original = obsvr.rules.evaluate_floor

    def response_only(rules, text, target="prompt", *a, **k):
        if target == "response":
            raise RuntimeError("response floor bug")
        return original(rules, text, target, *a, **k)

    monkeypatch.setattr(obsvr.rules, "evaluate_floor", response_only)
    assert _call(client).choices[0].message.content == "fake openai answer"
    _reset()


def test_post_call_failure_withholds_the_stored_copy_under_its_own_marker(monkeypatch):
    """Storing text nothing scanned into an evidence record would be the
    'fake enforcement' the principles forbid - and it must not look like a
    successful redaction."""
    import obsvr.rules
    from obsvr.policy import UNSCANNED_PLACEHOLDER, apply_post_call_policy

    cfg = _init(fail_mode="open")
    monkeypatch.setattr(obsvr.rules, "evaluate_floor",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("response floor bug")))
    out = apply_post_call_policy("sensitive answer", {}, cfg)  # called directly: response phase only

    assert out["decision"] == "flag"  # never redact_response: caller untouched
    assert out["redacted_response"] == UNSCANNED_PLACEHOLDER
    assert not UNSCANNED_PLACEHOLDER.startswith("[REDACTED"), (
        "the unscanned marker must not be confusable with a real redaction"
    )
    failure = out["compliance"]["detector_failure"]
    assert failure["phase"] == "response"
    assert failure["stored_unscanned"] is True
    _reset()


def test_event_builder_canary_net_failure_does_not_reach_the_host(monkeypatch):
    """This net runs on every emitted event on every path, including paths that
    never touch the policy engine."""
    import obsvr.canary
    from obsvr.events import build_audit_event
    from obsvr.policy import UNSCANNED_PLACEHOLDER

    cfg = _init(fail_mode="open")
    obsvr.mint_canary("planted-token-value")
    monkeypatch.setattr(obsvr.canary, "scan_for_canary",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("canary net bug")))

    event = build_audit_event(cfg, provider="openai", model="gpt-4o", operation="chat",
                              source="test", prompt="secret prompt", response="answer")
    assert event["prompt"] == UNSCANNED_PLACEHOLDER
    failure = event["metadata"]["obsvr_telemetry"]["detector_failure"]
    assert failure["phase"] == "event_build"
    assert failure["stored_unscanned"] is True
    _reset()


def test_stored_copy_redactor_never_persists_unvetted_text():
    """``redact_for_storage`` is the single point every stored audit copy
    passes through - blocked-event prompts, post-call stored responses, the
    observe-path fields, and the framework integrations' stored text. It is
    guarded there rather than at each of its call sites because the answer is
    the same at all of them, which is what P-02 means by one resolution point.

    Twin: sdk-typescript/tests/unit/detector-guard-response.test.ts.
    """
    from obsvr.deobfuscate import redact_for_storage
    from obsvr.policy import UNSCANNED_PLACEHOLDER, get_detector_error_count

    _init(fail_mode="open")

    class _Hostile:
        """Reaches the redactor's string operations and raises there."""

        def __getattr__(self, name):
            raise RuntimeError("redactor bug")

    stored = redact_for_storage(_Hostile(), None)
    assert stored == UNSCANNED_PLACEHOLDER
    assert get_detector_error_count() == 1
    _reset()


def test_stored_copy_redactor_leaves_a_healthy_redaction_alone():
    from obsvr.deobfuscate import redact_for_storage
    from obsvr.policy import get_detector_error_count

    _init(fail_mode="open")
    assert "[REDACTED_SSN]" in redact_for_storage("my ssn is 123-45-6789", None)
    assert get_detector_error_count() == 0
    _reset()


class TestOutboundRedactionApplication:
    """Enforcement APPLICATION: a redaction that could not be carried out.

    A third phase, and deliberately not the pre-call rule. Pre-call resolves by
    fail_mode because a DETECTION failure means the SDK does not know whether
    sensitive content is present. Here the scan already ran, already found
    something, and policy already said remove it - so failing open would
    transmit to a third-party provider exactly the content the SDK was told to
    strip. It fails CLOSED regardless of fail_mode, on the same reasoning the
    policy floor already uses: never forward content that cannot be guaranteed
    redacted.

    Twin: sdk-typescript/tests/unit/detector-guard-outbound.test.ts.
    """

    def test_fails_closed_on_both_fail_modes(self):
        from obsvr.policy import apply_outbound_redaction, get_detector_error_count

        for mode in ("open", "closed"):
            _reset()
            _init(fail_mode=mode)

            def _boom() -> None:
                raise RuntimeError("redactor bug")

            failed = apply_outbound_redaction(_boom)
            assert failed is not None, f"fail_mode={mode} must not let it through"
            assert failed["detector_failure"]["resolution"] == "closed"
            assert failed["detector_failure"]["phase"] == "enforcement_application"
            assert failed["rule_id"] == "sdk:detector_error"
            assert get_detector_error_count() == 1
        _reset()

    def test_reports_nothing_when_the_redaction_succeeds(self):
        from obsvr.policy import apply_outbound_redaction, get_detector_error_count

        _init(fail_mode="open")
        ran = []
        assert apply_outbound_redaction(lambda: ran.append(True)) is None
        assert ran == [True]
        assert get_detector_error_count() == 0
        _reset()

    def test_the_event_never_claims_a_redaction_that_did_not_happen(self):
        from obsvr.policy import (
            apply_outbound_redaction,
            outbound_redaction_blocked_compliance,
        )

        _init(fail_mode="open")
        base = {
            "event_type": "llm_call",
            "policy_version": "v1",
            "action_taken": "redacted",
            "action_reason": "pii_detected",
            "action_source": "builtin",
            "redacted_types": ["email", "ssn"],
            "blocked_types": [],
        }

        def _boom() -> None:
            raise RuntimeError("redactor bug")

        corrected = outbound_redaction_blocked_compliance(
            base, apply_outbound_redaction(_boom)
        )
        assert corrected["action_taken"] == "blocked"
        assert corrected["event_type"] == "blocked_call"
        assert corrected["redacted_types"] == []
        # What the scan found is now the reason for the refusal, not a list of
        # things removed - nothing was removed.
        assert corrected["blocked_types"] == ["email", "ssn"]
        assert corrected["rule_id"] == "sdk:detector_error"
        assert corrected["detector_failure"]["phase"] == "enforcement_application"
        # Provenance the policy already established survives.
        assert corrected["policy_version"] == "v1"
        _reset()

    def test_wrap_blocks_rather_than_forwarding_a_partial_redaction(self, monkeypatch):
        """End to end through wrap(): the redaction cannot be carried out, and
        the call is refused instead of sending the prompt the SDK was told to
        clean.

        The trigger used to be a read-only message — a dict subclass raising on
        ``__setitem__`` — back when the walk wrote to the caller's message. It
        no longer writes, it copies, so such a message is now redacted
        successfully and the call goes through; that is pinned by
        ``test_a_read_only_message_is_redacted_not_refused`` below.

        What still fails is the redactor itself raising, which is the same
        vector the TypeScript unit half already uses (`throw new Error(
        'redactor bug')`) and a genuine "the removal could not be carried out".
        The end-to-end TypeScript twin reaches it with a message that cannot be
        copied; a dict subclass cannot be made uncopyable in Python, because
        ``{**d}`` takes the C fast path and ignores an overridden ``keys()``.
        """
        import sys

        import obsvr
        import obsvr.wrap  # noqa: F401 - ensure the module is in sys.modules
        from obsvr.errors import ObsvrPolicyError
        from obsvr.policy import get_detector_error_count

        # `obsvr.wrap` the ATTRIBUTE is the re-exported function, so the module
        # has to come from sys.modules rather than from attribute access.
        wrap_mod = sys.modules["obsvr.wrap"]

        _reset()
        obsvr.init(api_key="test", ingest_url="https://x.test", fail_mode="open",
                   pii_policy={"action": "redact", "types": ["ssn"]})

        def _boom(_text):
            raise RuntimeError("redactor bug")

        # The outbound rewrite now asks `outbound_redactor` which redactor the
        # detected types require — Presidio joins it for the six types the regex
        # tier cannot locate — so THAT is the seam, and it is the precise one:
        # patching `redact_builtin_pii` itself also breaks the stored-copy
        # redaction and counts three failures where this asks about one.
        monkeypatch.setattr(wrap_mod, "outbound_redactor", lambda *_a, **_k: _boom)

        class _Completions:
            def create(self, **_kw):
                return {"choices": [{"message": {"content": "ok"}}]}

        class _Chat:
            def __init__(self):
                self.completions = _Completions()

        class _Client:
            def __init__(self):
                self.chat = _Chat()

        client = obsvr.wrap(_Client())
        with pytest.raises(ObsvrPolicyError):
            client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "my ssn is 123-45-6789"}],
            )
        assert get_detector_error_count() == 1
        _reset()

    def test_a_read_only_message_is_redacted_not_refused(self):
        """A message the caller does not want written to is COPIED and
        redacted, and the call succeeds.

        The behaviour this replaces: such a message made the redaction walk
        raise, which resolved closed and refused the call — obsvr punishing a
        caller for handing over an object obsvr was about to rewrite. Twin of
        the TypeScript `a frozen caller message is redacted, not refused`.
        """
        import obsvr
        from obsvr.policy import get_detector_error_count

        class _ReadOnlyMessage(dict):
            """Readable by the scanner, and it refuses to be written to."""

            def __setitem__(self, *_args):
                raise TypeError("message is read-only")

        _reset()
        obsvr.init(api_key="test", ingest_url="https://x.test", fail_mode="open",
                   pii_policy={"action": "redact", "types": ["ssn"]})

        seen = {}

        class _Completions:
            def create(self, **kw):
                seen.update(kw)
                return {"choices": [{"message": {"content": "ok"}}]}

        class _Chat:
            def __init__(self):
                self.completions = _Completions()

        class _Client:
            def __init__(self):
                self.chat = _Chat()

        msg = _ReadOnlyMessage(role="user", content="my ssn is 123-45-6789")
        client = obsvr.wrap(_Client())
        res = client.chat.completions.create(model="gpt-4o", messages=[msg])

        # The call SUCCEEDS...
        assert res == {"choices": [{"message": {"content": "ok"}}]}
        assert get_detector_error_count() == 0
        # ...the provider got the redacted text, so this is not "redaction was
        # skipped to make the call work"...
        sent = str(seen)
        assert "123-45-6789" not in sent
        assert "[REDACTED_SSN]" in sent
        # ...and the caller's own object is untouched, which is the whole point.
        assert msg["content"] == "my ssn is 123-45-6789"
        _reset()


class TestCheckOnlyAndProvenanceSurfaces:
    """Shadow rules and the policy-version hash.

    Both are structurally always OPEN, and for the same reason: neither
    decides anything. A shadow rule runs after the active decision is final
    and is defined as never decision-affecting, so honouring fail_mode="closed"
    there would let it block a call - the one thing shadow mode promises it
    cannot do. The policy version is a provenance field recording which rules a
    decision ran under.

    Twin: sdk-typescript/tests/unit/detector-guard-response.test.ts.
    """

    def test_the_policy_version_hash_never_raises_at_its_callers(self):
        from obsvr.policy import get_detector_error_count
        from obsvr.rules import derive_policy_version

        _init(fail_mode="open")

        class _HostileRule:
            enabled = True
            id = "r1"

            def __getattr__(self, name):
                raise RuntimeError("rule shape bug")

        assert derive_policy_version([_HostileRule()]) == "unknown"
        assert get_detector_error_count() == 1
        _reset()

    def test_a_healthy_policy_version_is_unchanged(self):
        from obsvr.policy import get_detector_error_count
        from obsvr.rules import derive_policy_version

        _init(fail_mode="open")
        assert derive_policy_version([]) == "none"
        assert get_detector_error_count() == 0
        _reset()

    def test_a_broken_shadow_rule_cannot_block_even_fail_closed(self, monkeypatch):
        """fail_mode='closed' is the strong case: a shadow rule that blocked
        would break the one promise shadow mode makes.

        The rule itself is VALID and the shadow EVALUATION is what raises,
        which is the case this asserts. It used to stand in a duck-typed object
        with no ``conditions`` — a rule the engine cannot evaluate at all,
        which now fails closed on the active pass in its own right
        (``test_a_rule_that_is_not_a_rule_fails_closed`` below). The two are
        different failures and the fixture was conflating them.
        """
        import obsvr
        from obsvr import rules as rules_mod
        from obsvr.policy import apply_pre_call_policy, get_detector_error_count

        _reset()
        obsvr.init(api_key="test", fail_mode="closed")

        def _boom(*_a, **_k):
            raise RuntimeError("shadow bug")

        monkeypatch.setattr(rules_mod, "evaluate_shadow_rules", _boom)
        cfg = get_config()
        object.__setattr__(
            cfg,
            "policy_rules",
            [
                rules_mod.PolicyRule(
                    id="s1",
                    name="s1",
                    enabled=True,
                    action="block",
                    type="keyword",
                    conditions={"keywords": ["hello"]},
                    mode="shadow",
                )
            ],
        )

        res = apply_pre_call_policy(
            "hello", cfg, provider="openai", operation="chat"
        )
        assert res["decision"] != "block", "a shadow rule must never block"
        assert res["compliance"]["shadow_outcome"] is None
        assert get_detector_error_count() >= 1
        _reset()

    def test_a_rule_that_is_not_a_rule_fails_closed(self):
        """fail_mode='open' is the strong case here, and the reason this class
        is carved out of it.

        ``fail_mode`` prices a detector CRASHING on some input. A rule the
        engine cannot read is not that — there is no input for which it would
        have worked — so it resolves closed whatever fail_mode says. Reached
        by writing straight to the resolved config, because ``init()`` refuses
        this rule outright; both guards exist and this one is the backstop.
        """
        import obsvr
        from obsvr.policy import apply_pre_call_policy

        _reset()
        obsvr.init(api_key="test", fail_mode="open")
        cfg = get_config()
        object.__setattr__(cfg, "policy_rules", ["not-a-rule"])

        res = apply_pre_call_policy(
            "hello", cfg, provider="openai", operation="chat"
        )
        assert res["decision"] == "block", (
            "a declared rule the engine cannot evaluate resolved OPEN"
        )
        assert res["compliance"]["detector_failure"]["resolution"] == "closed"
        _reset()
