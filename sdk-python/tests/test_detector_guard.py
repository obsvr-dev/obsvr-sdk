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
