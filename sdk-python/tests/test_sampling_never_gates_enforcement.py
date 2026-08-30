"""The sampling invariant, twin of
sdk-typescript/tests/unit/sampling-never-gates-enforcement.test.ts.

``config.py`` and ``sender.should_sample``'s own docstring both state:

    "Sampling gates audit EMISSION only - it never gates enforcement:
     PII/policy/hook/kill-switch checks run on every call regardless of
     sample_rate. Lowering sample_rate reduces ingest volume, not the
     per-call enforcement cost."

Nothing asserted it. Every integration that returned early on an unsampled call
returned ABOVE its policy call, so at ``sample_rate=0`` the PII scan did not run
and the governed record was destroyed: no redaction of the stored copy, no
action_taken, and zero audit events.

Both halves are asserted deliberately. Checking only that enforcement survives
would pass an implementation that emits unconditionally, trading a security bug
for an ingest-volume bug; and the emission half is what makes the enforcement
half falsifiable, by proving ``sample_rate`` genuinely reaches the surface.
"""

import uuid
from typing import Any, Dict, List

import obsvr
from obsvr import config as _config
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.langchain import ObsvrCallbackHandler

SSN = "123-45-6789"


class _FakeLLMResult:
    """Shaped like a LangChain LLMResult for the handler's extractor."""

    def __init__(self, text: str) -> None:
        self.generations = [[type("G", (), {"text": text, "message": None})()]]
        self.llm_output: Dict[str, Any] = {}


class _Recorder:
    """Captures what the sender was handed, without a network peer."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def __call__(self, config: Any, event: Dict[str, Any]) -> None:
        self.events.append(event)


def _drive(monkeypatch: Any, sample_rate: float, text: str) -> Dict[str, Any]:
    rec = _Recorder()
    # events.emit_event sends via `sender.send_audit_async` (obsvr/events.py:638),
    # so that is the choke point to capture — patching obsvr.events sees nothing.
    monkeypatch.setattr("obsvr.sender.send_audit_async", rec, raising=False)

    _config._reset()
    obsvr.init(
        api_key="k",
        ingest_url="https://x",
        sample_rate=sample_rate,
        pii_policy={"rules": {"ssn": "block"}},
    )

    handler = ObsvrCallbackHandler()
    run_id = uuid.uuid4()
    blocked = False
    try:
        handler.on_chat_model_start(
            {"id": ["langchain", "chat_models", "openai", "ChatOpenAI"]},
            [[{"role": "user", "content": text}]],
            run_id=run_id,
            invocation_params={"model": "gpt-4o-mini"},
        )
    except ObsvrPolicyError:
        blocked = True
    else:
        handler.on_llm_end(_FakeLLMResult("assistant reply"), run_id=run_id)

    stored = " ".join(str(e.get("prompt", "")) for e in rec.events)
    return {
        "events": rec.events,
        "count": len(rec.events),
        "blocked": blocked,
        "stored_has_raw_secret": SSN in stored,
        "actions": [e.get("action_taken") for e in rec.events],
    }


# -- enforcement half: the PII scan runs at every rate ----------------------
# Pre-fix these failed at sample_rate 0 - zero events, no scan, no redaction.


def test_pii_scan_runs_at_sample_rate_zero(monkeypatch: Any) -> None:
    r = _drive(monkeypatch, 0.0, f"my ssn is {SSN}")
    assert r["blocked"], "the callback allowed a provider-bound blocked prompt"
    assert r["count"] >= 1, "a governed call emitted nothing at sample_rate 0"
    assert not r["stored_has_raw_secret"], "the raw SSN was stored unredacted"


def test_governed_event_is_never_sampled_out(monkeypatch: Any) -> None:
    r = _drive(monkeypatch, 0.0, f"my ssn is {SSN}")
    assert any(a == "blocked" for a in r["actions"]), (
        f"no governed verdict recorded at sample_rate 0: {r['actions']}"
    )


def test_same_verdict_at_sample_rate_one(monkeypatch: Any) -> None:
    r = _drive(monkeypatch, 1.0, f"my ssn is {SSN}")
    assert r["blocked"]
    assert r["count"] >= 1
    assert not r["stored_has_raw_secret"]
    assert any(a == "blocked" for a in r["actions"])


# -- emission half: sampling still samples ----------------------------------
# Also the falsifiability control for the tests above: it proves sample_rate
# reaches this surface, so a governed event surviving rate 0 is an exemption
# rather than a gate that never fired.


def test_clean_allowed_call_is_still_sampled_out(monkeypatch: Any) -> None:
    r = _drive(monkeypatch, 0.0, "what is a good tomato variety for a cold climate")
    assert r["count"] == 0, f"sampling stopped sampling: {r['actions']}"


def test_clean_allowed_call_emits_at_sample_rate_one(monkeypatch: Any) -> None:
    r = _drive(monkeypatch, 1.0, "what is a good tomato variety for a cold climate")
    assert not r["blocked"]
    assert r["count"] >= 1
    assert all(a == "allowed" for a in r["actions"])
