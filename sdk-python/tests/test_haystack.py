"""Tests for the Haystack integration.

Haystack is not installed here; ObsvrGuard uses a shim @component decorator so
the governance node is still constructable and its run() logic runs. What these
tests establish is therefore bounded: a block raises out of run(), a redact
returns scrubbed text, an allow passes through.

They do NOT establish that a raise aborts a real Pipeline before the downstream
Generator, because a shimmed component is not in a pipeline graph — that is a
property of Haystack, not of this code, and asserting it from here would be the
same shape of vacuous coverage the canary wiring test carried. It was measured
separately, out of tree, against a real Pipeline and a real Generator on both
ends of the supported range, graded on whether the provider received bytes.
"""
import pytest

import obsvr
from obsvr.integrations.haystack import ObsvrGuard, ObsvrHaystackBlocked


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _mini_pipeline(guard, prompt):
    """Emulate a 2-node pipeline: guard -> sink. A raise aborts before sink."""
    sink = {"ran": False, "prompt": None}
    out = guard.run(prompt)  # raises on block, aborting the pipeline
    sink["ran"] = True
    sink["prompt"] = out["prompt"]
    return sink


def test_clean_prompt_passes_through(sent):
    _init()
    guard = ObsvrGuard()
    out = guard.run("summarize this document")
    assert out["prompt"] == "summarize this document"
    assert out["blocked"] is False


def test_block_aborts_pipeline_before_sink(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    guard = ObsvrGuard()
    with pytest.raises(ObsvrHaystackBlocked):
        _mini_pipeline(guard, "the ssn is 123-45-6789")
    assert sent[0]["event_type"] == "blocked_call"


def test_downstream_never_runs_on_block(sent):
    _init(on_pre_call=lambda e: "block")
    guard = ObsvrGuard()
    sink = {"ran": False}
    try:
        out = guard.run("anything")
        sink["ran"] = True
    except ObsvrHaystackBlocked:
        pass
    assert sink["ran"] is False


def test_redact_forwards_governed_prompt(sent):
    _init(pii_policy={"rules": {"email": "redact"}})
    guard = ObsvrGuard()
    out = _mini_pipeline(guard, "email me at alice@example.com")
    assert "alice@example.com" not in out["prompt"]
    assert "[REDACTED_EMAIL]" in out["prompt"]
