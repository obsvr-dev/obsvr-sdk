"""Tests for the Haystack 2.x integration.

Haystack is not installed; ObsvrGuard uses a shim @component decorator so the
governance node is still constructable and its run() logic runs. The behavior
tests prove a block raises out of run() (which aborts a real pipeline before the
downstream generator runs).
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
