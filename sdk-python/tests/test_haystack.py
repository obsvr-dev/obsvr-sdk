"""Tests for the Haystack integration.

Haystack is not installed here; ObsvrGuard uses a shim @component decorator so
the governance node is still constructable and its run() logic runs. What these
tests establish is therefore bounded: a block omits the downstream prompt, a
redact returns scrubbed text, and an allow passes through.

The real-package regression separately drives this conditional output through
Haystack's synchronous and asynchronous schedulers.
"""

import obsvr
from obsvr.integrations.haystack import ObsvrGuard


def _init(**extra):
    extra.setdefault("policy_refresh_interval_s", 0)
    obsvr.init(api_key="k", ingest_url="http://localhost:9", **extra)


def _mini_pipeline(guard, prompt):
    """Emulate a 2-node pipeline: only a produced prompt activates the sink."""
    sink = {"ran": False, "prompt": None}
    out = guard.run(prompt)
    if "prompt" in out:
        sink["ran"] = True
        sink["prompt"] = out["prompt"]
    return out, sink


def test_clean_prompt_passes_through(sent):
    _init()
    guard = ObsvrGuard()
    out = guard.run("summarize this document")
    assert out["prompt"] == "summarize this document"
    assert out["blocked"] is False


def test_block_returns_terminal_branch_without_prompt(sent):
    _init(pii_policy={"rules": {"ssn": "block"}})
    guard = ObsvrGuard()
    raw_prompt = "the ssn is 123-45-6789"
    out, sink = _mini_pipeline(guard, raw_prompt)
    assert out == {
        "blocked": True,
        "redacted": False,
        "block_reason": "policy_blocked",
    }
    assert sink["ran"] is False
    assert raw_prompt not in repr(out)
    assert sent[0]["event_type"] == "blocked_call"
    assert raw_prompt not in repr(sent[0])


def test_downstream_never_runs_on_block(sent):
    _init(on_pre_call=lambda e: "block")
    guard = ObsvrGuard()
    out, sink = _mini_pipeline(guard, "anything")
    assert sink["ran"] is False
    assert out["blocked"] is True


def test_redact_forwards_governed_prompt(sent):
    _init(pii_policy={"rules": {"email": "redact"}})
    guard = ObsvrGuard()
    _, sink = _mini_pipeline(guard, "email me at alice@example.com")
    assert "alice@example.com" not in sink["prompt"]
    assert "[REDACTED_EMAIL]" in sink["prompt"]
