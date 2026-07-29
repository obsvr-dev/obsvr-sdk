"""Tool policy on the tracing-processor surface: recorded, never enforced.

Until this file existed, the tool-policy branches of the tracing processor had
NO test coverage of any kind. That is how a gate that stamped
``action_taken: "blocked"`` on calls which had already completed sat in a tree
with a four-figure green suite: nothing had ever driven it.

The behaviour pinned here is deliberately the weaker one. A TracingProcessor
cannot refuse a tool call — the provider's tracing layer catches and logs
everything its processor callbacks raise, and a function span does not end until
its tool has returned — so the honest record is the absence of a verdict, with
the reason attached. Enforcing would require a different hook; claiming to
enforce required only a wrong compliance blob.
"""

import obsvr
from obsvr.events import tool_gate_not_evaluated_compliance


class _FakeTrace:
    def __init__(self, trace_id):
        self.trace_id = trace_id


class _FakeFunctionSpanData:
    type = "function"

    def __init__(self, name):
        self.name = name
        self.input = '{"amount": 500}'


class _FakeSpan:
    def __init__(self, trace_id, span_id, name):
        self.trace_id = trace_id
        self.span_id = span_id
        self.span_data = _FakeFunctionSpanData(name)


def _processor_and_span(name="send_money", span_id="span-1"):
    from obsvr.integrations.openai_agents import ObsvrTracingProcessor

    proc = ObsvrTracingProcessor()
    proc.on_trace_start(_FakeTrace("trace-1"))
    return proc, _FakeSpan("trace-1", span_id, name)


def _telemetry(event):
    return (event.get("metadata") or {}).get("obsvr_telemetry") or {}


def test_denied_tool_records_not_evaluated_not_blocked(sent):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    proc, span = _processor_and_span()

    proc.on_span_end(span)

    verdicts = [e["action_taken"] for e in sent]
    assert "blocked" not in verdicts, (
        f"a refusal was claimed about a call that already returned: {verdicts}"
    )

    gated = [e for e in sent if e["action_taken"] == "not_evaluated"]
    assert len(gated) == 1, f"expected one not_evaluated verdict, got {verdicts}"
    detail = _telemetry(gated[0])["policy_not_evaluated"]
    assert detail["gate"] == "tool_gate"
    assert "tool_denied" in detail["reason"]
    # The reason has to say WHY there is no verdict, not merely that there
    # isn't one. "after the tool has already returned" is the whole finding.
    assert "already returned" in detail["reason"]


def test_the_processor_does_not_raise_on_a_denied_tool(sent):
    """Raising here was theatre, and the theatre is what misled.

    The tracing layer swallows processor exceptions, so the old ``raise`` never
    reached the run. It did, however, read like enforcement to anyone auditing
    the source, which is how the false record survived review.
    """
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    proc, span = _processor_and_span()

    proc.on_span_end(span)  # must not raise


def test_allowlist_miss_also_records_not_evaluated(sent):
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"allowed_tools": ["get_weather"]})
    proc, span = _processor_and_span()

    proc.on_span_end(span)

    gated = [e for e in sent if e["action_taken"] == "not_evaluated"]
    assert len(gated) == 1
    assert "tool_not_in_allowlist" in _telemetry(gated[0])["policy_not_evaluated"]["reason"]


def test_a_permitted_tool_is_not_marked_not_evaluated(sent):
    """The control. Without it every assertion above passes vacuously.

    If this surface stamped ``not_evaluated`` on everything, the tests above
    would be satisfied by a gate that had stopped reading policy at all.
    """
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["something_else"]})
    proc, span = _processor_and_span(name="get_weather")

    proc.on_span_end(span)

    assert [e["action_taken"] for e in sent] == ["allowed", "allowed"], (
        "a permitted tool should produce the run-start and tool-call events "
        "with no policy verdict attached"
    )
    assert any(e["operation"] == "openai_agents.tool.call" for e in sent)


def test_step_limit_records_not_evaluated(sent):
    """The step budget cannot halt this run either, and now says so.

    Previously this event carried no compliance at all, so it inherited the
    default and landed as an ordinary permitted call — a step-limit refusal that
    every `blocked_call` filter missed.
    """
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"max_steps": 1})
    proc, _ = _processor_and_span()

    proc.on_span_end(_FakeSpan("trace-1", "span-a", "get_weather"))  # step 0
    proc.on_span_end(_FakeSpan("trace-1", "span-b", "get_weather"))  # over limit

    limit_events = [
        e for e in sent
        if e["operation"] == "openai_agents.agent.policy.step_limit"
    ]
    assert len(limit_events) == 1
    assert limit_events[0]["action_taken"] == "not_evaluated"
    assert _telemetry(limit_events[0])["policy_not_evaluated"]["gate"] == "step_limit"


def test_loop_detection_records_the_finding_without_claiming_a_halt(sent):
    """A detected loop is real evidence; the halt is what did not happen."""
    obsvr.init(
        api_key="test",
        sample_rate=1,
        agent_policy={
            "loop_detection": {
                "max_iterations": 1,
                "window_ms": 60000,
                "action": "block",
            }
        },
    )
    proc, _ = _processor_and_span()

    proc.on_span_end(_FakeSpan("trace-1", "span-a", "get_weather"))
    proc.on_span_end(_FakeSpan("trace-1", "span-b", "get_weather"))

    loops = [e for e in sent if e["event_type"] == "loop_detected"]
    assert loops, f"the loop finding was dropped: {[e['operation'] for e in sent]}"
    assert loops[-1]["action_taken"] == "not_evaluated"
    assert loops[-1]["reason_code"] == "LOOP_DETECTED", (
        "the finding must stay filterable — only the claim to have acted changes"
    )
    detail = _telemetry(loops[-1])["policy_not_evaluated"]
    assert detail["gate"] == "loop_detection"


def test_loop_detection_still_claims_blocked_where_a_caller_can_halt(sent):
    """The control for ``can_halt``. A caller on a real boundary is unchanged.

    Without this, the fix above could have been "stop saying blocked anywhere",
    which would have quietly downgraded the integrations that do enforce.
    """
    from obsvr.agent_policy import apply_loop_detection, create_loop_detector

    obsvr.init(api_key="test", sample_rate=1)
    detector = create_loop_detector(
        {"max_iterations": 1, "window_ms": 60000, "action": "block"}
    )

    from obsvr.config import try_get_config
    config = try_get_config()

    apply_loop_detection(detector, config, agent_run_id="r", source="s",
                         operation="op", can_halt=True)
    result = apply_loop_detection(detector, config, agent_run_id="r", source="s",
                                  operation="op", can_halt=True)

    assert result["action"] == "block"
    assert sent[-1]["action_taken"] == "blocked"
    assert "policy_not_evaluated" not in _telemetry(sent[-1])


def test_the_not_evaluated_compliance_reaches_the_wire_shape():
    """The mirror, pinned directly.

    ``policy_not_evaluated`` has no top-level ingest column, so a builder that
    returned it without the metadata mirror would drop the reason silently —
    which is what this side did until now, while the TypeScript side carried it.
    """
    from obsvr.config import try_get_config
    from obsvr.events import build_audit_event

    obsvr.init(api_key="test", sample_rate=1)
    event = build_audit_event(
        try_get_config(),
        provider="unknown", model="unknown", operation="x.tool.call",
        source="test", prompt="", response="",
        compliance=tool_gate_not_evaluated_compliance(
            surface="x.tool.call", gate="tool_gate", reason="because",
        ),
    )

    assert event["action_taken"] == "not_evaluated"
    assert event["event_type"] == "tool_call"
    assert event["metadata"]["obsvr_telemetry"]["policy_not_evaluated"] == {
        "surface": "x.tool.call",
        "gate": "tool_gate",
        "reason": "because",
    }
    # Not a top-level field: ingest strips unknown top-level keys, and a test
    # asserting it there would pass while the value never left the process.
    assert "policy_not_evaluated" not in event
