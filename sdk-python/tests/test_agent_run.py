"""Agent-run lifecycle: ``agent_run(...)`` forms one run and every governed
action inside it auto-joins via the ambient ``agent_run_id``. This is what
populates the dashboard Runs tab for tool-governed frameworks.

Twin: sdk/tests/unit/agent-run.test.ts.
"""

import obsvr
from obsvr import agent_run, current_agent_run_id
from obsvr.span import span


def test_emits_run_start_and_finish_with_shared_id(sent):
    obsvr.init(api_key="test")
    with agent_run("my-agent", source="llamaindex_py"):
        pass

    start = next(e for e in sent if e["operation"] == "llamaindex_py.agent.run.start")
    finish = next(e for e in sent if e["operation"] == "llamaindex_py.agent.run.finish")
    assert start["metadata"]["agent_run_id"]
    assert finish["metadata"]["agent_run_id"] == start["metadata"]["agent_run_id"]
    assert finish["success"] is True


def test_finish_success_false_on_exception_and_reraises(sent):
    obsvr.init(api_key="test")
    raised = False
    try:
        with agent_run("boom-agent", source="llamaindex_py"):
            raise ValueError("agent exploded")
    except ValueError as e:
        raised = "agent exploded" in str(e)
    assert raised
    finish = next(e for e in sent if e["operation"] == "llamaindex_py.agent.run.finish")
    assert finish["success"] is False


def test_span_inside_run_carries_agent_run_id(sent):
    obsvr.init(api_key="test")
    with agent_run("tool-agent", source="vercel_ai_py"):
        with span("kb_search", "retrieval"):
            pass

    start = next(e for e in sent if e["operation"] == "vercel_ai_py.agent.run.start")
    span_ev = next(e for e in sent if e.get("operation") == "kb_search")
    assert span_ev["metadata"]["agent_run_id"] == start["metadata"]["agent_run_id"]


def test_no_agent_run_id_outside_a_run_scope(sent):
    obsvr.init(api_key="test")
    with span("orphan", "retrieval"):
        pass
    span_ev = next(e for e in sent if e.get("operation") == "orphan")
    assert span_ev["metadata"].get("agent_run_id") is None
    assert current_agent_run_id() is None


def test_current_agent_run_id_tracks_scope():
    assert current_agent_run_id() is None
    with agent_run("scoped", source="x"):
        assert current_agent_run_id() is not None
    assert current_agent_run_id() is None
