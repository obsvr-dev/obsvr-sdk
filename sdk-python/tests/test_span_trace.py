"""Span-to-trace linkage (SPAN_TRACE_LINKAGE.md): persists the functional proof
as a regression suite. A span scope carries a trace_id with the precedence
  explicit trace_id > enclosing scope's trace_id > own span_id (self-root)
and _emit_span_event stamps it into metadata["trace_id"] so ingest groups the
span with its run instead of orphaning it.
Twin: sdk/tests/unit/span-trace-linkage.test.ts.
"""

import obsvr
from obsvr.span import current_span, span, with_span


def test_explicit_trace_id_wins_and_is_inherited():
    with with_span("checkout_flow", "agent", trace_id="run-1"):
        assert current_span()["trace_id"] == "run-1"
        with with_span("plan_step", "chain"):
            assert current_span()["trace_id"] == "run-1"  # inherited


def test_nested_explicit_trace_id_overrides_inherited():
    with with_span("outer", "agent", trace_id="run-A"):
        with with_span("inner", "chain", trace_id="run-B"):
            assert current_span()["trace_id"] == "run-B"


def test_root_scope_self_roots_trace_id():
    with with_span("standalone", "chain"):
        ctx = current_span()
        assert ctx["trace_id"] == ctx["span_id"]


def test_spans_inside_with_span_carry_metadata_trace_id(sent):
    obsvr.init(api_key="test")
    with with_span("checkout_flow", "agent", trace_id="run-verify-1"):
        with span("kb_search", "retrieval"):
            pass
        with span("write_note", "memory"):
            pass
    spans = [e for e in sent if e.get("metadata", {}).get("obsvr_span")]
    assert len(spans) == 2
    assert all(e["metadata"]["trace_id"] == "run-verify-1" for e in spans)


def test_standalone_span_self_roots_distinct_trace_id(sent):
    obsvr.init(api_key="test")
    with span("orphan_check", "tool"):
        pass
    spans = [e for e in sent if e.get("operation") == "orphan_check"]
    assert len(spans) == 1
    meta = spans[0]["metadata"]
    assert meta["trace_id"] == meta["obsvr_span"]["span_id"]


def test_explicit_span_trace_id_overrides_enclosing_scope(sent):
    obsvr.init(api_key="test")
    with with_span("outer", "agent", trace_id="run-outer"):
        with span("pinned", "tool", trace_id="run-pinned"):
            pass
    spans = [e for e in sent if e.get("operation") == "pinned"]
    assert len(spans) == 1
    assert spans[0]["metadata"]["trace_id"] == "run-pinned"
