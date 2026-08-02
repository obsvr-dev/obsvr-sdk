"""Span-to-trace linkage: persists the functional proof
as a regression suite. A span scope carries a trace_id with the precedence
  explicit trace_id > enclosing scope's trace_id > own span_id (self-root)
and _emit_span_event stamps it into metadata["trace_id"] so ingest groups the
span with its run instead of orphaning it.
Twin: sdk-typescript/tests/unit/span-trace-linkage.test.ts.
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


# The two rows below guard behaviour of the public `span()` that had exactly one
# consumer in this repository — an ASGI middleware, since removed. Its test was
# the only thing holding either contract, and deleting it left both unguarded
# while the suite stayed green. Neither is a linkage property, so they sit at the
# end rather than among the trace_id rows above.


def test_a_span_whose_body_raises_records_failure(sent):
    """`span()` re-raises and still emits, marked failed.

    Without the `except BaseException` arm the exception propagates just the
    same and the event is still emitted by the `finally` — but it is emitted as
    a SUCCESS. Nothing else in the package drives that arm, so removing it is a
    silent change to a signed record: a request that blew up would be attested
    as having gone fine.
    """
    obsvr.init(api_key="test")
    boom = RuntimeError("handler exploded")
    try:
        with span("failing_op", "chain"):
            raise boom
    except RuntimeError as caught:
        assert caught is boom, "span() must re-raise the original, not wrap it"
    else:
        raise AssertionError("span() swallowed the exception")

    spans = [e for e in sent if e.get("operation") == "failing_op"]
    assert len(spans) == 1
    assert spans[0]["success"] is False


def test_attributes_are_read_at_span_exit_not_at_entry(sent):
    """The attrs dict is snapshotted in the `finally`, so a value written during
    the span lands on the event.

    This is what let the removed middleware set a response status it could not
    know at entry. It is a real property of the public API and it is written
    down nowhere else — `span()`'s own docstring does not state it — so a
    refactor that snapshots at entry would break callers silently.
    """
    obsvr.init(api_key="test")
    attrs = {"known.at.entry": "yes"}
    with span("late_attribute", "chain", attrs):
        attrs["known.only.at.exit"] = 201

    spans = [e for e in sent if e.get("operation") == "late_attribute"]
    assert len(spans) == 1
    emitted = spans[0]["metadata"]["obsvr_span"]["attributes"]
    assert emitted["known.at.entry"] == "yes"
    assert emitted["known.only.at.exit"] == 201
