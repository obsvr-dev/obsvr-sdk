"""Host metadata cannot break the caller's call.

Twin: sdk-typescript/tests/unit/metadata-trim-hostile.test.ts.

``_trim_metadata_to_budget`` measures the metadata bag with ``json.dumps`` before
deciding whether to shrink it, and that bag is CALLER-SUPPLIED. ``default=str``
already covers a value ``json`` cannot serialize, but two shapes raise straight
through it — a circular reference and a value whose own ``__str__`` raises — and
the trim runs on the caller's synchronous emit path, so the raise left the sender
and landed in the application's own call.

A bag that cannot be measured is treated as over budget and takes the trimming
branch that already exists for an oversized one: the posture ingest already
expects, rather than a new one.
"""
import pytest

import obsvr
from obsvr.events import _trim_metadata_to_budget, build_audit_event


class ExplodesOnStr:
    """``default=str`` reaches for ``str(obj)``; this one raises there."""

    def __repr__(self):  # pragma: no cover - only reached on a failure message
        return "<ExplodesOnStr>"

    def __str__(self):
        raise RuntimeError("this value refuses to be rendered")


def circular():
    md = {"trace_id": "trace-keep-me"}
    md["self"] = md
    return md


def exploding_value():
    return {"trace_id": "trace-keep-me", "ctx": ExplodesOnStr()}


HOSTILE = [
    pytest.param(circular, id="a circular reference"),
    pytest.param(exploding_value, id="a value whose __str__ raises"),
]


@pytest.mark.parametrize("build", HOSTILE)
def test_the_trim_does_not_raise(build):
    _trim_metadata_to_budget(build())  # must not raise


@pytest.mark.parametrize("build", HOSTILE)
def test_the_trim_keeps_the_grouping_key(build):
    """The whole point of the existing over-budget branch: ``trace_id``
    survives, so the event is still joined to its trace rather than orphaned."""
    out = _trim_metadata_to_budget(build())

    assert out["_obsvr_metadata_trimmed"] is True
    assert out["trace_id"] == "trace-keep-me"


@pytest.mark.parametrize("build", HOSTILE)
def test_building_an_event_with_it_does_not_raise_into_the_caller(build):
    obsvr.init(api_key="k", ingest_url="https://example.test")

    event = build_audit_event(
        obsvr.config.get_config(),
        provider="openai",
        model="gpt-4o",
        operation="chat.completions.create",
        source="test",
        prompt="hello",
        response="hi",
        success=True,
        metadata=build(),
    )

    assert event["metadata"]["_obsvr_metadata_trimmed"] is True
    assert event["metadata"]["trace_id"] == "trace-keep-me"


# ── the ordinary paths are unchanged ────────────────────────────────────────


def test_metadata_under_budget_rides_through_untouched():
    out = _trim_metadata_to_budget({"trace_id": "t", "tenant": "acme"})

    assert out["tenant"] == "acme"
    assert "_obsvr_metadata_trimmed" not in out


def test_metadata_over_budget_still_trims_to_the_reserved_keys():
    out = _trim_metadata_to_budget(
        {"trace_id": "t", "blob": "x" * 20_000, "tenant": "acme"}
    )

    assert out["_obsvr_metadata_trimmed"] is True
    assert out["trace_id"] == "t"
    assert "tenant" not in out


def test_the_span_attribute_bag_is_still_collapsed_first():
    out = _trim_metadata_to_budget(
        {
            "trace_id": "t",
            "tenant": "acme",
            "obsvr_span": {"name": "s", "attributes": {"big": "y" * 20_000}},
        }
    )

    # Shrinking the span alone got it under budget, so `tenant` survived.
    assert out["_obsvr_metadata_trimmed"] is True
    assert out["tenant"] == "acme"
    assert out["obsvr_span"]["attributes"] == {"_trimmed": True}


def test_a_value_json_cannot_serialize_is_still_stringified_not_trimmed():
    """The behaviour ``default=str`` was there for, kept: an ordinary
    non-serializable value is rendered, not treated as unmeasurable."""

    class Plain:
        def __str__(self):
            return "plain"

    out = _trim_metadata_to_budget({"trace_id": "t", "obj": Plain()})

    assert "_obsvr_metadata_trimmed" not in out
    assert isinstance(out["obj"], Plain)
