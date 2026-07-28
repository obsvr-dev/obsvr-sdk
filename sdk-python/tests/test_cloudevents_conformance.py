"""Cross-SDK CloudEvents v1.0 export conformance (Python side). Twin:
sdk/tests/unit/cloudevents-conformance.test.ts.

The canonical STRING is the contract - an interchange envelope that two SDKs
render differently is not an interchange envelope - so each case asserts the
exact bytes as well as the parsed shape.
"""

import json
import re
from pathlib import Path

import pytest

from obsvr.cloudevents import (
    rfc3339_from_epoch_ms,
    safe_serialize_cloud_event,
    serialize_cloud_event,
    to_cloud_event,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/cloudevents.json")
    .resolve()
    .read_text(encoding="utf-8")
)

ENVELOPE_CASES = FIXTURE["envelope_cases"]
TIME_CASES = FIXTURE["time_cases"]

RESERVED_ATTRIBUTES = {
    "id",
    "source",
    "specversion",
    "type",
    "datacontenttype",
    "dataschema",
    "subject",
    "time",
    "data",
}
EXTENSION_NAME = re.compile(r"^[a-z][a-z0-9]{0,19}$")


@pytest.mark.parametrize("case", ENVELOPE_CASES, ids=[c["id"] for c in ENVELOPE_CASES])
def test_envelope_projection(case):
    if case["sdk_support"].get("py") == "skip":
        pytest.skip(f"{case['id']}: sdk_support py=skip")
    event = case["event"]
    assert to_cloud_event(event) == case["expect"]["envelope"]
    assert serialize_cloud_event(event) == case["expect"]["serialized"]


@pytest.mark.parametrize("case", TIME_CASES, ids=[c["id"] for c in TIME_CASES])
def test_rfc3339_rendering(case):
    assert rfc3339_from_epoch_ms(case["epoch_ms"]) == case["expect"]


class TestSpecLevelInvariants:
    def test_required_attributes_are_non_empty_strings(self):
        for case in ENVELOPE_CASES:
            ce = to_cloud_event(case["event"])
            for key in ("id", "source", "specversion", "type"):
                assert isinstance(ce[key], str), (case["id"], key)
                assert ce[key], (case["id"], key)

    def test_optional_attributes_present_are_non_empty(self):
        for case in ENVELOPE_CASES:
            ce = to_cloud_event(case["event"])
            for key in ("subject", "time", "datacontenttype", "dataschema"):
                if key in ce:
                    assert str(ce[key]), (case["id"], key)

    def test_extension_names_follow_the_spec(self):
        for case in ENVELOPE_CASES:
            ce = to_cloud_event(case["event"])
            for key in ce:
                if key in RESERVED_ATTRIBUTES:
                    continue
                assert EXTENSION_NAME.match(key), (case["id"], key)

    def test_carries_the_audit_event_unmodified_by_reference(self):
        event = ENVELOPE_CASES[0]["event"]
        before = json.dumps(event, sort_keys=True)
        ce = to_cloud_event(event)
        assert ce["data"] is event
        assert json.dumps(event, sort_keys=True) == before

    def test_refuses_an_unrenderable_number_rather_than_disagreeing(self):
        # An integer past 2^53 is a value the two runtimes cannot render
        # identically, so claiming byte-identical output for it would be a lie.
        event = dict(ENVELOPE_CASES[0]["event"])
        event["metadata"] = {"huge": 12345678901234567890}
        with pytest.raises(ValueError):
            serialize_cloud_event(event)
        assert safe_serialize_cloud_event(event) is None

    def test_safe_serializer_returns_the_string_for_a_renderable_event(self):
        event = ENVELOPE_CASES[0]["event"]
        assert safe_serialize_cloud_event(event) == serialize_cloud_event(event)
