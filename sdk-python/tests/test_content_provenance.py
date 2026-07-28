"""Content-provenance on audit events. Twin:
sdk-typescript/tests/unit/content-provenance.test.ts.

``source`` names the integration that emitted an event; ``content_provenance``
names where inside the payload the content came from. The distinction is an
incident-triage one -- a prompt_injection in a ``user_turn`` is someone probing
your bot, the identical finding in a ``tool_result`` means an upstream source is
already compromised.

The property under test is as much about ABSENCE as presence: the field is set
only where an integration genuinely knows, and a guessed value is worse than no
value, because it gets read as evidence in exactly the incident where being
wrong costs the most.
"""

from obsvr.config import ResolvedConfig
from obsvr.events import CONTENT_PROVENANCE_METADATA_KEY, build_audit_event


def _cfg(**kw):
    defaults = dict(api_key="test", sample_rate=1)
    defaults.update(kw)
    return ResolvedConfig(**defaults)


def _event(**kw):
    return build_audit_event(
        _cfg(),
        provider="mcp",
        model="mcp",
        operation="mcp.tool.call",
        source="mcp",
        prompt="p",
        response="r",
        **kw,
    )


def test_absent_by_default():
    # Not None, not "unknown" -- the key must not be present at all.
    assert "content_provenance" not in _event()


def test_present_when_the_caller_knows():
    event = _event(content_provenance="tool_result")
    assert event["content_provenance"] == "tool_result"


def test_mirrored_onto_the_reserved_metadata_key():
    # Ingest has no column for the top-level name and strips unknown fields, so
    # the mirror is what actually survives the wire today.
    event = _event(content_provenance="tool_result")
    assert event["metadata"][CONTENT_PROVENANCE_METADATA_KEY] == "tool_result"


def test_no_mirror_when_unset():
    md = _event().get("metadata") or {}
    assert CONTENT_PROVENANCE_METADATA_KEY not in md


def test_reserved_key_survives_metadata_trimming():
    # A large event must not drop the provenance: the trimmer preserves
    # reserved keys, and this one is on that list.
    from obsvr.events import _trim_metadata_to_budget

    md = {CONTENT_PROVENANCE_METADATA_KEY: "tool_result", "junk": "x" * 20000}
    trimmed = _trim_metadata_to_budget(md)
    assert trimmed[CONTENT_PROVENANCE_METADATA_KEY] == "tool_result"


def test_it_is_not_a_policy_input():
    # Audit-record completeness only. Setting it must not move any compliance
    # field -- obsvr gates on session-taint reachability, not on source
    # classification, and this field must never quietly become a trust signal.
    plain = _event()
    tagged = _event(content_provenance="tool_result")
    for key in (
        "action_taken",
        "action_reason",
        "action_source",
        "event_type",
        "reason_code",
        "blocked_types",
        "redacted_types",
        "policy_version",
    ):
        assert plain.get(key) == tagged.get(key), key
