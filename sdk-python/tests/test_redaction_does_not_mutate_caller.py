"""Outbound PII redaction must not rewrite the caller's own objects.

``**kwargs`` makes the kwargs dict fresh at the call boundary, so rebinding
``kwargs["system"]`` was always safe — but the containers inside it are the
caller's, and redaction walked into ``messages`` and assigned
``msg["content"]``. A conversation history is normally a list the application
keeps and appends to, so one redacted turn rewrote the application's own history
and every later turn sent the placeholder where it believed it still held text.

The message-OBJECT branch was worse: it called ``setattr`` on the caller's model
instance and swallowed the failure, so the only cases it did not corrupt were
the ones that refused to be corrupted.

Twin: sdk-typescript/tests/unit/redaction-does-not-mutate-caller.test.ts.
"""

import pytest

import obsvr
from obsvr.config import _reset
from obsvr.errors import ObsvrPolicyError
from obsvr.wrap import wrap

SSN = "123-45-6789"


class _FakeClient:
    """Records exactly what the provider received."""

    def __init__(self):
        self.seen = None

        class _Completions:
            def create(_self, **kwargs):
                self.seen = kwargs
                return {
                    "choices": [{"message": {"content": "ok"}}],
                    "model": "gpt-4",
                }

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


class _MessageObject:
    """A provider-style message object, not a dict."""

    def __init__(self, role, content):
        self.role = role
        self.content = content


def _init(**extra):
    _reset()
    extra.setdefault("pii_policy", {"rules": {"ssn": "redact"}})
    obsvr.init(api_key="k", ingest_url="https://x", **extra)


class TestRedactionLeavesCallerObjectsAlone:
    def test_does_not_rewrite_a_message_dict_the_caller_still_holds(self):
        _init()
        client = _FakeClient()
        history = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"my ssn is {SSN}"},
        ]
        wrap(client).chat.completions.create(model="gpt-4", messages=history)

        # The provider must have received the redacted text — without this the
        # test would also pass if redaction had simply stopped working.
        sent = str(client.seen)
        assert SSN not in sent
        assert "[REDACTED_SSN]" in sent

        # And the caller's own list must be untouched.
        assert history[1]["content"] == f"my ssn is {SSN}"

    def test_does_not_rewrite_a_content_block_the_caller_still_holds(self):
        _init()
        client = _FakeClient()
        block = {"type": "text", "text": f"my ssn is {SSN}"}
        history = [{"role": "user", "content": [block]}]
        wrap(client).chat.completions.create(model="gpt-4", messages=history)

        sent = str(client.seen)
        assert SSN not in sent
        assert "[REDACTED_SSN]" in sent
        assert block["text"] == f"my ssn is {SSN}"

    def test_does_not_mutate_a_caller_message_object(self):
        _init()
        client = _FakeClient()
        msg = _MessageObject("user", f"my ssn is {SSN}")
        wrap(client).chat.completions.create(model="gpt-4", messages=[msg])

        # str() of the kwargs shows this object's default repr, not its
        # content, so assert on the object the provider actually received.
        delivered = client.seen["messages"][0]
        assert delivered is not msg, "the caller's own instance was forwarded"
        assert delivered.content == "my ssn is [REDACTED_SSN]"
        assert isinstance(delivered, _MessageObject), (
            "the copy must keep the provider's own type, not become a dict"
        )
        # The caller's own instance is unchanged.
        assert msg.content == f"my ssn is {SSN}"

    def test_does_not_rewrite_a_gemini_contents_part_the_caller_still_holds(self):
        _init()
        client = _FakeClient()
        part = {"text": f"my ssn is {SSN}"}
        contents = [{"role": "user", "parts": [part]}]
        wrap(client).chat.completions.create(model="gpt-4", contents=contents)

        assert SSN not in str(client.seen)
        assert part["text"] == f"my ssn is {SSN}"

    def test_a_read_only_message_is_redacted_and_the_call_succeeds(self):
        """The Python twin of the frozen-message case.

        This shape used to make the redaction walk raise, which resolved closed
        and refused the call.
        """

        class _ReadOnlyMessage(dict):
            def __setitem__(self, *_args):
                raise TypeError("message is read-only")

        _init()
        client = _FakeClient()
        msg = _ReadOnlyMessage(role="user", content=f"my ssn is {SSN}")
        res = wrap(client).chat.completions.create(model="gpt-4", messages=[msg])

        assert res == {"choices": [{"message": {"content": "ok"}}], "model": "gpt-4"}
        sent = str(client.seen)
        assert SSN not in sent
        assert "[REDACTED_SSN]" in sent
        assert msg["content"] == f"my ssn is {SSN}"

    def test_an_uncopyable_message_blocks_before_the_provider_is_called(self):
        class _UncopyableMessage:
            role = "user"

            def __init__(self, content):
                self.content = content

            def __copy__(self):
                raise TypeError("message cannot be copied")

        _init()
        client = _FakeClient()
        msg = _UncopyableMessage(f"my ssn is {SSN}")

        with pytest.raises(ObsvrPolicyError):
            wrap(client).chat.completions.create(model="gpt-4", messages=[msg])

        assert client.seen is None, "redaction failure must stop the provider call"
        assert msg.content == f"my ssn is {SSN}"

    def test_control_with_no_redacting_rule_the_ssn_goes_out_unchanged(self):
        # Without this row, "the caller's object is unchanged" would also be
        # satisfied by redaction never running at all.
        _init(pii_policy={"rules": {"ssn": "detect_only"}})
        client = _FakeClient()
        history = [{"role": "user", "content": f"my ssn is {SSN}"}]
        wrap(client).chat.completions.create(model="gpt-4", messages=history)

        assert SSN in str(client.seen)
        assert history[0]["content"] == f"my ssn is {SSN}"
