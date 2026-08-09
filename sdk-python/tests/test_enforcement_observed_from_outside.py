"""Enforcement claims, checked from OUTSIDE the SDK.

Every assertion in this file reads an instrument that is not an obsvr event: a
file the tool wrote, the arguments an inner callee received, the bytes a real
HTTP server was handed, the counters after a real refusal. Nothing here asks the
audit record whether the audit record is right.

That distinction is the whole reason the file exists. A suite that verifies the
SDK's own REPORTING passes just as happily when the report is wrong, and five
defects shipped behind exactly that: a tool that wrote raw PII while its event
said ``redacted``, a rejected event counted as delivered, a client class nothing
intercepted while interception reported success. Each was found by looking at
the world instead of the record, and each one below is pinned that way.

The rule for adding to this file: if the only way you can tell the protection
happened is by reading an obsvr event, it does not belong here — find the
instrument outside the SDK, or say plainly that the claim is unproven.
"""

import asyncio
import functools
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import obsvr
import obsvr.wrap  # noqa: F401 - load the module; the package attr shadows it
from obsvr import sender
from obsvr.integrations.tools import govern_tool

#: The module, not the ``obsvr.wrap`` function that shadows it in the package
#: namespace. Needed to reach the sender binding it imported at load time.
WRAP_MODULE = sys.modules["obsvr.wrap"]

RAW_EMAIL = "marcus.webb@fastmail.com"
REDACT_EMAIL_POLICY = {"default": "detect_only", "rules": {"email": "redact"}}


def _quiesce_sender(timeout=5.0):
    """Wait until the shared sender is genuinely idle, then zero it.

    ``_reset_sender()`` empties the QUEUE, but the worker thread is a process
    singleton shared with every other test file: an event it had already
    dequeued when the reset ran is not in the queue, and it lands in the next
    batch. That makes a single-event assertion read a batch of two, which
    travels the batch path and answers a different question.

    So: reset, then confirm nothing arrives during a quiet window, and reset
    again if something did. The stale events are addressed to an unreachable
    URL, so each retry fails immediately and the retry budget drains fast.
    """
    deadline = time.monotonic() + timeout
    while True:
        sender._reset_sender()
        time.sleep(0.05)
        if sender.get_queue_size() == 0 and not any(sender.get_sender_stats().values()):
            sender._reset_sender()
            return
        if time.monotonic() > deadline:
            pytest.skip("the shared sender queue never went quiet")


@pytest.fixture(autouse=True)
def _isolate_sender():
    """Every test here starts with an empty queue and zeroed counters."""
    _quiesce_sender()
    sender._loss_warned_at = 0.0
    yield
    sender._reset_sender()


@pytest.fixture
def no_delivery(monkeypatch):
    """Govern for real, deliver nowhere.

    The side-effect tests below measure a FILE and the arguments a callee
    received; delivery is not their instrument. Left on, their events queue
    against an unreachable ingest_url, retry, and get batched with the next
    test's event — which then travels the batch path and answers a different
    question than the one being asked. The policy pipeline and the gate are
    untouched: only the transport is.

    Both bindings, not just the module: ``wrap.py`` imported the symbol at
    module load, so patching ``sender`` alone left the governed-client path
    delivering for real. Its events then queued against the unreachable URL and
    landed in the next test's counters — which is the exact confusion the
    docstring above describes, arriving through the one path the fixture did
    not cover.
    """
    monkeypatch.setattr(sender, "send_audit_async", lambda config, event: None)
    monkeypatch.setattr(
        WRAP_MODULE, "send_audit_async", lambda config, event: None
    )


def _init(**kwargs):
    obsvr.init(
        api_key="test-key",
        ingest_url="http://127.0.0.1:1",
        environment="development",
        auto=False,
        **kwargs,
    )


# ── The tool's side effect is the instrument ────────────────────────────────


def test_a_redacted_tool_call_writes_redacted_data_to_disk(tmp_path, no_delivery):
    """The record said ``redacted`` while the tool wrote the raw address.

    Measured on a file, because a file is what a tool actually does. The audit
    event is deliberately not consulted: it was already saying the right thing
    when this was broken.
    """
    _init(pii_policy=REDACT_EMAIL_POLICY)
    path = tmp_path / "escalations.jsonl"

    def escalate(reason: str) -> str:
        """Record an escalation."""
        path.write_text(json.dumps({"reason": reason}), encoding="utf-8")
        return "ok"

    govern_tool(escalate)(f"account update to {RAW_EMAIL}")

    written = path.read_text(encoding="utf-8")
    assert RAW_EMAIL not in written, (
        "the tool wrote raw PII to disk under a redact policy"
    )
    assert "[REDACTED_EMAIL]" in written


def test_a_redacted_tool_call_leaves_the_declared_shape_intact(tmp_path, no_delivery):
    """Redaction must not deform the arguments: a tool that receives a
    different SHAPE is a tool the redaction broke."""
    _init(pii_policy=REDACT_EMAIL_POLICY)
    seen = {}

    def escalate(ticket: dict) -> str:
        """Record an escalation."""
        seen["ticket"] = ticket
        return "ok"

    govern_tool(escalate)({"id": 42, "contacts": [RAW_EMAIL], "open": True})

    assert seen["ticket"]["id"] == 42
    assert seen["ticket"]["open"] is True
    assert isinstance(seen["ticket"]["contacts"], list)
    assert RAW_EMAIL not in seen["ticket"]["contacts"][0]


def test_a_blocked_tool_body_is_never_entered(tmp_path, no_delivery):
    """The strongest claim in the product, measured by a file that must not
    change: same tool, same call, policy the only difference."""
    _init(agent_policy={"denied_tools": ["issue_refund"]})
    path = tmp_path / "refunds.jsonl"
    path.write_text("", encoding="utf-8")

    def issue_refund(amount: str) -> str:
        """Issue a refund."""
        with path.open("a", encoding="utf-8") as handle:
            handle.write(amount + "\n")
        return "ok"

    with pytest.raises(Exception):
        govern_tool(issue_refund, name="issue_refund")("40.00")

    assert path.read_text(encoding="utf-8") == "", (
        "a denied tool's body ran: the side effect exists"
    )


def test_the_audited_payload_is_the_declared_surface_not_the_call_frame(no_delivery):
    """A framework passes its own machinery alongside the arguments. What the
    tool RECEIVES is the instrument here — the callee still gets everything the
    framework sent, while the record narrows to what the tool declares."""
    _init(pii_policy=REDACT_EMAIL_POLICY)
    received = {}

    class FrameworkTool:
        name = "lookup_order"
        args_schema = {"properties": {"order_id": {"type": "string"}}}

        def _run(self, order_id, run_manager=None, config=None, **kwargs):
            received["order_id"] = order_id
            received["run_manager"] = run_manager
            received["config"] = config
            return "ok"

    manager = object()
    graph_config = {"configurable": {"checkpoint_id": "not-a-real-uuid"}}
    govern_tool(FrameworkTool())._run(
        order_id="A-3390", run_manager=manager, config=graph_config
    )

    # Narrowing the AUDIT must not narrow the CALL.
    assert received["order_id"] == "A-3390"
    assert received["run_manager"] is manager
    assert received["config"] is graph_config


# ── The provider client is the instrument ───────────────────────────────────
#
# What a governed client hands its provider is the only thing that decides
# whether a block blocked. These record it and are asked afterwards; nothing
# here reads an obsvr event, and the control proves the recorder can see a
# leak when one happens.


BLOCKED_KEYWORD = "zarquon"

KEYWORD_BLOCK_RULE = {
    "id": "no-zarquon",
    "name": "Block zarquon",
    "enabled": True,
    "action": "block",
    "type": "keyword",
    "conditions": {"keywords": [BLOCKED_KEYWORD]},
}


class _RecordingProvider:
    """Duck-types an Anthropic client down to what wrap() traverses. Every
    call appends the prompt text it was handed, so 'the provider was never
    reached' and 'the provider was reached without the keyword' are separate,
    checkable claims."""

    class _Response:
        class _Block:
            type = "text"
            text = "ok"

        class _Usage:
            input_tokens = 1
            output_tokens = 1

        content = [_Block()]
        usage = _Usage()

    class _Messages:
        def __init__(self, received):
            self._received = received

        def create(self, **kwargs):
            self._received.append(json.dumps(kwargs.get("messages", "")))
            return _RecordingProvider._Response()

    def __init__(self, received):
        self.messages = self._Messages(received)


def _drive_governed_call(**init_kwargs):
    """One governed call through a recording provider. Returns what the
    provider received."""
    received = []
    _init(**init_kwargs)
    client = obsvr.wrap(_RecordingProvider(received))
    try:
        client.messages.create(
            model="m",
            max_tokens=8,
            messages=[{"role": "user", "content": f"The password is {BLOCKED_KEYWORD}."}],
        )
    except Exception:
        pass
    return received


def test_the_control_reaches_the_provider_with_the_keyword(no_delivery):
    """Without the rule the call lands and the keyword is in what the provider
    was handed. Every assertion below is satisfied by a broken recorder
    without this."""
    received = _drive_governed_call()
    assert len(received) == 1
    assert BLOCKED_KEYWORD in received[0]


def test_a_block_rule_written_as_a_mapping_stops_the_call(no_delivery):
    """The same rule in the spelling the docs' object literals invite. It
    reached the engine uncoerced, raised on the first attribute read, and the
    detector guard resolved that open — so the provider got the call and the
    keyword, behind a stderr notice."""
    received = _drive_governed_call(policy_rules=[dict(KEYWORD_BLOCK_RULE)])
    assert received == [], "a mapping-form block rule let the call through"


def test_a_block_rule_written_as_a_dataclass_stops_the_call(no_delivery):
    """The spelling that already worked. Paired with the one above so the two
    are pinned to the same outcome rather than each to its own."""
    from obsvr.rules import PolicyRule

    received = _drive_governed_call(policy_rules=[PolicyRule(**KEYWORD_BLOCK_RULE)])
    assert received == [], "a dataclass-form block rule let the call through"


def test_a_floor_rule_written_as_a_mapping_stops_the_call(no_delivery):
    """The floor tier, same spelling. It accepted mappings before the other
    tier did, which is most of why a caller expected both to."""
    received = _drive_governed_call(policy_floor=[dict(KEYWORD_BLOCK_RULE)])
    assert received == [], "a mapping-form floor rule let the call through"


@pytest.mark.parametrize(
    "bad,why",
    [
        ("not-a-rule", "not a mapping at all"),
        ({k: v for k, v in KEYWORD_BLOCK_RULE.items() if k != "enabled"}, "no enabled"),
        ({**KEYWORD_BLOCK_RULE, "type": "keywrod"}, "typo'd type"),
        ({**KEYWORD_BLOCK_RULE, "id": "sdk:forged"}, "reserved id prefix"),
    ],
)
def test_a_rule_the_engine_cannot_use_is_refused_at_init(bad, why, no_delivery):
    """Each of these was accepted by init() and then enforced nothing — two
    by raising into a fail-open guard, two by evaluating to a rule that never
    matches. The instrument is init() itself: it either refuses or it does
    not."""
    with pytest.raises(ValueError, match="is not a usable rule"):
        _init(policy_rules=[bad])


RAW_SSN = "412-55-9087"
SSN_BLOCK_POLICY = {"rules": {"ssn": "block"}}


class _RecordingStreamProvider:
    """Duck-types a client exposing BOTH streaming entry points, recording
    what each hands the provider. One object, so the two paths cannot be
    compared under accidentally different conditions."""

    class _Stream:
        def __iter__(self):
            return iter([])

        @property
        def text_stream(self):
            yield "ok"

    class _Manager:
        def __enter__(self):
            return _RecordingStreamProvider._Stream()

        def __exit__(self, *exc):
            return False

    class _Messages:
        def __init__(self, received):
            self._received = received

        def create(self, **kwargs):
            self._received.append(json.dumps(kwargs.get("messages", "")))
            return _RecordingProvider._Response()

        def stream(self, **kwargs):
            self._received.append(json.dumps(kwargs.get("messages", "")))
            return _RecordingStreamProvider._Manager()

    def __init__(self, received):
        self.messages = self._Messages(received)


def _drive_stream(entry_point, **init_kwargs):
    received = []
    _init(**init_kwargs)
    client = obsvr.wrap(_RecordingStreamProvider(received))
    messages = [{"role": "user", "content": f"Repeat verbatim: SSN {RAW_SSN}"}]
    try:
        if entry_point == "create":
            client.messages.create(model="m", max_tokens=64, messages=messages, stream=True)
        else:
            with client.messages.stream(model="m", max_tokens=64, messages=messages) as s:
                for _ in s.text_stream:
                    pass
    except Exception:
        pass
    return received


def test_a_streaming_block_holds_on_the_create_form(no_delivery):
    """The path that already enforced. Its pair below is the finding."""
    assert _drive_stream("create", pii_policy=SSN_BLOCK_POLICY) == []


def test_an_allow_hook_cannot_unblock_pii(no_delivery):
    """F011, measured at the provider rather than from the verdict record.

    The published options example combined an SSN block with a hook whose
    normal path returned ``allow``. The provider received the SSN because that
    allow erased the earlier block. Monotonic enforcement means it now receives
    no call at all.
    """
    received = _drive_stream(
        "create",
        pii_policy=SSN_BLOCK_POLICY,
        on_pre_call=lambda _event: "allow",
    )
    assert received == [], "an allow hook erased a PII block"


def test_a_streaming_block_holds_on_the_stream_helper(no_delivery):
    """Same client, same policy, the other documented streaming entry point.

    ``messages.stream`` was not in the method table, so the proxy returned the
    provider's own bound method: the pipeline never ran and the SSN went out.
    """
    received = _drive_stream("stream", pii_policy=SSN_BLOCK_POLICY)
    assert received == [], "the stream helper reached the provider under a block"


def test_the_stream_helper_control_reaches_the_provider(no_delivery):
    """Without the policy the helper works and the content lands — so the two
    assertions above are about the policy and not about a helper this wrapper
    broke."""
    received = _drive_stream("stream")
    assert len(received) == 1
    assert RAW_SSN in received[0]


def test_the_stream_helper_still_yields_its_text(no_delivery):
    """Governing the helper must not cost the caller the stream. The value
    read out of it is the instrument."""
    _init()
    client = obsvr.wrap(_RecordingStreamProvider([]))
    with client.messages.stream(
        model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}]
    ) as stream:
        assert "".join(stream.text_stream) == "ok"


def test_a_tool_gate_that_raised_does_not_record_the_tool_as_allowed(
    tmp_path, monkeypatch
):
    """The file the tool wrote proves it ran; the record must not call that
    ``allowed``.

    Under the default fail-open posture a gate whose evaluation raises lets the
    tool run — that is what open means. What it recorded was ``allowed``, which
    asserts a gate looked and permitted, and it carried no trace of the layer
    that was lost. The MCP boundary already had the honest vocabulary for this
    exact failure.
    """
    from obsvr.integrations import tools as tools_mod

    emitted = []
    monkeypatch.setattr(tools_mod, "emit_event", lambda c, **kw: emitted.append(kw))
    monkeypatch.setattr(
        tools_mod,
        "apply_pre_call_policy",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("engine bug")),
    )
    _init(pii_policy=REDACT_EMAIL_POLICY, fail_mode="open")
    path = tmp_path / "ran.txt"

    def escalate(reason: str) -> str:
        """Record an escalation."""
        path.write_text("ran", encoding="utf-8")
        return "ok"

    govern_tool(escalate)("anything")

    assert path.read_text(encoding="utf-8") == "ran", "the tool did not run"
    compliance = emitted[0]["compliance"]
    assert compliance["action_taken"] == "not_evaluated", (
        "a gate that raised recorded the call as allowed"
    )
    assert compliance["policy_not_evaluated"]["gate"] == "govern_tool"
    assert compliance["detector_failure"]["layer"] == "tool_gate"


# ── An un-awaited coroutine is the instrument ───────────────────────────────
#
# The callee is the ground truth here and the record is the claim under test,
# which is the one direction the rule at the top of this file permits: the
# event is not being asked to VOUCH for anything, it is being checked for
# asserting something the world disagrees with.


class _AsyncRecordingProvider:
    """Reproduces the shape both provider SDKs actually ship.

    Their async ``create`` is decorated by a ``@required_args`` validator that
    is a plain function, so ``inspect.iscoroutinefunction`` answers False about
    a method that returns a coroutine. The decorator is spelled out rather than
    mocked away, because it is the whole defect.
    """

    class _Messages:
        def __init__(self, entered):
            self._entered = entered

            async def _create(**kwargs):
                entered.append(kwargs)
                return _RecordingProvider._Response()

            @functools.wraps(_create)
            def _required_args(**kwargs):  # deliberately NOT async
                return _create(**kwargs)

            self.create = _required_args

    def __init__(self, entered):
        self.messages = self._Messages(entered)


def test_no_event_describes_a_call_that_has_not_happened(monkeypatch):
    """A coroutine that is constructed and never awaited has contacted nobody.

    The sync pipeline ran on the async client, so an event with
    ``success: True``, an empty response and zero latency was written at
    construction time — before the provider was reached, and while the call
    could still fail. The un-awaited coroutine is what makes the disagreement
    checkable: the callee provably did not run.
    """
    emitted = []
    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", lambda c, e: emitted.append(e))
    entered = []
    _init()

    client = obsvr.wrap(_AsyncRecordingProvider(entered))
    coro = client.messages.create(
        model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}]
    )
    try:
        assert entered == [], "the provider ran before the coroutine was awaited"
        assert emitted == [], (
            "an audit event described a call the provider never received"
        )
    finally:
        coro.close()


def test_the_async_path_still_records_the_call_it_did_make(monkeypatch):
    """The control. Without it the assertion above is satisfied by a wrapper
    that stopped emitting altogether."""
    emitted = []
    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", lambda c, e: emitted.append(e))
    entered = []
    _init()

    client = obsvr.wrap(_AsyncRecordingProvider(entered))
    asyncio.run(
        client.messages.create(
            model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}]
        )
    )

    assert len(entered) == 1
    assert len(emitted) == 1
    assert emitted[0]["response"] == "ok"


# ── A real Presidio sidecar is the instrument ───────────────────────────────
#
# Six of the nineteen PII types have no built-in regex pattern, so only the
# NLP analyzer can locate them. What the provider receives decides whether a
# `redact` verdict on one of those six was carried out.

RAW_PERSON = "Marcus Webb"


class _PresidioHandler(BaseHTTPRequestHandler):
    """Answers /analyze and /anonymize, or refuses, as the test dictates."""

    def log_message(self, *args):  # noqa: A003 - silence the default stderr log
        pass

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        half = "analyze" if self.path.endswith("/analyze") else "anonymize"
        if half not in self.server.obsvr_up:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.endswith("/analyze"):
            text = body.get("text", "")
            start = text.find(RAW_PERSON)
            payload = (
                [{"entity_type": "PERSON", "start": start,
                  "end": start + len(RAW_PERSON), "score": 0.99}]
                if start >= 0 else []
            )
        else:
            payload = {"text": body.get("text", "").replace(RAW_PERSON, "[REDACTED_PERSON]")}
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


@pytest.fixture
def presidio_server():
    server = HTTPServer(("127.0.0.1", 0), _PresidioHandler)
    # Which halves answer. They are controlled separately because they fail
    # differently: an analyzer that does not answer DETECTS nothing, so no
    # redaction is claimed and the fail-open posture applies honestly. An
    # anonymizer that does not answer fails AFTER policy has said remove it,
    # which is the applied-redaction case.
    server.obsvr_up = {"analyze", "anonymize"}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _drive_with_presidio(server):
    url = f"http://127.0.0.1:{server.server_address[1]}"
    received = []
    _init(
        # `name` is the internal label the analyzer's PERSON entity maps to,
        # and one of the six with no built-in regex pattern.
        pii_policy={"default": "detect_only", "rules": {"name": "redact"}},
        presidio_analyzer_url=url,
        presidio_anonymizer_url=url,
    )
    client = obsvr.wrap(_RecordingProvider(received))
    raised = None
    try:
        client.messages.create(
            model="m", max_tokens=8,
            messages=[{"role": "user", "content": f"escalate to {RAW_PERSON} today"}],
        )
    except Exception as err:
        raised = type(err).__name__
    return received, raised


def test_an_nlp_only_type_is_removed_from_what_the_provider_receives(
    presidio_server, no_delivery
):
    """`person` has no built-in regex pattern, so the regex tier cannot
    remove it. The outbound rewrite used that tier alone while the analyzer
    produced only the STORED copy — the record read `redacted` and the name
    went to the provider."""
    received, raised = _drive_with_presidio(presidio_server)
    assert raised is None, f"the allowed call was refused: {raised}"
    assert len(received) == 1
    assert RAW_PERSON not in received[0], "an NLP-only type reached the provider"
    assert "[REDACTED_PERSON]" in received[0]


def test_an_unreachable_anonymizer_blocks_rather_than_forwarding_the_name(
    presidio_server, no_delivery
):
    """The applied-redaction rule. The analyzer found the name and policy said
    remove it; the anonymizer then did not answer. The regex tier has no
    pattern for this type, so falling back to it would forward exactly the
    content policy named — the call is refused instead."""
    presidio_server.obsvr_up = {"analyze"}
    received, raised = _drive_with_presidio(presidio_server)
    assert received == [], "the name was forwarded after the anonymizer went away"
    assert raised == "ObsvrPolicyError"


def test_an_unreachable_analyzer_detects_nothing_and_claims_nothing(
    presidio_server, no_delivery
):
    """The other half, and it is NOT a block. An analyzer that never answered
    detected nothing, so no redaction was ever claimed: the call proceeds under
    the documented fail-open posture and the record does not say `redacted`.
    Distinguishing the two is the point — the SDK used to be unable to tell a
    detector that found nothing from one that never ran."""
    presidio_server.obsvr_up = set()
    received, raised = _drive_with_presidio(presidio_server)
    assert raised is None
    assert len(received) == 1, "the fail-open posture stopped a call it should allow"


# ── A real ingest server is the instrument ──────────────────────────────────


class _IngestHandler(BaseHTTPRequestHandler):
    """Answers however the test told it to, and records what it received."""

    def log_message(self, *args):  # noqa: A003 - silence the default stderr log
        pass

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            self.server.obsvr_requests.append(json.loads(raw or b"{}"))
        except Exception:
            self.server.obsvr_requests.append(None)
        status, body = self.server.obsvr_response
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def ingest_server():
    server = HTTPServer(("127.0.0.1", 0), _IngestHandler)
    server.obsvr_response = (200, {"count": 1})
    server.obsvr_requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _deliver_one(server, status, body):
    """Emit one event against the live server and return the delivery counters."""
    sender._reset_sender()
    obsvr.init(
        api_key="test-key",
        ingest_url=f"http://127.0.0.1:{server.server_address[1]}",
        environment="development",
        auto=False,
    )
    # Drain whatever init itself enqueued, THEN arm the response and zero the
    # counters — otherwise a policy event rides along and the assertion is about
    # a batch of two, which takes the batch path and answers a different
    # question than the one this test asks.
    server.obsvr_response = (200, {"count": 1})
    sender.flush(timeout=5)
    _quiesce_sender()
    server.obsvr_response = (status, body)

    from obsvr.config import get_config
    from obsvr.events import emit_event

    emit_event(
        get_config(),
        provider="test",
        model="m",
        operation="chat",
        source="test",
        prompt="p",
        response="r",
    )
    sender.flush(timeout=5)
    return sender.get_sender_stats()


def test_a_refused_event_is_never_counted_as_delivered(ingest_server):
    """403 on the single-event path. The server stored nothing; ``sent`` must
    not claim otherwise. This is the counter the reporter measured lying."""
    stats = _deliver_one(ingest_server, 403, {"error": "invalid_sdk_signature"})
    assert stats["sent"] == 0, "a refused event was counted as delivered"
    assert stats["dropped_rejected"] == 2  # refused event plus its refused gap marker


def test_a_2xx_that_enumerates_a_reject_is_not_a_delivery(ingest_server):
    """The single-event path never read the response body, so a 200 refusing
    the event inside it counted as a clean delivery of that same event."""
    stats = _deliver_one(
        ingest_server,
        200,
        {"count": 0, "rejected": [{"index": 0, "error": "policy_blocked"}]},
    )
    assert stats["sent"] == 0
    assert stats["dropped_rejected"] == 2  # refused event plus its refused gap marker


def test_a_short_accepted_count_is_reconciled(ingest_server):
    """The response says how many it took. Taking fewer than it was sent is a
    refusal whether or not the server enumerated it."""
    stats = _deliver_one(ingest_server, 200, {"count": 0})
    assert stats["sent"] == 0
    assert stats["dropped_rejected"] == 2  # refused event plus its refused gap marker


def test_an_accepted_event_still_counts_as_delivered(ingest_server):
    """The control. Without it every assertion above is satisfied by a sender
    that counts nothing at all."""
    stats = _deliver_one(ingest_server, 200, {"count": 1})
    assert stats["sent"] == 1
    assert stats["dropped_rejected"] == 0


def test_a_refused_policy_change_uses_the_signed_sender(ingest_server):
    """A policy change used to POST outside the sender and ignore the status.

    The real server is the instrument: it receives the governance event and
    refuses it, while the shared sender must report zero deliveries and both
    terminal refusals (the change and its one non-recursive gap marker). No
    audit-event verdict is used to grade the outcome.
    """
    from obsvr.config import set_tenant_policy
    from obsvr.rules import PolicyRule

    sender._reset_sender()
    obsvr.init(
        api_key="test-key",
        ingest_url=f"http://127.0.0.1:{ingest_server.server_address[1]}",
        environment="development",
        auto=False,
    )
    ingest_server.obsvr_requests.clear()
    ingest_server.obsvr_response = (403, {"error": "invalid_sdk_signature"})

    set_tenant_policy(
        "tenant-policy-log",
        [PolicyRule(
            id="deny-export",
            name="deny export",
            enabled=True,
            action="block",
            type="keyword",
            conditions={"keywords": ["export"]},
        )],
        changed_by="admin",
    )
    sender.flush(timeout=5)

    stats = sender.get_sender_stats()
    assert stats["sent"] == 0
    assert stats["dropped_rejected"] == 2
    assert len(ingest_server.obsvr_requests) == 2
    assert ingest_server.obsvr_requests[0]["event_type"] == "policy_changed"
    assert isinstance(ingest_server.obsvr_requests[0].get("sdk_sig"), str)
    assert ingest_server.obsvr_requests[1]["operation"] == "audit.gap"


def test_delivery_loss_is_reported_at_default_settings(ingest_server, caplog):
    """Nothing on this path used to speak unless debug=True, so a run that
    delivered nothing looked exactly like a run that delivered everything."""
    sender._loss_warned_at = 0.0
    with caplog.at_level("WARNING", logger="obsvr"):
        _deliver_one(ingest_server, 403, {"error": "invalid_sdk_signature"})
    assert any("were NOT recorded" in record.message for record in caplog.records), (
        "audit events were lost and the SDK said nothing at default settings"
    )
