"""Direct-provider execution must cross the trusted profile-2.1 runtime."""

import asyncio
import copy
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

import obsvr
from obsvr import sender
from obsvr.action_context_v2 import action_target_hash
from obsvr.config import _reset
from obsvr.device_identity import load_device_signer
from obsvr.intent_alignment_v2 import intent_policy_v2_hash
from obsvr.strict_admission_v2_1 import STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA
from obsvr.strict_evaluation_evidence_v2_1 import (
    create_trusted_evaluation_evidence_provider_v2_1,
)
from obsvr.strict_identity_evidence_v2_1 import (
    create_strict_identity_evidence_v2_1_authority,
)
from obsvr.strict_provider_boundary_v2_1 import (
    ObsvrStrictProviderBoundaryV21Error,
    StrictProviderBoundaryV21Capability,
    strict_provider_target_v2_1,
)
from obsvr.strict_receipt_coordinator_v2_1 import (
    StrictReceiptCoordinatorV21,
    create_trusted_intent_decision_provider_v2_1,
)
from obsvr.strict_receipt_runtime_v2_1 import StrictReceiptRuntimeV21
from obsvr.strict_receipt_v2_1 import strict_receipt_v2_1_key_id


B = "b" * 64


class Response:
    choices = []


class Completions:
    def __init__(self):
        self.calls = []
        self.failure = None

    def create(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        if self.failure is not None:
            raise self.failure
        return Response()


class Chat:
    def __init__(self):
        self.completions = Completions()


class FakeOpenAI:
    def __init__(self):
        self.base_url = "https://api.openai.com/v1"
        self.chat = Chat()


def init(**extra):
    _reset()
    sender._reset_sender()
    obsvr.init(api_key="test", sample_rate=0, **extra)


def capability(
    target="https://api.openai.com/v1",
    base=None,
    before_accepted=None,
):
    key_path = Path(tempfile.mkdtemp(prefix="obsvr-boundary-v21-")) / "seed.key"
    key_path.write_text("00" * 32, encoding="ascii")
    signer = load_device_signer(str(key_path))
    policy = {
        "schema": "obsvr-intent-policy-v2",
        "profile_version": "2.0",
        "intent_scopes": [
            {
                "intent_id": "serve",
                "allowed_actions": [
                    {"kind": "model_call", "name": "chat.completions.create"}
                ],
                "allowed_targets": [target],
                "allowed_requested_scopes": ["model:invoke"],
                "allowed_data_classifications": [],
            }
        ],
    }
    now = iter(range(1_000, 10_000))
    tokens = iter(range(1, 10_000))
    contexts = []

    def evaluate(context):
        contexts.append(copy.deepcopy(context))
        return copy.deepcopy(base or {"action_taken": "allowed"})

    coordinator = StrictReceiptCoordinatorV21(
        signer=signer,
        policy=policy,
        tenant_id="tenant-1",
        session_id="session-1",
        sdk_language="python",
        clock=lambda: next(now),
        defer_ttl_ms=500,
        identity_authority=create_strict_identity_evidence_v2_1_authority(),
        identity_snapshot=lambda timestamp: {
            "schema": "obsvr-strict-identity-evidence-v2-1",
            "profile_version": "2.1",
            "relationship": "direct",
            "receipt_time_ms": timestamp,
            "requester": {
                "requester_ref_hash": B,
                "principal_type": "agent",
                "role_ids": ["worker"],
                "privilege_scopes": ["model:invoke"],
            },
            "initiator": {
                "agent_ref_hash": B,
                "key_id": strict_receipt_v2_1_key_id(signer.raw_public_key),
                "role_ids": ["worker"],
                "privilege_scopes": ["model:invoke"],
            },
            "delegation_chain": [],
        },
        intent_decision_provider=create_trusted_intent_decision_provider_v2_1(evaluate),
        evaluation_evidence_provider=(
            create_trusted_evaluation_evidence_provider_v2_1(
                lambda: {
                    "effective_policy": {
                        "version": "policy-1",
                        "artifact_hash": intent_policy_v2_hash(policy),
                        "matched_rule_ids": ["serve"],
                    },
                    "detector_requirements": [],
                    "detector_results": [],
                }
            )
        ),
        pid=lambda: 7,
        prepared_token_factory=lambda: f"prepared-{next(tokens)}",
    )
    checkpoints = []

    class CheckpointStore:
        def save(self, checkpoint):
            checkpoints.append(copy.deepcopy(checkpoint))

    def transport(_target, headers, _body, _timeout, _limit):
        if before_accepted is not None:
            before_accepted()
        body = json.dumps(
            {
                "schema": STRICT_RECEIPT_V2_1_ADMISSION_SCHEMA,
                "ok": True,
                "status": "accepted",
                "receipt_hash": headers["Idempotency-Key"],
                "accepted_at_ms": 10,
            }
        ).encode()
        return 200, body

    runtime = StrictReceiptRuntimeV21(
        coordinator=coordinator,
        admission_config={
            "ingest_url": "https://example.com",
            "api_key": "test",
            "max_attempts": 1,
            "resolver": lambda _host: ["8.8.8.8"],
            "trusted_pinned_transport": transport,
        },
        checkpoint_store=CheckpointStore(),
    )
    return SimpleNamespace(
        runtime=runtime,
        contexts=contexts,
        checkpoints=checkpoints,
        value=obsvr.create_strict_provider_boundary_v2_1(
            runtime=runtime,
            context=lambda _call: {
                "active_intents": ["serve"],
                "requested_scopes": ["model:invoke"],
                "run_id": "run-1",
                "thread_id": "thread-1",
            },
        ),
    )


def test_exact_cleaned_invocation_is_admitted_before_one_provider_call():
    init()
    strict = capability()
    raw = FakeOpenAI()
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    assert isinstance(
        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hello"}],
            obsvr_metadata={"request_id": "caller-value"},
        ),
        Response,
    )
    assert raw.chat.completions.calls == [
        {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]}
    ]
    action = strict.checkpoints[0]["receipt"]["body"]["action"]
    assert strict.contexts[0]["action"] == {
        "kind": "model_call",
        "name": "chat.completions.create",
        "arguments_hash": action["arguments_hash"],
        "target_hash": action_target_hash("https://api.openai.com/v1"),
        "data_classifications": [],
        "requested_scopes": ["model:invoke"],
    }
    assert action["action_id"] != "caller-value"


def test_endpoint_is_reresolved_and_identical_calls_get_unique_actions():
    init()
    raw = FakeOpenAI()
    raw.base_url = "https://api.groq.com/openai/v1"
    strict = capability(raw.base_url)
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    for _ in range(2):
        client.chat.completions.create(model="m", messages=[])
    receipts = [
        item["receipt"] for item in strict.checkpoints if item["phase"] == "prepared"
    ]
    assert receipts[0]["body"]["action"]["target_hash"] == (
        action_target_hash("https://api.groq.com/openai/v1")
    )
    assert (
        receipts[0]["body"]["action"]["action_id"]
        != receipts[1]["body"]["action"]["action_id"]
    )


def test_denial_legacy_block_stream_and_async_never_contact_provider():
    init()
    denied = capability(base={"action_taken": "blocked"})
    raw = FakeOpenAI()
    client = obsvr.wrap(raw, strict_receipt_v2_1=denied.value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        client.chat.completions.create(model="m", messages=[])
    assert error.value.code == "not_authorized"
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        client.chat.completions.create(model="m", messages=[], stream=True)
    assert error.value.code == "unsupported_surface"
    assert raw.chat.completions.calls == []

    init(pii_policy={"rules": {"ssn": "block"}})
    blocked_strict = capability()
    blocked_raw = FakeOpenAI()
    blocked = obsvr.wrap(blocked_raw, strict_receipt_v2_1=blocked_strict.value)
    with pytest.raises(Exception):
        blocked.chat.completions.create(
            model="m", messages=[{"role": "user", "content": "123-45-6789"}]
        )
    assert blocked_raw.chat.completions.calls == []
    assert blocked_strict.checkpoints == []

    class AsyncCompletions:
        async def create(self, **_kwargs):
            raise AssertionError("provider contacted")

    async_raw = FakeOpenAI()
    async_raw.chat.completions = AsyncCompletions()
    async_client = obsvr.wrap(async_raw, strict_receipt_v2_1=capability().value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error):
        asyncio.run(async_client.chat.completions.create(model="m", messages=[]))


def test_forged_capability_disabled_mode_and_provider_error():
    init()
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error):
        obsvr.wrap(
            FakeOpenAI(), strict_receipt_v2_1=StrictProviderBoundaryV21Capability()
        )

    raw = FakeOpenAI()
    failure = RuntimeError("provider failed")
    raw.chat.completions.failure = failure
    client = obsvr.wrap(raw, strict_receipt_v2_1=capability().value)
    with pytest.raises(RuntimeError) as error:
        client.chat.completions.create(model="m", messages=[])
    assert error.value is failure

    init(disabled=True)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error):
        obsvr.wrap(FakeOpenAI(), strict_receipt_v2_1=capability().value)


def test_unbranded_runtime_is_rejected():
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        obsvr.create_strict_provider_boundary_v2_1(
            runtime=object(),
            context=lambda _call: {
                "active_intents": ["serve"],
                "requested_scopes": [],
                "run_id": "run",
            },
        )
    assert error.value.code == "runtime_unavailable"


def test_endpoint_change_after_admission_fails_closed():
    init()
    raw = FakeOpenAI()
    strict = capability(
        raw.base_url,
        before_accepted=lambda: setattr(raw, "base_url", "https://api.openai.com/v2"),
    )
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        client.chat.completions.create(model="m", messages=[])
    assert error.value.code == "context_unavailable"
    assert raw.chat.completions.calls == []


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.openai.com/v1",
        "https://user:secret@api.openai.com/v1",
        "https://api.openai.com/v1?key=secret",
        "https://api.openai.com/v1#fragment",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.5/v1",
        "https://example.com/v1",
        "https://api.openai.com/v1/../evil",
        "https://api.openai.com/v1/%2e%2e/evil",
    ],
)
def test_unsafe_endpoint_never_contacts_provider(base_url):
    init()
    raw = FakeOpenAI()
    raw.base_url = base_url
    strict = capability()
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        client.chat.completions.create(model="m", messages=[])
    assert error.value.code == "context_unavailable"
    assert strict.checkpoints == []
    assert raw.chat.completions.calls == []


def test_unreadable_endpoint_and_every_unlisted_callable_fail_closed():
    init()

    class HiddenEndpoint:
        def __init__(self):
            self.chat = Chat()
            self.embeddings = type(
                "Embeddings", (), {"create": lambda _self, **_kw: None}
            )()
            self.unknown = type(
                "Unknown",
                (),
                {"nested": type("Nested", (), {"execute": lambda _self: None})()},
            )()

        @property
        def base_url(self):
            raise RuntimeError("hidden")

        def with_options(self):
            return self

    raw = HiddenEndpoint()
    client = obsvr.wrap(raw, strict_receipt_v2_1=capability().value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        client.chat.completions.create(model="m", messages=[])
    assert error.value.code == "context_unavailable"
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error):
        client.embeddings.create(input="x")
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error):
        client.unknown.nested.execute()
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error):
        client.with_options()
    assert raw.chat.completions.calls == []


def test_non_json_invocation_fails_safely_before_runtime_or_provider():
    init()
    strict = capability()
    raw = FakeOpenAI()
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as error:
        client.chat.completions.create(
            model="m", messages=[], secret_callback=lambda: "never serialize me"
        )
    assert error.value.code == "context_unavailable"
    assert str(error.value) == "obsvr strict provider boundary: context_unavailable"
    assert strict.checkpoints == []
    assert raw.chat.completions.calls == []


def test_current_gemini_client_endpoint_resolves_without_network_access():
    genai = pytest.importorskip("google.genai")
    client = genai.Client(api_key="test")
    try:
        assert strict_provider_target_v2_1(client) == (
            "https://generativelanguage.googleapis.com/"
        )
        assert (
            strict_provider_target_v2_1(
                type("Client", (), {"base_url": "https://api.openai.com/v1/"})()
            )
            == "https://api.openai.com/v1"
        )
        assert (
            strict_provider_target_v2_1(
                type("Client", (), {"base_url": "https://api.anthropic.com/"})()
            )
            == "https://api.anthropic.com/"
        )
        assert (
            strict_provider_target_v2_1(
                type(
                    "Client",
                    (),
                    {"base_url": "https://api.groq.com/openai/v1"},
                )()
            )
            == "https://api.groq.com/openai/v1"
        )
        assert (
            strict_provider_target_v2_1(
                type(
                    "Client",
                    (),
                    {"base_url": "https://API.OPENAI.COM:443/v1///"},
                )()
            )
            == "https://api.openai.com/v1"
        )
    finally:
        client.close()


def test_runtime_runner_and_proxy_internals_are_not_replaceable_or_exposed():
    init()
    strict = capability()
    raw = FakeOpenAI()
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    with pytest.raises(AttributeError):
        strict.runtime.run_decision = lambda **_kwargs: {"status": "executed"}
    with pytest.raises(AttributeError):
        _ = client._obsvr_target
    with pytest.raises(AttributeError):
        _ = client._obsvr_options
    with pytest.raises(AttributeError):
        object.__getattribute__(client, "_obsvr_target")
    with pytest.raises(AttributeError):
        object.__getattribute__(client, "_obsvr_options")
    for name in ("_coordinator", "_admission_config", "_checkpoint_store"):
        with pytest.raises(AttributeError):
            object.__getattribute__(strict.runtime, name)
    client.chat.completions.create(model="m", messages=[])
    assert len(raw.chat.completions.calls) == 1
    assert [item["phase"] for item in strict.checkpoints] == [
        "prepared",
        "remote_accepted",
        "committed",
        "invocation_started",
        "terminal",
    ]


def test_class_replacement_before_construction_is_not_blessed(monkeypatch):
    init()
    replacement_calls = []

    def replacement(self, **_kwargs):
        replacement_calls.append(self)
        return {"status": "executed", "value": "bypass"}

    monkeypatch.setattr(StrictReceiptRuntimeV21, "run_decision", replacement)
    monkeypatch.setattr(StrictReceiptRuntimeV21, "_run_locked", replacement)
    strict = capability()
    raw = FakeOpenAI()
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    client.chat.completions.create(model="m", messages=[])
    assert replacement_calls == []
    assert len(raw.chat.completions.calls) == 1
    assert len(strict.checkpoints) == 5
