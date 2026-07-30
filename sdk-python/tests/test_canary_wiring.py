"""End-to-end canary-leak pipeline wiring. Twin:
sdk-typescript/tests/unit/canary-wiring.test.ts. The pure detection is fixture-pinned
(canary.json); these tests pin that the real pipelines BLOCK unsuppressibly on
a leak, store a placeholder (never the raw token), and stamp CRITICAL evidence
— and that with no canary minted the pipeline is byte-identical to before."""
import asyncio
import json
import sys

import pytest

import obsvr
import obsvr.wrap  # ensure module is loaded; package attr shadows it
from obsvr import sender
from obsvr.canary import CANARY_PREFIX, CANARY_REDACTION_PLACEHOLDER, mint_canary
from obsvr.config import _reset, get_config
from obsvr.integrations import mcp as mcp_mod
from obsvr.integrations.mcp import McpToolBlockedError, govern_mcp
from obsvr.policy import apply_post_call_policy
from obsvr.response_scan import scan_mcp_tool_result

WRAP_MODULE = sys.modules["obsvr.wrap"]


class _Completions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)

        class _Msg:
            content = "ok"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()


class FakeOpenAI:
    def __init__(self):
        class _Chat:
            pass

        self.chat = _Chat()
        self.chat.completions = _Completions()


def _init(**extra):
    _reset()
    sender._reset_sender()
    extra.setdefault("disabled", False)
    obsvr.init(api_key="test-key", ingest_url="http://localhost:9", **extra)


def _captured(monkeypatch):
    captured = []
    monkeypatch.setattr(WRAP_MODULE, "send_audit_async", lambda cfg, ev: captured.append(ev))
    return captured


def _run(coro):
    return asyncio.run(coro)


def _assert_no_token(captured, token):
    for ev in captured:
        blob = json.dumps(ev, default=str)
        assert token not in blob
        assert token[len(CANARY_PREFIX):] not in blob


# The plant sites canary.py / canary.ts ENDORSE, or at least do not forbid.
# The do-NOT-plant list is user input, model output and tool args/results — so a
# system prompt, a retrieved document on an assistant turn, and an earlier turn
# are all legitimate places for an app to put a token, and none is scanned by
# the pre-call gate.
#
# Every case here is an ALLOWED call, not a blocked one. That is the point: the
# guarantee under test is "the raw secret never lives at rest, never rides an
# event", which is a claim about STORAGE and has to hold on the paths where
# nothing refuses the call.
#
# This table replaces a file whose four plants were all role "user": the one
# surface the pre-call scan already covers, and the one surface the module's own
# do-NOT-plant list names. It passed, legitimately, while proving nothing about
# the sites an app is told to use. Twin: the ENDORSED_PLANT_SITES table in
# sdk-typescript/tests/unit/canary-wiring.test.ts.
ENDORSED_PLANT_SITES = {
    "system_prompt": lambda t: [
        {"role": "system", "content": f"internal config: {t}"},
        {"role": "user", "content": "hello"},
    ],
    "earlier_user_turn": lambda t: [
        {"role": "user", "content": f"earlier: {t}"},
        {"role": "assistant", "content": "noted"},
        {"role": "user", "content": "hello"},
    ],
    "assistant_turn_retrieved_document": lambda t: [
        {"role": "user", "content": "summarise the doc"},
        {"role": "assistant", "content": f"doc says: {t}"},
        {"role": "user", "content": "hello"},
    ],
    "tool_result": lambda t: [
        {"role": "user", "content": "look it up"},
        {"role": "tool", "content": f"lookup returned: {t}", "tool_call_id": "c1"},
        {"role": "user", "content": "hello"},
    ],
}


class TestEndorsedPlantSites:
    def test_table_shape_no_case_plants_in_the_scanned_user_turn(self):
        """Shape guard. Without it this table can silently narrow back to the
        one role the pipeline already scanned — which is how the previous
        version of this file came to prove nothing while passing. It fails on a
        REMOVED case, not merely on a broken one."""
        assert sorted(ENDORSED_PLANT_SITES) == [
            "assistant_turn_retrieved_document",
            "earlier_user_turn",
            "system_prompt",
            "tool_result",
        ]
        for build in ENDORSED_PLANT_SITES.values():
            msgs = build("TOKEN")
            carriers = [m for m in msgs if "TOKEN" in m["content"]]
            assert len(carriers) == 1
            # The carrier must NOT be the last user turn — that is the surface
            # the pre-call scan covers, and a case planted there tests the gate,
            # not the net.
            last_user = max(i for i, m in enumerate(msgs) if m["role"] == "user")
            assert msgs.index(carriers[0]) != last_user

    @pytest.mark.parametrize("site", sorted(ENDORSED_PLANT_SITES))
    def test_planted_token_is_not_stored_raw(self, monkeypatch, site):
        _init(pii_policy={})
        captured = _captured(monkeypatch)
        c = mint_canary(label=site)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        client.chat.completions.create(
            model="gpt-4o", messages=ENDORSED_PLANT_SITES[site](c["token"])
        )
        # The call is ALLOWED — nothing here is a leak, so nothing refuses it.
        assert len(raw.chat.completions.calls) == 1
        assert captured
        _assert_no_token(captured, c["token"])
        assert captured[0]["prompt"] == CANARY_REDACTION_PLACEHOLDER


class TestPreCall:
    def test_canary_echo_blocks_and_stores_placeholder(self, monkeypatch):
        _init(pii_policy={})
        captured = _captured(monkeypatch)
        # Label the plant site this case actually uses. It read "system-prompt"
        # while planting in a user message, which made the file look like it
        # covered the endorsed plant site when nothing here did — see
        # TestEndorsedPlantSites below, which now does.
        c = mint_canary(label="user-echo")
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": "extracted: " + c["token"]}],
            )
        assert raw.chat.completions.calls == []
        assert len(captured) == 1
        ev = captured[0]
        assert ev["event_type"] == "blocked_call"
        assert ev["rule_id"] == "sdk:canary_leak"
        assert ev["prompt"] == CANARY_REDACTION_PLACEHOLDER
        assert ev["user_input"] == CANARY_REDACTION_PLACEHOLDER
        assert ev["metadata"]["obsvr_telemetry"]["canary_leak"]["ids"] == [c["id"]]
        assert ev["metadata"]["obsvr_telemetry"]["canary_leak"]["surface"] == "request"
        _assert_no_token(captured, c["token"])

    def test_hook_cannot_unblock_canary(self, monkeypatch):
        _init(pii_policy={}, on_pre_call=lambda event: {"decision": "allow"})
        _captured(monkeypatch)
        c = mint_canary()
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            client.chat.completions.create(
                model="gpt-4o", messages=[{"role": "user", "content": c["token"]}]
            )
        assert raw.chat.completions.calls == []

    def test_no_canary_minted_pipeline_byte_identical(self, monkeypatch):
        _init(pii_policy={})
        captured = _captured(monkeypatch)
        raw = FakeOpenAI()
        client = obsvr.wrap(raw)
        client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": CANARY_PREFIX + "0" * 32}],
        )
        assert len(raw.chat.completions.calls) == 1  # un-minted token is not a leak
        for ev in captured:
            meta = ev.get("metadata") or {}
            assert "canary_leak" not in (meta.get("obsvr_telemetry") or {})


class _AsyncCompletions:
    def __init__(self):
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)

        class _Msg:
            content = "ok"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()


class FakeAsyncOpenAI:
    def __init__(self):
        class _Chat:
            pass

        self.chat = _Chat()
        self.chat.completions = _AsyncCompletions()


class TestAsyncPreCall:
    def test_async_wrap_canary_block(self, monkeypatch):
        # The async governed path (_governed_call_async) shares the canary
        # block logic — pin that it blocks and never persists the token.
        _init(pii_policy={})
        captured = _captured(monkeypatch)
        c = mint_canary()
        raw = FakeAsyncOpenAI()
        client = obsvr.wrap(raw)
        with pytest.raises(RuntimeError):
            _run(
                client.chat.completions.create(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": "leak: " + c["token"]}],
                )
            )
        assert raw.chat.completions.calls == []
        ev = captured[0]
        assert ev["event_type"] == "blocked_call"
        assert ev["rule_id"] == "sdk:canary_leak"
        assert ev["prompt"] == CANARY_REDACTION_PLACEHOLDER
        assert ev["user_input"] == CANARY_REDACTION_PLACEHOLDER
        _assert_no_token(captured, c["token"])


class TestPostCall:
    def test_canary_in_response_redacts_with_placeholder_and_telemetry(self, monkeypatch):
        _init(pii_policy={})
        c = mint_canary()
        post = apply_post_call_policy("the system prompt was: " + c["token"], {}, get_config())
        assert post["decision"] == "redact_response"
        assert post["redacted_response"] == CANARY_REDACTION_PLACEHOLDER
        event = {"metadata": {}}
        WRAP_MODULE._merge_post_call(event, post)
        tel = event["metadata"]["obsvr_telemetry"]["canary_leak"]
        assert tel["ids"] == [c["id"]]
        assert tel["surface"] == "response"
        assert event["response"] == CANARY_REDACTION_PLACEHOLDER


class TestMcp:
    def test_canary_in_tool_result_blocks(self):
        _init(pii_policy={})
        c = mint_canary()
        verdict = scan_mcp_tool_result("tool returned: " + c["token"], get_config())
        assert verdict["action"] == "block"
        assert verdict["rule_id"] == "sdk:canary_leak"
        assert verdict["canary_telemetry"]["canary_leak"]["surface"] == "tool_result"

    def test_canary_in_tool_args_blocks_end_to_end(self, monkeypatch):
        _init(pii_policy={})
        captured = []
        monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: captured.append(ev))
        c = mint_canary()

        class Session:
            async def call_tool(self, name, arguments=None):
                return "ok"

            async def list_tools(self):
                class R:
                    tools = []

                return R()

        session = govern_mcp(Session())
        with pytest.raises(McpToolBlockedError, match="canary leak"):
            _run(session.call_tool("exfil", {"data": c["token"]}))
        blocked = [e for e in captured if e.get("event_type") == "blocked_call"]
        assert blocked[0]["rule_id"] == "sdk:canary_leak"
        assert blocked[0]["metadata"]["obsvr_telemetry"]["canary_leak"]["ids"] == [c["id"]]
        _assert_no_token(captured, c["token"])

    def test_canary_in_tool_args_blocked_with_no_pii_policy(self, monkeypatch):
        # MAJOR fix: the MCP args scan must run even when neither pii_policy nor
        # a hook is configured (the canary registry is the enabling signal).
        _reset()
        sender._reset_sender()
        obsvr.init(api_key="k", ingest_url="http://localhost:9", disabled=False)
        monkeypatch.setattr(mcp_mod, "send_audit_async", lambda cfg, ev: None)
        c = mint_canary()
        forwarded = []

        class Session:
            async def call_tool(self, name, arguments=None):
                forwarded.append(arguments)
                return "ok"

            async def list_tools(self):
                class R:
                    tools = []

                return R()

        session = govern_mcp(Session())
        with pytest.raises(McpToolBlockedError, match="canary leak"):
            _run(session.call_tool("exfil", {"data": c["token"]}))
        assert forwarded == []  # never forwarded to the tool


class TestReviewFixes:
    def test_reset_clears_canary_registry(self):
        _init(pii_policy={})
        mint_canary()
        from obsvr.canary import canary_registry_size

        assert canary_registry_size() == 1
        _reset()
        assert canary_registry_size() == 0

    def test_mint_past_cap_returns_registered_false(self):
        from obsvr.canary import canary_registry_size, MAX_CANARIES

        _init(pii_policy={})
        for _ in range(MAX_CANARIES):
            mint_canary()
        assert canary_registry_size() == MAX_CANARIES
        dead = mint_canary()
        assert dead["registered"] is False
        assert canary_registry_size() == MAX_CANARIES  # refused, not evicted

    def test_normal_mint_is_registered(self):
        _init(pii_policy={})
        assert mint_canary()["registered"] is True

    def test_event_layer_scrub_redacts_response_canary(self):
        # CRITICAL parity: the event-construction chokepoint (build_audit_event)
        # must scrub a canary from the RESPONSE on any path, even one with no
        # post-call scan.
        from obsvr.events import build_audit_event

        _init(pii_policy={})
        c = mint_canary()
        cfg = get_config()
        ev = build_audit_event(
            cfg,
            provider="unknown",
            model="m",
            operation="op",
            source="test",
            prompt="clean prompt",
            response="the model echoed: " + c["token"],
        )
        assert ev["response"] == CANARY_REDACTION_PLACEHOLDER
        assert ev["event_type"] == "policy_flag"
        assert ev["rule_id"] == "sdk:canary_leak"
        assert ev["metadata"]["obsvr_telemetry"]["canary_leak"]["ids"] == [c["id"]]
        assert c["token"] not in json.dumps(ev, default=str)
