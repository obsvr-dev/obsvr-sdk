"""govern_tool — the framework-agnostic tool boundary, offline.

The live proof that real frameworks dispatch through the governed callable is
in the integration harness; what is pinned HERE is the governor's own
contract: which shapes it gates, that a refusal precedes the tool body, that
the full pre-call net runs (not the observe-only subset), and that it never
breaks a caller whose tool it cannot recognize.
"""

import asyncio

import pytest
from pydantic import BaseModel

import obsvr
from obsvr import sender
from obsvr.errors import ObsvrPolicyError
from obsvr.integrations.tools import govern_tool, govern_tools
from obsvr.tool_content_hash import TOOL_CONTENT_HASH_METADATA_KEY


@pytest.fixture
def sent(monkeypatch):
    captured = []
    monkeypatch.setattr(
        sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured


@pytest.fixture(autouse=True)
def _fresh_governed_names(monkeypatch):
    """The governed-name registry is process-lifetime ON PURPOSE at runtime;
    in tests that lifetime is cross-test pollution, so each test gets its own."""
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())


class _RunShapedTool:
    name = "send_money"
    description = "moves money"

    def __init__(self):
        self.calls = []

    def _run(self, amount: int = 0):
        self.calls.append(amount)
        return f"sent {amount}"


class _AsyncPairTool:
    name = "send_money"

    def __init__(self):
        self.calls = []

    def _run(self, amount: int = 0):
        self.calls.append(("sync", amount))
        return "ok"

    async def _arun(self, amount: int = 0):
        self.calls.append(("async", amount))
        return "ok"


def test_denied_tool_raises_before_the_body_runs(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["send_money"]})
    tool = _RunShapedTool()
    governed = govern_tool(tool)

    with pytest.raises(ObsvrPolicyError):
        governed._run(amount=500)

    assert tool.calls == [], "the tool body ran despite the refusal"
    blocked = [e for e in sent if e.get("action_taken") == "blocked"]
    assert blocked and blocked[0]["operation"] == "tool.policy.tool_blocked"
    assert blocked[0]["metadata"]["tool_name"] == "send_money"
    assert TOOL_CONTENT_HASH_METADATA_KEY in blocked[0]["metadata"]


def test_allowed_tool_runs_and_is_audited(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["other"]})
    tool = _RunShapedTool()
    governed = govern_tool(tool)

    assert governed._run(amount=7) == "sent 7"
    assert tool.calls == [7]
    calls = [e for e in sent if e.get("operation") == "tool.call"]
    assert calls and calls[0].get("action_taken") == "allowed"
    assert TOOL_CONTENT_HASH_METADATA_KEY in calls[0]["metadata"]


def test_the_async_half_of_a_pair_is_gated_too(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["send_money"]})
    governed = govern_tool(_AsyncPairTool())

    with pytest.raises(ObsvrPolicyError):
        asyncio.run(governed._arun(amount=1))
    with pytest.raises(ObsvrPolicyError):
        governed._run(amount=1)


def test_allowlist_absence_refuses(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"allowed_tools": ["other"]})
    governed = govern_tool(_RunShapedTool())
    with pytest.raises(ObsvrPolicyError):
        governed._run(amount=1)
    blocked = [e for e in sent if e.get("action_taken") == "blocked"]
    assert blocked[0]["metadata"]["reason"] == "tool_not_in_allowlist"


def test_the_full_precall_net_runs_not_the_observe_subset(sent):
    """A pii_policy of {"ssn": "block"} must refuse the CALL — the posture
    obsvr.wrap() has, which the callback integrations do not."""
    obsvr.init(api_key="test", sample_rate=1, pii_policy={"ssn": "block"})
    tool = _RunShapedTool()
    governed = govern_tool(tool)

    with pytest.raises(ObsvrPolicyError):
        governed._run(amount="my ssn is 078-05-1120")
    assert tool.calls == []
    assert any(e.get("action_taken") == "blocked" for e in sent)


def test_a_tainted_session_loses_a_destructive_governed_tool_under_flag(sent):
    """The taint latch's destructive-capability gate runs AT the governed
    tool's own boundary, through the same pre-call pipeline MCP uses: in a
    tainted session, a tool named in destructive_tools is refused before it
    runs, under the default `flag` action and not only under `block`."""
    from obsvr.session_taint import _reset_session_taint, derive_session_key, mark_tainted

    _reset_session_taint()
    try:
        obsvr.init(
            api_key="test",
            sample_rate=1,
            session_taint={
                "enabled": True,
                "action": "flag",
                "destructive_tools": ["send_money"],
            },
        )
        mark_tainted(derive_session_key({"user_id": "mallory"}), "prompt_injection", 1.0)

        tool = _RunShapedTool()
        governed = govern_tool(tool, metadata={"user_id": "mallory"})
        with pytest.raises(ObsvrPolicyError):
            governed._run(amount=500)
        assert tool.calls == [], "a tainted session executed a destructive tool"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked and blocked[-1].get("rule_id") == "sdk:session_tainted", (
            f"blocked records: {[(e.get('operation'), e.get('rule_id')) for e in blocked]}"
        )
        # An untainted principal keeps the same tool.
        clean = govern_tool(_RunShapedTool(), metadata={"user_id": "alice"})
        assert clean._run(amount=1) == "sent 1"
    finally:
        _reset_session_taint()


def test_the_original_object_is_not_mutated(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["send_money"]})
    tool = _RunShapedTool()
    governed = govern_tool(tool)

    assert governed is not tool
    assert "_run" not in vars(tool), "the caller's own tool grew a gate"
    # And the ungoverned original still runs — proving the gate lives on the
    # copy, which is the object the caller passes to the agent.
    assert tool._run(amount=1) == "sent 1"


def test_pydantic_tool_shape_copies_and_gates(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["send_money"]})

    class _PydanticTool(BaseModel):
        name: str = "send_money"
        description: str = "moves money"

        def _run(self, amount: int = 0):
            raise AssertionError("body must not run")

    governed = govern_tool(_PydanticTool())
    with pytest.raises(ObsvrPolicyError):
        governed._run(amount=500)


def test_a_bare_callable_is_wrapped(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["transfer"]})
    calls = []

    def transfer(amount: int) -> str:
        calls.append(amount)
        return "done"

    governed = govern_tool(transfer)
    with pytest.raises(ObsvrPolicyError):
        governed(500)
    assert calls == []


def test_an_unrecognized_shape_is_returned_unchanged(sent):
    obsvr.init(api_key="test", sample_rate=1)

    class _Opaque:
        name = "mystery"

    opaque = _Opaque()
    assert govern_tool(opaque) is opaque


def test_uninitialized_sdk_passes_through(sent):
    # No init(): the governed tool must behave exactly like the original.
    import obsvr.config as config_mod

    saved = getattr(config_mod, "_config", None)
    try:
        config_mod._config = None
        tool = _RunShapedTool()
        governed = govern_tool(tool)
        assert governed._run(amount=3) == "sent 3"
        assert sent == []
    finally:
        config_mod._config = saved


def test_govern_tools_wraps_each(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["send_money"]})
    governed = govern_tools([_RunShapedTool(), _RunShapedTool()])
    for g in governed:
        with pytest.raises(ObsvrPolicyError):
            g._run(amount=1)


class _CrewaiShapedTool:
    """``run()`` calls ``self.func`` directly, bypassing ``_run`` — crewai's
    ``Tool`` shape, and the one that let a governed tool block on the ReAct
    path while executing on the native path before ``func`` was co-gated."""

    name = "send_money"
    description = "moves money"

    def __init__(self):
        self.calls = []
        self.func = lambda **kw: (self.calls.append(kw), "sent")[1]

    def _run(self, **kw):
        return self.func(**kw)

    def run(self, **kw):
        return self.func(**kw)


def test_the_run_to_func_shortcut_is_gated_too(sent):
    obsvr.init(api_key="test", sample_rate=1, agent_policy={"denied_tools": ["send_money"]})
    tool = _CrewaiShapedTool()
    governed = govern_tool(tool)

    with pytest.raises(ObsvrPolicyError):
        governed.run(amount=500)
    assert tool.calls == [], "run() reached the body around the _run gate"


def test_a_delegating_entry_point_is_gated_and_audited_once(sent):
    """_run delegates to func; both are gated; one invocation must produce
    exactly one verdict and one audit event — double-charging is how a step
    budget silently drifts."""
    obsvr.init(api_key="test", sample_rate=1)
    tool = _CrewaiShapedTool()
    governed = govern_tool(tool)

    governed._run(amount=1)
    assert tool.calls == [{"amount": 1}]
    calls = [e for e in sent if e.get("operation") == "tool.call"]
    assert len(calls) == 1, f"one invocation, {len(calls)} audit events"


def test_is_tool_governed_reports_wrapped_names(sent):
    from obsvr.integrations.tools import is_tool_governed

    obsvr.init(api_key="test", sample_rate=1)
    assert not is_tool_governed("send_money")
    govern_tool(_CrewaiShapedTool())
    assert is_tool_governed("send_money")


def test_the_governor_is_exported_from_the_package_root(sent):
    """TS parity: `import { obsvrGovernTool } from "@obsvr/sdk"` is the
    documented form — the Python twin must not hide behind a submodule path."""
    assert obsvr.govern_tool is govern_tool
    assert obsvr.govern_tools is govern_tools
    assert "govern_tool" in obsvr.__all__ and "govern_tools" in obsvr.__all__


def test_signature_survives_wrapping_for_schema_inference(sent):
    """Frameworks infer arg schemas from the callable's signature (crewai's
    _set_args_schema inspects _run). functools.wraps + __wrapped__ keep
    inspect.signature reading the ORIGINAL signature through the gate."""
    import inspect as _inspect

    obsvr.init(api_key="test", sample_rate=1)
    governed = govern_tool(_RunShapedTool())
    assert "amount" in _inspect.signature(governed._run).parameters


class _CacheableTool:
    """A crewai-shaped tool that lets the framework decide about memoization."""

    name = "read_secret"
    description = "reads a secret"

    def __init__(self):
        self.calls = 0
        self.cache_function = lambda _args=None, _result=None: True

    def _run(self, **kwargs):
        self.calls += 1
        return "SECRET"


def test_a_governed_tool_refuses_framework_result_caching(sent):
    """A cache hit answers from the framework's memory without entering the
    callable, so it escapes this gate AND leaves no execution to count — the
    marker reads zero for the opposite of the right reason. Measured on
    CrewAI: allowed once, denied after, the caller still got the payload."""
    obsvr.init(api_key="test", sample_rate=1)
    tool = _CacheableTool()
    governed = govern_tool(tool)

    assert governed.cache_function() is False, "a governed result must not be cached"
    assert governed.cache_function({"a": 1}, "SECRET") is False
    # The caller's own object is untouched; only the governed copy declines.
    assert tool.cache_function() is True


def test_declining_the_cache_never_breaks_a_tool_without_one(sent):
    """The refusal is shape-based, like the exec-attr table: a tool carrying
    no cache_function is returned gated and otherwise unchanged."""
    obsvr.init(api_key="test", sample_rate=1)
    governed = govern_tool(_RunShapedTool())
    assert not hasattr(governed, "cache_function")
    assert governed._run(amount=3) == "sent 3"


def test_an_async_invoke_alias_is_gated_alongside_invoke(sent):
    """One logical entry point, two spellings, and only one of them gated.

    Haystack's ``Tool`` pairs ``invoke`` with ``invoke_async`` rather than
    ``ainvoke``, and its Agent reaches only ``invoke_async`` on the async path.
    Measured before this was added: the same governed tool refused under
    ``Agent.run`` and executed under ``Agent.run_async``, returning its payload
    with no event recorded at all.
    """
    import asyncio

    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    from obsvr.integrations.tools import govern_tool

    ran = []

    class _Tool:
        name = "send_money"
        description = "moves money"

        def invoke(self, **kwargs):
            ran.append("sync")
            return "PAYLOAD"

        async def invoke_async(self, **kwargs):
            ran.append("async")
            return "PAYLOAD"

    governed = govern_tool(_Tool())
    for call in (lambda: governed.invoke(amount=1),
                 lambda: asyncio.run(governed.invoke_async(amount=1))):
        with pytest.raises(ObsvrPolicyError):
            call()
    assert ran == []


def test_a_tool_without_an_async_alias_resolves_exactly_as_before(sent):
    """The alias table is additive: nothing that lacks the spelling changes."""
    from obsvr.integrations.tools import _resolve_exec_attrs

    class _Invoke:
        def invoke(self, **kwargs):
            return None

    class _InvokePair:
        def invoke(self, **kwargs):
            return None

        async def ainvoke(self, **kwargs):
            return None

    assert _resolve_exec_attrs(_Invoke()) == ("invoke",)
    assert _resolve_exec_attrs(_InvokePair()) == ("invoke", "ainvoke")
