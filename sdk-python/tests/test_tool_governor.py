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


# ── The exec-attr table, pinned per supported framework ──────────────────────
#
# Three spellings have been found one at a time — crewai's `func`, `ainvoke`,
# and Haystack's `invoke_async` — each after a live run where a governed tool
# executed anyway. The shapes below were read off the REAL tool classes in each
# framework's own venv (py/integrations/_exec_attr_sweep.py in the harness) and
# are modelled here so the table is checked against all nine on every commit.
#
# Two things are pinned at once, and the second is why the file exists: WHICH
# attributes each shape resolves to, so an addition to the table cannot quietly
# move an existing framework onto a different entry point.


class _CrewAIBaseTool:
    """crewai.tools.BaseTool — `_run`/`_arun` plus public `run`/`arun`."""

    name = "t"
    description = "d"

    def _run(self, **kw): ...
    async def _arun(self, **kw): ...
    def run(self, **kw): ...
    async def arun(self, **kw): ...


class _CrewAIStructuredTool:
    """crewai.tools.structured_tool.CrewStructuredTool — no `_arun`."""

    name = "t"
    description = "d"

    def _run(self, **kw): ...
    def invoke(self, **kw): ...
    async def ainvoke(self, **kw): ...
    func = staticmethod(lambda **kw: None)


class _LangChainStructuredTool:
    """langchain_core.tools.StructuredTool — the widest shape in the set."""

    name = "t"
    description = "d"

    def _run(self, **kw): ...
    async def _arun(self, **kw): ...
    def invoke(self, **kw): ...
    async def ainvoke(self, **kw): ...
    def run(self, **kw): ...
    async def arun(self, **kw): ...
    func = staticmethod(lambda **kw: None)


class _LlamaIndexFunctionTool:
    """llama_index FunctionTool — public call/acall over private callables,
    with `fn`/`async_fn`/`real_fn` exposed as read-only PROPERTIES."""

    def __init__(self):
        self._fn = lambda **kw: None
        self._async_fn = lambda **kw: None
        self._real_fn = lambda **kw: None

    def call(self, **kw): ...
    async def acall(self, **kw): ...

    @property
    def fn(self): return self._fn

    @property
    def async_fn(self): return self._async_fn

    @property
    def real_fn(self): return self._real_fn


class _HaystackTool:
    """haystack.tools.Tool — pairs `invoke` with `invoke_async`, NOT `ainvoke`."""

    name = "t"
    description = "d"

    def invoke(self, **kw): ...
    async def invoke_async(self, **kw): ...


class _Ag2Tool:
    """autogen.tools.Tool — its ONLY match is `func`, a read-only property."""

    def __init__(self):
        self._func = lambda **kw: None

    @property
    def func(self): return self._func

    def __call__(self, *a, **kw): return self._func(*a, **kw)


class _OpenAIAgentsFunctionTool:
    """agents.FunctionTool — one async entry point, input at position 1."""

    name = "t"
    description = "d"

    async def on_invoke_tool(self, ctx, args): ...


class _PydanticAITool:
    """pydantic_ai.tools.Tool — carries NO execute attribute at all."""

    name = "t"


@pytest.mark.parametrize(
    "label,shape,expected",
    [
        ("crewai.BaseTool", _CrewAIBaseTool, ("_run", "_arun")),
        ("crewai.CrewStructuredTool", _CrewAIStructuredTool, ("_run", "func")),
        ("langchain.StructuredTool", _LangChainStructuredTool, ("_run", "_arun", "func")),
        ("llamaindex.FunctionTool", _LlamaIndexFunctionTool, ("call", "acall")),
        ("haystack.Tool", _HaystackTool, ("invoke", "invoke_async")),
        ("openai_agents.FunctionTool", _OpenAIAgentsFunctionTool, ("on_invoke_tool",)),
        # Recognized by NOTHING gateable: the only match is a property.
        ("autogen.tools.Tool", _Ag2Tool, ()),
        # No execute attribute at all; governed at the toolset boundary instead.
        ("pydantic_ai.Tool", _PydanticAITool, ()),
    ],
)
def test_the_table_resolves_each_supported_framework_to_these_attrs(label, shape, expected):
    """ORDER IS THE CONTRACT, so it is asserted rather than trusted."""
    from obsvr.integrations.tools import _resolve_exec_attrs

    assert _resolve_exec_attrs(shape()) == expected, label


def test_a_read_only_property_is_not_an_entry_point_and_does_not_break_the_caller(sent):
    """F-5-7. ag2's `Tool.func` is a property with no setter, and
    `object.__setattr__` honours data descriptors — so the write raised
    `AttributeError` straight out of the caller's program.

    Governing a caller must not damage the caller. The property is not a
    gateable entry point, so the TOOL ITSELF comes back, unchanged and still
    usable."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    from obsvr.integrations.tools import govern_tool, is_tool_governed

    tool = _Ag2Tool()
    governed = govern_tool(tool, name="send_money")  # must not raise

    assert governed is tool, "a tool that cannot be gated must come back as it was"
    assert callable(governed.func), "the caller's tool must still work"
    assert not is_tool_governed("send_money"), (
        "the name must NOT be registered — the audit rails on other surfaces "
        "stand down for a registered name, so claiming one here would turn a "
        "coverage gap into their silence"
    )


def test_a_read_write_property_installs_nothing_and_is_also_refused(sent):
    """The quieter half of the same defect. A property WITH a setter accepts
    the write, runs the setter, and leaves lookup returning the original — a
    gate the caller believes in and does not have."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    from obsvr.integrations.tools import govern_tool

    class _Settable:
        def __init__(self):
            self._stored = lambda **kw: "ran"

        @property
        def invoke(self): return self._stored

        @invoke.setter
        def invoke(self, value): self._elsewhere = value

    tool = _Settable()
    governed = govern_tool(tool, name="send_money")
    assert governed is tool
    assert governed.invoke() == "ran"


def test_a_writable_slot_is_still_gated(sent):
    """Slots are storage, not behaviour: shadowing one DOES reach dispatch, so
    the descriptor filter must not sweep them up with properties."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    from obsvr.integrations.tools import govern_tool

    class _Slotted:
        __slots__ = ("invoke", "name")

        def __init__(self):
            self.name = "send_money"
            self.invoke = lambda **kw: "ran"

    governed = govern_tool(_Slotted())
    with pytest.raises(ObsvrPolicyError):
        governed.invoke(amount=1)


def test_a_readonly_c_level_attr_degrades_instead_of_raising(sent):
    """`functools.partial.func` is the same descriptor TYPE as a slot and
    refuses the write, which is why the install site verifies rather than
    trusting resolution."""
    import functools

    obsvr.init(api_key="test", sample_rate=1, agent_policy={})
    from obsvr.integrations.tools import govern_tool

    part = functools.partial(lambda x: x, 1)
    governed = govern_tool(part, name="send_money")  # must not raise
    assert governed is part
    assert governed() == 1


def test_a_plain_function_is_still_wrapped_directly(sent):
    """The bare-callable branch is unchanged: a plain function carries none of
    the table's names, so narrowing that branch to non-tool-objects leaves it
    exactly where it was."""
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    from obsvr.integrations.tools import govern_tool

    ran = []

    def send_money(amount=0):
        ran.append(amount)
        return "PAYLOAD"

    governed = govern_tool(send_money)
    with pytest.raises(ObsvrPolicyError):
        governed(amount=1)
    assert ran == []


def test_a_write_that_lands_but_never_reaches_lookup_is_refused(sent):
    """The install site VERIFIES rather than trusting resolution, and this is
    the case only the verification can see.

    A lookup-forwarding proxy — what wrapt's C `ObjectProxy` is — accepts
    `object.__setattr__` into its own instance dict and then never consults it,
    because `__getattribute__` forwards to the wrapped object. Nothing about the
    descriptor on the class says so, so the shadowability filter passes it and
    the write raises nothing: the gate would be reported installed and would
    never run. Confirming the attribute now RESOLVES to the wrapper is what
    catches it.
    """
    obsvr.init(api_key="test", sample_rate=1,
               agent_policy={"denied_tools": ["send_money"]})
    from obsvr.integrations.tools import govern_tool, is_tool_governed

    class _Inner:
        name = "send_money"

        def invoke(self, **kw):
            return "ran"

    class _Forwarding:
        def __init__(self, inner):
            object.__setattr__(self, "_inner", inner)

        def __getattribute__(self, item):
            if item == "_inner":
                return object.__getattribute__(self, "_inner")
            return getattr(object.__getattribute__(self, "_inner"), item)

        def __copy__(self):
            # Copy to another PROXY. Without this, copy.copy forwards through
            # the proxy and returns the INNER object, and the leg would be
            # measuring copy semantics rather than the install verification.
            return _Forwarding(object.__getattribute__(self, "_inner"))

    tool = _Forwarding(_Inner())
    governed = govern_tool(tool, name="send_money")

    assert governed is tool, "a gate that cannot be installed must not be claimed"
    assert governed.invoke() == "ran", "the caller's tool must still work"
    assert not is_tool_governed("send_money"), (
        "the name must not be registered for a gate that was never installed"
    )


# ── The caller principal reaches the enforcing channel ───────────────────────
#
# The `user_id=` wrap-time kwarg is the documented way to attach the audit
# principal. The principal reaches ENFORCEMENT through the metadata dict —
# quota buckets, the session-taint key, approval binding and the decision-input
# hash all read `metadata.user_id` — so the kwarg must be folded into that dict
# (see `_identity_meta`), or the caller gets a signed principal on the record
# and none of the user-scoped enforcement.


def _probe_kwarg_identity_scopes_enforcement(sent):
    """Proving body for the fold, factored out so the disarm test below can
    require it to fail. Asserts: the quota meters the caller's own bucket and
    not "default"; the refusal record names the principal at top level AND
    inside the decision-input hash; and the shared bucket stays unmetered, so
    an unattributed tool still runs."""
    from obsvr.decision_record import (
        build_decision_input,
        compute_decision_input_hash,
    )
    from obsvr.rules import PolicyRule, _quota_store, _reset_quota
    from obsvr.session_taint import (
        _reset_session_taint,
        derive_session_key,
        mark_tainted,
    )

    _reset_quota()
    _reset_session_taint()
    try:
        obsvr.init(
            api_key="test",
            sample_rate=1,
            policy_rules=[
                PolicyRule(
                    id="q1", name="user-quota", enabled=True, action="block",
                    type="quota",
                    conditions={
                        "quota_limit": 1, "quota_window_ms": 60000,
                        "quota_scope": "user_id",
                    },
                )
            ],
            session_taint={"enabled": True, "action": "block"},
        )
        # Arm the pre-call net the way a real deployment is armed — the taint
        # store is non-empty — without touching the principal under test.
        mark_tainted(
            derive_session_key({"user_id": "someone-else"}), "prompt_injection", 1.0
        )

        tool = _RunShapedTool()
        governed = govern_tool(tool, user_id="mallory")
        assert governed._run(amount=1) == "sent 1"
        assert "user_id:mallory" in _quota_store, (
            f"the wrap-time principal did not reach the quota meter; "
            f"buckets: {sorted(_quota_store)}"
        )
        assert "user_id:default" not in _quota_store, (
            "the caller's usage was metered into the shared bucket"
        )

        with pytest.raises(ObsvrPolicyError):
            governed._run(amount=2)
        assert tool.calls == [1], "the body ran despite the spent quota"

        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked, "the refusal emitted no blocked event"
        ev = blocked[-1]
        assert ev.get("user_id") == "mallory", (
            "the record of mallory being refused does not say it was mallory"
        )
        assert ev["metadata"].get("user_id") == "mallory"
        expected = compute_decision_input_hash(
            build_decision_input(
                rules_hash=ev["policy_version"],
                degraded=False,
                target="request",
                evaluated_text='{"amount": 2}',
                user_id="mallory",
                service_name=None,
                tenant_id=None,
                hook="not_configured",
            )
        )
        assert ev.get("decision_input_hash") == expected, (
            "the decision-input hash does not commit to the caller principal"
        )

        # The shared bucket was never metered on mallory's behalf: a tool
        # governed with no principal still runs on its first call.
        anon = govern_tool(_RunShapedTool())
        assert anon._run(amount=3) == "sent 3", (
            "the shared bucket was exhausted by an attributed caller"
        )
    finally:
        _reset_session_taint()
        _reset_quota()


def test_the_wrap_time_principal_scopes_quota_and_the_refusal_record(sent):
    _probe_kwarg_identity_scopes_enforcement(sent)


def test_the_wrap_time_principal_keys_the_taint_latch(sent):
    """`govern_tool(tool, user_id=...)` engages the session-taint latch under
    the caller's own key, exactly as the metadata form already does — one
    principal, one latch key, whichever spelling attached it."""
    from obsvr.session_taint import (
        _reset_session_taint,
        derive_session_key,
        mark_tainted,
    )

    _reset_session_taint()
    try:
        obsvr.init(
            api_key="test", sample_rate=1,
            session_taint={"enabled": True, "action": "block"},
        )
        mark_tainted(
            derive_session_key({"user_id": "mallory"}), "prompt_injection", 1.0
        )

        tool = _RunShapedTool()
        governed = govern_tool(tool, user_id="mallory")
        with pytest.raises(ObsvrPolicyError):
            governed._run(amount=500)
        assert tool.calls == [], "a tainted principal executed the tool"
        blocked = [e for e in sent if e.get("action_taken") == "blocked"]
        assert blocked and blocked[-1].get("rule_id") == "sdk:session_tainted"
        assert blocked[-1].get("user_id") == "mallory"
        assert blocked[-1]["metadata"].get("user_id") == "mallory"

        # An untainted principal keeps the same tool.
        clean = govern_tool(_RunShapedTool(), user_id="alice")
        assert clean._run(amount=1) == "sent 1"
    finally:
        _reset_session_taint()


def test_the_wrap_time_kwarg_overlays_metadata_identity():
    """Fold precedence, pinned to the other identity-threading surfaces
    (pydantic_ai, bedrock, vertex, haystack, mcp): start from ``metadata``,
    the wrap-time kwargs overlay it. One ordering on every surface beats
    either ordering on some."""
    from obsvr.integrations.tools import _identity_meta

    assert _identity_meta(
        {"metadata": {"user_id": "meta"}, "user_id": "kwarg"}
    ) == {"user_id": "kwarg"}
    assert _identity_meta(
        {"metadata": {"user_id": "meta", "tenant_id": "t1"}}
    ) == {"user_id": "meta", "tenant_id": "t1"}
    assert _identity_meta({"user_id": "u", "service_name": "s"}) == {
        "user_id": "u", "service_name": "s",
    }
    assert _identity_meta({}) is None
    assert _identity_meta(None) is None


def test_identity_fold_is_actually_threaded(sent, monkeypatch):
    """Non-vacuity: revert the fold to the raw-metadata passthrough it
    replaced and the proving body above MUST fail. A green identity proof
    that cannot go red is not proving the identity is threaded."""
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(
        tools_mod, "_identity_meta",
        lambda options: (options or {}).get("metadata"),
    )
    with pytest.raises(AssertionError):
        _probe_kwarg_identity_scopes_enforcement(sent)


# ── Idempotence: governing twice yields one gate ─────────────────────────────
#
# govern_tool marks the object it verifiably installed a wrapper on and
# returns an already-marked object unchanged. Without the marker a second
# wrap re-gates the first wrapper's callables — the per-call `inflight` guard
# is allocated fresh per govern_tool call and cannot see across wraps — so
# one invocation is evaluated and audited twice, which is how a step budget
# silently drifts.


def test_governing_twice_evaluates_and_audits_once_per_invocation(sent, monkeypatch):
    from obsvr.integrations import tools as tools_mod
    from obsvr.session_taint import (
        _reset_session_taint,
        derive_session_key,
        mark_tainted,
    )

    evaluations = []
    real_apply = tools_mod.apply_pre_call_policy

    def counting_apply(*args, **kwargs):
        evaluations.append(1)
        return real_apply(*args, **kwargs)

    monkeypatch.setattr(tools_mod, "apply_pre_call_policy", counting_apply)

    _reset_session_taint()
    try:
        obsvr.init(
            api_key="test", sample_rate=1,
            session_taint={"enabled": True, "action": "block"},
        )
        # Arm the pre-call net so the evaluation counter counts something.
        mark_tainted(
            derive_session_key({"user_id": "someone-else"}), "prompt_injection", 1.0
        )

        tool = _RunShapedTool()
        governed_once = govern_tool(tool)
        governed_twice = govern_tool(governed_once)
        assert governed_twice is governed_once, (
            "governing a governed tool must return it unchanged"
        )

        assert governed_twice._run(amount=1) == "sent 1"
        assert tool.calls == [1]
        assert len(evaluations) == 1, (
            f"one invocation was evaluated {len(evaluations)} times"
        )
        calls = [e for e in sent if e.get("operation") == "tool.call"]
        assert len(calls) == 1, (
            f"one invocation emitted {len(calls)} audit events"
        )
    finally:
        _reset_session_taint()


def test_governing_a_wrapped_bare_callable_twice_wraps_once(sent):
    obsvr.init(api_key="test", sample_rate=1)

    def transfer(amount: int = 0):
        return f"sent {amount}"

    governed_once = govern_tool(transfer, name="transfer")
    governed_twice = govern_tool(governed_once, name="transfer")
    assert governed_twice is governed_once

    assert governed_twice(amount=1) == "sent 1"
    calls = [e for e in sent if e.get("operation") == "tool.call"]
    assert len(calls) == 1, f"one invocation emitted {len(calls)} audit events"


class _PropertyLockedTool:
    """Recognized shape whose only entry point is a data descriptor, so
    nothing is gateable — until the test swaps the property for a method."""

    name = "locked_tool"

    def __init__(self):
        self.calls = []

    @property
    def run(self):  # a data descriptor: not shadowable, so not gateable
        return None


def _probe_empty_handed_pass_leaves_the_tool_governable(sent):
    """Proving body: a tool where nothing was gateable is NOT marked, so a
    later attempt — once the shape has become gateable — still installs a
    real gate. Factored out so the disarm test can require it to fail."""
    from obsvr.integrations.tools import _GOVERNED_MARKER_ATTR

    obsvr.init(
        api_key="test", sample_rate=1,
        agent_policy={"denied_tools": ["locked_tool"]},
    )
    tool = _PropertyLockedTool()
    ungoverned = govern_tool(tool)
    assert ungoverned is tool, "an empty-handed pass must return the original"
    assert getattr(tool, _GOVERNED_MARKER_ATTR, False) is not True, (
        "a tool where nothing was gateable was marked governed"
    )

    # The shape becomes gateable (the property is replaced by a method) —
    # a legitimate re-attempt must install a real gate, not be refused by a
    # stale claim.
    del _PropertyLockedTool.run
    try:
        _PropertyLockedTool.run = lambda self, amount=0: self.calls.append(amount)
        governed = govern_tool(tool)
        with pytest.raises(ObsvrPolicyError):
            governed.run(amount=500)
        assert tool.calls == [], "the denied tool body ran"
    finally:
        del _PropertyLockedTool.run
        _PropertyLockedTool.run = property(lambda self: None)


def test_an_empty_handed_pass_leaves_the_tool_governable(sent):
    _probe_empty_handed_pass_leaves_the_tool_governable(sent)


def test_idempotence_marker_is_gated_on_the_install(sent, monkeypatch):
    """Non-vacuity: the mutant that marks UNCONDITIONALLY — including when
    nothing was gateable — must make the probe above fail, because the stale
    claim blocks the later legitimate gate. Simulated by marking the object
    on the empty-handed path exactly as that mutant would."""
    from obsvr.integrations.tools import _GOVERNED_MARKER_ATTR

    original_govern = govern_tool

    def marking_govern(tool, *args, **kwargs):
        result = original_govern(tool, *args, **kwargs)
        if result is tool:
            # the mutant: claim the object even though no gate was installed
            object.__setattr__(tool, _GOVERNED_MARKER_ATTR, True)
        return result

    monkeypatch.setitem(globals(), "govern_tool", marking_govern)
    with pytest.raises(AssertionError):
        _probe_empty_handed_pass_leaves_the_tool_governable(sent)
