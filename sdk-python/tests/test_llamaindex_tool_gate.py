"""The LlamaIndex tool gate: what it binds to, and what it refuses to bind to.

llama-index-core is not installed in this venv by design, so these tests model
the framework's shape rather than importing it. Every shape below is taken from
llama-index-core 0.14.23 and named where it came from; the live suite in the
harness is what proves the model matches the framework.
"""

import asyncio

import pytest

import obsvr
from obsvr.errors import ObsvrPolicyError


TOOL = "send_money"


@pytest.fixture(autouse=True)
def _fresh_governed_names(monkeypatch):
    """``govern_tool`` records every wrapped NAME process-wide, and the audit
    rails on other surfaces consult that registry to avoid stamping a verdict
    beside a real gate's own. Leaking a name out of this file therefore silences
    another surface's ``not_evaluated`` record and fails a test that has nothing
    to do with LlamaIndex — which is exactly what it did before this fixture."""
    from obsvr.integrations import tools as tools_mod

    monkeypatch.setattr(tools_mod, "_GOVERNED_TOOL_NAMES", set())


class _Metadata:
    """``ToolMetadata`` — LlamaIndex keeps the name, description and argument
    schema HERE rather than on the tool, which is why the gate supplies its own
    descriptor read."""

    def __init__(self, name=TOOL, description="moves money", fn_schema=None):
        self.name = name
        self.description = description
        self.fn_schema = fn_schema

    def get_name(self):
        return self.name


class _FunctionTool:
    """``FunctionTool`` at 0.14.23: public ``call``/``acall`` over three private
    references to the callable. ``fn``/``async_fn``/``real_fn`` are read-only
    properties over them, which is why the gate replaces the private names."""

    def __init__(self, body, name=TOOL, fn_schema=None):
        self.metadata = _Metadata(name=name, fn_schema=fn_schema)
        self._fn = body
        self._async_fn = None
        self._real_fn = body

    @property
    def fn(self):
        return self._fn

    @property
    def real_fn(self):
        return self._real_fn

    def call(self, *args, **kwargs):
        return self._fn(*args, **kwargs)

    async def acall(self, *args, **kwargs):
        return self._fn(*args, **kwargs)


class _Agent:
    """``BaseWorkflowAgent``: the two attrs the gate feature-detects."""

    def __init__(self, tools=(), retrieved=()):
        self.tools = list(tools)
        self._retrieved = list(retrieved)

    async def get_tools(self, _input=None):
        return list(self.tools) + list(self._retrieved)

    async def _call_tool(self, tool, tool_input):
        return await tool.acall(**tool_input)

    async def dispatch(self, name=TOOL, **kwargs):
        tools = await self.get_tools(name)
        by_name = {t.metadata.name: t for t in tools}
        return await self._call_tool(by_name[name], kwargs)


class _Workflow:
    """``AgentWorkflow``: its own ``get_tools`` reads each member's ``tools``
    directly rather than calling the member's ``get_tools``, so the two are
    separate convergence points."""

    def __init__(self, agents):
        self.agents = dict(agents)

    async def get_tools(self, agent_name, _input=None):
        return list(self.agents[agent_name].tools)

    async def _call_tool(self, tool, tool_input):
        return await tool.acall(**tool_input)

    async def dispatch(self, agent_name, name=TOOL, **kwargs):
        tools = await self.get_tools(agent_name, name)
        by_name = {t.metadata.name: t for t in tools}
        return await self._call_tool(by_name[name], kwargs)


@pytest.fixture
def calls():
    return []


def _tool(calls, name=TOOL):
    def body(amount=0):
        calls.append(amount)
        return f"sent {amount}"

    return _FunctionTool(body, name=name)


def _deny(*names):
    obsvr.init(api_key="k", agent_policy={"denied_tools": list(names)})


def _allow():
    obsvr.init(api_key="k", agent_policy={})


def test_the_gate_refuses_a_denied_tool_from_the_tools_list(sent, calls):
    from obsvr.integrations.llamaindex import govern_agent

    agent = _Agent(tools=[_tool(calls)])
    govern_agent(agent)
    _deny(TOOL)

    with pytest.raises(ObsvrPolicyError):
        asyncio.run(agent.dispatch(amount=500))
    assert calls == [], "the denied tool's body ran"
    assert any(e["operation"] == "tool.policy.tool_blocked" for e in sent)


def test_the_gate_reaches_a_tool_the_caller_could_not_have_wrapped(sent, calls):
    """The tool_retriever route: the tool is not on the agent when the caller
    installs the gate, and arrives mid-turn from the retriever. Measured live as
    a bypass of a hand-applied wrapper; this pins that the binder closes it."""
    from obsvr.integrations.llamaindex import govern_agent

    agent = _Agent(tools=[], retrieved=[_tool(calls)])
    govern_agent(agent)
    _deny(TOOL)

    with pytest.raises(ObsvrPolicyError):
        asyncio.run(agent.dispatch(amount=500))
    assert calls == []


def test_the_gate_walks_a_workflows_member_agents(sent, calls):
    """The handoff route: the denied tool lives on the handoff TARGET, and the
    workflow reads that agent's own tools rather than the caller's list."""
    from obsvr.integrations.llamaindex import govern_agent

    worker = _Agent(tools=[_tool(calls)])
    workflow = _Workflow({"boss": _Agent(tools=[]), "worker": worker})
    govern_agent(workflow)
    _deny(TOOL)

    with pytest.raises(ObsvrPolicyError):
        asyncio.run(workflow.dispatch("worker", amount=500))
    assert calls == []
    # Bound on the member too, so running it directly is governed as well.
    with pytest.raises(ObsvrPolicyError):
        asyncio.run(worker.dispatch(amount=500))
    assert calls == []


def test_an_allowed_tool_still_runs_and_is_audited(sent, calls):
    """The paired allow control. A gate that refused everything would pass
    every deny test in this file."""
    from obsvr.integrations.llamaindex import govern_agent

    agent = _Agent(tools=[_tool(calls)])
    govern_agent(agent, user_id="u-1")
    _allow()

    assert asyncio.run(agent.dispatch(amount=7)) == "sent 7"
    assert calls == [7]
    tool_calls = [e for e in sent if e["operation"] == "tool.call"]
    assert len(tool_calls) == 1, "one dispatch must yield exactly one audit event"
    assert tool_calls[0]["user_id"] == "u-1"


def test_one_dispatch_yields_one_verdict_though_two_attrs_are_gated(sent, calls):
    """``call`` delegates to ``_fn`` and BOTH are gated, so the reentrancy guard
    is what keeps a single invocation from being judged and audited twice."""
    from obsvr.integrations.llamaindex import govern_agent

    agent = _Agent(tools=[_tool(calls)])
    govern_agent(agent)
    _allow()

    tools = asyncio.run(agent.get_tools())
    tools[0].call(amount=7)
    assert calls == [7]
    assert len([e for e in sent if e["operation"] == "tool.call"]) == 1


def test_the_codeact_route_is_gated_because_real_fn_is(sent, calls):
    """``CodeActAgent`` hands the model ``tool.real_fn`` and executes generated
    Python that calls it by name — the tool object is never invoked. Gating the
    private callable is what reaches that route."""
    from obsvr.integrations.llamaindex import govern_agent

    agent = _Agent(tools=[_tool(calls)])
    govern_agent(agent)
    _deny(TOOL)

    governed = asyncio.run(agent.get_tools())[0]
    with pytest.raises(ObsvrPolicyError):
        governed.real_fn(amount=500)
    assert calls == []


def test_the_sealed_digest_carries_the_frameworks_own_descriptor(sent, calls):
    """LlamaIndex keeps description and schema behind ``metadata``, so the
    generic reader finds neither. Two tools differing ONLY in schema must seal
    different digests, or the descriptor is not in the hash at all."""
    from obsvr.integrations.llamaindex import govern_agent

    class _Schema:
        @staticmethod
        def model_json_schema():
            return {"type": "object", "properties": {"amount": {"type": "integer"}}}

    _allow()
    plain = _Agent(tools=[_tool(calls)])
    govern_agent(plain)
    asyncio.run(plain.dispatch(amount=7))

    schema_tool = _FunctionTool(lambda amount=0: "x", fn_schema=_Schema)
    schemad = _Agent(tools=[schema_tool])
    govern_agent(schemad)
    asyncio.run(schemad.dispatch(amount=7))

    digests = [
        e["metadata"]["obsvr_tool_content_hash"]
        for e in sent
        if e["operation"] == "tool.call"
    ]
    assert len(digests) == 2
    assert digests[0] != digests[1], (
        "the two tools differ only in their metadata.fn_schema; identical "
        "digests mean the descriptor never reached the hash"
    )


def test_it_refuses_loudly_where_the_seam_is_absent(calls):
    """The F-1b-2 lesson: an installer that cannot be consulted must say so
    rather than arm a gate the caller believes in and does not have."""
    from obsvr.integrations.llamaindex import govern_agent

    class _NotAnAgent:
        async def get_tools(self, _input=None):
            return []

        # no _call_tool: registration half without the dispatch half

    with pytest.raises(ImportError, match="govern_tool"):
        govern_agent(_NotAnAgent())


def test_detach_restores_the_original_assembly(sent, calls):
    from obsvr.integrations.llamaindex import govern_agent

    agent = _Agent(tools=[_tool(calls)])
    original = type(agent).get_tools
    detach = govern_agent(agent)
    detach()
    detach()  # idempotent

    assert agent.get_tools.__func__ is original
    _deny(TOOL)
    assert asyncio.run(agent.dispatch(amount=7)) == "sent 7"
    assert calls == [7], "detached: the gate must be gone, not merely quiet"
