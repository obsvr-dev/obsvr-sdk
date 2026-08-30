"""LangChain (Python) integration — a callback handler that gates models and tools.

LangChain dispatches model-start callbacks before entering the model
implementation and propagates handler errors when ``raise_error`` is true.
The handler therefore applies the shared pre-call policy at that boundary and
raises a typed policy error before provider dispatch. LangChain does not expose
a stable callback API for replacing the provider-bound prompt, so a requested
redaction that cannot be applied is resolved closed rather than leaked.

Tool calls are not. ``on_tool_start`` is a real pre-execution gate: the tool
base class dispatches it before the ``try`` that guards execution, and this
handler sets ``raise_error``, so a refusal escapes ``run()`` before the tool
body is reached. ``agent_policy``'s allow/deny list and per-run step budget are
both decided there.

The step budget needs a run to belong to, and finding one is the part that has
to be done by hand. Neither runtime says "an agent started" in the argument the
old code read: ``on_chain_start`` receives ``serialized=None`` from the graph
runtime at both the graph root and every node, and from ``Chain.invoke`` on the
classic executor, with the identity carried in a separate ``name`` keyword.
Neither runtime hands a callback more than its immediate parent either, and
under the graph runtimes a tool's immediate parent is the node that dispatched
it rather than the run. So this handler records the chain edges it is given,
treats the outermost run as the agent run, and walks upward from a tool call to
find it.
"""

# Interception: LangChain Python callback API (non-mutating). Pass ObsvrCallbackHandler() via callbacks=[...] — no LangChain internals are modified.

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .. import sender as _sender
from ..binding_report import record_binding
from ..agent_policy import (
    apply_loop_detection,
    check_steps,
    create_loop_detector,
    resolve_loop_detection,
    unrecognized_step_action_meta,
)
from ..config import try_get_config
from ..events import (
    blocked_call_error,
    emit_event,
    infer_provider_from_string,
    step_limit_compliance,
    tool_denied_compliance,
    tool_gate_not_evaluated_compliance,
)
from ..errors import ObsvrPolicyError
from ..policy import (
    apply_pre_call_policy,
    blocked_prompt_for_storage,
    blocked_user_input_for_storage,
)
from ..reason_codes import ReasonCode
from ..span import emit_span
from ..span_attributes import SPAN_ATTR
from .tools import _identity_meta

try:  # pragma: no cover - exercised only when langchain-core is installed
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore

    record_binding("langchain", "langchain_core.callbacks.BaseCallbackHandler")
except ImportError as _exc:  # shim base class so import never fails
    record_binding(
        "langchain", "langchain_core.callbacks.BaseCallbackHandler", _exc
    )

    class BaseCallbackHandler:  # type: ignore
        pass


SOURCE = "langchain_py"

# The ancestry map is fed by chain starts and drained by chain ends. A caller
# that abandons a stream generator mid-run leaves ends undelivered, so the map
# is bounded rather than trusted to drain.
_MAX_TRACKED_CHAINS = 4096
_MAX_ANCESTRY_HOPS = 64


def _get(obj: Any, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _message_role(msg: Any) -> str:
    role = _get(msg, "role")
    if role is None:
        role = _get(msg, "type")
    if role is None:
        role = type(msg).__name__.lower()
    return str(getattr(role, "value", role))


def _message_content(msg: Any) -> str:
    content = _get(msg, "content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            text = _get(part, "text")
            if isinstance(text, str):
                parts.append(text)
        return " ".join(parts)
    return ""


# ---------------------------------------------------------------------------
# Agent policy helpers
# ---------------------------------------------------------------------------


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (allowed, reason). reason is empty string when allowed."""
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")  # None = all allowed
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


# Metadata keys the graph runtime attaches to every run it owns. Unlike tags,
# metadata is INHERITABLE (``CallbackManager.get_child`` copies
# ``inheritable_metadata`` and adds the step tag with ``inherit=False``), so
# these reach a nested run where ``graph:step:N`` does not.
_GRAPH_METADATA_KEYS = ("langgraph_step", "langgraph_node", "ls_integration")


def _names_an_agent(
    serialized: Any,
    tags: Optional[List[str]],
    name: Optional[str],
    metadata: Any,
) -> bool:
    """Whether this chain event identifies itself as an agent or a graph.

    ``serialized`` is read LAST and is not relied on, because the framework
    almost never fills it in: the graph runtime passes a literal ``None`` at
    both the graph root and every node, the classic executor passes ``None``
    from ``Chain.invoke``, and ``Runnable._call_with_config`` defaults it to
    ``None`` at every call site but the prompt classes. The identity travels in
    the separate ``name`` keyword ("AgentExecutor", "LangGraph", the node name)
    and in the graph metadata. Reading only ``serialized`` is what left the
    per-run controls with no run to attach to on either runtime.
    """
    if isinstance(name, str) and "agent" in name.lower():
        return True
    # "LangGraph" is the compiled graph's default name; it contains no "agent".
    if isinstance(name, str) and "langgraph" in name.lower():
        return True
    if isinstance(metadata, dict) and any(k in metadata for k in _GRAPH_METADATA_KEYS):
        return True
    if isinstance(tags, list) and "agent" in [str(t).lower() for t in tags]:
        return True
    id_parts = (_get(serialized, "id") or [])
    id_str = ".".join(str(p) for p in id_parts).lower()
    if "agentexecutor" in id_str or "agent" in id_str:
        return True
    ser_name = str(_get(serialized, "name") or "").lower()
    if "agent" in ser_name:
        return True
    return False


class ObsvrCallbackHandler(BaseCallbackHandler):
    """Attach to LangChain via callbacks=[ObsvrCallbackHandler()]."""

    name = "obsvr_audit_handler"
    # langchain-core SWALLOWS handler exceptions unless raise_error is True,
    # so the policy-block ValueErrors below would never stop the chain
    # without it. Non-policy failures never escape regardless: every
    # callback body catches its own exceptions and only re-raises blocks.
    raise_error = True

    def __init__(self, **options: Any) -> None:
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._agent_runs: Dict[str, Dict[str, Any]] = {}
        self._retrievals: Dict[str, Dict[str, Any]] = {}
        self._options = options
        # run_id -> parent_run_id, for every chain run this handler has seen.
        # A callback is handed its IMMEDIATE parent only, and under the graph
        # runtimes a tool's immediate parent is the node that dispatched it, not
        # the run the budget belongs to. The edge set is enough to rebuild the
        # ancestry because every node traces its own chain start.
        self._chain_parents: Dict[str, Optional[str]] = {}
        # Tool calls the legacy agent-action callback has already ruled on, per
        # run. Both pre-tool callbacks reach the same gate and the classic
        # executor delivers BOTH for one tool call, so the second delivery must
        # be consumed or the tool is charged two steps and audited twice. This
        # is a per-call credit rather than a latch: a latch is set once and read
        # forever, so one classic run would disarm the gate for every later run
        # on the same handler. Twin of `_sawAgentAction` in the TypeScript
        # handler, which still has the latch.
        self._action_gated: Dict[str, int] = {}

    # -- run ancestry -------------------------------------------------------

    def _remember_parent(self, run_key: str, parent_key: Optional[str]) -> None:
        """Record one chain edge, bounded so an abandoned stream cannot grow it."""
        if len(self._chain_parents) >= _MAX_TRACKED_CHAINS:
            for stale in list(self._chain_parents)[: _MAX_TRACKED_CHAINS // 4]:
                self._chain_parents.pop(stale, None)
        self._chain_parents[run_key] = parent_key

    def _agent_key_at_or_above(self, key: Optional[str]) -> Optional[str]:
        """The nearest ancestor (or self) that owns agent-run state."""
        hops = 0
        while key is not None and hops < _MAX_ANCESTRY_HOPS:
            if key in self._agent_runs:
                return key
            key = self._chain_parents.get(key)
            hops += 1
        return None

    def _agent_state_for(self, run_id: Any, parent_run_id: Any) -> Optional[Dict[str, Any]]:
        """The agent run a tool/retriever callback belongs to, by walking upward."""
        for start in (parent_run_id, run_id):
            if start is None:
                continue
            key = self._agent_key_at_or_above(str(start))
            if key is not None:
                return self._agent_runs[key]
        return None

    # -- agent chain starts / ends -----------------------------------------

    def on_chain_start(
        self,
        serialized: Any,
        inputs: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            run_key = str(run_id)
            parent_key = str(parent_run_id) if parent_run_id is not None else None
            self._remember_parent(run_key, parent_key)

            named_agent = _names_an_agent(
                serialized, tags, kwargs.get("name"), metadata
            )
            # The outermost traced run IS the agent run: it is the invocation the
            # caller attached this handler to, and it is the one signal both
            # runtimes give unconditionally. A chain that names itself an agent
            # opens its own run too, but only when no ancestor already owns one,
            # so a graph does not open a second budget at every node.
            if parent_run_id is not None:
                if not named_agent or self._agent_key_at_or_above(parent_key) is not None:
                    return
            if run_key in self._agent_runs:
                return

            config = try_get_config()
            if config is None:
                return

            agent_run_id = str(uuid.uuid4())
            agent_state: Dict[str, Any] = {
                "agent_run_id": agent_run_id,
                "start_time": time.time(),
                "step_count": 0,
                # A run that never calls a tool is an ordinary chain, and this
                # handler is attached to plenty of those. Announcing it only
                # once it does something agentic keeps the run record for runs
                # that have one, without adding a pair of events to every
                # prompt-and-model chain in the process.
                "announced": False,
            }
            loop_block = resolve_loop_detection(getattr(config, "agent_policy", None))
            if loop_block is not None:
                agent_state["loop_detector"] = create_loop_detector(loop_block)
            self._agent_runs[run_key] = agent_state

            if named_agent:
                self._announce_run(config, agent_state)
        except Exception:
            pass

    def _announce_run(self, config: Any, agent_state: Dict[str, Any]) -> None:
        if agent_state.get("announced"):
            return
        agent_state["announced"] = True
        emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation="langchain.agent.run.start",
            source=SOURCE,
            prompt="",
            response="",
            metadata={"agent_run_id": agent_state["agent_run_id"]},
            options=self._options or None,
        )

    def on_chain_end(
        self,
        outputs: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._chain_parents.pop(str(run_id), None)
            self._action_gated.pop(str(run_id), None)
            run_state = self._agent_runs.pop(str(run_id), None)
            if run_state is None:
                return
            if not run_state.get("announced"):
                return
            config = try_get_config()
            if config is None:
                return

            agent_run_id = run_state["agent_run_id"]
            policy = getattr(config, "agent_policy", None) or {}
            output_policy = policy.get("output_policy") or {}
            denied_topics = output_policy.get("denied_topics") or []

            # Extract output text
            output_text = ""
            if isinstance(outputs, dict):
                for key in ("output", "result", "text", "answer"):
                    val = outputs.get(key)
                    if isinstance(val, str):
                        output_text = val
                        break
            if not output_text:
                output_text = str(outputs) if outputs else ""

            # Check output policy
            blocked_topic = None
            for topic in denied_topics:
                if topic.lower() in output_text.lower():
                    blocked_topic = topic
                    break

            if blocked_topic:
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="langchain.agent.policy.output_blocked",
                    source=SOURCE,
                    prompt="",
                    response=output_text,
                    success=False,
                    metadata={
                        "agent_run_id": agent_run_id,
                        "blocked_topic": blocked_topic,
                    },
                    options=self._options or None,
                )
                raise ValueError("[obsvr] Output blocked by agent policy")

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.agent.run.finish",
                source=SOURCE,
                prompt="",
                response=output_text,
                latency_ms=(time.time() - run_state["start_time"]) * 1000,
                metadata={"agent_run_id": agent_run_id},
                options=self._options or None,
            )
        except ValueError:
            raise  # output policy blocks must propagate
        except Exception:
            pass

    def on_chain_error(
        self,
        error: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            self._chain_parents.pop(str(run_id), None)
            self._action_gated.pop(str(run_id), None)
            run_state = self._agent_runs.pop(str(run_id), None)
            if run_state is None:
                return
            if not run_state.get("announced"):
                return
            config = try_get_config()
            if config is None:
                return

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.agent.run.finish",
                source=SOURCE,
                prompt="",
                response="",
                success=False,
                error=error,
                latency_ms=(time.time() - run_state["start_time"]) * 1000,
                metadata={"agent_run_id": run_state["agent_run_id"]},
                options=self._options or None,
            )
        except Exception:
            pass

    # -- agent actions (tool calls) ----------------------------------------

    def on_tool_start(
        self,
        serialized: Any,
        input_str: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Any = None,
        metadata: Any = None,
        inputs: Any = None,
        **kwargs: Any,
    ) -> None:
        """THE PRE-EXECUTION TOOL GATE. Runs before the tool, per tool, fails closed.

        This is the hook the tool policy always needed and did not have. The gate
        lived only in ``on_agent_action``, which the classic executor still fires
        but the graph runtimes never do — so on a modern install the gate observed
        nothing and refused nothing while still producing a complete audit trail.

        Three properties make this an enforcement point rather than another
        telemetry callback, and all three are properties of the framework rather
        than of this code:

        - The tool base class dispatches ``on_tool_start`` BEFORE the ``try`` that
          guards tool execution, so an exception raised here escapes ``run()``
          before the tool body is reached and is not converted into a tool result
          by the framework's own error handling.
        - The dispatcher re-raises a handler's exception when the handler sets
          ``raise_error``, which this one does. Without that flag the refusal
          would be logged and ignored.
        - The graph tool runner reaches the same dispatch through ``invoke``, and
          although it wraps the call broadly, its default error handler re-raises
          anything that is not its own invocation error — so a policy refusal
          still propagates and the tool still does not run.

        The tool NAME comes from ``serialized["name"]``, which the base class
        fills in from the tool instance itself at both dispatch sites and is
        therefore the only trustworthy source. The ``name`` keyword is the RUN
        name, and under the graph runtimes the run name is the graph node — every
        tool in a graph arrives as ``name="tools"``. Reading it would compare the
        node's name against the policy and match nothing, so it is not read at
        all. (The TypeScript twin is the other way round: there the serialized id
        is the tool CLASS and the run name is the reliable one.)
        """
        if self._consume_action_gate(run_id, parent_run_id):
            return
        self._gate_tool(
            tool_name=self._tool_name_from_start(serialized),
            tool_input=inputs if inputs is not None else input_str,
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    @staticmethod
    def _tool_name_from_start(serialized: Any) -> str:
        """The tool's own name, from the one field the framework fills in."""
        name = _get(serialized, "name")
        if isinstance(name, str) and name:
            return name
        return ""

    def _consume_action_gate(self, run_id: Any, parent_run_id: Any) -> bool:
        """Whether the legacy callback already ruled on THIS tool call.

        Credited per call and spent per call. The predecessor was a handler-wide
        latch, so a single run on the classic executor left every later
        ``on_tool_start`` on that handler returning early — a gate that looked
        installed and refused nothing, on a runtime that delivers no other
        pre-tool callback.
        """
        for start in (parent_run_id, run_id):
            if start is None:
                continue
            key: Optional[str] = str(start)
            hops = 0
            while key is not None and hops < _MAX_ANCESTRY_HOPS:
                pending = self._action_gated.get(key, 0)
                if pending > 0:
                    self._action_gated[key] = pending - 1
                    return True
                key = self._chain_parents.get(key)
                hops += 1
        return False

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        # The classic executor's pre-tool callback; the graph runtimes dispatch
        # it nowhere. Credited against this run so the modern hook does not gate
        # the same call a second time.
        key = str(run_id) if run_id is not None else str(parent_run_id)
        self._action_gated[key] = self._action_gated.get(key, 0) + 1
        self._gate_tool(
            tool_name=str(getattr(action, "tool", None) or ""),
            tool_input=getattr(action, "tool_input", None),
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    def _gate_tool(
        self,
        tool_name: str,
        tool_input: Any,
        run_id: Any = None,
        parent_run_id: Any = None,
    ) -> None:
        """One gate, reached from whichever pre-tool callback the runtime delivers.

        Shared rather than duplicated. Two copies of a tool gate is how the
        step-limit fail-open survived in four places at once, and it is the thing
        that must not happen to the control that decides whether a tool runs.
        """
        try:
            config = try_get_config()
            if config is None:
                return

            # The run this call belongs to, found by walking the recorded chain
            # ancestry. The immediate parent is the dispatching node under the
            # graph runtimes and the executor itself under the classic one, so a
            # direct lookup finds a budget on one runtime and nothing on the
            # other — which is how the per-run controls came to hold nothing.
            agent_state = self._agent_state_for(run_id, parent_run_id)
            if agent_state is not None:
                self._announce_run(config, agent_state)
            agent_run_id = agent_state["agent_run_id"] if agent_state else ""
            step_index = agent_state["step_count"] if agent_state else 0

            policy = getattr(config, "agent_policy", None) or {}

            # Check tool policy
            if not tool_name and (
                policy.get("denied_tools") or policy.get("allowed_tools") is not None
            ):
                # Both dispatch sites fill the tool's own name in, so this is the
                # rail for a build that stops doing so rather than a path taken
                # today. A policy that names tools and a call that cannot be
                # named is a gap; recording it is the only honest answer, and
                # inventing an allow or a block would both be worse.
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="langchain.agent.policy.tool_not_evaluated",
                    source=SOURCE,
                    prompt="",
                    response="",
                    success=False,
                    metadata={"agent_run_id": agent_run_id, "step_index": step_index},
                    compliance=tool_gate_not_evaluated_compliance(
                        surface="langchain.on_tool_start",
                        gate="tool_gate",
                        reason=(
                            "the pre-tool callback carried no tool name, so the "
                            "tool policy had nothing to match this call against"
                        ),
                    ),
                    options=self._options or None,
                )
            if tool_name:
                ok, reason = _check_tool(tool_name, policy)
                if not ok:
                    emit_event(
                        config,
                        provider="unknown",
                        model="unknown",
                        operation="langchain.agent.policy.tool_blocked",
                        source=SOURCE,
                        prompt="",
                        response="",
                        success=False,
                        metadata={
                            "agent_run_id": agent_run_id,
                            "tool_name": tool_name,
                            "reason": reason,
                            "step_index": step_index,
                        },
                        compliance=tool_denied_compliance(),
                        options=self._options or None,
                    )
                    raise ValueError(
                        f"[obsvr] Tool blocked by agent policy: {tool_name}"
                    )

            # Check step limit
            count = agent_state["step_count"] if agent_state else 0
            step_action, invalid_step_action = check_steps(count, policy)

            if agent_state:
                agent_state["step_count"] = count + 1
                # Loop detection
                detector = agent_state.get("loop_detector")
                if detector is not None:
                    loop_result = apply_loop_detection(
                        detector,
                        config,
                        agent_run_id=agent_state["agent_run_id"],
                        source=SOURCE,
                        operation="langchain.agent",
                    )
                    if loop_result and loop_result["action"] == "block":
                        raise ValueError("[obsvr] Loop detected: iteration limit exceeded")

            if step_action == "block":
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="langchain.agent.policy.step_limit",
                    source=SOURCE,
                    prompt="",
                    response="",
                    success=False,
                    metadata={
                        "agent_run_id": agent_run_id,
                        "step_count": count,
                        "step_index": step_index,
                        **unrecognized_step_action_meta(invalid_step_action),
                    },
                    compliance=step_limit_compliance(),
                    options=self._options or None,
                )
                raise ValueError("[obsvr] Step limit reached")

            if step_action == "escalate":
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="langchain.agent.policy.step_limit",
                    source=SOURCE,
                    prompt="",
                    response="",
                    metadata={
                        "agent_run_id": agent_run_id,
                        "step_count": count,
                        "step_index": step_index,
                        "escalated": True,
                    },
                    options=self._options or None,
                )

            tool_input_text = str(tool_input) if tool_input is not None else ""

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.tool.call",
                source=SOURCE,
                prompt=tool_input_text,
                response="",
                metadata={
                    "agent_run_id": agent_run_id,
                    "tool_name": tool_name,
                    "step_index": step_index,
                },
                options=self._options or None,
            )
        except ValueError:
            raise  # policy blocks must propagate
        except Exception:
            pass

    # -- tool ends ---------------------------------------------------------

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            config = try_get_config()
            if config is None:
                return

            agent_state = self._agent_state_for(run_id, parent_run_id)
            agent_run_id = agent_state["agent_run_id"] if agent_state else ""

            output_text = str(output) if output is not None else ""
            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.tool.result",
                source=SOURCE,
                # ``output_text`` is what the tool returned, handed to us by
                # LangChain's own tool-end callback -- the one place in this
                # integration where the origin of the text is not in doubt.
                content_provenance="tool_result",
                prompt="",
                response=output_text,
                metadata={"agent_run_id": agent_run_id},
                options=self._options or None,
            )
        except Exception:
            pass

    def on_tool_error(
        self,
        error: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            config = try_get_config()
            if config is None:
                return

            agent_state = self._agent_state_for(run_id, parent_run_id)
            agent_run_id = agent_state["agent_run_id"] if agent_state else ""

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.tool.result",
                source=SOURCE,
                prompt="",
                response="",
                success=False,
                error=error,
                metadata={"agent_run_id": agent_run_id},
                options=self._options or None,
            )
        except Exception:
            pass

    # -- retriever start / end / error --------------------------------------
    #
    # Emitted as SIGNED execution spans through the M3B pipeline (emit_span),
    # twin of the TS handleRetriever* trio. Only the query HASH and document
    # COUNT are recorded, never retrieval text.

    def on_retriever_start(
        self,
        serialized: Any,
        query: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        name: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        try:
            if try_get_config() is None:
                return
            agent_state = self._agent_state_for(run_id, parent_run_id)
            id_path = None
            if isinstance(serialized, dict):
                id_path = serialized.get("id")
            source = name or (
                str(id_path[-1]) if isinstance(id_path, list) and id_path else "retriever"
            )
            self._retrievals[str(run_id)] = {
                "start": time.monotonic(),
                "source": source,
                "query_hash": hashlib.sha256(str(query or "").encode("utf-8")).hexdigest(),
                "agent_run_id": agent_state["agent_run_id"] if agent_state else None,
            }
        except Exception:
            pass

    def on_retriever_end(
        self,
        documents: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        state = self._retrievals.pop(str(run_id), None)
        if not state:
            return
        try:
            emit_span(
                kind="retrieval",
                name=state["source"],
                ok=True,
                trace_id=state["agent_run_id"],
                attributes={
                    SPAN_ATTR["RETRIEVAL_SOURCE"]: state["source"],
                    SPAN_ATTR["RETRIEVAL_QUERY_HASH"]: state["query_hash"],
                    SPAN_ATTR["RETRIEVAL_DOCUMENT_COUNT"]: (
                        len(documents) if isinstance(documents, (list, tuple)) else 0
                    ),
                    "duration_ms": round((time.monotonic() - state["start"]) * 1000),
                },
            )
        except Exception:
            pass

    def on_retriever_error(
        self,
        error: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        state = self._retrievals.pop(str(run_id), None)
        if not state:
            return
        try:
            emit_span(
                kind="retrieval",
                name=state["source"],
                ok=False,
                trace_id=state["agent_run_id"],
                attributes={
                    SPAN_ATTR["RETRIEVAL_SOURCE"]: state["source"],
                    SPAN_ATTR["RETRIEVAL_QUERY_HASH"]: state["query_hash"],
                    SPAN_ATTR["RETRIEVAL_DOCUMENT_COUNT"]: 0,
                    "duration_ms": round((time.monotonic() - state["start"]) * 1000),
                },
            )
        except Exception:
            pass

    # -- LLM starts --------------------------------------------------------

    def on_llm_start(
        self, serialized: Any, prompts: Any, *, run_id: Any = None,
        parent_run_id: Any = None, **kwargs: Any
    ) -> None:
        try:
            prompt = "\n".join(p for p in (prompts or []) if isinstance(p, str))
            self._start(serialized, prompt, None, run_id, kwargs,
                        parent_run_id=parent_run_id)
        except ObsvrPolicyError:
            raise
        except Exception:
            pass

    def on_chat_model_start(
        self, serialized: Any, messages: Any, *, run_id: Any = None,
        parent_run_id: Any = None, **kwargs: Any
    ) -> None:
        try:
            lines = []
            user_text: Optional[str] = None
            for batch in messages or []:
                for msg in batch or []:
                    role = _message_role(msg)
                    content = _message_content(msg)
                    lines.append(f"{role}: {content}")
                    if role in ("user", "human"):
                        user_text = content
            self._start(serialized, "\n".join(lines), user_text, run_id, kwargs,
                        parent_run_id=parent_run_id)
        except ObsvrPolicyError:
            raise
        except Exception:
            pass

    def _start(
        self,
        serialized: Any,
        prompt: str,
        user_text: Optional[str],
        run_id: Any,
        kwargs: Dict[str, Any],
        parent_run_id: Any = None,
    ) -> None:
        config = try_get_config()
        if config is None:
            return
        # Sampling gates only clean-event emission. The pre-call policy
        # boundary still runs on every invocation.
        should_audit = _sender.should_emit(config)

        serialized = serialized or {}
        id_parts = _get(serialized, "id") or []
        id_str = ".".join(str(p) for p in id_parts)
        provider = infer_provider_from_string(id_str)

        invocation = kwargs.get("invocation_params") or {}
        metadata = kwargs.get("metadata") or {}
        ser_kwargs = _get(serialized, "kwargs") or {}
        model = (
            invocation.get("model")
            or metadata.get("ls_model_name")
            or (_get(ser_kwargs, "model") if isinstance(ser_kwargs, dict) else None)
            or (str(id_parts[-1]) if id_parts else "unknown")
        )

        # Link to parent agent run if available
        parent_agent_run_id = None
        if parent_run_id is not None:
            parent_state = self._agent_state_for(None, parent_run_id)
            if parent_state:
                parent_agent_run_id = parent_state["agent_run_id"]

        run_meta: Dict[str, Any] = {}
        if parent_agent_run_id:
            run_meta["agent_run_id"] = parent_agent_run_id

        policy_metadata: Dict[str, Any] = {}
        callback_metadata = kwargs.get("metadata")
        if isinstance(callback_metadata, dict):
            policy_metadata.update(callback_metadata)
        option_metadata = self._options.get("metadata")
        if isinstance(option_metadata, dict):
            policy_metadata.update(option_metadata)
        identity_options = dict(self._options)
        identity_options["metadata"] = policy_metadata
        identity_meta = _identity_meta(identity_options)

        policy = apply_pre_call_policy(
            prompt,
            config,
            provider=provider,
            operation="langchain.llm",
            metadata=identity_meta,
            model=str(model),
            turn_text=user_text or prompt,
        )
        compliance = policy["compliance"]

        if policy["decision"] == "redact":
            compliance = dict(compliance)
            compliance.update(
                {
                    "event_type": "blocked_call",
                    "action_taken": "blocked",
                    "action_reason": "policy_violation",
                    "reason_code": ReasonCode.POLICY_VIOLATION.value,
                    "redacted_types": [],
                    "blocked_types": list(
                        dict.fromkeys(
                            list(compliance.get("blocked_types") or [])
                            + list(compliance.get("redacted_types") or [])
                        )
                    ),
                    "rule_id": "sdk:outbound_redaction_unsupported",
                    "policy_reason": (
                        "LangChain model-start callbacks cannot replace the "
                        "provider-bound request; blocked instead of forwarding "
                        "unredacted content"
                    ),
                }
            )

        telemetry: Dict[str, Any] = {}
        if policy.get("canary_telemetry") is not None:
            telemetry.update(policy["canary_telemetry"])
        if policy.get("floor_telemetry") is not None:
            telemetry.update(policy["floor_telemetry"])
        if telemetry:
            run_meta["obsvr_telemetry"] = telemetry

        if policy["decision"] == "block" or compliance["action_taken"] == "blocked":
            emit_event(
                config,
                provider=provider,
                model=str(model),
                operation="langchain.llm",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt, compliance, policy.get("security_normalized")
                ),
                response="",
                user_input=blocked_user_input_for_storage(user_text or prompt, policy),
                latency_ms=0,
                success=False,
                status_code=403,
                compliance=compliance,
                metadata=run_meta or None,
                options=self._options or None,
            )
            raise blocked_call_error(compliance)

        self._runs[str(run_id)] = {
            "prompt": prompt,
            "user_text": user_text,
            "model": model,
            "provider": provider,
            "start_time": time.time(),
            "compliance": compliance,
            "agent_run_id": parent_agent_run_id,
            "metadata": run_meta or None,
            # Allowed: emit only when sampled in. Anything the scan acted on is
            # enforcement evidence and is always recorded, as are errors.
            "audit_this_call": (
                should_audit
                or compliance.get("action_reason", "none") != "none"
            ),
        }

    # -- LLM ends ----------------------------------------------------------

    def on_llm_end(self, response: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        try:
            state = self._runs.pop(str(run_id), None)
            if state is None:
                return
            # Sampled out and the scan found nothing: the run was still
            # governed, only this clean record is dropped. on_llm_error emits
            # regardless — an error is enforcement evidence.
            if not state.get("audit_this_call", True):
                return
            config = try_get_config()
            if config is None:
                return

            text = ""
            generations = _get(response, "generations") or []
            first = None
            if generations and generations[0]:
                first = generations[0][0]
            if first is not None:
                raw = _get(first, "text")
                if isinstance(raw, str) and raw:
                    text = raw
                else:
                    message = _get(first, "message")
                    content = _get(message, "content")
                    if isinstance(content, str):
                        text = content

            llm_output = _get(response, "llm_output") or {}
            usage = (
                _get(llm_output, "token_usage")
                or _get(llm_output, "tokenUsage")
                or _get(llm_output, "estimated_token_usage")
                or {}
            )
            input_tokens = _get(usage, "prompt_tokens") or _get(usage, "promptTokens")
            output_tokens = _get(usage, "completion_tokens") or _get(
                usage, "completionTokens"
            )
            total_tokens = _get(usage, "total_tokens") or _get(usage, "totalTokens")

            prompt = state["prompt"]
            user_text = state["user_text"]
            emit_event(
                config,
                provider=state["provider"],
                model=state["model"],
                operation="langchain.llm",
                source=SOURCE,
                prompt=prompt,
                response=text,
                user_input=user_text,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                latency_ms=(time.time() - state["start_time"]) * 1000,
                compliance=state["compliance"],
                metadata=state.get("metadata"),
                options=self._options or None,
            )
        except Exception:
            pass

    def on_llm_error(self, error: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        try:
            state = self._runs.pop(str(run_id), None)
            if state is None:
                return
            config = try_get_config()
            if config is None:
                return
            prompt = state["prompt"]
            emit_event(
                config,
                provider=state["provider"],
                model=state["model"],
                operation="langchain.llm",
                source=SOURCE,
                prompt=prompt,
                response="",
                success=False,
                error=error,
                latency_ms=(time.time() - state["start_time"]) * 1000,
                compliance=state["compliance"],
                metadata=state.get("metadata"),
                options=self._options or None,
            )
        except Exception:
            pass
