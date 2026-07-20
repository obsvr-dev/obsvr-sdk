"""LangChain (Python) integration — observe-only callback handler.

Pairs on_llm_start/on_chat_model_start with on_llm_end/on_llm_error by
run_id. PII policy applies to the *stored* copy (block is downgraded to
redact-in-event) because the request already went to the LLM.

Agent-level tracing: on_chain_start/end/error track AgentExecutor runs
and enforce agent_policy (tool restrictions, step limits, output controls).
on_agent_action and on_tool_end/error capture individual tool invocations.
"""

# Interception: LangChain Python callback API (non-mutating). Pass ObsvrCallbackHandler() via callbacks=[...] — no LangChain internals are modified.

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .. import sender as _sender
from ..config import try_get_config
from ..events import emit_event, infer_provider_from_string
from ..deobfuscate import redact_for_storage
from ..policy import apply_observe_policy
from ..span import emit_span
from ..span_attributes import SPAN_ATTR

try:  # pragma: no cover - exercised only when langchain-core is installed
    from langchain_core.callbacks import BaseCallbackHandler  # type: ignore
except ImportError:  # shim base class so import never fails

    class BaseCallbackHandler:  # type: ignore
        pass


SOURCE = "langchain_py"


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


def _check_steps(count: int, policy: Dict[str, Any]) -> str:
    """Return 'allow', 'block', or 'escalate' based on step limit."""
    limit = policy.get("max_steps")
    if limit is None:
        return "allow"
    return "allow" if count < limit else policy.get("step_limit_action", "block")


def _is_agent_chain(
    serialized: Any,
    tags: Optional[List[str]],
) -> bool:
    """Return True when this chain event looks like an AgentExecutor run."""
    id_parts = (_get(serialized, "id") or [])
    id_str = ".".join(str(p) for p in id_parts).lower()
    if "agentexecutor" in id_str or "agent" in id_str:
        return True
    if isinstance(tags, list) and "agent" in [str(t).lower() for t in tags]:
        return True
    name = str(_get(serialized, "name") or "").lower()
    if "agent" in name:
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

    # -- agent chain starts / ends -----------------------------------------

    def on_chain_start(
        self,
        serialized: Any,
        inputs: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            if not _is_agent_chain(serialized, tags):
                return
            config = try_get_config()
            if config is None:
                return

            agent_run_id = str(uuid.uuid4())
            self._agent_runs[str(run_id)] = {
                "agent_run_id": agent_run_id,
                "start_time": time.time(),
                "step_count": 0,
            }

            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.agent.run.start",
                source=SOURCE,
                prompt="",
                response="",
                metadata={"agent_run_id": agent_run_id},
                options=self._options or None,
            )
        except Exception:
            pass

    def on_chain_end(
        self,
        outputs: Any,
        *,
        run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            run_state = self._agent_runs.pop(str(run_id), None)
            if run_state is None:
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
            run_state = self._agent_runs.pop(str(run_id), None)
            if run_state is None:
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

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        try:
            config = try_get_config()
            if config is None:
                return

            # Find agent run state from parent_run_id or run_id
            agent_state = self._agent_runs.get(str(parent_run_id)) or \
                          self._agent_runs.get(str(run_id))
            agent_run_id = agent_state["agent_run_id"] if agent_state else ""
            step_index = agent_state["step_count"] if agent_state else 0

            tool_name = str(getattr(action, "tool", None) or "")
            policy = getattr(config, "agent_policy", None) or {}

            # Check tool policy
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
                        options=self._options or None,
                    )
                    raise ValueError(
                        f"[obsvr] Tool blocked by agent policy: {tool_name}"
                    )

            # Check step limit
            count = agent_state["step_count"] if agent_state else 0
            step_action = _check_steps(count, policy)

            if agent_state:
                agent_state["step_count"] = count + 1

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
                    },
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

            tool_input = getattr(action, "tool_input", None)
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

            agent_state = self._agent_runs.get(str(parent_run_id)) or \
                          self._agent_runs.get(str(run_id))
            agent_run_id = agent_state["agent_run_id"] if agent_state else ""

            output_text = str(output) if output is not None else ""
            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="langchain.tool.result",
                source=SOURCE,
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

            agent_state = self._agent_runs.get(str(parent_run_id)) or \
                          self._agent_runs.get(str(run_id))
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
            agent_state = self._agent_runs.get(str(parent_run_id)) or \
                          self._agent_runs.get(str(run_id))
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
        if not _sender.should_sample(config.sample_rate):
            return

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

        observed = apply_observe_policy(prompt, config)

        # Link to parent agent run if available
        parent_agent_run_id = None
        if parent_run_id is not None:
            parent_state = self._agent_runs.get(str(parent_run_id))
            if parent_state:
                parent_agent_run_id = parent_state["agent_run_id"]

        run_meta: Optional[Dict[str, Any]] = None
        if parent_agent_run_id:
            run_meta = {"agent_run_id": parent_agent_run_id}

        self._runs[str(run_id)] = {
            "prompt": prompt,
            "user_text": user_text,
            "model": model,
            "provider": provider,
            "start_time": time.time(),
            "compliance": observed["compliance"],
            "redact": observed["should_redact_stored"],
            # View-only hit: stored copies use a whole-text placeholder.
            "redact_via": observed.get("stored_redaction_via"),
            "agent_run_id": parent_agent_run_id,
            "metadata": run_meta,
        }

    # -- LLM ends ----------------------------------------------------------

    def on_llm_end(self, response: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        try:
            state = self._runs.pop(str(run_id), None)
            if state is None:
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
            if state["redact"]:
                via = state.get("redact_via")
                prompt = redact_for_storage(prompt, via)
                text = redact_for_storage(text, via)
                if user_text is not None:
                    user_text = redact_for_storage(user_text, via)

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
            if state["redact"]:
                prompt = redact_for_storage(prompt, state.get("redact_via"))
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
