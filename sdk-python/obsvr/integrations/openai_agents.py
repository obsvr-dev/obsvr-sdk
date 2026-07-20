"""OpenAI Agents Python SDK integration.

Implements the TracingProcessor interface for the openai-agents Python SDK.
Duck-typed against span/trace objects to avoid version coupling.

Usage::

    from agents import add_trace_processor
    from obsvr.integrations.openai_agents import ObsvrTracingProcessor

    obsvr.init(api_key="...")
    add_trace_processor(ObsvrTracingProcessor())

The ``add_trace_processor`` function is the standard registration API in
openai-agents. Consult your installed package's documentation if the API
has changed in newer versions.
"""

# Interception: openai-agents TracingProcessor interface (non-mutating).
# Registered via add_trace_processor() — no SDK internals are mutated.

import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from .. import sender as _sender
from ..config import try_get_config
from ..events import emit_event

SOURCE = "openai_agents_py"


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


def _as_text(value: Any) -> str:
    """Coerce a span input/output value to a plain string."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value)
    except Exception:
        return str(value)


def _span_type(span: Any) -> str:
    """Extract the span type string, checking both span and span.span_data."""
    span_data = getattr(span, "span_data", span)
    return str(getattr(span_data, "type", None) or getattr(span, "type", None) or "")


class ObsvrTracingProcessor:
    """TracingProcessor for the openai-agents Python SDK.

    Emits audit events for agent run lifecycle, tool calls (function spans),
    and LLM generations. Enforces ``agent_policy`` tool restrictions and step
    limits at function span boundaries.

    Register via::

        from agents import add_trace_processor
        add_trace_processor(ObsvrTracingProcessor())
    """

    def __init__(self) -> None:
        # trace_id -> {step_count: int, start_time: float}
        self._run_context: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Trace-level callbacks
    # ------------------------------------------------------------------

    def on_trace_start(self, trace: Any) -> None:
        """Emit openai_agents.agent.run.start when a trace begins."""
        try:
            config = try_get_config()
            if config is None:
                return
            trace_id: str = str(getattr(trace, "trace_id", None) or uuid.uuid4())
            self._run_context[trace_id] = {
                "step_count": 0,
                "start_time": time.monotonic(),
            }
            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="openai_agents.agent.run.start",
                source=SOURCE,
                prompt="",
                response="",
                metadata={"agent_run_id": trace_id},
            )
        except Exception:
            pass

    def on_trace_end(self, trace: Any) -> None:
        """Emit openai_agents.agent.run.finish when a trace ends."""
        try:
            config = try_get_config()
            if config is None:
                return
            trace_id: str = str(getattr(trace, "trace_id", None) or "")
            state = self._run_context.pop(trace_id, {})
            latency_ms: Optional[int] = None
            if "start_time" in state:
                latency_ms = int((time.monotonic() - state["start_time"]) * 1000)
            emit_event(
                config,
                provider="unknown",
                model="unknown",
                operation="openai_agents.agent.run.finish",
                source=SOURCE,
                prompt="",
                response="",
                latency_ms=latency_ms,
                metadata={"agent_run_id": trace_id},
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Span-level callbacks
    # ------------------------------------------------------------------

    def on_span_start(self, span: Any) -> None:
        """No-op — wait for span end to have complete data."""

    def on_span_end(self, span: Any) -> None:
        """Emit tool-call or LLM-call events when a span completes."""
        try:
            config = try_get_config()
            if config is None:
                return
            if not _sender.should_sample(config.sample_rate):
                return

            span_data = getattr(span, "span_data", span)
            stype = _span_type(span)
            trace_id: str = str(getattr(span, "trace_id", None) or "")
            state = self._run_context.get(trace_id, {})

            if stype == "function":
                # Tool call span
                tool_name: str = str(
                    getattr(span_data, "name", None) or getattr(span, "name", None) or ""
                )
                step_index: int = state.get("step_count", 0)
                policy: Dict[str, Any] = getattr(config, "agent_policy", None) or {}

                if tool_name:
                    ok, reason = _check_tool(tool_name, policy)
                    if not ok:
                        emit_event(
                            config,
                            provider="unknown",
                            model="unknown",
                            operation="openai_agents.agent.policy.tool_blocked",
                            source=SOURCE,
                            prompt="",
                            response="",
                            success=False,
                            metadata={
                                "agent_run_id": trace_id,
                                "tool_name": tool_name,
                                "reason": reason,
                                "step_index": step_index,
                            },
                        )
                        raise RuntimeError(
                            f"[obsvr] Tool blocked by agent policy: {tool_name}"
                        )

                    step_action = _check_steps(step_index, policy)
                    state["step_count"] = step_index + 1

                    if step_action == "block":
                        emit_event(
                            config,
                            provider="unknown",
                            model="unknown",
                            operation="openai_agents.agent.policy.step_limit",
                            source=SOURCE,
                            prompt="",
                            response="",
                            success=False,
                            metadata={
                                "agent_run_id": trace_id,
                                "step_count": step_index,
                                "step_index": step_index,
                            },
                        )
                        raise RuntimeError("[obsvr] Step limit reached")

                    if step_action == "escalate":
                        emit_event(
                            config,
                            provider="unknown",
                            model="unknown",
                            operation="openai_agents.agent.policy.step_limit",
                            source=SOURCE,
                            prompt="",
                            response="",
                            metadata={
                                "agent_run_id": trace_id,
                                "step_count": step_index,
                                "step_index": step_index,
                                "escalated": True,
                            },
                        )
                else:
                    state["step_count"] = step_index + 1

                raw_input = getattr(span_data, "input", None) or getattr(span, "input", None)
                emit_event(
                    config,
                    provider="unknown",
                    model="unknown",
                    operation="openai_agents.tool.call",
                    source=SOURCE,
                    prompt=_as_text(raw_input),
                    response="",
                    metadata={
                        "agent_run_id": trace_id,
                        "tool_name": tool_name,
                        "step_index": step_index,
                    },
                )

            elif stype == "generation":
                # LLM generation span
                model: str = str(
                    getattr(span_data, "model", None) or getattr(span, "model", None) or "unknown"
                )
                raw_input = getattr(span_data, "input", None) or getattr(span, "input", None)
                raw_output = getattr(span_data, "output", None) or getattr(span, "output", None)
                emit_event(
                    config,
                    provider="openai",
                    model=model,
                    operation="llm",
                    source=SOURCE,
                    prompt=_as_text(raw_input),
                    response=_as_text(raw_output),
                    metadata={"agent_run_id": trace_id},
                )

        except RuntimeError:
            raise  # policy errors must propagate
        except Exception:
            pass
