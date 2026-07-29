"""OpenAI Agents Python SDK integration.

Implements the TracingProcessor interface for the openai-agents Python SDK.
Duck-typed against span/trace objects to avoid version coupling.

REGISTRATION. ``obsvr.init()`` already registers this processor whenever
``agents`` is importable, so the normal setup is init() alone::

    import obsvr
    obsvr.init(api_key="...")

Registering it yourself as well is harmless (the call is recorded once, see
obsvr/dedupe.py) but unnecessary — the pairing used to emit every
event twice. If you opted out with ``obsvr.init(auto=False)``, register it
manually::

    from agents import add_trace_processor
    from obsvr.integrations.openai_agents import ObsvrTracingProcessor

    add_trace_processor(ObsvrTracingProcessor())

The ``add_trace_processor`` function is the standard registration API in
openai-agents. Consult your installed package's documentation if the API
has changed in newer versions.

SPAN COVERAGE. Both LLM span types are handled: ``generation`` (the Chat
Completions path, which carries the configured model alias) and ``response``
(the Responses path, which is the DEFAULT — ``get_use_responses_by_default()``
returns True — and carries only the served snapshot).
"""

# Interception: openai-agents TracingProcessor interface (non-mutating).
# Registered via add_trace_processor() — no SDK internals are mutated.

import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from .. import sender as _sender
from ..agent_policy import apply_loop_detection, create_loop_detector, resolve_loop_detection
from ..config import try_get_config
from ..events import emit_event, tool_denied_compliance
from ..token_usage import read_token_usage
from ..dedupe import claim_emission

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


def _field(obj: Any, *names: str) -> Any:
    """First present attribute or key among ``names``.

    Span payloads arrive as pydantic models on the Responses path and as plain
    dicts elsewhere, so every read here has to work both ways.
    """
    for name in names:
        if isinstance(obj, dict):
            if name in obj:
                return obj[name]
        else:
            value = getattr(obj, name, None)
            if value is not None:
                return value
    return None


def _responses_prompt(raw_input: Any) -> str:
    """Render a Responses-API input list as `role: content` lines."""
    if not isinstance(raw_input, list):
        return _as_text(raw_input)
    lines = []
    for item in raw_input:
        role = _field(item, "role") or "user"
        content = _field(item, "content")
        lines.append(f"{role}: {content if isinstance(content, str) else _as_text(content)}")
    return "\n".join(lines)


def _responses_output_text(output: Any) -> str:
    """Concatenate the text parts of a Responses-API output item list."""
    if not isinstance(output, list):
        return ""
    parts = []
    for item in output:
        content = _field(item, "content")
        if not isinstance(content, list):
            continue
        for block in content:
            text = _field(block, "text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


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
            # init() auto-registers a processor and a caller may register one
            # too; the SDK's list is append-only, so both see every callback.
            # Claiming records the run once.
            if not claim_emission(f"agents.run.start:{trace_id}"):
                return
            self._run_context[trace_id] = {
                "step_count": 0,
                "start_time": time.monotonic(),
            }
            loop_block = resolve_loop_detection(getattr(config, "agent_policy", None))
            if loop_block is not None:
                self._run_context[trace_id]["loop_detector"] = create_loop_detector(loop_block)
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
            if not claim_emission(f"agents.run.finish:{trace_id}"):
                return
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
            span_id = getattr(span, "span_id", None)
            # Claim the span once, keyed on the SDK's own id. With no id to key
            # on, emitting is the right default: a duplicate record is a lesser
            # fault than a dropped one.
            if span_id and not claim_emission(f"agents.span:{trace_id}:{span_id}"):
                return
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
                            compliance=tool_denied_compliance(),
                        )
                        raise RuntimeError(
                            f"[obsvr] Tool blocked by agent policy: {tool_name}"
                        )

                    step_action = _check_steps(step_index, policy)
                    state["step_count"] = step_index + 1

                    # Loop detection
                    detector = state.get("loop_detector")
                    if detector is not None:
                        loop_result = apply_loop_detection(
                            detector,
                            config,
                            agent_run_id=trace_id,
                            source=SOURCE,
                            operation="openai_agents.agent",
                        )
                        if loop_result and loop_result["action"] == "block":
                            raise RuntimeError(
                                "[obsvr] Loop detected: iteration limit exceeded"
                            )

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
                # LLM generation span — the Chat Completions path. This span
                # carries the CONFIGURED model alias, which is the field the
                # event schema wants.
                model: str = str(
                    getattr(span_data, "model", None) or getattr(span, "model", None) or "unknown"
                )
                raw_input = getattr(span_data, "input", None) or getattr(span, "input", None)
                raw_output = getattr(span_data, "output", None) or getattr(span, "output", None)
                usage = read_token_usage(
                    getattr(span_data, "usage", None) or getattr(span, "usage", None)
                )
                emit_event(
                    config,
                    provider="openai",
                    model=model,
                    operation="llm",
                    source=SOURCE,
                    prompt=_as_text(raw_input),
                    response=_as_text(raw_output),
                    input_tokens=usage["input_tokens"],
                    output_tokens=usage["output_tokens"],
                    total_tokens=usage["total_tokens"],
                    metadata={"agent_run_id": trace_id},
                )

            elif stype == "response":
                # LLM call on the RESPONSES path — and this is the default.
                # agents.models._openai_shared.get_use_responses_by_default()
                # returns True, so an ordinary agent run produces `response`
                # spans and no `generation` span at all. Handling only the two
                # branches above meant the default configuration emitted no LLM
                # audit event whatsoever: no prompt, no response, no model, no
                # tokens. The run.start / run.finish and tool-call events still
                # arrived, so the trail looked populated while the model calls
                # themselves — the thing being governed — were absent.
                resp = _field(span_data, "response") or {}
                model = str(_field(resp, "model") or "unknown")
                usage = read_token_usage(
                    _field(resp, "usage") or _field(span_data, "usage")
                )
                emit_event(
                    config,
                    provider="openai",
                    # This is the RESOLVED served snapshot, not the configured
                    # alias. The alias is unrecoverable here: ResponseSpanData
                    # carries only (response, input, usage), the agent span
                    # carries no model, and trace metadata is caller-supplied —
                    # so no span in this path ever holds it. Recorded in `model`
                    # because it is the only model information that exists, with
                    # the substitution stated in metadata rather than left for a
                    # reader to infer from model == model_resolved.
                    model=model,
                    operation="llm",
                    source=SOURCE,
                    prompt=_responses_prompt(_field(span_data, "input")),
                    response=_responses_output_text(_field(resp, "output")),
                    input_tokens=usage["input_tokens"],
                    output_tokens=usage["output_tokens"],
                    total_tokens=usage["total_tokens"],
                    metadata={
                        "agent_run_id": trace_id,
                        "response_id": _field(resp, "id"),
                        "model_alias_unavailable": True,
                    },
                )

        except RuntimeError:
            raise  # policy errors must propagate
        except Exception:
            pass
