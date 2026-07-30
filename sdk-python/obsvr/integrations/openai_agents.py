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

THIS INTEGRATION RECORDS TOOL POLICY; IT DOES NOT ENFORCE IT. Read this before
configuring ``agent_policy`` against it.

A TracingProcessor cannot refuse anything. The provider's tracing layer invokes
every processor callback inside its own ``try/except Exception`` and only logs
what it catches, so an exception raised from ``on_span_start`` or
``on_span_end`` never reaches the agent run. On top of that, the tool gate here
lives in ``on_span_end`` — a function span ENDS after its tool has returned, so
by the time the gate sees the call there is nothing left to prevent.

Both halves were measured, not inferred: a spy tool recorded that it had
already been entered when the gate ran, and the swallowing is visible in the
installed package's own tracing provider.

So ``denied_tools``, ``allowed_tools`` and ``max_steps`` are OBSERVED on this
surface. When one of them would have refused a call, the event says
``action_taken: "not_evaluated"`` and carries the reason in
``metadata.obsvr_telemetry.policy_not_evaluated``. It previously said
``blocked``, which asserted a refusal of a call that had in fact completed and
returned its result to the caller.

For tool policy that actually refuses, gate at a boundary that can: the
framework's own tool hooks are awaited before the tool is invoked and their
exceptions are NOT swallowed, and the MCP integration is the reference
implementation of a gate at the invocation boundary.
"""

# Interception: openai-agents TracingProcessor interface (non-mutating).
# Registered via add_trace_processor() — no SDK internals are mutated.

import json
import time
import uuid
from typing import Any, Dict, Optional, Tuple

from .. import sender as _sender
from ..agent_policy import (
    apply_loop_detection,
    check_steps,
    create_loop_detector,
    resolve_loop_detection,
    unrecognized_step_action_meta,
)
from ..config import try_get_config
from ..deobfuscate import redact_for_storage
from ..events import emit_event, tool_gate_not_evaluated_compliance
from ..policy import apply_observe_policy
from ..token_usage import read_token_usage
from ..dedupe import claim_emission

SOURCE = "openai_agents_py"


def _govern_stored(
    prompt_text: str, response_text: str, config: Any
) -> Tuple[str, str, Optional[Dict[str, Any]]]:
    """Run the observe-only PII net over what an event is about to STORE.

    This integration is a ``TracingProcessor`` and cannot refuse anything — the
    framework wraps every processor callback in its own ``try``/``except`` and
    only logs — so this is emphatically NOT enforcement and the returned
    compliance says so: ``redacted``, never ``blocked``. The call has already
    happened by the time a span ends.

    What it does stop is raw PII coming to rest in a signed event. Every other
    observe-only integration on this side has run this net for as long as it has
    existed; this one ran no policy pipeline of any kind, so at any sample rate
    it wrote whatever the agent said straight into the chain. The canary half
    was already covered — that net lives in ``events.build_audit_event`` and
    fires on every path — so the gap was the PII half alone.

    Twin posture: ``langchain.py`` and ``llamaindex.py``, deliberately, because
    a third spelling of the same decision is how two of them drift.
    """
    joined = "\n".join(t for t in (prompt_text, response_text) if t)
    if not joined:
        return prompt_text, response_text, None
    observed = apply_observe_policy(joined, config)
    compliance = observed.get("compliance")
    if not observed.get("should_redact_stored"):
        return prompt_text, response_text, compliance
    via = observed.get("stored_redaction_via")
    return (
        redact_for_storage(prompt_text, via) if prompt_text else prompt_text,
        redact_for_storage(response_text, via) if response_text else response_text,
        compliance,
    )


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    """Return (allowed, reason). reason is empty string when allowed."""
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")  # None = all allowed
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


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
            # Sampling gates the EMISSION of clean span records, never the tool
            # gate or the step limit. Returning here skipped _check_tool and
            # check_steps below, so a sub-1.0 sample_rate silently disabled the
            # agent policy on a fraction of traffic. Carry the decision to the
            # emit sites; the policy events below are enforcement evidence and
            # are emitted regardless, as wrap.py ``_emit_audit`` already does.
            should_audit = _sender.should_sample(config.sample_rate)

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
                            operation="openai_agents.agent.policy.tool_not_evaluated",
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
                            compliance=tool_gate_not_evaluated_compliance(
                                surface="openai_agents.tool.call",
                                gate="tool_gate",
                                reason=(
                                    f"tool policy would have refused this call "
                                    f"({reason}), but the decision is reached "
                                    f"after the tool has already returned and "
                                    f"cannot bind it"
                                ),
                            ),
                        )

                    step_action, invalid_step_action = check_steps(step_index, policy)
                    state["step_count"] = step_index + 1

                    # Loop detection. can_halt=False: see the module docstring —
                    # raising from a trace processor cannot stop this run, so the
                    # finding is recorded without claiming the halt happened.
                    detector = state.get("loop_detector")
                    if detector is not None:
                        apply_loop_detection(
                            detector,
                            config,
                            agent_run_id=trace_id,
                            source=SOURCE,
                            operation="openai_agents.agent",
                            can_halt=False,
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
                                **unrecognized_step_action_meta(invalid_step_action),
                            },
                            compliance=tool_gate_not_evaluated_compliance(
                                surface="openai_agents.agent.policy.step_limit",
                                gate="step_limit",
                                reason=(
                                    "the step budget is exhausted but this "
                                    "surface cannot halt the run; the limit is "
                                    "observed, not enforced"
                                ),
                            ),
                        )

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
                if should_audit:
                    _p, _r, _c = _govern_stored(_as_text(raw_input), "", config)
                    emit_event(
                        config,
                        provider="unknown",
                        model="unknown",
                        operation="openai_agents.tool.call",
                        source=SOURCE,
                        prompt=_p,
                        response=_r,
                        compliance=_c,
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
                if should_audit:
                    _p, _r, _c = _govern_stored(
                        _as_text(raw_input), _as_text(raw_output), config
                    )
                    emit_event(
                        config,
                        provider="openai",
                        model=model,
                        operation="llm",
                        source=SOURCE,
                        prompt=_p,
                        response=_r,
                        compliance=_c,
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
                if should_audit:
                    _resp_p, _resp_r, _resp_c = _govern_stored(
                        _responses_prompt(_field(span_data, "input")),
                        _responses_output_text(_field(resp, "output")),
                        config,
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
                        prompt=_resp_p,
                        response=_resp_r,
                        compliance=_resp_c,
                        input_tokens=usage["input_tokens"],
                        output_tokens=usage["output_tokens"],
                        total_tokens=usage["total_tokens"],
                        metadata={
                            "agent_run_id": trace_id,
                            "response_id": _field(resp, "id"),
                            "model_alias_unavailable": True,
                        },
                    )

        except Exception:
            # Nothing raised from here reaches the caller: the provider's
            # tracing layer wraps every processor callback in its own
            # try/except and logs. A `raise` used to sit above this to "let
            # policy errors propagate", which is precisely the belief that
            # produced a record claiming a refusal that never occurred.
            pass
