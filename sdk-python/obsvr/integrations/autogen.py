"""AutoGen integration — hook-based audit with real pre-send enforcement.

register_obsvr(agent) registers two ConversableAgent hooks:
  - process_all_messages_before_reply: captures the conversation context
  - process_message_before_send: audits the outgoing reply and CAN
    redact or block it per the configured PII policy (the message has
    not been sent yet, so this is real enforcement).

patch_initiate_chat(agent) wraps agent.initiate_chat to add run-level
tracing (start/finish events) and agent_policy enforcement (tool checks,
step limits, strict PII).
"""

# Interception: AutoGen register_hook() API (non-mutating). Hooks are registered through the framework's official hook system; no agent attributes are mutated.

import threading
import uuid
from typing import Any, Dict, Tuple

from .. import sender as _sender
from ..config import try_get_config
from ..events import blocked_call_error, emit_event
from ..deobfuscate import redact_for_storage, run_configured_pii_scan
from ..policy import (
    apply_pre_call_policy,
    blocked_prompt_for_storage,
    redact_builtin_pii,
)

SOURCE = "autogen"

# Thread-local storage for per-conversation run context (thread-safe).
_run_local = threading.local()


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


# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------


def _message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            return content
    return ""


def _extract_function_name(message: Any) -> Any:
    """Extract function/tool name from a message with tool-call content."""
    if not isinstance(message, dict):
        return None
    # OpenAI function_call format
    fc = message.get("function_call")
    if isinstance(fc, dict):
        name = fc.get("name")
        if isinstance(name, str) and name:
            return name
    # OpenAI tool_calls format
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list) and tool_calls:
        first = tool_calls[0]
        if isinstance(first, dict):
            fn = first.get("function")
            if isinstance(fn, dict):
                name = fn.get("name")
                if isinstance(name, str) and name:
                    return name
    return None


def _model_of(agent: Any) -> str:
    llm_config = getattr(agent, "llm_config", None)
    if isinstance(llm_config, dict):
        model = llm_config.get("model")
        if isinstance(model, str) and model:
            return model
        config_list = llm_config.get("config_list")
        if isinstance(config_list, list) and config_list:
            first = config_list[0]
            if isinstance(first, dict) and isinstance(first.get("model"), str):
                return first["model"]
    return "unknown"


def register_obsvr(agent: Any, **options: Any) -> Any:
    """Register obsvr audit hooks on a ConversableAgent."""
    state: Dict[str, str] = {"context": ""}

    def _before_reply(messages: Any) -> Any:
        try:
            if isinstance(messages, list):
                texts = []
                for msg in messages:
                    text = _message_text(msg)
                    if text:
                        texts.append(text)
                state["context"] = "\n".join(texts)
        except Exception:
            pass
        return messages

    def _before_send(
        sender: Any = None,
        message: Any = None,
        recipient: Any = None,
        silent: Any = None,
        **kwargs: Any,
    ) -> Any:
        config = try_get_config()
        if config is None:
            return message
        try:
            # sampling gates ONLY audit emission, never enforcement —
            # the tool/step/PII agent-policy checks below must run for every
            # message, or a low sample_rate would silently disable the gate.
            should_audit = _sender.should_sample(config.sample_rate)

            # Build base metadata with agent_run_id if inside a traced run
            agent_run_id = getattr(_run_local, "agent_run_id", None)
            meta: Dict[str, Any] = {}
            if agent_run_id:
                meta["agent_run_id"] = agent_run_id

            # Agent policy enforcement
            policy = getattr(config, "agent_policy", None) or {}

            # Check tool calls
            func_name = _extract_function_name(message)
            if func_name is not None:
                ok, reason = _check_tool(func_name, policy)
                if not ok:
                    emit_event(
                        config,
                        provider="unknown",
                        model=_model_of(agent),
                        operation="autogen.agent.policy.tool_blocked",
                        source=SOURCE,
                        prompt="",
                        response="",
                        success=False,
                        metadata={**meta, "tool_name": func_name, "reason": reason},
                        options=options or None,
                    )
                    raise RuntimeError(
                        f"[obsvr] Tool blocked by agent policy: {func_name}"
                    )

                # Only count tool calls toward the step limit
                step_count = getattr(_run_local, "step_count", 0)
                step_action = _check_steps(step_count, policy)
                _run_local.step_count = step_count + 1

                if step_action == "block":
                    emit_event(
                        config,
                        provider="unknown",
                        model=_model_of(agent),
                        operation="autogen.agent.policy.step_limit",
                        source=SOURCE,
                        prompt="",
                        response="",
                        success=False,
                        metadata={**meta, "step_count": step_count},
                        options=options or None,
                    )
                    raise RuntimeError("[obsvr] Step limit reached")

                if step_action == "escalate":
                    emit_event(
                        config,
                        provider="unknown",
                        model=_model_of(agent),
                        operation="autogen.agent.policy.step_limit",
                        source=SOURCE,
                        prompt="",
                        response="",
                        metadata={**meta, "step_count": step_count, "escalated": True},
                        options=options or None,
                    )

            # Strict PII check (when allow_pii_access: False)
            if getattr(_run_local, "strict_pii", False):
                text = _message_text(message)
                if text:
                    scan = run_configured_pii_scan(
                        text, getattr(config, "deobfuscation", None)
                    )
                    if scan["pii_detected"]:
                        strict_meta = {**meta, "detected_types": scan["detected_types"]}
                        if scan.get("via") is not None:
                            # Server-side normalizer mirror: seal which view defeated the
                            # obfuscation on the blocked record.
                            strict_meta["security_normalized"] = scan["via"]
                        emit_event(
                            config,
                            provider="unknown",
                            model=_model_of(agent),
                            operation="autogen.agent.policy.pii_blocked",
                            source=SOURCE,
                            # View-only hit: whole-text placeholder (no span).
                            prompt=redact_for_storage(text, scan.get("via")),
                            response="",
                            success=False,
                            status_code=403,
                            metadata=strict_meta,
                            options=options or None,
                        )
                        raise RuntimeError(
                            "[obsvr] Run blocked: PII detected and allow_pii_access is False"
                        )

            text = _message_text(message)
            # Thread caller identity into the rules context so USER-SCOPED (and
            # service-scoped) quota rules meter the right bucket, not 'default'.
            identity_meta = dict(meta)
            if options.get("user_id"):
                identity_meta["user_id"] = options["user_id"]
            if options.get("service_name"):
                identity_meta["service_name"] = options["service_name"]
            result = apply_pre_call_policy(
                text, config, provider="unknown", operation="autogen.send",
                metadata=identity_meta or None,
            )
            compliance = result["compliance"]

            if result["decision"] == "block":
                emit_event(
                    config,
                    provider="unknown",
                    model=_model_of(agent),
                    operation="autogen.send",
                    source=SOURCE,
                    prompt=blocked_prompt_for_storage(
                        text, compliance, result.get("security_normalized")
                    ),
                    response="",
                    success=False,
                    status_code=403,
                    latency_ms=0,
                    compliance=compliance,
                    metadata=meta if meta else None,
                    options=options or None,
                )
                raise blocked_call_error(compliance)

            if result["decision"] == "redact":
                redacted = redact_builtin_pii(text)
                if isinstance(message, dict):
                    message["content"] = redacted
                elif isinstance(message, str):
                    message = redacted
                text = redacted

            # Governed (blocked/redacted) events always emit; a clean allowed
            # message is emitted only when sampled in.
            if should_audit or compliance.get("action_taken") != "allowed":
                emit_event(
                    config,
                    provider="unknown",
                    model=_model_of(agent),
                    operation="autogen.send",
                    source=SOURCE,
                    prompt=state["context"] or text,
                    response=text,
                    compliance=compliance,
                    metadata=meta if meta else None,
                    options=options or None,
                )
            return message
        except RuntimeError:
            raise  # blocked_call_error and policy errors must propagate
        except Exception:
            return message

    agent.register_hook("process_all_messages_before_reply", _before_reply)
    agent.register_hook("process_message_before_send", _before_send)
    return agent


def patch_initiate_chat(agent: Any, **options: Any) -> None:
    """Wrap agent.initiate_chat to add run-level audit and agent_policy enforcement.

    Patches the bound method on this specific instance only — no class mutation.
    Emits ``autogen.conversation.run.start`` and ``autogen.conversation.run.finish``
    events. Enforces ``allow_pii_access``, step limit, and tool restrictions via
    the shared ``_run_local`` thread-local used by ``_before_send``.

    Usage::

        from obsvr.integrations.autogen import register_obsvr, patch_initiate_chat
        agent = ConversableAgent(...)
        register_obsvr(agent)
        patch_initiate_chat(agent)
        agent.initiate_chat(other_agent, message="Hello")
    """
    original_initiate_chat = agent.initiate_chat

    def _patched_initiate_chat(*args: Any, **kwargs: Any) -> Any:
        config = try_get_config()
        if config is None:
            return original_initiate_chat(*args, **kwargs)

        agent_run_id = str(uuid.uuid4())
        _run_local.agent_run_id = agent_run_id
        _run_local.step_count = 0

        policy = getattr(config, "agent_policy", None) or {}
        _run_local.strict_pii = not policy.get("allow_pii_access", True)

        emit_event(
            config,
            provider="unknown",
            model=_model_of(agent),
            operation="autogen.conversation.run.start",
            source=SOURCE,
            prompt="",
            response="",
            metadata={"agent_run_id": agent_run_id},
            options=options or None,
        )
        try:
            result = original_initiate_chat(*args, **kwargs)
        finally:
            emit_event(
                config,
                provider="unknown",
                model=_model_of(agent),
                operation="autogen.conversation.run.finish",
                source=SOURCE,
                prompt="",
                response="",
                metadata={"agent_run_id": agent_run_id},
                options=options or None,
            )
            # Clear thread-local run context
            _run_local.agent_run_id = None
            _run_local.step_count = 0
            _run_local.strict_pii = False

        return result

    agent.initiate_chat = _patched_initiate_chat
