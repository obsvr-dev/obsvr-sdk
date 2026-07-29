"""AutoGen integration — hook-based audit with real pre-send enforcement.

TARGETS THE ag2 DISTRIBUTION, not the older one the extra used to name. This
code binds `ConversableAgent.register_hook`, the AutoGen 0.2.x API whose
maintained continuation is ag2. The previously declared distribution now
resolves to the 0.4+ rewrite, whose agent class has neither `register_hook` nor
`initiate_chat` — `register_obsvr()` raises there and nothing is governed.
Supported range is `ag2>=0.3.2,<1.0`; ag2 1.0.0 removed `ConversableAgent` and
renamed the import package. Binding is duck-typed, so an existing install of the
old distribution inside its working range still works.

register_obsvr(agent) registers two ConversableAgent hooks:
  - process_all_messages_before_reply: captures the conversation context
  - process_message_before_send: audits the outgoing reply and CAN
    redact or block it per the configured PII policy (the message has
    not been sent yet, so this is real enforcement).

patch_initiate_chat(agent) wraps agent.initiate_chat to add run-level
tracing (start/finish events) and agent_policy enforcement (tool checks,
step limits, strict PII).

TOOL POLICY ENFORCES HERE, AND IT IS THE HOOK'S TIMING THAT EARNS THAT. The
send hook runs before the message leaves, so refusing it stops the recipient
from ever seeing the tool call. Two conditions on that:

- Register on every agent that can EMIT a tool call, not just the initiator.
  The hook fires on the sender; tool calls come from the assistant. Registering
  on the proxy alone leaves tool policy inert while still emitting a complete
  audit trail. See patch_initiate_chat's docstring.
- Every call in a `tool_calls` array is checked, and the step budget is charged
  per call. Both used to read only `tool_calls[0]`, which made enforcement
  depend on position: a denied tool second in a batch was delivered and run
  with no event and no exception.

A tool call whose name cannot be read is refused rather than skipped.
"""

# Interception: AutoGen register_hook() API (non-mutating). Hooks are registered through the framework's official hook system; no agent attributes are mutated.

import threading
import uuid
from typing import Any, Dict, Tuple

from .. import sender as _sender
from ..config import try_get_config
from ..events import (
    blocked_call_error,
    emit_event,
    step_limit_compliance,
    tool_denied_compliance,
)
from ..deobfuscate import redact_for_storage, run_configured_pii_scan
from ..policy import (
    apply_pre_call_policy,
    blocked_prompt_for_storage,
    redact_builtin_pii,
)

SOURCE = "autogen"

# Thread-local storage for per-conversation run context (thread-safe).
#
# SCOPE OF THE STEP BUDGET, stated because it surprised us. `patch_initiate_chat`
# is what gives `max_steps` a per-conversation scope: it zeroes the counter when
# a chat starts. Registered WITHOUT it, there is no conversation boundary to
# observe, so the counter is per thread for the life of the process and a second
# conversation inherits whatever the first spent. In a long-lived process that
# eventually exhausts the budget permanently, at which point every tool call is
# refused — a control that decays into a blanket denial. Use
# `patch_initiate_chat` whenever `max_steps` is configured.
_run_local = threading.local()


def _reset_run_state() -> None:
    """Test seam: forget the thread's run context.

    Without this the step counter outlives config resets, so one test's spent
    budget silently became the next one's starting point.
    """
    _run_local.agent_run_id = None
    _run_local.step_count = 0
    _run_local.strict_pii = False


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


def _extract_function_names(message: Any) -> Tuple[list, int]:
    """Every tool this message asks for, plus a count of unreadable requests.

    READS ALL OF ``tool_calls``, NOT JUST THE FIRST. Reading only
    ``tool_calls[0]`` made enforcement depend on position: with
    ``denied_tools: ["send_money"]``, a message carrying
    ``[get_weather, send_money]`` was checked as ``get_weather``, delivered, and
    the recipient then executed ``send_money`` — no event, no exception. The
    same defect handed ``max_steps`` a free evasion, because one message cost
    one step no matter how many calls it carried.

    The second return value is how many entries carried a capability request
    this function could NOT resolve to a name. Those cannot be checked, and an
    uncheckable request is refused rather than waved through — a gate that
    silently ignores what it cannot parse is not a gate.
    """
    if not isinstance(message, dict):
        return [], 0

    names = []
    unreadable = 0

    # OpenAI function_call format (single, legacy).
    fc = message.get("function_call")
    if isinstance(fc, dict):
        name = fc.get("name")
        if isinstance(name, str) and name:
            names.append(name)
        else:
            unreadable += 1

    # OpenAI tool_calls format (a list, and it may hold more than one).
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for call in tool_calls:
            fn = call.get("function") if isinstance(call, dict) else None
            name = fn.get("name") if isinstance(fn, dict) else None
            if isinstance(name, str) and name:
                names.append(name)
            else:
                unreadable += 1

    return names, unreadable


def _cfg_get(cfg: Any, key: str) -> Any:
    """Read `key` off a mapping OR an object, without caring which it is.

    llm_config used to be a plain dict and is an LLMConfig object on every
    modern release. Duck-typed rather than isinstance-checked against the
    framework's class: importing it to type-check would turn a soft dependency
    into a hard one, and the attribute is what this code actually needs.
    """
    if cfg is None:
        return None
    if isinstance(cfg, dict):
        return cfg.get(key)
    try:
        return getattr(cfg, key, None)
    except Exception:  # pragma: no cover - exotic __getattr__
        return None


def _model_of(agent: Any) -> str:
    """The configured model name, or "unknown".

    WAS DICT-ONLY, AND SILENTLY WRONG. This read llm_config only when it was a
    dict, so once the framework introduced the LLMConfig object the test was
    False and every event on every modern release recorded model "unknown" — on
    an agent whose own config names the model. Governance was unaffected; the
    evidence was degraded exactly where the supported range is newest, which is
    the failure shape that looks like nothing at all.
    """
    llm_config = getattr(agent, "llm_config", None)
    if llm_config is None:
        return "unknown"

    model = _cfg_get(llm_config, "model")
    if isinstance(model, str) and model:
        return model

    config_list = _cfg_get(llm_config, "config_list")
    if isinstance(config_list, (list, tuple)) and config_list:
        first_model = _cfg_get(config_list[0], "model")
        if isinstance(first_model, str) and first_model:
            return first_model
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

            # Check tool calls. EVERY call in the message, in order — the
            # message is delivered whole, so one denied name anywhere in it
            # means the whole message must be refused.
            func_names, unreadable = _extract_function_names(message)

            if unreadable:
                emit_event(
                    config,
                    provider="unknown",
                    model=_model_of(agent),
                    operation="autogen.agent.policy.tool_blocked",
                    source=SOURCE,
                    prompt="",
                    response="",
                    success=False,
                    metadata={
                        **meta,
                        "reason": "tool_name_unreadable",
                        "unreadable_tool_calls": unreadable,
                    },
                    compliance=tool_denied_compliance(),
                    options=options or None,
                )
                raise RuntimeError(
                    f"[obsvr] Tool blocked by agent policy: {unreadable} tool "
                    f"call(s) carried no readable name and cannot be checked"
                )

            for index, func_name in enumerate(func_names):
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
                        metadata={
                            **meta,
                            "tool_name": func_name,
                            "reason": reason,
                            # Which call in the batch, and how many there were.
                            # Position is what used to decide whether the gate
                            # saw a name at all.
                            "tool_call_index": index,
                            "tool_call_count": len(func_names),
                        },
                        compliance=tool_denied_compliance(),
                        options=options or None,
                    )
                    raise RuntimeError(
                        f"[obsvr] Tool blocked by agent policy: {func_name}"
                    )

            # The step budget is charged PER CALL, not per message. Charging per
            # message let a batch of N calls cost one step, which made the limit
            # trivially evadable by the same batching that defeated the gate.
            for index, func_name in enumerate(func_names):
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
                        metadata={
                            **meta,
                            "step_count": step_count,
                            "tool_name": func_name,
                            "tool_call_index": index,
                            "tool_call_count": len(func_names),
                        },
                        compliance=step_limit_compliance(),
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
                        metadata={
                            **meta,
                            "step_count": step_count,
                            "escalated": True,
                            "tool_name": func_name,
                            "tool_call_index": index,
                        },
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

    REGISTER ON EVERY AGENT THAT CAN EMIT A TOOL CALL. The send hook fires on
    the agent doing the sending, and tool calls come from the assistant, not
    from the proxy that starts the conversation. The example here used to
    register on the initiator alone, which left tool policy inert while still
    producing a full, plausible audit trail — the configuration most likely to
    be copied was the one that governed nothing.

    Usage::

        from obsvr.integrations.autogen import register_obsvr, patch_initiate_chat

        assistant = ConversableAgent(...)   # emits the tool calls
        proxy = ConversableAgent(...)       # starts the conversation

        register_obsvr(assistant)           # REQUIRED for tool policy
        register_obsvr(proxy)               # audits the proxy's own messages
        patch_initiate_chat(proxy)          # run scope + per-chat step budget

        proxy.initiate_chat(assistant, message="Hello")

    ``patch_initiate_chat`` is what resets the step budget at each chat. Without
    it the counter is per thread for the life of the process, so a second
    conversation inherits whatever the first spent.
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
