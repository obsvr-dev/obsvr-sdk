"""AutoGen integration — a pre-send message gate and a pre-execution tool gate.

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

install_tool_gate() gates the OTHER END — the point where a registered function
is actually invoked. See its docstring; the short version is that the send hook
governs the message and this governs the execution, and only the second one is
on every route.

THE SEND HOOK ENFORCES, AND IT IS THE HOOK'S TIMING THAT EARNS THAT. It runs
before the message leaves, so refusing it stops the recipient from ever seeing
the tool call, and the framework wraps the hook loop in no try/except — the
refusal propagates and the delivery never happens. Three conditions on that:

- Register on every agent that can EMIT a tool call, not just the initiator.
  The hook fires on the sender; tool calls come from the assistant. Registering
  on the proxy alone leaves tool policy inert while still emitting a complete
  audit trail. See patch_initiate_chat's docstring.
- Every call in a `tool_calls` array is checked, and the step budget is charged
  per call. Both used to read only `tool_calls[0]`, which made enforcement
  depend on position: a denied tool second in a batch was delivered and run
  with no event and no exception.
- IT GOVERNS THE MESSAGE, SO IT ONLY GOVERNS ROUTES THAT SEND ONE.
  `_process_message_before_send` has exactly two call sites in the framework,
  `send` and `a_send`. A caller that hands a tool-call dict straight to
  `generate_reply`, `receive` or `execute_function` reaches the tool without
  passing either — measured live, denied tool, side effect written. So can an
  agent the caller never constructs: `run()` builds a hidden executor holding
  every callable and no hooks, and group and swarm chats build their own tool
  executors the same way. `install_tool_gate()` exists for that whole class,
  and it is the mechanism to install if you only install one.

A tool call whose name cannot be read is refused rather than skipped.

`max_steps` IS THE ONE CONTROL HERE WITH A SCOPE THIS FRAMEWORK DOES NOT
SUPPLY. It needs a conversation boundary to count against, and only
`patch_initiate_chat` provides one. Registered without it, the limit is not
applied and each affected tool call is recorded `not_evaluated` — see
`patch_initiate_chat`'s docstring for why that is preferred to enforcing an
unscoped counter. The tool allow/deny gate is unaffected and needs no run
scope.
"""

# Interception: AutoGen register_hook() API (non-mutating). Hooks are registered through the framework's official hook system; no agent attributes are mutated.

import threading
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import sender as _sender
from ..agent_policy import check_steps, unrecognized_step_action_meta
from ..config import try_get_config
from ..events import (
    blocked_call_error,
    emit_event,
    step_limit_compliance,
    tool_denied_compliance,
    tool_gate_not_evaluated_compliance,
)
from ..deobfuscate import redact_for_storage, run_configured_pii_scan
from ..policy import (
    apply_pre_call_policy,
    blocked_prompt_for_storage,
    redact_builtin_pii,
)
from .tools import govern_tool

SOURCE = "autogen"

#: Set on the callables :func:`install_tool_gate` puts into a function map, so a
#: map entry is governed once rather than re-wrapped on every dispatch. Without
#: it the gate would add a layer per call and the audit would grow a record per
#: layer.
_GATED_MARKER = "_obsvr_autogen_gated"

#: The three halves this gate needs, probed by attribute presence rather than by
#: version string. Both executors must exist AND the map they read must be
#: reachable; a build carrying the methods without the map would take the
#: install and govern nothing.
_TOOL_GATE_CAPABILITY_ATTRS = ("execute_function", "a_execute_function")

# Thread-local storage for per-conversation run context (thread-safe).
#
# SCOPE OF THE STEP BUDGET. `patch_initiate_chat` is what gives `max_steps` a
# per-conversation scope: it zeroes the counter when a chat starts and holds an
# `agent_run_id` for the duration. A live `agent_run_id` is therefore the one
# observable fact that says a conversation scope exists — nothing else sets it.
#
# Registered WITHOUT that helper there is no conversation boundary for the send
# hook to observe, so the counter would be per thread for the life of the
# process: a later conversation inherits whatever an earlier one spent, and in a
# long-lived process the budget exhausts permanently, after which every tool
# call is refused. `max_steps` is therefore NOT APPLIED when it cannot be
# scoped, and `_step_scope_not_evaluated` records the absence on each affected
# tool call. Use `patch_initiate_chat` whenever `max_steps` is configured.
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


#: Why `max_steps` carries no verdict when the run-level helper is absent. One
#: string so the event, the module docstring and the published grading cannot
#: drift into describing the limit three different ways.
STEP_SCOPE_UNAVAILABLE_REASON = (
    "max_steps needs a conversation scope to count against, and only "
    "patch_initiate_chat supplies one; without it the counter is per thread for "
    "the life of the process, so the limit is recorded rather than applied"
)


def _step_scope_not_evaluated(
    config: Any,
    agent: Any,
    meta: Dict[str, Any],
    policy: Dict[str, Any],
    func_names: list,
    options: Dict[str, Any],
) -> None:
    """Record that `max_steps` was configured and could not be scoped.

    THIS IS THE ABSENCE OF A CONTROL, AND IT IS ON THE RECORD ON PURPOSE. The
    alternative to enforcing an unscoped counter is not silence: a control that
    denies legitimate work gets switched off by whoever is on call, and then
    there is neither the control nor any evidence that it is gone.
    `not_evaluated` keeps the gap visible to the next reader and auditable
    afterwards.

    Deliberately NOT `allowed`, which would assert that a budget was checked and
    had room, and not `blocked`, which would assert a refusal.

    One event per tool call, carrying the same `tool_call_index` /
    `tool_call_count` the enforcing branch carries. The enforcing branch charges
    per call, so recording per message here would make the number of
    `step_limit` events depend on whether the limit was scoped — and the whole
    point of this record is that the two configurations stay comparable.
    """
    for index, func_name in enumerate(func_names):
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
                "max_steps": policy.get("max_steps"),
                "tool_name": func_name,
                "tool_call_index": index,
                "tool_call_count": len(func_names),
                # The scope the counter actually has, named so a reader does not
                # have to infer it from the absence of `agent_run_id`.
                "step_limit_scope": "process_thread",
            },
            compliance=tool_gate_not_evaluated_compliance(
                surface="autogen.agent.policy.step_limit",
                gate="step_limit",
                reason=STEP_SCOPE_UNAVAILABLE_REASON,
            ),
            options=options or None,
        )


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
            #
            # It is charged only inside a conversation scope. `agent_run_id` is
            # set by `patch_initiate_chat` and by nothing else, so its absence
            # means the counter has no boundary to reset against — see the note
            # on `_run_local`. Enforcing it there would refuse tool calls on the
            # strength of a budget an earlier conversation spent, which is a
            # refusal no configured limit asked for.
            if func_names and policy.get("max_steps") is not None and not agent_run_id:
                _step_scope_not_evaluated(
                    config, agent, meta, policy, func_names, options
                )
                func_names_for_step_budget: list = []
            else:
                func_names_for_step_budget = func_names

            for index, func_name in enumerate(func_names_for_step_budget):
                step_count = getattr(_run_local, "step_count", 0)
                step_action, invalid_step_action = check_steps(step_count, policy)
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
                            **unrecognized_step_action_meta(invalid_step_action),
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

    ``patch_initiate_chat`` IS WHAT MAKES ``max_steps`` APPLY AT ALL. It is what
    scopes the budget to one conversation, and the send hook has no other way to
    see a conversation boundary. Registered without it, the limit is **not
    enforced**: each affected tool call is recorded ``not_evaluated`` with the
    reason, rather than charged against a counter that is per thread for the life
    of the process.

    That is a deliberate weakening of an enforcement control, and it is the
    lesser of the two available failures. An unscoped counter is not a step
    limit: a second conversation inherits what the first spent, so in a
    long-lived process the budget exhausts permanently and every tool call after
    that is refused. A control that decays into a blanket denial gets switched
    off by whoever is on call, leaving neither the control nor a record that it
    is gone. Reporting the absence keeps it visible and auditable instead. The
    tool allow/deny gate is unaffected and needs no run scope.
    """
    original_initiate_chat = agent.initiate_chat

    def _patched_initiate_chat(*args: Any, **kwargs: Any) -> Any:
        config = try_get_config()
        if config is None:
            return original_initiate_chat(*args, **kwargs)

        # SAVED AND RESTORED, NOT CLEARED. This used to zero the run context on
        # the way out, so a nested `initiate_chat` on a patched agent handed the
        # OUTER conversation a fresh budget on return — and now that an absent
        # `agent_run_id` means "not enforced", clearing it would also have
        # dropped the outer conversation's limit for the rest of its run. The
        # scope a nested chat suspends is the scope it must give back.
        outer = (
            getattr(_run_local, "agent_run_id", None),
            getattr(_run_local, "step_count", 0),
            getattr(_run_local, "strict_pii", False),
        )

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
            # Hand the enclosing conversation its scope back. At the outermost
            # chat `outer` is the empty state, so this still clears.
            (
                _run_local.agent_run_id,
                _run_local.step_count,
                _run_local.strict_pii,
            ) = outer

        return result

    agent.initiate_chat = _patched_initiate_chat


# ---------------------------------------------------------------------------
# Pre-execution tool gate
# ---------------------------------------------------------------------------


def _conversable_agent_class() -> Any:
    """The class every tool-executing agent on this framework inherits from."""
    try:
        from autogen import ConversableAgent  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised only without ag2
        raise ImportError(
            "[obsvr] install_tool_gate() needs the ag2 distribution "
            "(`pip install \"ag2>=0.3.2,<1.0\"`). ag2 1.0 removed "
            "ConversableAgent and renamed the import package, and the classic "
            "line now also publishes as ag2-classic."
        ) from exc
    return ConversableAgent


def _govern_map_entry(agent: Any, func_name: str) -> Optional[Tuple[Dict[str, Any], str, Any]]:
    """Replace one function-map entry with a governed one. Returns the undo."""
    function_map = getattr(agent, "_function_map", None)
    if not isinstance(function_map, dict):
        return None
    original = function_map.get(func_name)
    if original is None or getattr(original, _GATED_MARKER, False):
        return None
    gated = govern_tool(original, name=func_name)
    if gated is original:
        return None
    try:
        setattr(gated, _GATED_MARKER, True)
    except Exception:
        # A callable that will not carry the marker is still gated; it is only
        # re-wrapped on the next dispatch, which costs a duplicate audit record
        # rather than a missed verdict. Never refuse the gate over bookkeeping.
        pass
    function_map[func_name] = gated
    return (function_map, func_name, original)


def install_tool_gate() -> Callable[[], None]:
    """Gate every registered function at the point AutoGen invokes it.

    Wraps ``ConversableAgent.execute_function`` and ``a_execute_function`` on the
    CLASS, and governs the ``_function_map`` entry the call is about to run —
    with the full pre-call net ``obsvr.govern_tool`` carries: allow/deny,
    ``policy_rules``, the floor, PII, ``on_pre_call``, canary, the session-taint
    destructive gate, and a signed ``tool.call`` event with the sealed
    tool-content digest.

    WHY THE CLASS AND NOT AN INSTANCE. The agent that executes a tool is
    routinely one the caller never constructs and cannot reach to register:
    ``run()`` builds a hidden executor in a background thread and registers
    every callable on it, and group and swarm chats each build their own tool
    executor the same way. Every one of them is a ``ConversableAgent``, so the
    class is the only place a gate reaches all of them. This is process-global
    and deliberate, the same posture as the CrewAI hook gate.

    WHY IT IS THE MECHANISM THAT COVERS THE ROUTES. ``_function_map`` is read
    fresh at call time by both executors at every version in the supported
    range, and every route that runs a registered function goes through one of
    them — including the ones the send hook cannot see, because they never send
    a message: a hand-built ``receive``, a direct ``generate_reply``, a direct
    ``execute_function``, and ``GPTAssistantAgent``, whose tool calls arrive
    inside an OpenAI Assistants run object rather than a chat message.

    REFUSAL IS THE FRAMEWORK'S OWN FAILED-TOOL CONTRACT, not an abort. The gate
    raises ``ObsvrPolicyError`` from inside the callable; ``execute_function``
    catches it, reports ``is_exec_success=False`` and hands the model
    ``Error: [obsvr] ...`` as the tool result, so the conversation continues and
    the tool body was never entered. The send hook answers the same question the
    other way — it raises out of ``send`` and the chat stops — so choose by what
    a denial should do to the run, and note that the ``run()`` family catches
    that raise and demotes it to an ``ErrorEvent`` on the response stream.

    NOT COVERED, stated rather than implied:

    - ``RealtimeAgent``. Its tools live in a separate registry
      (``_registered_realtime_tools``) that no executor reads, and its observer
      awaits the callable directly. Gate those functions with
      ``obsvr.govern_tool`` before registering them.
    - Code execution. ``generate_code_execution_reply`` runs code blocks out of
      message CONTENT, not a ``tool_calls`` array. It is not a tool call, so no
      tool allow/deny list bounds it — govern the executor, not this list.

    Idempotent: a second call returns a handle for the install already in place.
    Returns a handle that restores both class methods and every function-map
    entry this gate replaced. Raises ``ImportError`` LOUDLY on a build missing
    either executor rather than installing a gate that is never consulted.
    """
    conversable = _conversable_agent_class()
    missing = [
        attr
        for attr in _TOOL_GATE_CAPABILITY_ATTRS
        if not callable(getattr(conversable, attr, None))
    ]
    if missing:
        raise ImportError(
            "[obsvr] this ag2 build exposes no tool-execution boundary to "
            f"gate: ConversableAgent carries no {', '.join(missing)}. Refusing "
            "to install a gate that would never be consulted — gate the "
            "functions themselves with obsvr.govern_tool before registering "
            "them."
        )

    existing = getattr(conversable, "_obsvr_tool_gate_detach", None)
    if callable(existing):
        return existing

    undo: List[Tuple[Dict[str, Any], str, Any]] = []
    originals = {
        attr: getattr(conversable, attr) for attr in _TOOL_GATE_CAPABILITY_ATTRS
    }

    def _prepare(agent: Any, func_call: Any) -> None:
        try:
            name = func_call.get("name", "") if isinstance(func_call, dict) else ""
            if not name:
                return
            entry = _govern_map_entry(agent, name)
            if entry is not None:
                undo.append(entry)
        except Exception:
            # Never let bookkeeping break a dispatch. A failure here leaves the
            # call ungoverned by THIS mechanism, which is a coverage gap and not
            # a false record: nothing has claimed to refuse it.
            pass

    sync_original = originals["execute_function"]
    async_original = originals["a_execute_function"]

    def _execute_function(self: Any, func_call: Any, *args: Any, **kwargs: Any) -> Any:
        _prepare(self, func_call)
        return sync_original(self, func_call, *args, **kwargs)

    async def _a_execute_function(
        self: Any, func_call: Any, *args: Any, **kwargs: Any
    ) -> Any:
        _prepare(self, func_call)
        return await async_original(self, func_call, *args, **kwargs)

    conversable.execute_function = _execute_function
    conversable.a_execute_function = _a_execute_function

    removed = False

    def _uninstall() -> None:
        nonlocal removed
        if removed:
            return
        removed = True
        for attr, original in originals.items():
            try:
                setattr(conversable, attr, original)
            except Exception:
                pass
        for function_map, name, original in undo:
            try:
                if getattr(function_map.get(name), _GATED_MARKER, False):
                    function_map[name] = original
            except Exception:
                pass
        undo.clear()
        try:
            delattr(conversable, "_obsvr_tool_gate_detach")
        except Exception:
            pass

    conversable._obsvr_tool_gate_detach = _uninstall
    return _uninstall
