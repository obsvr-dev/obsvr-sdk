"""Haystack 2.x / 3.x integration — a prompt guard and an agent tool gate.

Two independent mechanisms, and they govern different things:

- ``ObsvrGuard`` is a pipeline ``@component`` that governs the PROMPT flowing
  through it (PII scan, structured rules, the pre-call hook / HITL).
- ``install_tool_gate_hook`` / ``ObsvrToolGateHook`` is a Haystack ``before_tool``
  hook that governs which TOOLS an ``Agent`` may call. It is registered as
  ``Agent(hooks={"before_tool": [...]})`` and the Agent runs it before it
  resolves the pending tool calls, so a refusal lands before any tool is
  dispatched — before the executor that would otherwise run the batch in
  parallel, which is why refusing one call cannot race a sibling.

The hook rules on the tool CALL rather than on a tool object, which is what
makes it total on this framework: an Agent can be handed tools at construction,
handed a different list per ``run(tools=...)``, hand them to a ``Toolset`` that
spawns per run, or rebuild them entirely through a ``to_dict``/``from_dict``
round-trip, and every one of those routes still arrives as a named call in the
Agent's own state. Allow/deny only; ``obsvr.govern_tool`` carries the rest of
the pre-call net (PII, floor, canary, the destructive-capability gate) and
raises instead, so the two answer abort-vs-deny differently on purpose.

``ObsvrGuard`` is a real Haystack ``@component``: drop it into a Pipeline ahead
of your Generator and wire its ``prompt`` output into the Generator's text
input. On every run it applies the obsvr pre-call pipeline (built-in PII scan,
structured rules, the pre-call hook / HITL) to the prompt flowing through it:

- BLOCK  -> ``run`` raises. A raising component aborts ``pipeline.run()``, so
            the downstream Generator never executes — a real, enforceable stop.
- REDACT -> the redacted prompt is emitted downstream (the Generator sees the
            governed text, never the raw PII).
- ALLOW  -> the prompt passes through unchanged.

All three were driven against a real Pipeline and a real Generator on both ends
of the supported range, graded on the bytes the provider received rather than
on the return value: blocked reaches the provider zero times while an allowed
run through the same pipeline reaches it once, and a redacted run puts the
scrubbed text on the wire while the same prompt under no policy puts the raw
value there.

The guard itself is version-independent; only the Generator you put behind it
differs, because Haystack 3.0 removed the text ``OpenAIGenerator`` and its
``prompt`` socket. Both forms::

    from haystack import Pipeline
    from obsvr.integrations.haystack import ObsvrGuard
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               pii_policy={"rules": {"ssn": "block"}})
    pipe = Pipeline()
    pipe.add_component("guard", ObsvrGuard())

    # haystack-ai 2.x
    from haystack.components.generators import OpenAIGenerator
    pipe.add_component("llm", OpenAIGenerator())
    pipe.connect("guard.prompt", "llm.prompt")

    # haystack-ai 3.x — no text generator ships any more; the chat generator's
    # `messages` socket accepts a bare str, so the same wire still type-checks
    from haystack.components.generators.chat import OpenAIChatGenerator
    pipe.add_component("llm", OpenAIChatGenerator())
    pipe.connect("guard.prompt", "llm.messages")

    pipe.run({"guard": {"prompt": "..."}})
"""

# Interception: Haystack 2.x @component node (non-mutating). Placed in the
# pipeline graph; a policy block raises out of run(), aborting the pipeline
# before the downstream generator runs.

from typing import Any, Dict, Optional, Tuple

from ..config import try_get_config
from ..binding_report import record_binding
from ..errors import ObsvrPolicyError
from ..events import emit_event, tool_denied_compliance
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage

SOURCE = "haystack_py"
PROVIDER = "haystack"

try:  # real Haystack component registration when installed
    from haystack import component as _component  # type: ignore

    _HAS_HAYSTACK = True
    record_binding("haystack", "haystack.component")
except Exception as _exc:  # pragma: no cover - Haystack not installed
    _HAS_HAYSTACK = False
    record_binding("haystack", "haystack.component", _exc)

    class _ComponentShim:
        """Duck-types haystack.component enough to define the class + run I/O."""

        def __call__(self, cls: Any) -> Any:
            return cls

        def output_types(self, **_kw: Any):
            def _deco(fn: Any) -> Any:
                return fn

            return _deco

    _component = _ComponentShim()  # type: ignore


class ObsvrHaystackBlocked(RuntimeError):
    """Raised inside run() when the prompt is blocked by policy; aborts the pipeline."""


@_component
class ObsvrGuard:
    """Policy-enforcing Haystack component. Governs the prompt passing through.

    ``options`` may carry ``user_id`` / ``service_name`` / ``metadata``.
    """

    def __init__(self, **options: Any) -> None:
        self._options: Dict[str, Any] = options

    def _identity_meta(self) -> Optional[Dict[str, Any]]:
        opts = self._options or {}
        meta = dict(opts.get("metadata") or {})
        if opts.get("user_id") is not None:
            meta["user_id"] = opts["user_id"]
        if opts.get("service_name") is not None:
            meta["service_name"] = opts["service_name"]
        return meta or None

    @_component.output_types(prompt=str, blocked=bool, redacted=bool)
    def run(self, prompt: str) -> Dict[str, Any]:
        cfg = try_get_config()
        if cfg is None:
            return {"prompt": prompt, "blocked": False, "redacted": False}

        opts = self._options or None
        result = apply_pre_call_policy(
            prompt, cfg, provider=PROVIDER, operation="haystack.pipeline.run",
            metadata=self._identity_meta(),
        )
        compliance = result["compliance"]

        if result["decision"] == "block":
            emit_event(
                cfg, provider=PROVIDER, model="unknown", operation="haystack.pipeline.run",
                source=SOURCE,
                prompt=blocked_prompt_for_storage(
                    prompt, compliance, result.get("security_normalized")
                ),
                response="", success=False, status_code=403, compliance=compliance,
                options=opts,
            )
            raise ObsvrHaystackBlocked("[obsvr] Prompt blocked by policy")

        out_prompt = prompt
        redacted = False
        if result["decision"] == "redact":
            out_prompt = result["redacted_prompt"]
            redacted = True

        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="haystack.pipeline.run",
            source=SOURCE, prompt=out_prompt, response="", compliance=compliance,
            options=opts,
        )
        return {"prompt": out_prompt, "blocked": False, "redacted": redacted}


# ---------------------------------------------------------------------------
# Catching a block through a Pipeline
# ---------------------------------------------------------------------------


def is_obsvr_block(error: BaseException) -> bool:
    """Whether this exception is (or was caused by) an obsvr policy refusal.

    Worth having because ``except ObsvrHaystackBlocked`` around ``pipeline.run()``
    catches nothing on haystack-ai 3.x: a component's exception is re-raised as
    ``PipelineRuntimeError`` with the original demoted to ``__cause__``, and an
    async pipeline wraps a second time. The refusal is still there and the run
    still stopped; only the type a caller sees at the top changed. Driving the
    Agent directly instead of through a Pipeline raises the obsvr error
    unwrapped, so callers who want one branch for both shapes want this.
    """
    seen = 0
    current: Optional[BaseException] = error
    while current is not None and seen < 16:
        if isinstance(current, (ObsvrHaystackBlocked, ObsvrPolicyError)):
            return True
        current = current.__cause__ or current.__context__
        seen += 1
    return False


# ---------------------------------------------------------------------------
# Agent tool gate — a before_tool hook
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


def _hook_dispatch_present() -> bool:
    """Whether this build's Agent actually CONSULTS before_tool hooks.

    Registration alone is not the capability. A hook accepted by a build whose
    run loop never asks about it is a gate the caller believes in and does not
    have, so both halves are probed by attribute presence rather than by
    comparing version strings, which forks and vendored builds get wrong.
    """
    try:
        from haystack.hooks.protocol import BEFORE_TOOL  # type: ignore # noqa: F401
        from haystack.hooks.invocation import _run_hooks  # type: ignore
        from haystack.components.agents.agent import Agent  # type: ignore
    except Exception as exc:
        # The probe's verdict goes back to the caller; the bind outcome ALSO
        # lands on the report, so "this build has no hook dispatch" is
        # programmatically visible and not only a returned False.
        record_binding("haystack", "haystack.hooks.protocol", exc)
        return False
    record_binding("haystack", "haystack.hooks.protocol")
    if not callable(_run_hooks):
        return False
    try:
        import inspect

        return "hooks" in inspect.signature(Agent.__init__).parameters
    except Exception:
        return False


class ObsvrToolGateHook:
    """Haystack ``before_tool`` hook that refuses tools ``agent_policy`` denies.

    Refusal follows the framework's own contract for this hook point rather than
    raising: the denied call is taken out of the pending tool-call message and
    answered with an error tool result, which is what the Agent re-reads after
    hooks run, so the tool is never dispatched and the run continues with the
    model told why. Sibling calls in the same batch that the policy allows are
    left in place. Pass ``on_denial="abort"`` to raise
    ``ObsvrHaystackBlocked`` instead, which the Agent does not catch.
    """

    #: The Agent refuses a hook registered at a point it does not support.
    allowed_hook_points = ("before_tool",)

    def __init__(self, on_denial: str = "deny", **options: Any) -> None:
        if on_denial not in ("deny", "abort"):
            raise ValueError(
                "[obsvr] on_denial must be 'deny' (answer the model and continue) "
                "or 'abort' (raise out of the run)"
            )
        self._on_denial = on_denial
        self._options: Dict[str, Any] = options

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "obsvr.integrations.haystack.ObsvrToolGateHook",
            "init_parameters": {"on_denial": self._on_denial, **self._options},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObsvrToolGateHook":
        return cls(**(data.get("init_parameters") or {}))

    # -- the gate -----------------------------------------------------------

    def run(self, state: Any) -> None:
        cfg = try_get_config()
        if cfg is None:
            return
        policy = getattr(cfg, "agent_policy", None) or {}
        if not policy.get("denied_tools") and policy.get("allowed_tools") is None:
            return

        messages = list((getattr(state, "data", None) or {}).get("messages") or [])
        if not messages:
            return
        last = messages[-1]
        calls = list(getattr(last, "tool_calls", None) or [])
        if not calls:
            return

        allowed_calls = []
        refusals = []
        for call in calls:
            tool_name = str(getattr(call, "tool_name", "") or "")
            ok, reason = _check_tool(tool_name, policy) if tool_name else (True, "")
            if ok:
                allowed_calls.append(call)
                continue
            refusals.append((call, tool_name, reason))
            emit_event(
                cfg, provider=PROVIDER, model="unknown",
                operation="haystack.agent.policy.tool_blocked",
                source=SOURCE, prompt="", response="", success=False,
                metadata={"tool_name": tool_name, "reason": reason},
                compliance=tool_denied_compliance(),
                options=self._options or None,
            )

        if not refusals:
            return
        if self._on_denial == "abort":
            names = ", ".join(name for _, name, _ in refusals)
            raise ObsvrHaystackBlocked(
                f"[obsvr] Tool blocked by agent policy: {names}"
            )
        self._rewrite(state, messages, last, allowed_calls, refusals)

    async def run_async(self, state: Any) -> None:
        # The Agent offloads a sync-only hook to a thread, so this exists for
        # directness rather than necessity; the verdict is identical either way.
        self.run(state)

    @staticmethod
    def _rewrite(state, messages, last, allowed_calls, refusals) -> None:
        """Answer each denied call and leave the allowed ones pending.

        The Agent inspects only the LAST message after hooks run, so the message
        carrying the surviving calls has to end up there; when every call was
        refused, the tail is a tool result and the step dispatches nothing.
        """
        from haystack.dataclasses import ChatMessage  # type: ignore
        from haystack.components.agents.state.state_utils import (  # type: ignore
            replace_values,
        )

        def assistant_with(calls):
            return ChatMessage.from_assistant(
                text=getattr(last, "text", None),
                meta=getattr(last, "meta", None),
                name=getattr(last, "name", None),
                tool_calls=calls,
            )

        tail = []
        for call, tool_name, reason in refusals:
            tail.append(assistant_with([call]))
            tail.append(
                ChatMessage.from_tool(
                    tool_result=(
                        f"[obsvr] Tool blocked by agent policy: {tool_name} "
                        f"({reason}). Do not retry it; answer without it."
                    ),
                    origin=call,
                    error=True,
                )
            )
        if allowed_calls:
            tail.append(assistant_with(allowed_calls))
        state.set("messages", messages[:-1] + tail, handler_override=replace_values)


def install_tool_gate_hook(**options: Any) -> ObsvrToolGateHook:
    """Build the ``before_tool`` gate, refusing loudly where it cannot bind.

    Register it with ``Agent(hooks={"before_tool": [install_tool_gate_hook()]})``.
    """
    if not _hook_dispatch_present():
        raise ImportError(
            "[obsvr] this Haystack build has no before_tool hook point, so the "
            "pre-execution tool gate cannot install. Gate the tools themselves "
            "instead: obsvr.govern_tool"
        )
    return ObsvrToolGateHook(**options)
