"""Semantic Kernel (SK) integration — a function-invocation filter.

SK routes every kernel-function invocation through its filter chain: a filter
receives a ``FunctionInvocationContext`` and a ``next`` callable, and either
calls ``await next(context)`` to execute the function or short-circuits by NOT
calling ``next``. Not calling ``next`` is the real block — the function never
runs.

``obsvr_function_invocation_filter`` runs the obsvr pipeline BEFORE the function
executes:

- tool allow/deny (``agent_policy``) on the function name,
- built-in PII scan + structured rules + the pre-call hook (HITL) on the
  function arguments.

On a BLOCK the filter sets ``context.result`` to a blocked ``FunctionResult``
and returns WITHOUT calling ``next`` — the kernel function is never invoked.

Usage::

    from semantic_kernel import Kernel
    from obsvr.integrations.semantic_kernel import obsvr_function_invocation_filter
    import obsvr

    obsvr.init(api_key="...", ingest_url="https://...",
               agent_policy={"denied_tools": ["delete_records"]})
    kernel = Kernel()
    kernel.add_filter("function_invocation", obsvr_function_invocation_filter)
"""

# Interception: SK function-invocation filter (non-mutating). Registered through
# kernel.add_filter; a block sets context.result and returns without calling
# next(), so the kernel function never executes.

import json
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from ..config import try_get_config
from ..events import emit_event
from ..policy import apply_pre_call_policy, blocked_prompt_for_storage

try:  # real FunctionResult when SK is installed; a marker is used otherwise
    from semantic_kernel.functions import FunctionResult as _FunctionResult  # type: ignore

    _HAS_SK = True
except Exception:  # pragma: no cover - SK not installed
    _FunctionResult = None  # type: ignore
    _HAS_SK = False

SOURCE = "semantic_kernel"
PROVIDER = "semantic_kernel"


def _check_tool(tool_name: str, policy: Dict[str, Any]) -> Tuple[bool, str]:
    denied = policy.get("denied_tools") or []
    allowed = policy.get("allowed_tools")
    if tool_name in denied:
        return False, "tool_denied"
    if allowed is not None and tool_name not in allowed:
        return False, "tool_not_in_allowlist"
    return True, ""


def _function_name(context: Any) -> str:
    fn = getattr(context, "function", None)
    name = getattr(fn, "name", None)
    if not name and isinstance(fn, dict):
        name = fn.get("name")
    return str(name or "unknown")


def _arguments_dict(context: Any) -> Dict[str, Any]:
    args = getattr(context, "arguments", None)
    if args is None:
        return {}
    if isinstance(args, dict):
        return dict(args)
    try:
        # KernelArguments is a Mapping.
        return {k: args[k] for k in args}  # type: ignore[index]
    except Exception:
        return {}


def _args_prompt(tool_name: str, args: Dict[str, Any]) -> str:
    try:
        return f"{tool_name}({json.dumps(args, default=str)})"
    except Exception:
        return f"{tool_name}(...)"


def _blocked_function_result(context: Any, message: str) -> Any:
    fn = getattr(context, "function", None)
    if _FunctionResult is not None and fn is not None:
        try:
            return _FunctionResult(function=fn, value=message)
        except Exception:  # pragma: no cover - defensive across SK versions
            pass
    return {"obsvr_blocked": True, "value": message}


def _identity_meta(options: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    meta = dict(options.get("metadata") or {})
    if options.get("user_id") is not None:
        meta["user_id"] = options["user_id"]
    if options.get("service_name") is not None:
        meta["service_name"] = options["service_name"]
    return meta or None


async def _govern(context: Any, options: Dict[str, Any]) -> bool:
    """Run the pre-call pipeline. Returns True if BLOCKED (caller must not call
    next); False to proceed. Sets context.result on block."""
    cfg = try_get_config()
    if cfg is None:
        return False
    opts = options or None
    tool_name = _function_name(context)
    policy = getattr(cfg, "agent_policy", None) or {}

    ok, reason = _check_tool(tool_name, policy)
    if not ok:
        emit_event(
            cfg, provider=PROVIDER, model="unknown",
            operation="semantic_kernel.function.policy.tool_blocked", source=SOURCE,
            prompt="", response="", success=False, status_code=403,
            metadata={"function_name": tool_name, "reason": reason}, options=opts,
        )
        try:
            context.result = _blocked_function_result(
                context, f"[obsvr] Function '{tool_name}' blocked by policy: {reason}"
            )
        except Exception:
            pass
        return True

    args = _arguments_dict(context)
    prompt_text = _args_prompt(tool_name, args)
    result = apply_pre_call_policy(
        prompt_text, cfg, provider=PROVIDER, operation="semantic_kernel.function.invoke",
        metadata=_identity_meta(options),
    )
    compliance = result["compliance"]
    if result["decision"] == "block":
        emit_event(
            cfg, provider=PROVIDER, model="unknown", operation="semantic_kernel.function.invoke",
            source=SOURCE,
            prompt=blocked_prompt_for_storage(
                prompt_text, compliance, result.get("security_normalized")
            ),
            response="", success=False, status_code=403, compliance=compliance,
            metadata={"function_name": tool_name}, options=opts,
        )
        try:
            context.result = _blocked_function_result(
                context, f"[obsvr] Function '{tool_name}' invocation blocked by policy"
            )
        except Exception:
            pass
        return True

    emit_event(
        cfg, provider=PROVIDER, model="unknown", operation="semantic_kernel.function.invoke",
        source=SOURCE, prompt=result["redacted_prompt"], response="",
        compliance=compliance, metadata={"function_name": tool_name}, options=opts,
    )
    return False


async def obsvr_function_invocation_filter(
    context: Any, next: Callable[[Any], Awaitable[None]]
) -> None:
    """SK function-invocation filter. Governs the function pre-execution."""
    blocked = await _govern(context, {})
    if blocked:
        return  # do NOT call next -> the kernel function never runs
    await next(context)


def make_function_invocation_filter(
    **options: Any,
) -> Callable[[Any, Callable[[Any], Awaitable[None]]], Awaitable[None]]:
    """Build a function-invocation filter bound to caller-identity ``options``."""

    async def _filter(context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        blocked = await _govern(context, options)
        if blocked:
            return
        await next(context)

    return _filter
