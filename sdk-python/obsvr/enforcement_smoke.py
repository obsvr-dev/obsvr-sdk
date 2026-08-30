"""Runtime smoke checks for caller-owned governed factories."""

import inspect
from typing import Any, Awaitable, Callable, Dict


def _validate(name: str, invoke_blocked_call: Callable, transport_calls: Callable) -> str:
    if not isinstance(name, str) or not name.strip():
        raise TypeError("enforcement smoke name must be nonblank")
    if not callable(invoke_blocked_call) or not callable(transport_calls):
        raise TypeError("enforcement smoke requires invoke_blocked_call and transport_calls")
    return name.strip()


def _result(name: str, blocked: bool, before: int, after: int) -> Dict[str, Any]:
    if after != before:
        raise RuntimeError(
            f"{name} enforcement smoke reached downstream transport ({after - before} call(s))"
        )
    if not blocked:
        raise RuntimeError(f"{name} enforcement smoke did not reject the deny case")
    return {"name": name, "blocked": True, "transport_calls": 0}


def assert_enforcement_boundary(
    name: str, invoke_blocked_call: Callable[[], Any], transport_calls: Callable[[], int]
) -> Dict[str, Any]:
    """Require one synchronous deny case to reject before downstream transport."""
    normalized = _validate(name, invoke_blocked_call, transport_calls)
    before = transport_calls()
    blocked = False
    try:
        value = invoke_blocked_call()
    except Exception:
        blocked = True
    else:
        if inspect.isawaitable(value):
            if inspect.iscoroutine(value):
                value.close()
            raise TypeError("use assert_enforcement_boundary_async for an async call")
    return _result(normalized, blocked, before, transport_calls())


async def assert_enforcement_boundary_async(
    name: str,
    invoke_blocked_call: Callable[[], Awaitable[Any]],
    transport_calls: Callable[[], int],
) -> Dict[str, Any]:
    """Require one asynchronous deny case to reject before downstream transport."""
    normalized = _validate(name, invoke_blocked_call, transport_calls)
    before = transport_calls()
    blocked = False
    try:
        await invoke_blocked_call()
    except Exception:
        blocked = True
    return _result(normalized, blocked, before, transport_calls())
