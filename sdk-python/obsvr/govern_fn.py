"""Ergonomic governance for application-owned callables."""

from __future__ import annotations

import time
from typing import Any, Callable, Optional, TypeVar, overload

from .binding_report import record_binding
from .integrations.tools import govern_tool

F = TypeVar("F", bound=Callable[..., Any])
_MAX_TEXT_BYTES = 256
_GOVERNED_FUNCTION_MARKER = "__obsvr_governed_function__"


def _bounded_text(value: Any, field: str, *, required: bool = False) -> Optional[str]:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{field} must be a nonblank string")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise TypeError(f"{field} exceeds {_MAX_TEXT_BYTES} UTF-8 bytes")
    return normalized


def govern_fn(
    fn: F,
    *,
    name: Optional[str] = None,
    surface: str = "action",
    consequence: Optional[str] = None,
    description: Optional[str] = None,
    user_id: Optional[str] = None,
    service_name: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> F:
    """Return a governed callable with the same sync or async shape as ``fn``.

    The implementation reuses :func:`govern_tool`, so block happens before the
    function body and redaction changes the arguments the function receives.
    A retained reference to the original function remains a bypass and is
    recorded as a coverage exclusion.
    """
    if not callable(fn):
        raise TypeError("fn must be callable")
    if getattr(fn, _GOVERNED_FUNCTION_MARKER, False) is True:
        return fn

    resolved_name = _bounded_text(
        name if name is not None else getattr(fn, "__name__", None),
        "name",
        required=True,
    )
    if surface not in {"action", "workflow"}:
        raise TypeError("surface must be action or workflow")
    resolved_consequence = _bounded_text(consequence, "consequence")
    resolved_description = _bounded_text(description, "description")
    action_metadata = {
        "surface": surface,
        "name": resolved_name,
        **(
            {"consequence": resolved_consequence}
            if resolved_consequence is not None
            else {}
        ),
    }
    governed = govern_tool(
        fn,
        name=resolved_name,
        descriptor={
            "name": resolved_name,
            **(
                {"description": resolved_description}
                if resolved_description is not None
                else {}
            ),
        },
        user_id=user_id,
        service_name=service_name,
        metadata={**(metadata or {}), "obsvr_action": action_metadata},
    )
    setattr(governed, _GOVERNED_FUNCTION_MARKER, True)
    record_binding(
        "govern_fn",
        resolved_name,
        metadata={
            "enforcement_depth": "enforce",
            "initialized_at_ms": int(time.time() * 1000),
            "exclusions": ["calls through retained raw function aliases"],
        },
    )
    return governed


@overload
def govern(fn: F, /) -> F: ...


@overload
def govern(
    fn: None = None,
    /,
    **options: Any,
) -> Callable[[F], F]: ...


def govern(fn: Optional[F] = None, /, **options: Any) -> Any:
    """Decorator or direct wrapper form of :func:`govern_fn`."""

    def decorate(target: F) -> F:
        return govern_fn(target, **options)

    return decorate if fn is None else decorate(fn)


__all__ = ["govern", "govern_fn"]
