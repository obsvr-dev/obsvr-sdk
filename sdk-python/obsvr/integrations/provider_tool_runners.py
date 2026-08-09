"""Install obsvr's tool gate before a provider runner snapshots its tools.

Provider runners receive a list of local runnable-tool objects and build their
dispatch registry during construction. Wrapping after construction is too late:
the runner already holds the original callbacks. This helper is intentionally
small—the enforcement implementation remains :func:`govern_tool`, so explicit
tool governance and runner-installed governance cannot drift.

Raw tool-definition dictionaries are left unchanged. They describe hosted or
server-side tools and expose no local callback that a client SDK can refuse.
"""

from typing import Any, Iterable, Mapping

from .tools import govern_tool


def govern_runner_tools(
    tools: Iterable[Any], options: Mapping[str, Any] | None = None
) -> list[Any]:
    """Return a new tool list with every local runnable object governed."""
    gate_options = dict(options or {})
    return [
        tool if isinstance(tool, dict) else govern_tool(tool, **gate_options)
        for tool in tools
    ]
