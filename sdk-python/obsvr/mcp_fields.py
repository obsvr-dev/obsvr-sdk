"""Descriptor field reads that survive the MCP protocol's two spellings.

An MCP tool descriptor carries the same field under two names depending on
which major of the ``mcp`` package produced it. Through 1.x the Python models
declared the wire spelling directly, so ``tool.inputSchema`` was the attribute.
2.0 moved the protocol types onto a snake_case base with
``alias_generator=to_camel``: the wire is unchanged (``inputSchema`` is still
what crosses the socket) but the attribute is now ``tool.input_schema``. The
same move renamed ``nextCursor`` and ``annotations.destructiveHint``.

A ``getattr`` for one spelling reads as ABSENT rather than raising against the
other, which is the dangerous shape: a descriptor scan finds no schema to scan,
a descriptor hash commits to a document with the schema missing from it, and a
capability gate finds no hint to gate on. Each control goes quiet while
reporting success.

Reading both spellings is therefore not a version shim to be removed once 1.x
is dropped — it is how this SDK reads a descriptor, and it holds for a fork, a
backport or a vendored build whose version string says nothing useful. One
definition, imported by every reader: the alternative is the same fix applied
to three of the four places that need it.
"""

from typing import Any, Optional

__all__ = ["snake_of", "descriptor_field"]


def snake_of(name: str) -> str:
    """``inputSchema`` -> ``input_schema``. Already-snake names pass through."""
    out = []
    for ch in name:
        if ch.isupper():
            out.append("_")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def descriptor_field(tool: Any, name: str, default: Optional[Any] = None) -> Any:
    """Read ``name`` off a tool descriptor under either protocol spelling.

    Accepts an attribute-style model (what the ``mcp`` package hands back) or a
    plain dict, and tries the given name before its snake_case twin. The first
    spelling that yields a non-``None`` value wins, so a descriptor carrying the
    field under the expected name reads exactly as it did before.
    """
    if tool is None:
        return default
    spellings = [name]
    twin = snake_of(name)
    if twin != name:
        spellings.append(twin)
    for spelling in spellings:
        if isinstance(tool, dict):
            value = tool.get(spelling)
        else:
            value = getattr(tool, spelling, None)
            if value is None and hasattr(tool, "get"):
                try:
                    value = tool.get(spelling)
                except Exception:  # noqa: BLE001 - a mapping-shaped model that refuses
                    value = None
        if value is not None:
            return value
    return default
