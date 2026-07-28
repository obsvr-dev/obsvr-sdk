"""The one place token counts are read out of a usage payload.

Twin of ``sdk-typescript/src/proxy/extractors/token-usage.ts``; the two must
accept the same shapes and refuse in the same cases, because an event's token
fields are part of the cross-language contract.

WHY THIS EXISTS. Token counts were read independently at seven sites here and
fourteen in TypeScript, and the sites disagreed about how to say "unknown".
Some returned ``None``; others defaulted a missing field to ``0``. Zero is the
wrong answer for a governance product: when an upstream field is renamed or
removed while the usage container survives, a defaulted ``0`` records a
measurement that never happened, and nothing downstream can tell it apart from
a call that genuinely consumed nothing. A missing count and a zero count are
different facts, and only one of them is a bug.

So this module NEVER fabricates. Absent stays absent.

WHAT IT ACCEPTS. The union of the shapes the supported providers and frameworks
actually emit, which is wider than any single site knew about:

    snake_case wire    prompt_tokens / completion_tokens / total_tokens
                       input_tokens / output_tokens / total_tokens
    camelCase flat     inputTokens / outputTokens / totalTokens
    camelCase legacy   promptTokens / completionTokens / totalTokens
    Gemini             prompt_token_count / candidates_token_count /
                       total_token_count (and the camelCase spellings)
    Bedrock Titan      inputTextTokenCount
    NESTED             inputTokens = {total, noCache, cacheRead, cacheWrite}
                       outputTokens = {total, text, reasoning}

The nested form is the one that broke a live integration: a framework turned
``inputTokens`` from a number into an object and deleted ``totalTokens``, so
every reader that asked "is this a number?" quietly answered "no tokens" for
both counts and for the total derived from them. Reading ``total`` out of an
object slot is therefore not a special case for one framework — it is the shape
a version bump can turn any of these into.

Containers are read by attribute OR by key, because provider SDKs hand back
pydantic models, dataclasses and plain dicts interchangeably, and a reader that
only understood one of those silently missed the others.
"""

from typing import Any, Dict, Optional, Tuple

#: A usage container was present and no known field matched. Stamped into
#: reserved telemetry so an unreadable payload stays distinguishable from a
#: provider that reported nothing — different facts, only one a defect.
SHAPE_UNRECOGNIZED = "unrecognized"
#: No usage container at all, or one carrying nothing. Normal; never stamped.
SHAPE_ABSENT = "absent"
#: At least one known field matched.
SHAPE_RECOGNIZED = "recognized"

_INPUT_ALIASES = (
    "input_tokens",
    "prompt_tokens",
    "inputTokens",
    "promptTokens",
    "prompt_token_count",
    "promptTokenCount",
    "inputTextTokenCount",
)

_OUTPUT_ALIASES = (
    "output_tokens",
    "completion_tokens",
    "outputTokens",
    "completionTokens",
    "candidates_token_count",
    "candidatesTokenCount",
)

_TOTAL_ALIASES = (
    "total_tokens",
    "totalTokens",
    "total_token_count",
    "totalTokenCount",
)


def _member(container: Any, name: str) -> Tuple[bool, Any]:
    """(present, value) for a key or attribute. Presence is reported separately
    from the value so a genuine 0 is never mistaken for a missing field.

    Reflection over a caller-supplied object is guarded: a provider model with a
    computed property that raises must not turn a token read into a failed
    governed call. An attribute that cannot be read is simply not present.
    """
    try:
        if isinstance(container, dict):
            if name in container:
                return True, container[name]
            return False, None
        if hasattr(container, name):
            return True, getattr(container, name)
    except Exception:
        return False, None
    return False, None


def _finite(value: Any) -> Optional[int]:
    """An int, or nothing. ``bool`` is excluded deliberately: it is an ``int``
    subclass in Python, and ``True`` is not a token count."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # Providers occasionally send whole numbers as floats; a fractional
        # token count is not a count, so only exact integers are accepted.
        if value == value and value not in (float("inf"), float("-inf")) and value.is_integer():
            return int(value)
    return None


def _slot(value: Any) -> Optional[int]:
    """One token slot: a bare number, or an object carrying a numeric ``total``.

    Only ``total`` is read out of the nested form. The siblings (``cacheRead``,
    ``reasoning``, ...) are real data but they are cost DETAIL, not the count
    itself, and they already have a home in the telemetry channel — folding
    them in here would make one number mean two things.
    """
    direct = _finite(value)
    if direct is not None:
        return direct
    if value is not None and not isinstance(value, (str, bytes)):
        present, inner = _member(value, "total")
        if present:
            return _finite(inner)
    return None


def _first_alias(container: Any, aliases: Tuple[str, ...]) -> Optional[int]:
    for name in aliases:
        present, raw = _member(container, name)
        if present:
            value = _slot(raw)
            if value is not None:
                return value
    return None


def _has_any_member(container: Any) -> bool:
    """Whether the container carries anything at all — the difference between
    "the provider sent an empty usage object" (nothing to read, normal) and
    "the provider sent fields obsvr does not recognise" (a shape moved)."""
    try:
        if isinstance(container, dict):
            return len(container) > 0
        return any(not n.startswith("_") for n in dir(container))
    except Exception:
        return False


def normalize_token_usage(container: Any) -> Tuple[Optional[Dict[str, int]], str]:
    """Read token counts out of a provider or framework usage container.

    Returns ``(usage, shape)``. ``usage`` is omitted entirely (``None``) unless
    at least one count was actually read, and carries only the keys that were.

    ``total`` is derived from input + output when the payload does not state it.
    That is arithmetic over two known values, not a fabricated measurement, and
    it is the only source of a total since the nested shape dropped
    ``totalTokens`` outright.
    """
    if container is None or isinstance(container, (str, bytes, int, float, bool)):
        return None, SHAPE_ABSENT

    input_tokens = _first_alias(container, _INPUT_ALIASES)
    output_tokens = _first_alias(container, _OUTPUT_ALIASES)
    stated_total = _first_alias(container, _TOTAL_ALIASES)

    if input_tokens is None and output_tokens is None and stated_total is None:
        # Present but unreadable — unless it is empty, in which case the
        # provider reported nothing, which is the same fact as sending nothing.
        return None, SHAPE_UNRECOGNIZED if _has_any_member(container) else SHAPE_ABSENT

    total = stated_total
    if total is None and input_tokens is not None and output_tokens is not None:
        total = input_tokens + output_tokens

    usage: Dict[str, int] = {}
    if input_tokens is not None:
        usage["input_tokens"] = input_tokens
    if output_tokens is not None:
        usage["output_tokens"] = output_tokens
    if total is not None:
        usage["total_tokens"] = total
    return usage, SHAPE_RECOGNIZED


def read_token_usage(container: Any) -> Dict[str, Optional[int]]:
    """The counts as the three-key dict the event builder expects, with ``None``
    for anything that could not be read.

    Callers that need to distinguish "unreadable" from "not reported" — the
    ones that stamp ``usage_shape`` — should call :func:`normalize_token_usage`.
    """
    usage, _shape = normalize_token_usage(container)
    usage = usage or {}
    return {
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "total_tokens": usage.get("total_tokens"),
    }
