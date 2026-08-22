"""Shared canonical text and collection limits for strict SDK artifacts."""

from __future__ import annotations

from typing import Any, Callable, List

STRICT_IDENTIFIER_MAX_BYTES = 256
STRICT_SET_MAX_ITEMS = 64
STRICT_TARGET_MAX_BYTES = 1_024
STRICT_CONTEXT_MAX_BYTES = 65_536
STRICT_PRIOR_ACTIONS_MAX_ITEMS = 256


def _is_ascii_whitespace(character: str) -> bool:
    code = ord(character)
    return code == 0x20 or 0x09 <= code <= 0x0D


def bounded_canonical_text(
    value: Any,
    field: str,
    max_bytes: int,
    fail: Callable[[str], Any],
) -> str:
    if not isinstance(value, str):
        fail(f"{field} must be a nonblank string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        fail(f"{field} contains an unpaired surrogate")
    if not value or all(_is_ascii_whitespace(character) for character in value):
        fail(f"{field} must be a nonblank string")
    if len(value.encode("utf-8")) > max_bytes:
        fail(f"{field} exceeds {max_bytes} UTF-8 bytes")
    return value


def code_point_key(value: str) -> tuple[int, ...]:
    return tuple(ord(character) for character in value)


def normalized_bounded_set(
    value: Any,
    field: str,
    max_items: int,
    max_item_bytes: int,
    fail: Callable[[str], Any],
) -> List[str]:
    if not isinstance(value, list):
        fail(f"{field} must be an array")
    if len(value) > max_items:
        fail(f"{field} exceeds {max_items} items")
    values = [
        bounded_canonical_text(item, f"{field}[{index}]", max_item_bytes, fail)
        for index, item in enumerate(value)
    ]
    return sorted(set(values), key=code_point_key)
