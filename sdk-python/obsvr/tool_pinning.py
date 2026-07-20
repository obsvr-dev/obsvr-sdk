"""MCP tool-descriptor content-hash pinning (rug-pull defense).

EXACT parity with sdk/src/policy/tool-pinning.ts.

The attack: a tool presents a benign descriptor at review/discovery time,
then the server swaps it later -- a poisoned description the model will
read, or a widened input schema that exfiltrates extra arguments. Name
alone identifies nothing; the CONTENT of the descriptor is the identity.

Defense: hash a canonical projection of each descriptor seen at
list_tools. Pins come from two sources, in precedence order:

1. Config pins (``mcp_tool_policy["pinning"]["pins"][name]``) --
   operator-declared, version-controlled, survive restarts. Authoritative.
2. TOFU (trust-on-first-use) -- the first hash seen for a name in this
   governed session's lifetime. A later change keeps flagging/blocking
   until the operator explicitly pins the new hash: the store NEVER
   silently re-pins (a "re-register to re-pin" pattern would let the
   attacker's swap ratify itself).

Hashing reuses the SDK's cross-language-pinned canonicalization
(``_canonical_json`` == TS ``stableStringify``, pinned by rules_hash.json)
and the full SHA-256 digest -- never truncated. Vectors pinned in
conformance/fixtures/tool_pinning.json.

Honest boundary: TOFU pins live in-process and die with it -- a restart is
a fresh TOFU window. Config pins are the durable mechanism; the per-tool
hash is surfaced on signed inventory/call events precisely so an operator
can copy an observed hash into config. Pins are keyed by tool name within
one governed session, so two servers governed by the same process do not
collide; config pins are global by name.
"""

import threading
from typing import Any, Dict, List, Optional

from .decision_record import sha256_hex
import json
import math

# Bounded per-session store cap (house style: refuse past the cap rather
# than evict -- eviction would silently DROP protection for a pinned tool).
MAX_PINNED_TOOLS = 10_000

_MAX_SAFE_INT = 2 ** 53 - 1  # JS Number.MAX_SAFE_INTEGER


def _canonical_number(n: Any) -> str:
    """Canonical number serialization BYTE-IDENTICAL to the TS twin
    (``canonicalNumber``). The rules-hash canonicalizer delegates numbers to
    json.dumps / JSON.stringify, which DISAGREE cross-language for legal JSON
    numbers (whole-valued floats "1.0" vs "1", exponent forms, -0, ints past
    2^53). A descriptor is attacker-controlled JSON, so that divergence would
    make the same tool hash differently in the two SDKs. This formatter fixes
    the agreeing cases and FAILS CLOSED (raises -> hash_error -> flag/block,
    never a bypass) on values the two runtimes cannot represent identically.
    """
    if isinstance(n, bool):
        raise ValueError("tool-pin: bool is not a number")
    if not (isinstance(n, (int, float)) and math.isfinite(n)):
        raise ValueError("tool-pin: non-finite number in descriptor")
    is_int = (n == int(n))
    if is_int and abs(n) <= _MAX_SAFE_INT:
        i = int(n)
        return "0" if i == 0 else str(i)
    if (not is_int) and 1e-4 <= abs(n) < 1e16:
        return repr(float(n))
    raise ValueError("tool-pin: number outside cross-SDK-stable range")


def _canonical_json_for_hash(value: Any) -> str:
    """Canonical JSON for hashing (dedicated to tool descriptors; NOT the
    frozen rules-hash canonicalizer). Sorted object keys, nested nulls KEPT
    (only the top-level projection omits absent fields), strings/keys via the
    native JSON string serializer (ensure_ascii=False, identical escaping to
    the TS JSON.stringify), numbers via _canonical_number. Raises on
    unsupported/undecidable values so the caller fails closed.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _canonical_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json_for_hash(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + _canonical_json_for_hash(value[k])
                for k in keys
            )
            + "}"
        )
    raise ValueError("tool-pin: unsupported value type in descriptor: %r" % type(value))


def _field(tool: Any, attr: str) -> Any:
    """Read a descriptor field from an attr-style object (mcp.types.Tool) or
    a plain dict -- the same dual-access convention scan_tool_description uses.
    """
    v = getattr(tool, attr, None)
    if v is None and isinstance(tool, dict):
        v = tool.get(attr)
    return v


def _plain(value: Any) -> Any:
    """Convert a pydantic model (mcp.types annotations etc.) to plain JSON
    data so canonical serialization sees the same value TS sees on the wire.
    ``exclude_none`` mirrors the wire form (absent fields are absent, not
    null); non-model values pass through and any non-serializable leftovers
    fail closed at hash time (never silently stringified).
    """
    # exclude_none=False: keep EXPLICIT nested nulls the server put on the
    # wire (e.g. annotations {"readOnlyHint": true, "idempotentHint": null}),
    # matching the TS projection (which keeps nested nulls) and the Python
    # plain-dict path (json None -> null). exclude_none=True would drop them
    # and diverge dict-input from pydantic-input and TS from Python.
    dump = getattr(value, "model_dump", None)  # pydantic v2
    if callable(dump):
        try:
            return dump(by_alias=True, exclude_none=False, mode="json")
        except Exception:
            pass
    dump = getattr(value, "dict", None)  # pydantic v1
    if callable(dump):
        try:
            return dump(by_alias=True, exclude_none=False)
        except Exception:
            pass
    return value


def canonical_tool_descriptor(tool: Any) -> Dict[str, Any]:
    """Canonical projection of a tool descriptor: the security-relevant
    fields under FIXED canonical keys, absent/None fields OMITTED (never
    null) -- same convention as the canonical rules projection. Includes
    title/annotations/outputSchema: MCP behavior hints (readOnlyHint,
    destructiveHint, ...) change what a reviewer approved just as much as
    the description does.
    """
    out: Dict[str, Any] = {}
    annotations = _field(tool, "annotations")
    if annotations is not None:
        out["annotations"] = _plain(annotations)
    description = _field(tool, "description")
    if description is not None:
        out["description"] = description
    input_schema = _field(tool, "inputSchema")
    if input_schema is not None:
        out["input_schema"] = _plain(input_schema)
    name = _field(tool, "name")
    if name is not None:
        out["name"] = name
    output_schema = _field(tool, "outputSchema")
    if output_schema is not None:
        out["output_schema"] = _plain(output_schema)
    title = _field(tool, "title")
    if title is not None:
        out["title"] = title
    return out


def tool_descriptor_hash(tool: Any) -> str:
    """Full SHA-256 (lowercase 64-hex) over the canonical descriptor JSON.
    Byte-identical in both SDKs; pinned by tool_pinning.json hash_cases.
    Raises on a non-serializable descriptor (callers fail CLOSED).
    """
    return sha256_hex(_canonical_json_for_hash(canonical_tool_descriptor(tool)))


def evaluate_tool_pin(
    config_pin: Optional[str] = None,
    tofu_pin: Optional[str] = None,
    observed_hash: Optional[str] = None,
    mode: Optional[str] = None,
    require_pin: bool = False,
) -> Dict[str, Any]:
    """Pure pin decision (fixture-pinned in tool_pinning.json decision_cases).

    Config pin wins over TOFU; a hashing failure (``observed_hash`` None)
    fails CLOSED (treated as a mismatch); an unpinned tool passes unless
    ``require_pin``. Hash comparison is case-insensitive on the pin side.

    STRICT MODE (require_pin): only an operator CONFIG pin satisfies -- a
    TOFU pin does NOT (else a brand-new/aliased tool's first listing would be
    a pin_required violation AND record its own hash as the TOFU pin, so the
    next listing would trust it). require_pin therefore means "config-pinned
    tools only"; TOFU is disabled under it. TS parity: evaluateToolPin.

    Returns ``{"status", "enforcement"}`` plus optional ``expected`` /
    ``observed`` / ``source`` / ``reason`` keys (absent, never None -- the
    same key-absent idiom the deobfuscation ``via`` uses).
    """
    enforce = "block" if mode == "block" else "flag"
    effective_tofu = None if require_pin else tofu_pin
    pin = config_pin if config_pin is not None else effective_tofu
    source = (
        "config"
        if config_pin is not None
        else "tofu" if effective_tofu is not None else None
    )

    if observed_hash is None:
        # Fail closed: could not derive a hash for the descriptor.
        out: Dict[str, Any] = {
            "status": "mismatch",
            "enforcement": enforce,
            "reason": "hash_error",
        }
        if pin is not None:
            out["expected"] = pin.lower()
            out["source"] = source
        return out
    if pin is not None:
        if pin.lower() == observed_hash:
            return {
                "status": "ok",
                "enforcement": "none",
                "expected": pin.lower(),
                "observed": observed_hash,
                "source": source,
            }
        return {
            "status": "mismatch",
            "enforcement": enforce,
            "expected": pin.lower(),
            "observed": observed_hash,
            "source": source,
            "reason": "descriptor_hash_mismatch",
        }
    if require_pin:
        return {
            "status": "unpinned",
            "enforcement": enforce,
            "observed": observed_hash,
            "reason": "pin_required",
        }
    return {"status": "unpinned", "enforcement": "none", "observed": observed_hash}


class ToolPinStore:
    """Bounded per-session TOFU + verdict store (thread-safe)."""

    def __init__(self) -> None:
        self._tofu: Dict[str, str] = {}
        self._verdicts: Dict[str, Dict[str, Any]] = {}
        self._saturated = False
        self._lock = threading.Lock()

    def get_tofu_pin(self, name: str) -> Optional[str]:
        with self._lock:
            return self._tofu.get(name)

    def record_tofu_pin(self, name: str, hash_hex: str) -> None:
        """Record a first sighting. No-op if already pinned (no silent
        re-pin, ever) or the store is full (refuse, don't evict)."""
        with self._lock:
            if name in self._tofu:
                return
            if len(self._tofu) >= MAX_PINNED_TOOLS:
                self._saturated = True
                return
            self._tofu[name] = hash_hex

    def get_verdict(self, name: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._verdicts.get(name)

    def set_verdict(self, name: str, verdict: Dict[str, Any]) -> None:
        with self._lock:
            if len(self._verdicts) >= MAX_PINNED_TOOLS and name not in self._verdicts:
                self._saturated = True
                return
            self._verdicts[name] = verdict

    def pinned_names(self) -> List[str]:
        with self._lock:
            return list(self._tofu.keys())

    def saturated(self) -> bool:
        with self._lock:
            return self._saturated


def resolve_tool_pinning(
    mcp_tool_policy: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Resolve the pinning sub-config (absent/disabled => None). Accepts the
    same snake_case/camelCase aliasing the rest of mcp_tool_policy uses.
    Returns ``{"enabled": True, "mode", "pins", "require_pin"}``.
    """
    if not mcp_tool_policy:
        return None
    p = mcp_tool_policy.get("pinning")
    if not isinstance(p, dict) or not p.get("enabled"):
        return None
    return {
        "enabled": True,
        "mode": "block" if p.get("mode") == "block" else "warn",
        "pins": p.get("pins") if isinstance(p.get("pins"), dict) else None,
        "require_pin": bool(
            p.get("require_pin") if p.get("require_pin") is not None else p.get("requirePin")
        ),
    }
