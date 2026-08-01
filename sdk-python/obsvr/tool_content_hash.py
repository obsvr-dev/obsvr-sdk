"""tool_content_hash producer (``obsvr-tool-content-v1``).

Twin of sdk-typescript/src/policy/tool-content-hash.ts; the byte contract of record is
conformance/fixtures/tool_content_hash.json, and every vector there must
produce the same 64-hex digest in both languages.

Sealed evidence of exactly WHICH tool content and arguments an agent saw on a
given tool call. The hash is a single 64-hex field stamped on tool-call events;
the platform's ledger seals it, so a descriptor swap or a rug-pulled MCP server
becomes attributable after the fact: the customer discloses the parts, anyone
recomputes the hash, and it either matches the anchored root or it does not.

The document is deliberately reconstructable offline from disclosed parts - the
same replay property ``decision_input_hash`` has::

    tool_content_hash = sha256hex( canonical({
      schema:            "obsvr-tool-content-v1",
      tool_name:         <the name the call targeted>,
      descriptor_sha256: sha256hex( canonical({name, description, input_schema}) ),
      args_sha256:       sha256hex( canonical(<call arguments>) ),
    }) )

Why this is NOT the descriptor-pinning hash
-------------------------------------------
``tool_descriptor_hash`` (tool_pinning.py) is a trust-on-first-use rug-pull
DEFENSE over a 6-field descriptor projection, in-process and free to evolve
with pinning policy. This is a platform EVIDENCE contract: a document binding
the tool name, a narrower platform-defined 3-field descriptor projection
``{name, description, input_schema}``, and an ARGUMENTS digest that pinning
never covers because arguments are per-call, not per-descriptor. A tool can be
perfectly pinned and still produce a different tool_content_hash on every call,
which is the point. Changing this document is a cross-package breaking change;
changing the pinning projection is not.

Canonicalization
----------------
Reuses ``_canonical_json_for_hash`` from tool_pinning.py: sorted keys, no
insignificant whitespace, and the cross-SDK-stable number formatter that
REFUSES values the two runtimes cannot represent identically rather than
normalizing them away. Sealed evidence is not re-issuable, so a missing hash
beats a collidable one - callers treat a raise as "omit the field".

Absent optional fields are OMITTED from the descriptor projection, never
serialized as null.

Where the descriptor comes from
-------------------------------
The MCP call path - the only boundary this is wired at in Python, the same
scope the TS twin's MCP half has - carries only ``(name, arguments)``, and the
SDK keeps descriptor HASHES from discovery (for pinning), never the
descriptors. So MCP tool-call events commit to the tool name and arguments
with the empty-descriptor digest. That is the honest record of what the
producer actually saw, and it is stable: the same call always yields the same
hash. Giving MCP a real descriptor digest means retaining descriptors from
``tools/list``, which is its own change - and one the TS twin has not made
either, so the two stay level. A caller holding a real descriptor — each SDK
reaches this through its tool governor, ``obsvrGovernTool`` in TypeScript and
``integrations.tools.govern_tool`` here — can pass it directly and get the
stronger digest.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .decision_record import sha256_hex
from .tool_pinning import _canonical_json_for_hash, _field, _plain

#: Schema tag of the canonical tool-content document.
TOOL_CONTENT_SCHEMA = "obsvr-tool-content-v1"


def canonical_tool_content_descriptor(descriptor: Any) -> Dict[str, Any]:
    """Canonical projection of the descriptor for the evidence contract:
    exactly ``{name, description, input_schema}``, absent/None fields omitted.

    ``input_schema`` is in the projection deliberately: a wrapper can keep a
    tool's name and description byte-identical and widen its input schema to
    exfiltrate extra arguments, which a name+description digest would miss.
    """
    out: Dict[str, Any] = {}
    if descriptor is None:
        return out
    description = _field(descriptor, "description")
    if description is not None:
        out["description"] = description
    input_schema = _field(descriptor, "inputSchema")
    if input_schema is not None:
        out["input_schema"] = _plain(input_schema)
    name = _field(descriptor, "name")
    if name is not None:
        out["name"] = name
    return out


def tool_content_descriptor_hash(descriptor: Any) -> str:
    """SHA-256 (lowercase 64-hex) over the canonical descriptor projection.
    Raises on descriptor content neither runtime can canonicalize identically.
    """
    return sha256_hex(_canonical_json_for_hash(canonical_tool_content_descriptor(descriptor)))


def tool_args_hash(args: Any) -> str:
    """SHA-256 (lowercase 64-hex) over the canonical call arguments. Absent or
    None arguments hash as the empty object, so "called with no arguments" and
    "called with {}" are the same evidence - they are the same call. Raises on
    arguments neither runtime can canonicalize identically."""
    return sha256_hex(_canonical_json_for_hash({} if args is None else _plain(args)))


def build_tool_content_document(
    tool_name: Optional[str] = None,
    descriptor: Any = None,
    args: Any = None,
) -> Dict[str, Any]:
    """Build the canonical tool-content document. Pure: no I/O, no clock, no
    per-process state, so the same call always yields the same document.

    ``tool_name`` falls back to the descriptor's own name when omitted, then to
    "" - a missing name is recorded as empty, never guessed, so the digest
    still commits to what was actually seen.
    """
    name = tool_name if isinstance(tool_name, str) and tool_name else None
    if name is None:
        descriptor_name = _field(descriptor, "name") if descriptor is not None else None
        name = descriptor_name if isinstance(descriptor_name, str) else ""
    return {
        "schema": TOOL_CONTENT_SCHEMA,
        "tool_name": name,
        "descriptor_sha256": tool_content_descriptor_hash(descriptor),
        "args_sha256": tool_args_hash(args),
    }


def canonicalize_tool_content(doc: Dict[str, Any]) -> str:
    """Canonical serialization of a tool-content document: sorted keys, no
    insignificant whitespace. This exact string is what gets hashed, so it is
    the byte contract both languages must reproduce."""
    return _canonical_json_for_hash(doc)


def compute_tool_content_hash(
    tool_name: Optional[str] = None,
    descriptor: Any = None,
    args: Any = None,
) -> str:
    """``tool_content_hash`` for one tool call: SHA-256 (lowercase 64-hex) of
    the canonical document. Bounded work - four small digests over content the
    caller already holds in memory - so it is safe on the call path.

    RAISES if any part cannot be canonicalized identically in both languages.
    A caller on the hot path must catch and omit the field: an absent
    ``tool_content_hash`` seals honestly as empty, a wrong one seals a lie.
    """
    return sha256_hex(
        canonicalize_tool_content(
            build_tool_content_document(tool_name=tool_name, descriptor=descriptor, args=args)
        )
    )


#: Reserved-metadata key the hash rides on until ingest has a column for it.
#:
#: Carriage and promotion plan (identical to the TS twin's, and the two must
#: move together):
#:
#: 1. (now) The SDK stamps ``metadata.obsvr_tool_content_hash`` on tool-call
#:    events. Consumers read it from metadata. The ingest wire schema has no
#:    such column today and strips unknown top-level fields, so emitting it
#:    there would lose it silently; reserved ``obsvr_*`` metadata is the same
#:    route ``obsvr_external_backend`` already takes, and the sender's trimmer
#:    preserves reserved keys so a large event cannot drop the evidence.
#: 2. Ingest adds a ``tool_content_hash`` column and accepts the reserved key
#:    as its source, backfilling from metadata.
#: 3. The SDK emits the top-level field and keeps mirroring into metadata for
#:    one minor release, then stops.
TOOL_CONTENT_HASH_METADATA_KEY = "obsvr_tool_content_hash"


def safe_tool_content_hash(
    tool_name: Optional[str] = None,
    descriptor: Any = None,
    args: Any = None,
) -> Optional[str]:
    """Hot-path wrapper: the hash, or None if it cannot be computed.

    ``compute_tool_content_hash`` raises on content the two languages cannot
    canonicalize identically. On a tool boundary that must not break the host
    call, and where a WRONG hash is strictly worse than none - sealed evidence
    cannot be reissued - the only correct response is to omit the field.
    """
    try:
        return compute_tool_content_hash(
            tool_name=tool_name, descriptor=descriptor, args=args
        )
    except Exception:
        return None


def tool_content_metadata(hash_value: Optional[str]) -> Dict[str, Any]:
    """The metadata fragment carrying the hash, empty when there is none. Apply
    it LAST at every emission site, after caller-supplied metadata, so a key
    collision can never overwrite sealed evidence - the same precedence the pin
    and normalizer stamps already use."""
    return {} if hash_value is None else {TOOL_CONTENT_HASH_METADATA_KEY: hash_value}
