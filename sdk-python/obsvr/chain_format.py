"""Audit-chain format - the content-hash preimage and signature payload.

Shared by the signer (sender.py) and the verifier (verify_chain.py) so the
two cannot drift apart. Twin: sdk-typescript/src/proxy/chain-format.ts. Pinned by
conformance/fixtures/signing_vectors.json, which both languages consume.

WHY FORMAT 2 EXISTS. Format 1 hashed the bare concatenation
``sha256(prompt + response)``, and a concatenation does not remember where
one field ended and the next began: ``sha256("AB" + "C")`` and
``sha256("A" + "BC")`` are the same digest. An event's content could
therefore be re-split at a different prompt/response boundary - moving text
from "what the model said" into "what the user said", or the reverse - and
the chain still verified. The chain's whole claim is attribution of who said
what, so the boundary must be part of what is signed.

Format 2 makes the preimage unambiguous by construction::

    sha256( "obsvr:content/2" || 0x00
            || u64be(len(prompt))   || prompt
            || u64be(len(response)) || response )

with both fields as UTF-8 bytes and lengths counted in bytes. A length
prefix per field means no re-split of the same bytes can reproduce the
preimage: the split points are stated inside it. The leading tag plus NUL
domain-separates this digest from every other sha256 in the SDK (the
tool-content hash, the pinning hash), so a digest minted for one purpose can
never be replayed as another. The 8-byte length cannot overflow for any
string either runtime can hold.

The signature payload also changes: format 2 leads with the format number
(``2|session|seq|ts|hash|prev``), so an event's format claim is itself under
the HMAC. The ``chain_format`` field on the event routes the verifier; a
forged or stripped field can only make verification FAIL (the recomputed
payload will not match), never redirect a signature minted under one format
into verifying under the other.

WHY FORMAT 3 EXISTS. Formats 1 and 2 sign the CONTENT and the ORDER, and
nothing else: the preimage was
``format | session | seq | timestamp | content_hash | prev_sig``, with no
decision field in it. So a party who could edit a stored event before ingest
could rewrite ``action_taken`` from "blocked" to "allowed" - inverting the
enforcement record - and the shipped offline verifier, run with the CORRECT API
key, still reported the chain valid. Measured, not theorised: a tamper matrix
over a real chain rewrote all eight of ``action_taken``, ``action_reason``,
``reason_code``, ``rule_id``, ``policy_version``, ``model``, ``provider`` and
``user_id``, and every one verified clean, while the content and ordering
controls broke exactly as they should.

The server countersignature was always the thing that sealed those fields, and
``SECURITY.md`` said so. But ``obsvr-verify`` is shipped as the user-facing
OFFLINE verifier, and a compliance officer running it got a clean result on a
fully rewritten verdict history. For an evidence product that is the worst
shape of defect available: a false negative that reads exactly like a true one.

Format 3 folds a decision digest into the preimage::

    3|session|seq|ts|content_hash|decision_hash|prev

The decision digest is framed the same way and for the same reason as the
format-2 content hash - eight fields concatenated bare would re-split at a
different boundary exactly as prompt/response did::

    sha256( "obsvr:decision/3" || 0x00
            || for each field, in DECISION_FIELD_ORDER:
                 presence_byte || u64be(len(value)) || value )

The presence byte (0x01 present, 0x00 absent) is what keeps an ABSENT field
distinct from one present-and-empty. Without it ``rule_id = None`` and
``rule_id = ""`` would produce the same preimage, and "no rule fired" would be
interchangeable with "a rule with an empty id fired".

The content hash is UNCHANGED between formats 2 and 3: the content framing did
not need fixing, and ``obsvr:content/2`` names the content-preimage version
rather than the chain format.

Formats 1 and 2 stay implemented here forever: chains signed before each change
are existing evidence and must keep verifying - explicitly, as the format they
were signed under, never silently under a newer rule. No two formats share a
valid signature, because each leads its payload with its own format number.
"""

import hashlib
import struct
from typing import Any, Dict, Optional

__all__ = [
    "CHAIN_FORMAT_LEGACY",
    "CHAIN_FORMAT_CONTENT_ONLY",
    "CHAIN_FORMAT_CURRENT",
    "CHAIN_FORMATS_SUPPORTED",
    "CONTENT_HASH_DOMAIN_TAG",
    "DECISION_HASH_DOMAIN_TAG",
    "DECISION_FIELD_ORDER",
    "content_hash",
    "decision_hash",
    "decision_fields_of",
    "signature_payload",
]

#: The pre-framing format: ``sha256(prompt + response)``, boundary unsigned.
CHAIN_FORMAT_LEGACY = 1
#: Length-prefixed, domain-tagged content preimage. Content and order only.
CHAIN_FORMAT_CONTENT_ONLY = 2
#: Content, order AND the decision fields. What the SDK signs today.
CHAIN_FORMAT_CURRENT = 3
#: Every format this build can verify, oldest first.
CHAIN_FORMATS_SUPPORTED = (1, 2, 3)
#: Domain tag leading every format-2 content preimage.
CONTENT_HASH_DOMAIN_TAG = b"obsvr:content/2"
#: Domain tag leading every format-3 decision preimage.
DECISION_HASH_DOMAIN_TAG = b"obsvr:decision/3"

#: The decision/attribution fields format 3 signs, in the ONE order the digest
#: is defined over. Both languages iterate this list; changing the order or the
#: membership changes every format-3 signature and requires a new format.
DECISION_FIELD_ORDER = (
    "action_taken",
    "action_reason",
    "reason_code",
    "rule_id",
    "policy_version",
    "model",
    "provider",
    "user_id",
)


def content_hash(fmt: int, prompt: str, response: str) -> str:
    """Content hash under the given chain format.

    Absent fields hash as empty - in format 2 an absent prompt is still a
    stated zero-length field, so ("", "x") and ("x", "") produce different
    digests where format 1 collided.
    """
    if fmt == CHAIN_FORMAT_LEGACY:
        return hashlib.sha256(
            ((prompt or "") + (response or "")).encode("utf-8")
        ).hexdigest()
    p = (prompt or "").encode("utf-8")
    r = (response or "").encode("utf-8")
    h = hashlib.sha256()
    h.update(CONTENT_HASH_DOMAIN_TAG)
    h.update(b"\x00")
    # u64 big-endian length prefix. Bytes, not code units - the two runtimes
    # agree on UTF-8 byte counts, not on their native string lengths.
    h.update(struct.pack(">Q", len(p)))
    h.update(p)
    h.update(struct.pack(">Q", len(r)))
    h.update(r)
    return h.hexdigest()


def decision_fields_of(event: Dict[str, Any]) -> Dict[str, Any]:
    """Read the signed decision fields off an event.

    ONE reader, used by both the signer and the verifier. If they read the field
    set differently - even in how they treat an absent value - every signature
    verifies as broken, and the bug would look like tampering. That failure mode
    is why this is not two functions.
    """
    out: Dict[str, Any] = {}
    for key in DECISION_FIELD_ORDER:
        value = event.get(key)
        out[key] = None if value is None else str(value)
    return out


def decision_hash(fields: Optional[Dict[str, Any]]) -> str:
    """Digest over the decision/attribution fields. Format 3 and later only.

    Each field contributes a presence byte, a u64be byte-length, and its UTF-8
    bytes, in ``DECISION_FIELD_ORDER``. The presence byte distinguishes an
    absent field from a present-and-empty one; the length prefix stops two
    different field sets sharing a preimage the way an unframed concatenation
    would.
    """
    src = fields or {}
    h = hashlib.sha256()
    h.update(DECISION_HASH_DOMAIN_TAG)
    h.update(b"\x00")
    for key in DECISION_FIELD_ORDER:
        value = src.get(key)
        present = value is not None
        h.update(b"\x01" if present else b"\x00")
        raw = (str(value) if present else "").encode("utf-8")
        h.update(struct.pack(">Q", len(raw)))
        h.update(raw)
    return h.hexdigest()


def signature_payload(
    fmt: int,
    session_id: str,
    seq_no: int,
    timestamp_sdk: int,
    prompt: str,
    response: str,
    prev_sig: Optional[str],
    decision: Optional[Dict[str, Any]] = None,
) -> str:
    """The exact string the HMAC signs.

    Formats 2 and 3 lead with the format number so the format claim is itself
    tamper-evident; format 1 is reproduced byte-for-byte as it always was,
    because its signatures already exist.

    ``decision`` is read only for format 3 and later. Passing it for an older
    format is harmless and changes nothing, which is what lets one call site
    sign any format.
    """
    fields = [
        session_id,
        str(seq_no),
        str(timestamp_sdk),
        content_hash(fmt, prompt, response),
    ]
    if fmt >= CHAIN_FORMAT_CURRENT:
        fields.append(decision_hash(decision))
    fields.append(prev_sig or "")
    if fmt != CHAIN_FORMAT_LEGACY:
        fields.insert(0, str(fmt))
    return "|".join(fields)
