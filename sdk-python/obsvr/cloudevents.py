"""CloudEvents v1.0 export (twin of sdk/src/proxy/cloudevents.ts).

An audit event is obsvr's own shape and every consumer of it needs an adapter.
CloudEvents is the CNCF interchange envelope those consumers already speak, so
one serializer removes an adapter from every sink an operator might want to fan
events out to - the same argument the OTel span mirror makes for the trace bus,
applied to the event bus.

This is a pure, additive projection. It runs when an operator asks for it,
never on the call path, and it never mutates the event: the envelope carries
the audit event verbatim as ``data``.

The mapping, and why each field is what it is
---------------------------------------------

===================  ==================================================
CloudEvents          obsvr
===================  ==================================================
``specversion``      fixed ``"1.0"``
``id``               ``seq_no``, else ``request_id`` - see below
``source``           ``urn:obsvr:session:<sdk_session_id>``
``type``             ``dev.obsvr.audit.<event_type>``
``subject``          ``operation``, when non-empty
``time``             ``timestamp_sdk`` as RFC 3339 UTC, when usable
``datacontenttype``  fixed ``"application/json"``
``dataschema``       fixed ``urn:obsvr:schema:audit-event:1``
``data``             the audit event, unmodified
===================  ==================================================

The spec makes ``(source, id)`` the deduplication key, and obsvr already has a
pair that means exactly that: the chain coordinate ``(sdk_session_id,
seq_no)``. Mapping one onto the other means a sink that dedupes CloudEvents
dedupes on the same identity the ledger does, instead of on a second,
differently-shaped notion of "same event". An event carrying no ``seq_no``
never entered the signed chain, so there is no chain coordinate to use; those
fall back to ``request_id``, and the uniqueness guarantee is then only as
strong as that field. Stating that is better than papering over it with a
generated id that would make every re-export look like a new event.

``dataschema`` is a URN rather than an https URL on purpose: a URL is a promise
that something is served there, and nothing is.

Two extension attributes are emitted so a sink can route without opening the
payload - the actual reason context attributes exist. Extension names are
lower-case alphanumerics per the spec, which is why they read as one word.

Byte-identical across SDKs
--------------------------

:func:`serialize_cloud_event` produces the canonical string form through the
same canonicalizer the tool hashes use, so the two languages emit the same
bytes for the same event and the fixture pins a string rather than a shape.
That canonicalizer REFUSES values the two runtimes cannot render identically
(integers past 2^53, exponent-notation extremes, non-finite), and so does this:
a "byte-identical" claim that quietly is not would be worse than an error.
Callers that would rather drop the export than fail use
:func:`safe_serialize_cloud_event`.
"""

from __future__ import annotations

import datetime
import math
from typing import Any, Dict, Optional

from .tool_pinning import _canonical_json_for_hash

__all__ = [
    "CLOUDEVENTS_SPEC_VERSION",
    "CLOUDEVENTS_TYPE_PREFIX",
    "CLOUDEVENTS_DATA_SCHEMA",
    "rfc3339_from_epoch_ms",
    "to_cloud_event",
    "serialize_cloud_event",
    "safe_serialize_cloud_event",
]

#: CloudEvents spec version this serializer emits.
CLOUDEVENTS_SPEC_VERSION = "1.0"

#: Reverse-DNS prefix for the ``type`` attribute, per the spec's SHOULD.
CLOUDEVENTS_TYPE_PREFIX = "dev.obsvr.audit"

#: Identifies the shape carried in ``data``. A URN, because nothing is served.
CLOUDEVENTS_DATA_SCHEMA = "urn:obsvr:schema:audit-event:1"

#: ``source`` for an event whose SDK session is unknown.
_UNKNOWN_SESSION_SOURCE = "urn:obsvr:session:unknown"

#: The range JavaScript's Date represents exactly; beyond it the value is not a
#: time. Bounded here too so both languages omit ``time`` for the same inputs.
_MAX_EPOCH_MS = 8_640_000_000_000_000

_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def rfc3339_from_epoch_ms(ms: Any) -> Optional[str]:
    """Milliseconds-since-epoch as RFC 3339 UTC with exactly three fractional
    digits.

    Written out rather than delegating to ``datetime.isoformat`` so the two
    SDKs have one spelled-out format to match instead of "whatever that runtime
    does" - ``isoformat`` emits microseconds and ``+00:00``, and JavaScript's
    ``toISOString`` switches to an expanded year form outside 0000-9999. Returns
    None for anything the format cannot represent, and the caller omits
    ``time``: an absent optional attribute is honest, a wrong timestamp is not.
    """
    if isinstance(ms, bool) or not isinstance(ms, (int, float)):
        return None
    if isinstance(ms, float) and not math.isfinite(ms):
        return None
    whole = int(ms)  # truncates toward zero, matching Math.trunc
    if abs(whole) > _MAX_EPOCH_MS:
        return None
    secs, millis = divmod(whole, 1000)  # floors, matching Date's negative case
    try:
        dt = _EPOCH + datetime.timedelta(seconds=secs)
    except (OverflowError, OSError, ValueError):
        return None
    if dt.year < 0 or dt.year > 9999:
        return None
    return (
        f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}"
        f"T{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        f".{millis:03d}Z"
    )


def _nonempty_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def to_cloud_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Project an audit event onto a CloudEvents v1.0 envelope.

    Pure: no clock, no I/O, no per-process state, so the same event always
    yields the same envelope. The event is carried by reference as ``data`` and
    is never modified.
    """
    session = _nonempty_str(event.get("sdk_session_id"))
    seq = event.get("seq_no")
    if isinstance(seq, int) and not isinstance(seq, bool):
        event_id = str(seq)
    elif isinstance(seq, float) and math.isfinite(seq):
        # Mirrors the TS side, where every number is one type: a whole float
        # renders without a trailing ".0" so the two agree.
        event_id = str(int(seq)) if seq.is_integer() else repr(seq)
    else:
        event_id = str(event.get("request_id") or "")

    envelope: Dict[str, Any] = {
        "specversion": CLOUDEVENTS_SPEC_VERSION,
        "id": event_id,
        "source": _UNKNOWN_SESSION_SOURCE
        if session is None
        else f"urn:obsvr:session:{session}",
        "type": f"{CLOUDEVENTS_TYPE_PREFIX}.{event.get('event_type')}",
        "datacontenttype": "application/json",
        "dataschema": CLOUDEVENTS_DATA_SCHEMA,
    }
    subject = _nonempty_str(event.get("operation"))
    if subject is not None:
        envelope["subject"] = subject
    time = rfc3339_from_epoch_ms(event.get("timestamp_sdk"))
    if time is not None:
        envelope["time"] = time
    if event.get("action_taken") is not None:
        envelope["obsvraction"] = event["action_taken"]
    if event.get("environment") is not None:
        envelope["obsvrenv"] = event["environment"]
    envelope["data"] = event
    return envelope


def serialize_cloud_event(event: Dict[str, Any]) -> str:
    """The canonical JSON string form: sorted keys, no insignificant
    whitespace, cross-SDK-stable numbers. THIS is the byte contract both
    languages reproduce, pinned by conformance/fixtures/cloudevents.json.

    RAISES on event content neither runtime can render identically.
    """
    return _canonical_json_for_hash(to_cloud_event(event))


def safe_serialize_cloud_event(event: Dict[str, Any]) -> Optional[str]:
    """:func:`serialize_cloud_event`, or None when the event carries content the
    two runtimes cannot render identically. For a fan-out loop that should skip
    one event rather than abandon the batch.
    """
    try:
        return serialize_cloud_event(event)
    except Exception:  # noqa: BLE001 - any canonicalization refusal
        return None
