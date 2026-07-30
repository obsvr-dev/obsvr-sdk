"""Fire-and-forget audit sender.

Bounded queue.Queue(100) + daemon worker thread, urllib.request POST to
{ingest_url}/ingest with X-API-Key, 429 backoff (1s -> 60s, x2), and an
atexit flush. Never blocks or breaks the caller's LLM path.

Every enqueued event is stamped with the SDK integrity chain, byte-for-byte
compatible with the TypeScript SDK (sdk-typescript/src/proxy/sender/fire-and-forget.ts)
so ingest-side verification code treats both identically:

- sdk_session_id : stable UUID per process lifetime
- seq_no         : monotonic 1-based counter
- timestamp_sdk  : epoch milliseconds at enqueue
- chain_format   : signing format number (see chain_format.py)
- prev_sig       : sdk_sig of the previous event (chain link; absent on first)
- sdk_sig        : HMAC-SHA256(key, payload) where
                   key = HMAC-SHA256("obsvr-sdk-signing-v1", api_key) and
                   payload = signature_payload(...) from chain_format.py
                   (format|session|seq|ts|content_hash|prev_sig, with the
                   content hash length-prefixed and domain-tagged)
"""

import atexit
import hashlib
import hmac as hmac_mod
import json
import logging
import random
import threading
import time
import uuid
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .audit_gap import (
    AUDIT_GAP_GOVERNANCE_EVENT,
    AUDIT_GAP_METADATA_KEY,
    AUDIT_GAP_OPERATION,
    AUDIT_GAP_REASON_QUEUE_OVERFLOW,
    format_audit_gap_prompt,
)
from .chain_format import (
    CHAIN_FORMAT_CURRENT,
    decision_fields_of,
    signature_payload,
)
from .config import ResolvedConfig

MAX_QUEUE_SIZE = 1000
SEND_BATCH_SIZE = 25
# Serialized-bytes budget per batch request: ingest's body limit is 1MB,
# so cap well under it and split (large prompts must not fail a whole
# batch; OTel Collector's items+bytes dual sizing is the reference).
MAX_BATCH_BYTES = 750_000
MAX_SEND_RETRIES = 5
INITIAL_BACKOFF_S = 1.0
MAX_BACKOFF_S = 60.0
INGEST_PATH = "/ingest"
INGEST_BATCH_PATH = "/ingest/batch"
API_KEY_HEADER = "X-API-Key"
SIGNING_SALT = b"obsvr-sdk-signing-v1"

_queue: "Queue[Any]" = Queue(maxsize=MAX_QUEUE_SIZE)
_backoff: Dict[str, float] = {"until": 0.0, "multiplier": 1.0}
# Set at process exit so the worker breaks out of its (up to 60s) backoff sleep
# and drains immediately — otherwise the atexit flush budget is defeated by a
# backoff armed during an ingest outage and queued events are lost.
_shutdown = threading.Event()
_dropped = 0
# Structured delivery counters (E33): loss must be VISIBLE, not just
# detectable at chain verification. Reported on the /policies status poll.
_stats: Dict[str, int] = {
    "enqueued": 0,
    "sent": 0,
    "retries": 0,
    "dropped_overflow": 0,
    "dropped_permanent": 0,
    "dropped_retry_exhausted": 0,
    # Events the server ACCEPTED the request for but REFUSED individually
    # (per-event rejects inside a 2xx batch response). Its own bucket, not
    # folded into the dropped_* aggregate above: a server-refused event and a
    # never-delivered event are different audit stories, and only the first
    # means the server saw the event and said no. Name matches the TS sender.
    "dropped_rejected": 0,
    # Signed gap markers emitted (see audit_gap.py), and the dropped events
    # those markers have put on the record.
    "gap_markers": 0,
    "gap_events_declared": 0,
}
_stats_lock = threading.Lock()
_worker = None
_worker_lock = threading.Lock()
_atexit_registered = False


def _bump(counter: str, n: int = 1) -> None:
    with _stats_lock:
        _stats[counter] = _stats.get(counter, 0) + n


def get_sender_stats() -> Dict[str, int]:
    """Snapshot of delivery counters (enqueued/sent/retries/drops)."""
    with _stats_lock:
        return dict(_stats)

# ── SDK integrity chain state (parity with TS fire-and-forget.ts) ────────────
_sdk_session_id: str = str(uuid.uuid4())
_seq_no = 0
_last_sig: Optional[str] = None
_signing_key: Optional[bytes] = None
_signing_key_source: Optional[str] = None
# Reentrant: send_audit_async holds it across sign + enqueue (atomic chain
# advance), and the public sign_event() re-acquires it inside that scope.
_sign_lock = threading.RLock()
# Overflow drops that no gap marker has declared yet. Incremented at the drop
# point, zeroed when a marker carrying them is signed into the chain. Guarded
# by _sign_lock, like the chain head it will be written into.
_gap_pending = 0
# Markers emitted this session - the ordinal in a marker's request_id.
_gap_marker_ordinal = 0
# The most recent config an event was enqueued under, so flush() can sign an
# outstanding marker at shutdown. flush() takes no config (atexit has none to
# give it), and a gap that is never declared because the process was on its way
# out is exactly the gap most worth recording.
_last_config: Optional[ResolvedConfig] = None


def derive_signing_key(api_key: str) -> bytes:
    """HKDF-Extract (RFC 5869 section 2.2): PRK = HMAC-SHA256(salt, api_key).

    Identical derivation to the TS SDK and to the ingest service's signing
    path, so the server re-derives the same key from the stored API key.
    """
    return hmac_mod.new(SIGNING_SALT, api_key.encode("utf-8"), hashlib.sha256).digest()


def _get_or_derive_signing_key(api_key: str) -> bytes:
    global _signing_key, _signing_key_source
    if _signing_key is None or _signing_key_source != api_key:
        _signing_key = derive_signing_key(api_key)
        _signing_key_source = api_key
    return _signing_key


def sign_event(event: Dict[str, Any], api_key: str) -> None:
    """Stamp session/sequence fields and the chained HMAC signature in place.

    Field order and payload format mirror the TS SDK exactly; the payload is
    built by chain_format.signature_payload (format 2: the format number
    leads the payload and the content hash is length-prefixed per field).
    """
    with _sign_lock:
        _sign_event_locked(event, api_key)


def _sign_event_locked(event: Dict[str, Any], api_key: str) -> None:
    """Signing body — the caller MUST already hold ``_sign_lock``. Advances the
    session sequence and chain head (``_seq_no`` / ``_last_sig``)."""
    global _seq_no, _last_sig
    # Local import: remote.py imports this module for delivery counters,
    # so a module-level import here would be a cycle.
    from .remote import SDK_VERSION

    _seq_no += 1
    event["sdk_session_id"] = _sdk_session_id
    event["seq_no"] = _seq_no
    event["timestamp_sdk"] = int(time.time() * 1000)
    # Forensics: the event alone should say which SDK build evaluated it. Not
    # part of the signature payload, so the chain format stays version-
    # independent (mirrors the TS SDK).
    event["sdk_version"] = f"python/{SDK_VERSION}"
    # Which signing format this event verifies under (see chain_format.py).
    # The field itself only routes the verifier; the format number is also
    # the leading element of the signature payload, so stripping or rewriting
    # this field can only fail verification, never redirect it.
    event["chain_format"] = CHAIN_FORMAT_CURRENT

    if _last_sig is not None:
        event["prev_sig"] = _last_sig

    key = _get_or_derive_signing_key(api_key)
    sig_payload = signature_payload(
        CHAIN_FORMAT_CURRENT,
        event["sdk_session_id"],
        event["seq_no"],
        event["timestamp_sdk"],
        event.get("prompt") or "",
        event.get("response") or "",
        event.get("prev_sig") or None,
        # Format 3: the verdict and its attribution are inside the signature.
        # Read through the shared reader so the verifier cannot disagree about
        # the field set. Signed LAST in the build, after every layer that can
        # still change a verdict has run - signing an interim decision would
        # seal a value the event does not carry.
        decision_fields_of(event),
    )
    event["sdk_sig"] = hmac_mod.new(
        key, sig_payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    _last_sig = event["sdk_sig"]


def should_sample(rate: float) -> bool:
    """Whether an ALLOWED-call audit event should be emitted. Gates audit
    emission only — never enforcement (which runs on every call), and governed
    (blocked/redacted/error) events are always emitted regardless."""
    if rate <= 0:
        return False
    if rate >= 1:
        return True
    return random.random() < rate


def _apply_backoff() -> None:
    """Jittered exponential backoff (equal jitter): the deterministic half
    guarantees spacing, the random half prevents many clients from
    retrying in lockstep after a shared ingest outage."""
    base = min(INITIAL_BACKOFF_S * _backoff["multiplier"], MAX_BACKOFF_S)
    backoff_s = base * (0.5 + random.random() / 2)
    _backoff["until"] = time.time() + backoff_s
    _backoff["multiplier"] *= 2


def _reset_backoff() -> None:
    _backoff["until"] = 0.0
    _backoff["multiplier"] = 1.0


def _classify_status(status: int, path: str) -> str:
    """Failure taxonomy (SPEC posture, OTel consumererror pattern):
    'ok'        2xx, or a final server-side verdict (single-event 403).
    'retryable' 408/429/5xx and transport errors: retrying can help.
    'permanent' every other 4xx: the same bytes will always fail
                (bad key, malformed event, body too large). Retrying a
                permanent failure only burns quota and hides the bug."""
    if 200 <= status < 300:
        return "ok"
    if status == 403 and path == INGEST_PATH:
        # Server-side policy block on the single-event path: final verdict.
        return "ok"
    if status in (408, 429) or status >= 500:
        return "retryable"
    if 400 <= status < 500:
        return "permanent"
    return "retryable"


#: The reject code ingest returns for an event it has already recorded.
DUPLICATE_EVENT_ERROR = "duplicate_event"


def _is_duplicate_conflict(raw: Any) -> bool:
    """Whether a 409 body is ingest's duplicate response.

    A duplicate means a retry raced a lost 2xx: the event is ALREADY durably
    recorded, so this is idempotent success. Counting it as a drop would
    fabricate a coverage gap for evidence that exists - the worst direction for
    an audit counter to be wrong in. Only this exact code is absorbed: a 409
    `sequence_fork` means that chain position belongs to a DIFFERENT signature
    and must stay a failure. An unreadable or non-JSON body is NOT a duplicate.
    (Twin of the TS sender's isDuplicateConflict.)
    """
    try:
        body = json.loads(raw)
    except Exception:
        return False
    return isinstance(body, dict) and body.get("error") == DUPLICATE_EVENT_ERROR


def _count_rejects(config: ResolvedConfig, body: Any, events: list) -> int:
    """Per-event rejects inside an ACCEPTED batch response.

    The request succeeded; the server refused individual events (policy_blocked,
    duplicate_event, ...). Those refusals are final - never retried - but they
    are also not deliveries, so counting them as sent would overstate coverage.
    Shape mirrors the TS sender: {count?, rejected?: [{index, error, message?}]}.
    """
    if not isinstance(body, dict):
        return 0
    rejected = body.get("rejected")
    if not isinstance(rejected, list) or not rejected:
        return 0
    drops = 0
    for entry in rejected:
        if not isinstance(entry, dict):
            drops += 1
            continue
        idx = entry.get("index")
        event = events[idx] if isinstance(idx, int) and 0 <= idx < len(events) else None
        label = (event or {}).get("request_id") or f"index {idx}"
        if entry.get("error") == DUPLICATE_EVENT_ERROR:
            # Already recorded: counts as sent, never as a drop.
            _debug_warn(config, f"Audit event already recorded (duplicate): {label}")
            continue
        drops += 1
        _debug_warn(
            config,
            f"Audit event rejected by server ({entry.get('error')}) - dropping: {label}",
        )
    # Never exceed the batch: a malformed body cannot inflate the counter.
    return min(drops, len(events))


def _debug_warn(config: ResolvedConfig, message: str) -> None:
    if getattr(config, "debug", False):
        logging.getLogger("obsvr").warning(message)


def _post(config: ResolvedConfig, path: str, payload: Any, events: Optional[list] = None) -> Any:
    """POST JSON; returns 'ok' | 'retryable' | 'permanent'.

    429 and retryable failures arm the (jittered) backoff window. When
    ``events`` is given (the batch path), the 2xx response BODY is read and the
    return becomes ``(verdict, rejected_count)`` - without reading it, a
    per-event refusal inside an accepted batch is invisible and miscounted as
    a delivery.
    """
    url = f"{config.ingest_url}{path}"
    data = json.dumps(payload).encode("utf-8")
    rejected = 0
    try:
        # Request construction is inside the guard because an unset ingest_url
        # makes the URL unusable, and that must be a delivery failure like any
        # other - retried, then counted as a drop - not an exception that kills
        # the worker thread. Same observable outcome as the TS sender, whose
        # fetch rejects on the same input.
        req = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                API_KEY_HEADER: config.api_key,
            },
            method="POST",
        )
        resp = urlopen(req, timeout=config.timeout)
        status = getattr(resp, "status", None)
        if status is None and hasattr(resp, "getcode"):
            status = resp.getcode()
        verdict = _classify_status(status or 0, path)
        if status == 409:
            # A 409 can arrive here rather than as an HTTPError depending on the
            # opener in use, so the duplicate check lives on both paths.
            try:
                if _is_duplicate_conflict(resp.read()):
                    verdict = "ok"
            except Exception:
                pass
        elif verdict == "ok" and events is not None:
            # Best-effort: a body that is absent, truncated, or not JSON means
            # no rejects were reported, never a failed delivery.
            try:
                raw = resp.read()
                rejected = _count_rejects(config, json.loads(raw), events)
            except Exception:
                rejected = 0
    except HTTPError as err:
        verdict = _classify_status(err.code, path)
        if err.code == 409:
            try:
                if _is_duplicate_conflict(err.read()):
                    # Single event or whole re-submitted batch: already recorded.
                    verdict = "ok"
            except Exception:
                pass
    except Exception:
        verdict = "retryable"
    if verdict == "ok":
        _reset_backoff()
    elif verdict == "retryable":
        _apply_backoff()
    return (verdict, rejected) if events is not None else verdict


def _send_event(config: ResolvedConfig, event: Dict[str, Any]) -> str:
    return _post(config, INGEST_PATH, event)


def _send_event_batch(config: ResolvedConfig, events: list) -> tuple:
    """One request for up to SEND_BATCH_SIZE events via /ingest/batch.

    The server accepts/rejects per event, so a blocked or duplicate event never
    costs the others; 'retryable' means a transport failure worth retrying.
    Returns ``(verdict, rejected_count)`` - the count of events the server
    refused individually, so the caller can account for them as delivered and
    refused rather than sent (twin of the TS sendEventBatch).
    """
    return _post(config, INGEST_BATCH_PATH, events, events=events)


def _worker_loop() -> None:
    """Drain the queue in batches bounded by BOTH item count and serialized
    bytes per request (a burst of N calls costs ~N/25 requests while large
    prompts split instead of failing the whole batch). Retryable failures
    requeue with a bounded per-item budget; permanent failures (4xx other
    than 408/429) dead-letter immediately: the same bytes will always fail."""
    global _dropped
    while True:
        first = _queue.get()
        batch = [first]
        try:
            batch_bytes = len(json.dumps(first[1]))
            while len(batch) < SEND_BATCH_SIZE:
                try:
                    item = _queue.get_nowait()
                except Empty:
                    break
                item_bytes = len(json.dumps(item[1]))
                if batch and batch_bytes + item_bytes > MAX_BATCH_BYTES:
                    # Byte budget reached: send what we have, put this one
                    # back for the next batch.
                    try:
                        _queue.put_nowait(item)
                    except Full:
                        _dropped += 1
                        _bump("dropped_overflow")
                    _queue.task_done()
                    break
                batch.append(item)
                batch_bytes += item_bytes

            wait = _backoff["until"] - time.time()
            if wait > 0 and not _shutdown.is_set():
                # Interruptible: at shutdown the worker drains immediately instead
                # of waiting out the backoff, so the atexit flush can deliver.
                _shutdown.wait(min(wait, MAX_BACKOFF_S))

            config = batch[0][0]
            events = [item[1] for item in batch]
            if len(events) == 1:
                verdict, rejected = _send_event(config, events[0]), 0
            else:
                verdict, rejected = _send_event_batch(config, events)
            if verdict == "ok":
                # Events the server refused individually were delivered but not
                # accepted: they count as rejected, never as sent. The batch
                # itself succeeded, so no backoff is armed for them.
                _bump("sent", len(events) - rejected)
                if rejected > 0:
                    _bump("dropped_rejected", rejected)
                    _dropped += rejected
            elif verdict == "permanent":
                _dropped += len(batch)
                _bump("dropped_permanent", len(batch))
            else:  # retryable
                for item in batch:
                    cfg, ev = item[0], item[1]
                    retries = item[2] if len(item) > 2 else 0
                    if retries < MAX_SEND_RETRIES:
                        try:
                            _queue.put_nowait((cfg, ev, retries + 1))
                            _bump("retries")
                        except Full:
                            _dropped += 1
                            _bump("dropped_overflow")
                    else:
                        _dropped += 1
                        _bump("dropped_retry_exhausted")
        except Exception:
            pass
        finally:
            for _ in batch:
                _queue.task_done()


def _ensure_worker() -> None:
    global _worker, _atexit_registered
    with _worker_lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(
                target=_worker_loop, name="obsvr-sender", daemon=True
            )
            _worker.start()
        if not _atexit_registered:
            atexit.register(_atexit_flush)
            _atexit_registered = True


def _atexit_flush() -> None:
    # Wake the worker out of any backoff sleep so it drains without waiting, then
    # give the flush a wider budget than a single backoff step.
    _shutdown.set()
    try:
        flush(timeout=5.0)
    except Exception:
        pass


def _stamp_integrity_flags(event: Dict[str, Any]) -> None:
    """Stamp per-event integrity flags into reserved metadata.

    One additive array carrying the degraded states an auditor must see even
    though nothing failed loudly - today only ``policy_verification_unavailable``
    (a policy key is pinned but no Ed25519 backend is installed). Stamped HERE
    because this is the single enqueue choke point every emission path uses, so
    "every affected event" needs no per-caller cooperation. Metadata is not part
    of the HMAC preimage (see ``_sign_event_locked``), so this cannot disturb the
    chain. Reserved-metadata carriage with a written promotion plan, per the
    ``obsvr_external_backend`` precedent; the trimmer preserves obsvr_* keys.
    """
    from .policy_verify import INTEGRITY_FLAGS_METADATA_KEY, integrity_flags

    flags = integrity_flags()
    if not flags:
        return
    md = dict(event.get("metadata") or {})
    existing = md.get(INTEGRITY_FLAGS_METADATA_KEY)
    merged = list(existing) if isinstance(existing, list) else []
    for flag in flags:
        if flag not in merged:
            merged.append(flag)
    md[INTEGRITY_FLAGS_METADATA_KEY] = merged
    event["metadata"] = md


def _build_gap_marker(config: ResolvedConfig, dropped: int) -> Dict[str, Any]:
    """Build the gap-marker event declaring ``dropped`` lost events.

    Shaped after the ``governance_disabled`` event: an SDK-authored
    ``policy_flag`` carrying its identity in ``metadata.governance_event``,
    since ingest's ``event_type`` enum has no member for a delivery-layer
    record and inventing one would get the marker rejected as malformed -
    losing the record of loss to the same failure it exists to report.

    ``policy_version`` is "none" rather than the live ruleset hash: no policy
    evaluated this event, and stamping a hash would assert that one did.
    Field-for-field twin of the TS ``buildGapMarker``.
    """
    global _gap_marker_ordinal
    _gap_marker_ordinal += 1
    return {
        "request_id": f"audit-gap-{_sdk_session_id}-{_gap_marker_ordinal}",
        "environment": getattr(config, "environment", None),
        "region": getattr(config, "default_region", None) or "unknown",
        "provider": "unknown",
        "model": "none",
        "operation": AUDIT_GAP_OPERATION,
        "source": "obsvr_sdk",
        # The claim itself, in the signed content preimage (see audit_gap.py).
        "prompt": format_audit_gap_prompt(dropped, AUDIT_GAP_REASON_QUEUE_OVERFLOW),
        "response": "",
        "success": True,
        "latency_ms": 0,
        "event_type": "policy_flag",
        "policy_version": "none",
        "action_taken": "allowed",
        "action_reason": "none",
        "action_source": "builtin",
        "redacted_types": [],
        "blocked_types": [],
        "metadata": {
            "governance_event": AUDIT_GAP_GOVERNANCE_EVENT,
            # Structured copy for querying. Unsigned - `prompt` is authoritative.
            AUDIT_GAP_METADATA_KEY: {
                "dropped": dropped,
                "reason": AUDIT_GAP_REASON_QUEUE_OVERFLOW,
            },
        },
    }


def _declare_pending_gap(
    config: Optional[ResolvedConfig], force: bool = False
) -> Optional[Dict[str, Any]]:
    """Put any undeclared overflow drops on the record. Caller holds ``_sign_lock``.

    Unforced, this needs room for the marker AND the event whose arrival proved
    there was room: a marker that displaced that event would drop it, re-open
    the gap, and emit one marker per event for as long as the burst lasted.

    ``force`` is for the flush path, and it is the case that matters most - a
    shutdown after a saturated burst finds the queue FULL, which is precisely
    when the capacity rule would refuse and the loss would die with the
    process. Forcing overshoots the bound by exactly one item, on a queue that
    is already draining, to keep the one event that says the others are gone.

    Returns the marker it enqueued, so the caller can mirror it to OTel once it
    is no longer holding the lock.
    """
    global _gap_pending
    if _gap_pending == 0 or config is None:
        return None
    if not force and _queue.qsize() + 2 > MAX_QUEUE_SIZE:
        return None

    dropped = _gap_pending
    marker = _build_gap_marker(config, dropped)
    sign_event(marker, config.api_key)
    try:
        if force:
            # Deliberately past maxsize: `put_nowait` would raise on the full
            # queue this path exists to handle. One item, on a draining queue.
            with _queue.mutex:
                _queue.queue.append((config, marker, 0))
                _queue.unfinished_tasks += 1
                _queue.not_empty.notify()
        else:
            _queue.put_nowait((config, marker, 0))
    except Full:
        # Lost the last slot to a racing producer. Leave the pending count
        # intact and let the next opportunity carry it - but the chain head
        # cannot stay advanced past an event that was never delivered.
        _rewind_chain_to(marker)
        return None
    _gap_pending = 0
    _bump("enqueued")
    _bump("gap_markers")
    _bump("gap_events_declared", dropped)
    _debug_warn(
        config,
        f"Recording audit gap in the signed chain: {dropped} dropped event(s)",
    )
    return marker


def _rewind_chain_to(event: Dict[str, Any]) -> None:
    """Undo the chain advance a signed-but-undelivered event caused.

    Caller holds ``_sign_lock``. Restores the head to the event's predecessor,
    which its own ``prev_sig`` still names.
    """
    global _seq_no, _last_sig
    _seq_no = int(event.get("seq_no") or 1) - 1
    _last_sig = event.get("prev_sig") or None


def send_audit_async(config: ResolvedConfig, event: Dict[str, Any]) -> None:
    """Enqueue an audit event for fire-and-forget sending.

    Drops the event when the queue is full (prevents memory growth).
    Every accepted event is signed into the SDK integrity chain before
    enqueueing, matching the TS SDK behavior.
    """
    global _dropped, _seq_no, _last_sig, _gap_pending, _last_config
    if config.disabled:
        return
    _stamp_integrity_flags(event)
    # sign and enqueue ATOMICALLY under the sign lock. If the put failed
    # AFTER signing (the queue filled between a bare full() check and put_nowait,
    # or a concurrent producer/worker took the last slot), the event would be
    # signed — advancing _seq_no/_last_sig — but never delivered, so the next
    # event's prev_sig references a seq the server never saw and the whole
    # chain fails verification. Holding the lock across check+sign+put lets us
    # roll the chain head back cleanly on Full.
    with _sign_lock:
        _last_config = config
        if _queue.full():
            _dropped += 1
            _bump("dropped_overflow")
            # Counted AND remembered: the counter is process-local and dies
            # with the process, so until a marker carries it into the signed
            # chain the loss is not on the record (see audit_gap.py).
            _gap_pending += 1
            return
        # The queue has room, so the gap that just ended can be declared.
        # Emitted BEFORE this event so the marker sits between the last event
        # that survived and the first one after the loss.
        marker = _declare_pending_gap(config)
        prev_seq, prev_sig = _seq_no, _last_sig
        # Public entry point (re-acquires the reentrant lock) so tests and
        # callers that hook sign_event still see every signed event.
        sign_event(event, config.api_key)
        try:
            _queue.put_nowait((config, event, 0))
            enqueued = True
        except Full:
            _seq_no, _last_sig = prev_seq, prev_sig  # roll back: never entered the chain
            _dropped += 1
            _bump("dropped_overflow")
            _gap_pending += 1
            enqueued = False
        if enqueued:
            _bump("enqueued")
    # Optional OTel mirror - fire-and-forget, never affects the audit path.
    # Marker first: that is its order in the chain. A marker that made it into
    # the queue is mirrored even when the event behind it did not.
    if marker is not None:
        _mirror(config, marker)
    if not enqueued:
        return
    _mirror(config, event)
    _ensure_worker()


def _mirror(config: ResolvedConfig, event: Dict[str, Any]) -> None:
    """OTel mirror, done outside the sign lock so a slow exporter cannot stall
    the chain."""
    from .otel_mirror import mirror_to_otel

    mirror_to_otel(config, event)


def get_queue_size() -> int:
    return _queue.qsize()


def get_dropped_count() -> int:
    return _dropped


def get_pending_gap_count() -> int:
    """Overflow drops not yet declared by a gap marker. Non-zero only between a
    drop and the next moment the queue had room; a flush drives it to zero."""
    return _gap_pending


def flush(timeout: float = 5.0) -> None:
    """Wait until all queued events are processed (graceful shutdown).

    Declares any outstanding gap first, so a shutdown that follows a saturated
    burst still leaves the loss on the record. Forced (reserve 0): the queue is
    about to drain, and a marker that misses this flush may never be written at
    all.
    """
    with _sign_lock:
        marker = _declare_pending_gap(_last_config, force=True)
    if marker is not None and _last_config is not None:
        _mirror(_last_config, marker)
        _ensure_worker()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _queue.unfinished_tasks == 0:
            return
        time.sleep(0.01)


def _reset_sender() -> None:
    """Reset sender state (tests only). The worker thread stays alive."""
    global _dropped, _seq_no, _last_sig, _signing_key, _signing_key_source
    global _gap_pending, _gap_marker_ordinal, _last_config
    while True:
        try:
            _queue.get_nowait()
            _queue.task_done()
        except Empty:
            break
    _reset_backoff()
    _shutdown.clear()
    _dropped = 0
    with _stats_lock:
        for k in _stats:
            _stats[k] = 0
    with _sign_lock:
        _seq_no = 0
        _last_sig = None
        _signing_key = None
        _signing_key_source = None
        _gap_pending = 0
        _gap_marker_ordinal = 0
        _last_config = None
