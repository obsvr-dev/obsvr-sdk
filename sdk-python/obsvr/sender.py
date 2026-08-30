"""Fire-and-forget audit sender.

Bounded queue.Queue(MAX_QUEUE_SIZE, currently 1000) + daemon worker thread, urllib.request POST to
{ingest_url}/ingest with X-API-Key, 429 backoff (1s -> 60s, x2), and a
shutdown flush on both atexit and SIGTERM/SIGINT. The delivery path never
blocks or breaks the caller's LLM path: the enqueue is non-blocking and the
POST happens on the worker thread.

The signal half exists because atexit alone does not run on a default-
disposition SIGTERM, which is how every container runtime stops a process --
so a rolling deploy dropped whatever the queue still held. Ownership rules,
and the two places the platform forces a departure from the TypeScript twin,
are stated in full above ``_install_signal_handlers``.

The one exception, stated because the blanket claim used to hide it: when
``otel.enabled`` is set, ``_mirror`` runs the exporter SYNCHRONOUSLY on the
caller's thread, so a slow OTel exporter does add to the caller's latency. It
runs after the enqueue, so it cannot delay or lose the audit event itself
(the TypeScript twin mirrors BEFORE its push and does not have that ordering
property).

Every enqueued event is stamped with the SDK integrity chain, byte-for-byte
compatible with the TypeScript SDK (sdk-typescript/src/proxy/sender/fire-and-forget.ts)
so ingest-side verification code treats both identically:

- sdk_session_id : stable UUID until fork or declared post-sign delivery loss
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
import os
import random
import signal
import threading
import time
import uuid
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .audit_gap import (
    AUDIT_GAP_GOVERNANCE_EVENT,
    AUDIT_GAP_METADATA_KEY,
    AUDIT_GAP_OPERATION,
    AUDIT_GAP_REASON_INGEST_REJECTED,
    AUDIT_GAP_REASON_PERMANENT_FAILURE,
    AUDIT_GAP_REASON_QUEUE_OVERFLOW,
    AUDIT_GAP_REASON_RETRY_EXHAUSTED,
    format_audit_gap_prompt,
    read_audit_gap_claim,
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
#: Budget for the shutdown flush, on every path that has one.
SHUTDOWN_FLUSH_TIMEOUT_S = 5.0

_queue: "Queue[Any]" = Queue(maxsize=MAX_QUEUE_SIZE)
# Unbounded, worker-only carry for ALREADY-SIGNED items that need the next
# byte-bounded batch or a retry. Its size is bounded by construction (one split
# item plus one failed SEND_BATCH_SIZE batch), while keeping it separate means
# producers can never consume the slot an older signed item needs to survive.
_worker_pending: "Queue[Any]" = Queue()
# One item that crossed the byte budget belongs before every other pending
# retry/item, so it gets its own front slot rather than going to the tail.
_worker_front: "Queue[Any]" = Queue(maxsize=1)
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
    "durable_write_failures": 0,
    "durable_deferred": 0,
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
#: Optional client-held device signing identity (see obsvr/device_identity.py).
#: Installed by init() when device_signing_key_file is configured; None means
#: exactly the pre-existing behaviour — HMAC only.
_device_signer: Optional[Any] = None


def configure_device_signer(signer: Optional[Any]) -> None:
    """Install (or clear) the device signing identity for this process.

    Called from init() with an already-loaded ``DeviceSigner``; the loud
    validation lives there. Under ``_sign_lock`` so an in-flight signing sees
    either the old identity or the new one, never a torn pair of fields.
    """
    global _device_signer
    with _sign_lock:
        _device_signer = signer
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
_queued_outbox_ids: set[str] = set()
# Serializes the filesystem record with its in-memory queue reservation. Without
# this lock, flush() can discover a just-persisted record before the producer
# records its id, enqueue it twice, and create duplicate loss declarations.
_durable_queue_lock = threading.RLock()


def configure_durable_delivery(config: ResolvedConfig) -> None:
    """Configure and replay the optional disk-backed audit outbox."""
    global _last_config
    from . import durable_outbox

    with _durable_queue_lock:
        durable_outbox.configure(getattr(config, "durable_delivery", None))
        _last_config = config
        _refill_durable_queue(config)
    if get_queue_size() > 0:
        _ensure_worker()


def get_delivery_status() -> Dict[str, Any]:
    """Return memory-delivery counters plus durable outbox state."""
    from . import durable_outbox

    return {"sender": get_sender_stats(), "durable": durable_outbox.status()}


def _refill_durable_queue(config: Optional[ResolvedConfig] = None) -> None:
    """Load persisted work into the bounded queue without duplicating it."""
    from . import durable_outbox

    cfg = config or _last_config
    if cfg is None or not durable_outbox.enabled():
        return
    with _durable_queue_lock:
        replayed = 0
        for record in durable_outbox.pending_records():
            record_id = record["id"]
            if record_id in _queued_outbox_ids:
                continue
            try:
                _queue.put_nowait((cfg, record["event"], 0, record_id))
            except Full:
                break
            _queued_outbox_ids.add(record_id)
            replayed += 1
        durable_outbox.mark_replayed(replayed)


def _reseed_chain_after_fork() -> None:
    """Give the child process its own chain, in the child.

    ``_sdk_session_id`` and ``_seq_no`` are module state, and ``os.fork()``
    copies module state. So the recommended deployment for this SDK's most
    common host -- a pre-forking application server, which imports the app in
    the parent and forks N workers -- gave every worker the SAME session id and
    a sequence that restarts from wherever the parent had got to. N workers
    produce N divergent chains all claiming one session, each one looking like a
    fork of the others. Ingest ALREADY detects this and calls it
    ``sequence_fork``: the detection existed and the prevention did not.

    Four things move, and the last two are why this is not a three-line change:

    * a fresh session id, because two chains must never claim one session;
    * ``_seq_no``/``_last_sig`` back to the start, because the child's first
      event is the head of a NEW chain, not a continuation of the parent's;
    * the QUEUE is replaced rather than inherited. The child would otherwise
      hold a copy of every event the parent had signed but not yet delivered,
      and deliver it a second time -- the parent still owns those, and they
      carry the parent's session and sequence, so a child re-sending them is a
      replay rather than a rescue. Dropping the child's copy is the correct
      half: the parent has not lost them;
    * every lock is rebuilt. Only the forking thread survives a fork, so a lock
      another thread happened to hold at that instant is held forever in the
      child. ``_sign_lock`` guards sign-and-enqueue, so inheriting it locked
      would hang the first governed call in every worker.

    Registered with ``after_in_child`` only, paired with an acquire/release of
    ``_sign_lock`` around the fork itself so the chain head cannot be observed
    mid-advance. What is deliberately NOT changed is the sign-and-enqueue
    atomicity this rests on: it stays a single reentrant-lock section with
    ``_seq_no``/``_last_sig`` rolled back on ``Full``, so a signed-but-undelivered
    event still cannot fork the chain on its own.

    Twin: none. The TypeScript SDK has no ``fork()`` to survive.
    """
    global _sdk_session_id, _seq_no, _last_sig
    global _queue, _worker_pending, _worker_front
    global _sign_lock, _stats_lock, _worker_lock, _durable_queue_lock, _worker
    global _gap_pending, _gap_marker_ordinal, _dropped

    _sign_lock = threading.RLock()
    _stats_lock = threading.Lock()
    _worker_lock = threading.Lock()
    _durable_queue_lock = threading.RLock()

    _sdk_session_id = str(uuid.uuid4())
    _seq_no = 0
    _last_sig = None

    # A fresh queue: drops the parent's undelivered events (the parent still has
    # them) and discards any queue-internal lock inherited in a locked state.
    _queue = Queue(maxsize=MAX_QUEUE_SIZE)
    _worker_pending = Queue()
    _worker_front = Queue(maxsize=1)

    # These describe the PARENT's losses and its markers. The child has had none.
    _gap_pending = 0
    _gap_marker_ordinal = 0
    _dropped = 0

    # The inherited Thread object names a thread that does not exist here.
    # `_ensure_worker` already re-checks `is_alive()`, so this is belt rather
    # than braces -- but a `_worker` that reports a dead thread is a confusing
    # thing to leave lying around in a child.
    _worker = None


def _acquire_sign_lock_before_fork() -> None:
    """Hold the chain lock across the fork so no thread is mid-advance."""
    _sign_lock.acquire()


def _release_sign_lock_after_fork() -> None:
    try:
        _sign_lock.release()
    except RuntimeError:
        # In the child the lock object has already been replaced by
        # _reseed_chain_after_fork, so there is nothing to release.
        pass


# POSIX only; Windows has no fork and no register_at_fork.
if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_acquire_sign_lock_before_fork,
        after_in_parent=_release_sign_lock_after_fork,
        after_in_child=_reseed_chain_after_fork,
    )


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
        decision_fields_of(event, CHAIN_FORMAT_CURRENT),
    )
    event["sdk_sig"] = hmac_mod.new(
        key, sig_payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if _device_signer is not None:
        # The optional second seal: the SAME payload, signed by the
        # operator-held Ed25519 key. Additive by construction — the HMAC
        # preimage above is byte-identical with or without it, so every
        # existing chain and verifier is untouched, while a verifier that
        # pins this key gets non-repudiation against every party that does
        # not hold it (an API-key holder included). The key id is inside the
        # device preimage, so neither it nor the version label can be
        # swapped without breaking the signature.
        event["device_key_id"] = _device_signer.key_id
        event["device_sig"] = _device_signer.sign_payload(sig_payload)
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


def should_emit(config: Any, *, governed: bool = False) -> bool:
    """Whether an audit event should pass the emission sampling gate.

    Monitor mode is an evidence-collection mode, so it records clean allowed
    events even when ``sample_rate`` is zero. Enforce mode retains the ordinary
    allowed-event sampling contract. Governed/error evidence is unconditional
    in either mode.
    """
    if governed or getattr(config, "enforcement_mode", "enforce") == "monitor":
        return True
    return should_sample(getattr(config, "sample_rate", 1.0))


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
    'ok'        2xx: the server accepted the request.
    'rejected'  the server answered, understood, and REFUSED (single-event
                403). Final like a permanent failure, but its own verdict
                because the server saw the event and said no, which is a
                different audit story from never having reached it.
    'retryable' 408/429/5xx and transport errors: retrying can help.
    'permanent' every other 4xx, and every 3xx: retrying the same bytes AT THE
                SAME MOMENT will not help (malformed event, body too large, an
                ingest URL that redirects). Auth-class 4xx (401/403) are in
                this class too, and they are the reason the header no longer
                says "the same bytes will always fail": that is key state, not
                a property of the bytes. Measured — a 401 is discarded with
                zero retries, and the identical event re-posted with the same
                key header succeeds once the sink answers 200. Retrying an
                auth failure in a hot loop burns quota and hides the bug, so it
                is still classed permanent; the event is discarded rather
                than held.

    ONLY A 2xx IS A DELIVERY. A 403 on the single-event path used to classify
    'ok', on the reasoning that a server-side policy refusal is a final verdict
    rather than something to retry. Final it is; delivered it is not, and 'ok'
    is the verdict that increments ``sent``. The batch path had it right all
    along — it reads the response body and books per-event refusals as
    ``dropped_rejected`` — so the same 403 was counted as a delivery or as a
    loss depending only on how many events happened to be queued behind it.
    Worse, the status is shared: a server that answers 403 for
    ``invalid_sdk_signature`` produced a run where the SDK reported 100%
    delivery and the sink had stored nothing.
    """
    if 200 <= status < 300:
        return "ok"
    if status == 403 and path == INGEST_PATH:
        return "rejected"
    if status in (408, 429) or status >= 500:
        return "retryable"
    if 300 <= status < 500:
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
    drops = 0
    duplicates = 0
    for entry in rejected if isinstance(rejected, list) else ():
        if not isinstance(entry, dict):
            drops += 1
            continue
        idx = entry.get("index")
        event = events[idx] if isinstance(idx, int) and 0 <= idx < len(events) else None
        label = (event or {}).get("request_id") or f"index {idx}"
        if entry.get("error") == DUPLICATE_EVENT_ERROR:
            # Already recorded: counts as sent, never as a drop.
            duplicates += 1
            _debug_warn(config, f"Audit event already recorded (duplicate): {label}")
            continue
        drops += 1
        _debug_warn(
            config,
            f"Audit event rejected by server ({entry.get('error')}) - dropping: {label}",
        )
    # RECONCILE AGAINST THE ACCEPTED COUNT. The response states how many it
    # took; a server that took fewer than it was sent has refused the rest
    # whether or not it enumerated them, and crediting the difference to
    # ``sent`` would overstate coverage on the strength of a field the sender
    # read and then ignored. A duplicate counts toward the delivered side, not
    # the shortfall: the server did not take it because it already had it.
    accepted = body.get("count")
    if isinstance(accepted, int) and not isinstance(accepted, bool):
        shortfall = len(events) - accepted - duplicates
        if shortfall > drops:
            _debug_warn(
                config,
                f"Ingest accepted {accepted} of {len(events)} audit events and "
                f"enumerated {drops} refusal(s); counting the "
                f"{shortfall - drops} unaccounted event(s) as dropped",
            )
            drops = shortfall
    # Never exceed the batch, and never below zero: a malformed body cannot
    # inflate the counter or manufacture deliveries.
    return max(0, min(drops, len(events)))


def _debug_warn(config: ResolvedConfig, message: str) -> None:
    if getattr(config, "debug", False):
        logging.getLogger("obsvr").warning(message)


#: Seconds between loss warnings. The first loss speaks immediately; a sustained
#: outage then costs one line a minute rather than one per event.
_LOSS_WARN_INTERVAL_S = 60.0
_loss_warned_at = 0.0


def _warn_events_lost(count: int, reason: str) -> None:
    """Say out loud, at DEFAULT settings, that audit events were lost.

    Everything else on this path speaks only under ``debug=True``, and that is
    how a run that delivered nothing looked like a run that delivered
    everything: the counters knew, the counters are not exported, and the
    process that held them exited. The same principle ``config.py`` states for
    configuration — silent misconfiguration of a governance SDK is itself a
    governance failure — applies at least as strongly to silent loss of the
    evidence, so this one is a warning nobody has to opt into.

    Rate-limited rather than once-per-process: a second outage an hour later is
    news again, and a burst is not.
    """
    global _loss_warned_at
    now = time.monotonic()
    if _loss_warned_at and now - _loss_warned_at < _LOSS_WARN_INTERVAL_S:
        return
    _loss_warned_at = now
    logging.getLogger("obsvr").warning(
        "obsvr: %d audit event(s) were NOT recorded (%s). The audit trail for "
        "this process is incomplete; obsvr.sender.get_sender_stats() has the "
        "counts, and debug=True logs each one.",
        count,
        reason,
    )


class _RefuseSilentRedirect(HTTPRedirectHandler):
    """Never let a redirect turn an audit POST into a body-less GET.

    urllib's default follows 301/302/303 by rewriting the request to a GET
    WITHOUT the body, so the event is discarded in the client and the redirect
    target's 200 is what the classifier sees — a delivery counted for bytes
    that were never sent anywhere. Refusing the redirect surfaces the 3xx
    instead, which classifies permanent: an ingest URL that redirects is a
    misconfiguration to fix, not a condition to retry around.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


#: The module's one HTTP entry point. Same name and same call shape as
#: ``urllib.request.urlopen``, which it replaces, so every caller and every test
#: seam is unchanged — what differs is the redirect disposition above.
urlopen = build_opener(_RefuseSilentRedirect).open


def _post(config: ResolvedConfig, path: str, payload: Any, events: Optional[list] = None) -> Any:
    """POST JSON; returns 'ok' | 'rejected' | 'retryable' | 'permanent'.

    429 and retryable failures arm the (jittered) backoff window. When
    ``events`` is given, the 2xx response BODY is read and the return becomes
    ``(verdict, rejected_count)`` - without reading it, a per-event refusal
    inside an accepted batch is invisible and miscounted as a delivery. BOTH
    call sites now pass it: the single-event path used to omit ``events``, so
    the body-reading branch was unreachable for it and a 200 carrying
    ``{"rejected": [...]}`` counted as a clean delivery of the event the server
    had just refused in that very response.
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
    if verdict in ("ok", "rejected"):
        # The server answered. The transport is healthy whichever way it ruled,
        # so the backoff window is cleared for both.
        _reset_backoff()
    elif verdict == "retryable":
        _apply_backoff()
    return (verdict, rejected) if events is not None else verdict


def _send_event(config: ResolvedConfig, event: Dict[str, Any]) -> tuple:
    """One request for one event via /ingest.

    Passes the event through as a one-item list so the accepted-response body is
    read here exactly as it is on the batch path. Returns
    ``(verdict, rejected_count)``.
    """
    return _post(config, INGEST_PATH, event, events=[event])


def _send_event_batch(config: ResolvedConfig, events: list) -> tuple:
    """One request for up to SEND_BATCH_SIZE events via /ingest/batch.

    The server accepts/rejects per event INSIDE AN ACCEPTED (2xx) batch, so a
    blocked or duplicate event reported that way costs only itself. A batch
    answered with a 4xx is a different case and the header used to elide it:
    the verdict applies to the whole request, so every event in it is discarded
    together. A 403 costs every event in the request on both paths now — it
    used to drop all 25 here and none on the single-event path, so what a
    refusal cost depended on how many events were queued behind it.
    'retryable' means a transport failure worth retrying.
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
    than 408/429) are discarded immediately: the same bytes will always fail."""
    global _dropped
    # Items removed from Queue must never be put back into a queue producers
    # can refill between get() and put_nowait(). Two such requeues existed:
    # byte-budget carry-over and retryable delivery. If either raced a full
    # queue, an ALREADY-SIGNED event was dropped, the next event linked to its
    # missing signature, and no gap marker was armed. Keep the bounded carry
    # locally instead: at most one byte-split item plus SEND_BATCH_SIZE retries,
    # and always drain it before reading newer queue entries.
    while True:
        _refill_durable_queue()
        try:
            first = _worker_front.get_nowait()
            _worker_front.task_done()
        except Empty:
            try:
                first = _worker_pending.get_nowait()
                _worker_pending.task_done()
            except Empty:
                first = _queue.get()
        batch = [first]
        completed = 1
        try:
            batch_bytes = len(json.dumps(first[1]))
            first_is_durable = len(first) > 3 and bool(first[3])
            while (
                len(batch) < SEND_BATCH_SIZE
                and read_audit_gap_claim(first[1]) is None
                and not first_is_durable
            ):
                try:
                    item = _worker_front.get_nowait()
                    _worker_front.task_done()
                except Empty:
                    try:
                        item = _worker_pending.get_nowait()
                        _worker_pending.task_done()
                    except Empty:
                        try:
                            item = _queue.get_nowait()
                        except Empty:
                            break
                item_is_gap_marker = read_audit_gap_claim(item[1]) is not None
                item_is_durable = len(item) > 3 and bool(item[3])
                if batch and item_is_durable:
                    _worker_front.put(item)
                    break
                if batch and item_is_gap_marker:
                    _worker_front.put(item)
                    break
                item_bytes = len(json.dumps(item[1]))
                if batch and batch_bytes + item_bytes > MAX_BATCH_BYTES:
                    # Byte budget reached: carry this already-signed item
                    # locally into the next batch. Requeueing it could race a
                    # producer for the last slot and silently break the chain.
                    _worker_front.put(item)
                    break
                batch.append(item)
                completed += 1
                batch_bytes += item_bytes
                if item_is_gap_marker:
                    break

            wait = _backoff["until"] - time.time()
            if wait > 0 and not _shutdown.is_set():
                # Interruptible: at shutdown the worker drains immediately instead
                # of waiting out the backoff, so the atexit flush can deliver.
                _shutdown.wait(min(wait, MAX_BACKOFF_S))

            config = batch[0][0]
            events = [item[1] for item in batch]
            if len(events) == 1:
                verdict, rejected = _send_event(config, events[0])
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
                    _warn_events_lost(rejected, "refused by the ingest service")
                    _declare_delivery_gap(
                        config,
                        events,
                        rejected,
                        AUDIT_GAP_REASON_INGEST_REJECTED,
                    )
                _finish_durable_items(
                    batch,
                    rejected_reason=(
                        AUDIT_GAP_REASON_INGEST_REJECTED if rejected else None
                    ),
                )
            elif verdict == "rejected":
                # The server saw the request and refused it outright. Final, so
                # never retried — and never counted as sent, because nothing was
                # stored at the other end.
                _dropped += len(batch)
                _bump("dropped_rejected", len(batch))
                _warn_events_lost(len(batch), "refused by the ingest service")
                _declare_delivery_gap(
                    config,
                    events,
                    len(events),
                    AUDIT_GAP_REASON_INGEST_REJECTED,
                )
                _finish_durable_items(
                    batch, rejected_reason=AUDIT_GAP_REASON_INGEST_REJECTED
                )
            elif verdict == "permanent":
                _dropped += len(batch)
                _bump("dropped_permanent", len(batch))
                _warn_events_lost(
                    len(batch), "permanently undeliverable to the ingest service"
                )
                _declare_delivery_gap(
                    config,
                    events,
                    len(events),
                    AUDIT_GAP_REASON_PERMANENT_FAILURE,
                )
                _finish_durable_items(
                    batch, rejected_reason=AUDIT_GAP_REASON_PERMANENT_FAILURE
                )
            else:  # retryable
                exhausted = []
                exhausted_items = []
                for item in batch:
                    cfg, ev = item[0], item[1]
                    retries = item[2] if len(item) > 2 else 0
                    if retries < MAX_SEND_RETRIES:
                        # Retry older signed events before newer queue entries.
                        # The carry is bounded by this batch and retains the
                        # original Queue unfinished-task obligation until the
                        # event reaches a terminal verdict.
                        outbox_id = item[3] if len(item) > 3 else None
                        _worker_pending.put((cfg, ev, retries + 1, outbox_id))
                        completed -= 1
                        _bump("retries")
                    else:
                        exhausted.append(ev)
                        exhausted_items.append(item)
                        _dropped += 1
                        _bump("dropped_retry_exhausted")
                        _warn_events_lost(1, "retry budget exhausted")
                if exhausted:
                    _finish_durable_items(
                        exhausted_items,
                        rejected_reason=AUDIT_GAP_REASON_RETRY_EXHAUSTED,
                    )
                    _declare_delivery_gap(
                        config,
                        exhausted,
                        len(exhausted),
                        AUDIT_GAP_REASON_RETRY_EXHAUSTED,
                    )
        except Exception:
            pass
        finally:
            for _ in range(completed):
                _queue.task_done()


def _finish_durable_items(items: list, rejected_reason: Optional[str] = None) -> None:
    """Acknowledge delivered durable records or move terminal failures aside."""
    from . import durable_outbox

    with _durable_queue_lock:
        for item in items:
            outbox_id = item[3] if len(item) > 3 else None
            if not outbox_id:
                continue
            try:
                if rejected_reason is None:
                    durable_outbox.acknowledge(outbox_id)
                else:
                    durable_outbox.dead_letter(outbox_id, rejected_reason)
            finally:
                # If the filesystem operation fails, make the still-pending
                # record eligible for a later refill instead of stranding it.
                _queued_outbox_ids.discard(outbox_id)


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
    _install_signal_handlers()


def _atexit_flush() -> None:
    # Wake the worker out of any backoff sleep so it drains without waiting, then
    # give the flush a wider budget than a single backoff step.
    _shutdown.set()
    try:
        flush(timeout=SHUTDOWN_FLUSH_TIMEOUT_S)
    except Exception:
        pass


# ── Signal handling ─────────────────────────────────────────────────────────
#
# WHO OWNS TERMINATION. Ported from the TypeScript twin
# (sdk-typescript/src/proxy/sender/fire-and-forget.ts, ``setupExitHandlers``),
# which is the reference implementation for these rules. Installing a handler
# REPLACES the disposition that was there, so a library that installs one and
# does not end the process swallows the signal outright — which is why the
# re-raise below exists at all. But an unconditional exit is worse: it ends the
# process while the host's own shutdown is still draining connections or
# committing a transaction, and calling obsvr.init() is not consent to that.
#
# So ownership goes to the host whenever the host has a disposition of its own,
# and three rules follow from that:
#
#   * CHAIN. A prior handler that is a Python callable is the host's shutdown.
#     Flush first, then call it and let it decide what happens next. obsvr never
#     ends the process on this path.
#   * FLUSH WITHIN THE EXISTING BUDGET. The same ``SHUTDOWN_FLUSH_TIMEOUT_S``
#     the atexit flush already uses, so a Python process drains identically
#     whichever way it is stopped. (The TypeScript budget is 2s on both of its
#     paths; the two SDKs' budgets already differed at exit and this change does
#     not narrow that.)
#   * RE-RAISE ONLY FROM SIG_DFL. If the prior disposition was the default, the
#     signal was going to end the process and nothing else was listening, so
#     obsvr restores the default and re-delivers — the process then dies BY the
#     signal, which is what a supervisor reads, rather than with an exit code
#     that merely encodes one.
#
# TWO DEPARTURES FROM THE TWIN, both forced by the platform rather than chosen:
#
#   1. Node keeps a LIST of listeners, so it can ask at signal time whether the
#      host installed one after obsvr did. A POSIX disposition is a single slot:
#      a host installing its handler after obsvr REPLACES obsvr's, and obsvr's
#      flush simply never runs. Ownership is therefore decided at INSTALL time
#      here, not at signal time. Install obsvr first (call ``init()`` early) or
#      chain to ``obsvr.flush()`` from your own handler.
#   2. SIG_IGN is left alone entirely — obsvr does not install over it. A
#      process that ignores SIGTERM is not going to die from it, so there is no
#      queue tail to save, and taking the signal over would break a disposition
#      the host set deliberately.
#
# A prior disposition of ``None`` means the handler was installed from outside
# Python and cannot be called. That is unknowable rather than absent, and it
# resolves the same way the twin resolves its unknowable case: keep the exit. A
# swallowed signal hangs the process forever where a truncated one merely ends
# it early.

#: Signals obsvr will take over. SIGINT and SIGTERM only: these are the two a
#: container runtime and an operator actually send, and each one taken is an
#: imposition that has to earn its place.
_SHUTDOWN_SIGNALS = ("SIGTERM", "SIGINT")

#: signum -> the disposition that was in place when obsvr installed over it.
_prior_dispositions: Dict[int, Any] = {}
_signal_handlers_installed = False
#: Guards re-entry: a second SIGTERM during the flush must not start another.
_signal_flush_started = False


def _install_signal_handlers() -> None:
    """Install the SIGTERM/SIGINT flush, once, if this thread may."""
    global _signal_handlers_installed
    if _signal_handlers_installed:
        return
    if threading.current_thread() is not threading.main_thread():
        # Only the main thread may set a disposition. The enqueue path runs on
        # whatever thread made the governed call, so this is reached from a
        # worker often enough to be normal, not an error: atexit still covers
        # an ordinary exit, and the next enqueue from the main thread installs.
        return
    installed_any = False
    for name in _SHUTDOWN_SIGNALS:
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            prior = signal.getsignal(signum)
        except (ValueError, OSError):
            continue
        if prior is signal.SIG_IGN:
            continue  # the host ignores it deliberately; see the note above
        try:
            signal.signal(signum, _handle_shutdown_signal)
        except (ValueError, OSError, RuntimeError):
            # Not settable here (a restricted embedding, or a platform without
            # this signal). atexit remains the coverage.
            continue
        _prior_dispositions[signum] = prior
        installed_any = True
    if installed_any:
        _signal_handlers_installed = True


def _handle_shutdown_signal(signum: int, frame: Any) -> None:
    """Flush, then hand the signal on to whoever owned it before obsvr did."""
    global _signal_flush_started
    prior = _prior_dispositions.get(signum, signal.SIG_DFL)

    if not _signal_flush_started:
        _signal_flush_started = True
        try:
            _atexit_flush()
        except Exception:  # noqa: BLE001 - shutdown must not raise out of a handler
            pass

    if callable(prior):
        # The host is shutting itself down. Flushed beside it; it chooses when
        # the process ends, and obsvr never ends it out from under a drain.
        #
        # Both latches come back off, because a host handler is allowed to
        # RETURN rather than exit. ``_shutdown`` is what makes the worker skip
        # its 429 backoff, so leaving it set on a process that keeps running
        # would leave the sender hammering a rate-limited ingest for the rest of
        # its life. If the host does exit, atexit sets it again on the way out.
        _signal_flush_started = False
        _shutdown.clear()
        prior(signum, frame)
        return

    # SIG_DFL, or a disposition installed from outside Python that cannot be
    # called. Restore the default and re-deliver, so the process dies BY the
    # signal rather than with an exit code standing in for one.
    try:
        signal.signal(signum, signal.SIG_DFL)
    except (ValueError, OSError, RuntimeError):
        pass
    os.kill(os.getpid(), signum)


def _reset_signal_handlers() -> None:
    """Restore the dispositions obsvr replaced (tests only)."""
    global _signal_handlers_installed, _signal_flush_started
    for signum, prior in list(_prior_dispositions.items()):
        try:
            signal.signal(signum, prior)
        except (ValueError, OSError, RuntimeError):
            pass
    _prior_dispositions.clear()
    _signal_handlers_installed = False
    _signal_flush_started = False


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


def _build_gap_marker(
    config: ResolvedConfig,
    dropped: int,
    reason: str = AUDIT_GAP_REASON_QUEUE_OVERFLOW,
) -> Dict[str, Any]:
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
        "prompt": format_audit_gap_prompt(dropped, reason),
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
                "reason": reason,
            },
        },
    }


def _declare_delivery_gap(
    config: ResolvedConfig,
    lost_events: list,
    dropped: int,
    reason: str,
) -> Optional[Dict[str, Any]]:
    """Start a fresh signed session after post-sign delivery loss.

    Older already-signed work remains ahead of the marker. Holding the signing
    lock across session rotation, signing, and queue insertion guarantees every
    future event follows it. If the lost event is itself a marker, stop: an
    unavailable ingest must not create an infinite marker-replacement loop.
    """
    global _sdk_session_id, _seq_no, _last_sig, _gap_marker_ordinal
    if dropped <= 0 or any(read_audit_gap_claim(event) is not None for event in lost_events):
        return None

    with _sign_lock:
        _sdk_session_id = str(uuid.uuid4())
        _seq_no = 0
        _last_sig = None
        _gap_marker_ordinal = 0
        marker = _build_gap_marker(config, dropped, reason)
        sign_event(marker, config.api_key)
        with _durable_queue_lock:
            outbox_id = _persist_gap_marker(marker)
            # This evidence may be armed while the bounded queue is full. Match
            # the forced overflow-marker rule: exceed the bound by one on a
            # queue that the current worker is already draining.
            with _queue.mutex:
                _queue.queue.append((config, marker, 0, outbox_id))
                _queue.unfinished_tasks += 1
                _queue.not_empty.notify()
            if outbox_id:
                _queued_outbox_ids.add(outbox_id)
        _bump("enqueued")
        _bump("gap_markers")
        _bump("gap_events_declared", dropped)
    _debug_warn(
        config,
        f"Starting a new signed audit session after {dropped} lost event(s): {reason}",
    )
    _mirror(config, marker)
    return marker


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


def _persist_gap_marker(marker: Dict[str, Any]) -> Optional[str]:
    """Persist a signed loss declaration when durable delivery is enabled."""
    from . import durable_outbox

    try:
        return durable_outbox.persist(marker)
    except Exception as exc:
        _bump("durable_write_failures")
        logging.getLogger("obsvr").warning(
            "durable persistence failed for an audit gap marker; using memory-only delivery: %s",
            exc,
        )
        return None


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
    from . import durable_outbox
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
        durable = durable_outbox.enabled()
        if _queue.full() and not durable:
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
        outbox_id = None
        with _durable_queue_lock:
            try:
                outbox_id = durable_outbox.persist(event)
            except Exception as exc:
                _bump("durable_write_failures")
                if durable_outbox.failure_mode() == "error":
                    _seq_no, _last_sig = prev_seq, prev_sig
                    raise RuntimeError(
                        "obsvr durable audit persistence failed before enqueue"
                    ) from exc
                logging.getLogger("obsvr").warning(
                    "durable audit persistence failed; continuing with memory-only delivery: %s",
                    exc,
                )
            try:
                _queue.put_nowait((config, event, 0, outbox_id))
                if outbox_id:
                    _queued_outbox_ids.add(outbox_id)
                enqueued = True
            except Full:
                if outbox_id:
                    _bump("durable_deferred")
                    enqueued = True
                else:
                    _seq_no, _last_sig = prev_seq, prev_sig
                    _dropped += 1
                    _bump("dropped_overflow")
                    _gap_pending += 1
                    enqueued = False
        if enqueued:
            _bump("enqueued")
    # Optional OTel mirror. NOT fire-and-forget: the exporter runs
    # synchronously on this thread. It does run AFTER the enqueue, so it cannot
    # delay or lose the audit event — only the caller's own latency is exposed
    # to a slow exporter.
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


def flush(timeout: float = SHUTDOWN_FLUSH_TIMEOUT_S) -> None:
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
        _refill_durable_queue()
        from . import durable_outbox

        if (
            _queue.unfinished_tasks == 0
            and durable_outbox.status().get("pending", 0) == 0
        ):
            return
        time.sleep(0.01)


def _reset_sender() -> None:
    """Reset sender state (tests only). The worker thread stays alive."""
    global _dropped, _seq_no, _last_sig, _signing_key, _signing_key_source
    global _gap_pending, _gap_marker_ordinal, _last_config, _device_signer
    from . import durable_outbox
    # Every carried item still owns an unfinished task on the public queue.
    while True:
        try:
            _worker_front.get_nowait()
            _worker_front.task_done()
            _queue.task_done()
        except Empty:
            break
    while True:
        try:
            _worker_pending.get_nowait()
            _worker_pending.task_done()
            _queue.task_done()
        except Empty:
            break
    while True:
        try:
            _queue.get_nowait()
            _queue.task_done()
        except Empty:
            break
    _reset_backoff()
    _shutdown.clear()
    _dropped = 0
    with _durable_queue_lock:
        _queued_outbox_ids.clear()
        durable_outbox.reset()
    with _stats_lock:
        for k in _stats:
            _stats[k] = 0
    with _sign_lock:
        _seq_no = 0
        _last_sig = None
        _signing_key = None
        _signing_key_source = None
        _device_signer = None
        _gap_pending = 0
        _gap_marker_ordinal = 0
        _last_config = None
