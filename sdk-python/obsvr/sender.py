"""Fire-and-forget audit sender.

Bounded queue.Queue(100) + daemon worker thread, urllib.request POST to
{ingest_url}/ingest with X-API-Key, 429 backoff (1s -> 60s, x2), and an
atexit flush. Never blocks or breaks the caller's LLM path.

Every enqueued event is stamped with the SDK integrity chain, byte-for-byte
compatible with the TypeScript SDK (sdk/src/proxy/sender/fire-and-forget.ts)
so ingest-side verification code treats both identically:

- sdk_session_id : stable UUID per process lifetime
- seq_no         : monotonic 1-based counter
- timestamp_sdk  : epoch milliseconds at enqueue
- prev_sig       : sdk_sig of the previous event (chain link; absent on first)
- sdk_sig        : HMAC-SHA256(key, session|seq|ts|content_hash|prev_sig)
                   where key = HMAC-SHA256("obsvr-sdk-signing-v1", api_key)
                   and content_hash = SHA-256(prompt + response)
"""

import atexit
import hashlib
import hmac as hmac_mod
import json
import random
import threading
import time
import uuid
from queue import Empty, Full, Queue
from typing import Any, Dict, Optional
from urllib.error import HTTPError
from urllib.request import Request, urlopen

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


def derive_signing_key(api_key: str) -> bytes:
    """HKDF-Extract (RFC 5869 section 2.2): PRK = HMAC-SHA256(salt, api_key).

    Identical derivation to the TS SDK and ingest/lib/signing.ts, so the
    server re-derives the same key from the stored API key.
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

    Field order and payload format mirror the TS SDK exactly:
      sig_payload = session|seq|timestamp_ms|sha256(prompt+response)|prev_sig
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

    if _last_sig is not None:
        event["prev_sig"] = _last_sig

    key = _get_or_derive_signing_key(api_key)
    content = (event.get("prompt") or "") + (event.get("response") or "")
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    sig_payload = "|".join(
        [
            event["sdk_session_id"],
            str(event["seq_no"]),
            str(event["timestamp_sdk"]),
            content_hash,
            event.get("prev_sig") or "",
        ]
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


def _post(config: ResolvedConfig, path: str, payload: Any) -> str:
    """POST JSON; returns 'ok' | 'retryable' | 'permanent'.
    429 and retryable failures arm the (jittered) backoff window."""
    url = f"{config.ingest_url}{path}"
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            API_KEY_HEADER: config.api_key,
        },
        method="POST",
    )
    try:
        resp = urlopen(req, timeout=config.timeout)
        status = getattr(resp, "status", None)
        if status is None and hasattr(resp, "getcode"):
            status = resp.getcode()
        verdict = _classify_status(status or 0, path)
    except HTTPError as err:
        verdict = _classify_status(err.code, path)
    except Exception:
        verdict = "retryable"
    if verdict == "ok":
        _reset_backoff()
    elif verdict == "retryable":
        _apply_backoff()
    return verdict


def _send_event(config: ResolvedConfig, event: Dict[str, Any]) -> str:
    return _post(config, INGEST_PATH, event)


def _send_event_batch(config: ResolvedConfig, events: list) -> str:
    """One request for up to SEND_BATCH_SIZE events via /ingest/batch. The
    server accepts/rejects per event, so a blocked or duplicate event never
    costs the others; 'retryable' means a transport failure worth retrying."""
    return _post(config, INGEST_BATCH_PATH, events)


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
            verdict = (
                _send_event(config, events[0])
                if len(events) == 1
                else _send_event_batch(config, events)
            )
            if verdict == "ok":
                _bump("sent", len(events))
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


def send_audit_async(config: ResolvedConfig, event: Dict[str, Any]) -> None:
    """Enqueue an audit event for fire-and-forget sending.

    Drops the event when the queue is full (prevents memory growth).
    Every accepted event is signed into the SDK integrity chain before
    enqueueing, matching the TS SDK behavior.
    """
    global _dropped, _seq_no, _last_sig
    if config.disabled:
        return
    # sign and enqueue ATOMICALLY under the sign lock. If the put failed
    # AFTER signing (the queue filled between a bare full() check and put_nowait,
    # or a concurrent producer/worker took the last slot), the event would be
    # signed — advancing _seq_no/_last_sig — but never delivered, so the next
    # event's prev_sig references a seq the server never saw and the whole
    # chain fails verification. Holding the lock across check+sign+put lets us
    # roll the chain head back cleanly on Full.
    with _sign_lock:
        if _queue.full():
            _dropped += 1
            _bump("dropped_overflow")
            return
        prev_seq, prev_sig = _seq_no, _last_sig
        # Public entry point (re-acquires the reentrant lock) so tests and
        # callers that hook sign_event still see every signed event.
        sign_event(event, config.api_key)
        try:
            _queue.put_nowait((config, event, 0))
        except Full:
            _seq_no, _last_sig = prev_seq, prev_sig  # roll back: never entered the chain
            _dropped += 1
            _bump("dropped_overflow")
            return
        _bump("enqueued")
    # Optional OTel mirror - fire-and-forget, never affects the audit path.
    from .otel_mirror import mirror_to_otel
    mirror_to_otel(config, event)
    _ensure_worker()


def get_queue_size() -> int:
    return _queue.qsize()


def get_dropped_count() -> int:
    return _dropped


def flush(timeout: float = 5.0) -> None:
    """Wait until all queued events are processed (graceful shutdown)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _queue.unfinished_tasks == 0:
            return
        time.sleep(0.01)


def _reset_sender() -> None:
    """Reset sender state (tests only). The worker thread stays alive."""
    global _dropped, _seq_no, _last_sig, _signing_key, _signing_key_source
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
