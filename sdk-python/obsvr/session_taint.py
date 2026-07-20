"""Session taint latch.

EXACT parity with sdk/src/policy/session-taint.ts.

When a prompt-injection or a canary leak is detected in a session, the session
is marked TAINTED. Subsequent EGRESS in that session -- a tool call, tool-call
arguments, an MCP call, a framework tool execution -- is then escalated
(flagged, or blocked in strict mode), because a session compromised once
should not be trusted to keep acting: the per-call scanners can miss a
cleverly staged exfiltration, but the latch remembers the session is suspect.

This is a session-level LATCH, not data-flow label propagation. Simpler taint
latches seed only on injection, block only remote URLs, unbounded and
forever; obsvr seeds on injection AND canary, escalates every egress the SDK
sees, bounds the store, and defaults to FLAG (not a blanket block).

Honest boundary (SECURITY.md): keyed on the caller-supplied session identity
(metadata.user_id ?? session_id ?? tenant_id); with no session id every call
shares the "global" bucket. In-process only (resets on restart).
"""

import threading
from typing import Any, Dict, Optional

MAX_TAINTED_SESSIONS = 10_000

# Process-global taint store, keyed by the caller-supplied session key.
_tainted: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


def _reset_session_taint() -> None:
    """Test hook -- clears the taint store."""
    with _lock:
        _tainted.clear()


def session_taint_size() -> int:
    """Number of tainted sessions (enforce/set sites skip work when 0)."""
    with _lock:
        return len(_tainted)


def _pick_identity(v: Any) -> Optional[str]:
    """An identity value counts only if it is a NON-EMPTY string or a finite
    number (bool excluded) — byte-identical to the TS ``pickIdentity``. A
    naive ``a or b`` chain would silently diverge from the TS ``a ?? b`` on
    falsy-but-present values; both SDKs now fall through consistently."""
    if isinstance(v, str):
        return None if v == "" else v
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return str(v)
    return None


def derive_session_key(metadata: Optional[Dict[str, Any]]) -> str:
    """Session key the taint latch uses: the first present, non-empty identity
    among user_id / session_id / tenant_id, else "global". SET and ENFORCE
    MUST call this on the same identity metadata or the latch silently
    no-ops."""
    m = metadata or {}
    return (
        _pick_identity(m.get("user_id"))
        or _pick_identity(m.get("session_id"))
        or _pick_identity(m.get("tenant_id"))
        or "global"
    )


def mark_tainted(session_key: str, reason: str, now: float) -> None:
    """Mark a session tainted. Monotonic: the FIRST reason is kept, only the
    timestamp refreshes. Bounded: evicts the oldest past the cap. ``now`` is
    injected for determinism.
    """
    with _lock:
        existing = _tainted.get(session_key)
        if existing is not None:
            existing["updated_at"] = now
            return
        if len(_tainted) >= MAX_TAINTED_SESSIONS:
            oldest_key = None
            oldest_at = float("inf")
            for k, v in _tainted.items():
                if v["updated_at"] < oldest_at:
                    oldest_at = v["updated_at"]
                    oldest_key = k
            if oldest_key is not None:
                del _tainted[oldest_key]
        _tainted[session_key] = {"reason": reason, "updated_at": now}


def taint_reason(session_key: str) -> Optional[str]:
    """The taint reason for a session, or None if not tainted."""
    with _lock:
        rec = _tainted.get(session_key)
        return rec["reason"] if rec is not None else None


def touch_taint(session_key: str, now: float) -> None:
    """Refresh a tainted session's recency (no-op if untainted). Called at
    ENFORCE so an actively-enforced compromised session is not evicted by an
    attacker flooding the store to age out a long-lived victim."""
    with _lock:
        rec = _tainted.get(session_key)
        if rec is not None:
            rec["updated_at"] = now


def evaluate_session_taint(
    session_key: str, config: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Pure enforcement decision at an egress point (fixture-pinned in
    taint.json). A tainted session escalates per mode; an untainted one is a
    no-op. Returns ``{"enforcement", "reason"?}``.
    """
    if not config or not config.get("enabled"):
        return {"enforcement": "none"}
    reason = taint_reason(session_key)
    if reason is None:
        return {"enforcement": "none"}
    enforcement = "block" if config.get("action") == "block" else "flag"
    return {"enforcement": enforcement, "reason": reason}


def resolve_session_taint(config: Any) -> Optional[Dict[str, Any]]:
    """Resolve the taint sub-config (absent/disabled => None)."""
    t = getattr(config, "session_taint", None)
    if not isinstance(t, dict) or not t.get("enabled"):
        return None
    return {"enabled": True, "action": "block" if t.get("action") == "block" else "flag"}
