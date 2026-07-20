"""Policy change audit log — parity with sdk/src/policy/policy-log.ts."""
import json
import logging
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

from .rules import PolicyRule, derive_policy_version


@dataclass
class PolicySnapshot:
    version: str
    timestamp: str  # ISO 8601
    rules_snapshot: str  # JSON string


@dataclass
class PolicyChangedEvent:
    event_type: str  # "policy_changed"
    timestamp: str
    previous_version: str
    new_version: str
    diff: Dict[str, List[str]]  # added, removed, modified
    tenant_id: Optional[str] = None
    changed_by: Optional[str] = None
    # wire fields the ingest schema requires (request_id + model) so the
    # event is ACCEPTED, not 400'd — parity with the TS PolicyChangedEvent. The
    # change detail also rides metadata.policy_change (the preserved channel).
    request_id: str = ""
    model: str = ""
    policy_version: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


MAX_SNAPSHOTS = 100
_snapshot_buffers: Dict[str, List[PolicySnapshot]] = {}


def _get_buffer(key: str) -> List[PolicySnapshot]:
    if key not in _snapshot_buffers:
        _snapshot_buffers[key] = []
    return _snapshot_buffers[key]


def snapshot_policy(rules: List[PolicyRule], tenant_id: Optional[str] = None) -> PolicySnapshot:
    """Store a snapshot of the current policy state."""
    snap = PolicySnapshot(
        version=derive_policy_version(rules),
        timestamp=datetime.now(timezone.utc).isoformat(),
        rules_snapshot=json.dumps([
            {"id": r.id, "name": r.name, "enabled": r.enabled,
             "action": r.action, "type": r.type,
             "conditions": r.conditions, "applies_to": r.applies_to}
            for r in rules
        ]),
    )
    key = tenant_id or "__global__"
    buf = _get_buffer(key)
    buf.append(snap)
    if len(buf) > MAX_SNAPSHOTS:
        buf.pop(0)
    return snap


def get_policy_at_time(
    timestamp: datetime,
    tenant_id: Optional[str] = None,
) -> Optional[PolicySnapshot]:
    """Binary search for the last snapshot at or before timestamp."""
    key = tenant_id or "__global__"
    buf = _get_buffer(key)
    if not buf:
        return None
    ts = timestamp.timestamp()
    result = None
    lo, hi = 0, len(buf) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        mid_ts = datetime.fromisoformat(buf[mid].timestamp.replace("Z", "+00:00")).timestamp()
        if mid_ts <= ts:
            result = buf[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    return result


def _compute_diff(prev: List[PolicyRule], next_rules: List[PolicyRule]) -> Dict[str, List[str]]:
    prev_map = {r.id: r for r in prev}
    next_map = {r.id: r for r in next_rules}
    added = [r.id for r in next_rules if r.id not in prev_map]
    removed = [r.id for r in prev if r.id not in next_map]
    modified = [
        r.id for r in next_rules
        if r.id in prev_map and json.dumps({"id": prev_map[r.id].id, "name": prev_map[r.id].name}) != json.dumps({"id": r.id, "name": r.name})
    ]
    return {"added": added, "removed": removed, "modified": modified}


def emit_policy_changed_event(
    prev_rules: List[PolicyRule],
    next_rules: List[PolicyRule],
    tenant_id: Optional[str] = None,
    changed_by: Optional[str] = None,
) -> PolicyChangedEvent:
    """Build and return a well-formed, sendable policy_changed event."""
    previous_version = derive_policy_version(prev_rules)
    new_version = derive_policy_version(next_rules)
    diff = _compute_diff(prev_rules, next_rules)
    return PolicyChangedEvent(
        event_type="policy_changed",
        timestamp=datetime.now(timezone.utc).isoformat(),
        tenant_id=tenant_id,
        previous_version=previous_version,
        new_version=new_version,
        changed_by=changed_by,
        diff=diff,
        request_id=str(uuid.uuid4()),
        model="",
        policy_version=new_version,
        metadata={
            "policy_change": {
                "previous_version": previous_version,
                "new_version": new_version,
                "changed_by": changed_by,
                "diff": diff,
            }
        },
    )


def send_policy_event(event: PolicyChangedEvent, ingest_url: str, api_key: str) -> None:
    """Fire-and-forget POST of a policy_changed event to /ingest (twin of TS
    sendPolicyEvent). Never raises — must not break the caller."""

    def _post() -> None:
        try:
            body = json.dumps(asdict(event)).encode("utf-8")
            req = Request(
                f"{ingest_url}/ingest",
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "X-API-Key": api_key},
            )
            with urlopen(req, timeout=5.0):  # noqa: S310 (ingest_url is operator config)
                pass
        except Exception:
            logging.getLogger("obsvr").debug("policy_changed event delivery failed", exc_info=False)

    threading.Thread(target=_post, name="obsvr-policy-event", daemon=True).start()


def _reset_policy_log() -> None:
    """Reset snapshot buffers (tests only)."""
    _snapshot_buffers.clear()
