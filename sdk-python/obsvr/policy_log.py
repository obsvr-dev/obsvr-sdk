"""Policy change audit log — parity with sdk-typescript/src/policy/policy-log.ts."""
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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


def snapshot_policy(
    rules: List[PolicyRule],
    tenant_id: Optional[str] = None,
    resolution: Optional[str] = None,
) -> PolicySnapshot:
    """Store a snapshot of the current policy state. ``resolution`` is the
    ruleset's declared conflict-resolution mode, so the snapshot's version
    matches the one stamped on decisions evaluated under it."""
    snap = PolicySnapshot(
        version=derive_policy_version(rules, resolution),
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
    resolution: Optional[str] = None,
) -> PolicyChangedEvent:
    """Build and return a well-formed, sendable policy_changed event.
    ``resolution`` (the declared conflict-resolution mode) applies to both
    versions: the mode is a property of the deployment's declaration, not of
    either rule list."""
    previous_version = derive_policy_version(prev_rules, resolution)
    new_version = derive_policy_version(next_rules, resolution)
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


def _reset_policy_log() -> None:
    """Reset snapshot buffers (tests only)."""
    _snapshot_buffers.clear()
