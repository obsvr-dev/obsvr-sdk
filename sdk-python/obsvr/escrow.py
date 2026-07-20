"""Fleet-quota escrow — client side of ADR-7 (twin of sdk/src/governance/escrow.ts).

WHY: the per-process quota meter in ``rules.py`` enforces a rule PER SDK
INSTANCE, so N horizontally-scaled workers get up to N x the configured limit
in aggregate (that module discloses the gap honestly). Escrow closes it WITHOUT
adding any per-call network latency.

HOW: the server allocator hands each instance a bounded LOCAL SHARE of a rule's
global budget on the periodic ``/policies`` poll, tagged with an ``epoch``.
Between polls the instance spends that share locally (one decrement per governed
call) and BLOCKS when it is exhausted — no network on the call path. On the next
poll the instance REPORTS how much of the granted share it used (tagged with the
epoch it was granted under), and the allocator reconciles the prior grant and
re-slices the global budget into a fresh share + epoch.

FAIL-CLOSED: on a poll failure no fresh grant arrives, so the instance keeps
spending only its residual share and then blocks — it NEVER fabricates share.
When a ``/policies`` response carries no escrow for a rule, escrow is not in
effect for it and the rule falls back to the per-process meter (backward
compatible with servers that never send escrow).

The decision semantics here are pinned cross-language by
``conformance/fixtures/quota_escrow.json``.
"""
import math
import threading
from typing import Any, Dict, Optional

# rule_id -> {"remaining": float, "epoch": int, "consumed": float}.
# Absence means "no escrow in effect for this rule".
_escrow_state: Dict[str, Dict[str, float]] = {}
_escrow_lock = threading.Lock()


def has_escrow(rule_id: str) -> bool:
    """Whether the server has an escrow grant in effect for this rule."""
    with _escrow_lock:
        return rule_id in _escrow_state


def apply_escrow_grant(rule_id: str, share: Any, epoch: Any) -> None:
    """Apply one grant for a rule.

    A grant whose epoch does not strictly exceed the rule's current epoch is
    treated as stale/replayed and ignored (mirrors the server's "a stale report
    against an old epoch is ignored" rule so a reordered or duplicated response
    can never resurrect a spent share or silently reset the consumption
    counter). Applying a grant resets the per-epoch consumption counter, so
    callers MUST snapshot consumption (``snapshot_consumption``) BEFORE applying
    a poll response.
    """
    # Never fabricate share: reject non-numeric / negative values outright.
    if not isinstance(share, (int, float)) or isinstance(share, bool):
        return
    if not isinstance(epoch, (int, float)) or isinstance(epoch, bool):
        return
    if math.isnan(share) or math.isinf(share) or share < 0:
        return
    if math.isnan(epoch) or math.isinf(epoch):
        return
    with _escrow_lock:
        existing = _escrow_state.get(rule_id)
        if existing is not None and epoch <= existing["epoch"]:
            return  # stale / replayed grant
        _escrow_state[rule_id] = {
            "remaining": float(math.floor(share)),
            "epoch": epoch,
            "consumed": 0.0,
        }


def apply_escrow_response(escrow_map: Optional[Dict[str, Any]]) -> None:
    """Apply the ``quota_escrow`` map from a ``/policies`` response.

    - Rules present in the map get their grant applied (stale epochs ignored).
    - Rules that currently hold escrow but are ABSENT from the map lose it and
      fall back to the per-process meter (contract: absent rule => no escrow).
    - An absent/invalid map clears all escrow (absent field => no escrow).
    NOTE: snapshot consumption BEFORE calling this — a fresh grant resets it.
    """
    if not isinstance(escrow_map, dict):
        with _escrow_lock:
            _escrow_state.clear()
        return
    with _escrow_lock:
        for rule_id in list(_escrow_state.keys()):
            if rule_id not in escrow_map:
                del _escrow_state[rule_id]
    for rule_id, grant in escrow_map.items():
        if isinstance(grant, dict) and "share" in grant and "epoch" in grant:
            apply_escrow_grant(rule_id, grant.get("share"), grant.get("epoch"))


def spend_escrow_share(rule_id: str) -> Dict[str, Any]:
    """Spend one unit of a rule's local share.

    Blocks (allowed=False) when the share is exhausted; never goes negative and
    never fabricates share. A blocked call does NOT count toward consumption
    (the resource was not used).
    """
    with _escrow_lock:
        grant = _escrow_state.get(rule_id)
        if grant is None:
            return {"escrow": False, "allowed": False, "remaining": 0}
        if grant["remaining"] <= 0:
            return {"escrow": True, "allowed": False, "remaining": 0}
        grant["remaining"] -= 1
        grant["consumed"] += 1
        return {"escrow": True, "allowed": True, "remaining": int(grant["remaining"])}


def peek_escrow_share(rule_id: str) -> Dict[str, Any]:
    """Peek a rule's share without consuming (check-only: shadow / explain,
    EV-22). Same allow/block decision as ``spend_escrow_share`` but
    side-effect free."""
    with _escrow_lock:
        grant = _escrow_state.get(rule_id)
        if grant is None:
            return {"escrow": False, "allowed": False, "remaining": 0}
        return {
            "escrow": True,
            "allowed": grant["remaining"] > 0,
            "remaining": int(grant["remaining"]),
        }


def snapshot_consumption() -> Dict[str, Dict[str, Any]]:
    """Snapshot consumption since each rule's current grant, for the next poll's
    ``quota_consumed`` report. Every rule with a live grant is reported (even
    consumed=0) so the allocator can reconcile the prior grant and reclaim the
    unused portion. Each entry is tagged with the epoch it was granted under."""
    with _escrow_lock:
        return {
            rule_id: {"consumed": int(grant["consumed"]), "epoch": grant["epoch"]}
            for rule_id, grant in _escrow_state.items()
        }


def get_escrow_status(rule_id: str) -> Optional[Dict[str, Any]]:
    """Current grant view for a rule (tests/inspection); None when none."""
    with _escrow_lock:
        grant = _escrow_state.get(rule_id)
        return dict(grant) if grant is not None else None


def _reset_escrow() -> None:
    """Test helper."""
    with _escrow_lock:
        _escrow_state.clear()
