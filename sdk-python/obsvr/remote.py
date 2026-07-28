"""Remote policy sync: polling, kill switch, fail-closed, approvals.

Parity with sdk-typescript/src/proxy/config.ts (policy poll + sync health) and
sdk-typescript/src/policy/approvals.ts:

- A daemon thread polls {ingest_url}/policies every refresh interval
  (immediate first poll), replacing config.policy_rules with server rules
  and updating the approval-grant set that rides along in the response.
- 401/403 from /policies means the API key was revoked or the project was
  paused in the dashboard (kill switch): all governed calls block until a
  later poll succeeds again.
- With fail_mode="closed", a sync gap longer than the staleness budget
  (default 3x refresh interval, min 90s) also blocks governed calls: the
  SDK can no longer prove it is enforcing current policy.
"""

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .config import ResolvedConfig
from .escrow import apply_escrow_response, snapshot_consumption

# Stable per-process id sent as X-Obsvr-Instance-Id on every /policies poll.
# Fleet-quota escrow (ADR-7) allocates a share per instance; without a distinct
# id, N replicas sharing one API key reconcile against ONE escrow record and
# either over-block or collectively overspend the budget (parity with TS).
_SDK_INSTANCE_ID = str(uuid.uuid4())

_sync = {
    "started_at": None,   # type: Optional[float]
    "last_success": None,  # type: Optional[float]
    "remote_disabled": False,
    "failures": 0,
    # Sorted ids of validator-rejected rules from the last poll; the
    # rejected-rule audit signal fires once per distinct set.
    "rejected_signature": "",
}
_sync_lock = threading.Lock()
_poll_thread: Optional[threading.Thread] = None
_poll_stop = threading.Event()

_grants: List[Dict[str, Any]] = []
_grants_lock = threading.Lock()

_VALID_ACTIONS = {"block", "redact", "flag"}
_VALID_TYPES = {
    "keyword", "regex", "topic_deny", "topic_allow", "pii", "action_gate",
    "namespace_isolation", "cross_tenant_block", "destructive_op_gate",
    "source_grounding", "environment_gate", "quota", "model_gate",
    "protocol_facet",
}

# Reported on the /policies poll (fleet status) and stamped on every signed
# event. Single-sourced from obsvr/_version.py (shared with __version__ and
# the pyproject dynamic version) so the wire can never drift from the package.
from ._version import __version__ as SDK_VERSION

# Capability descriptor sent on every poll: rule types this SDK build can
# enforce plus feature markers. The dashboard warns when a saved rule's
# type is outside a connected client's capabilities (parity with TS
# SDK_CAPABILITIES in proxy/config.ts).
SDK_CAPABILITIES = ",".join(
    sorted(_VALID_TYPES)
    # "quota_escrow" signals the allocator that this instance honors
    # escrow-share grants (quota_escrow on /policies) so a fleet-wide quota can
    # be enforced without per-call network latency (ADR-7).
    # "external_policy_backend" signals this instance can consult an inbound
    # OPA/Cedar backend, merged DENY-WINS with local rules (ADR-4).
    + ["shadow_mode", "approval_pinning", "rules_hash", "quota_escrow", "external_policy_backend"]
)


#: Rule-id namespaces the SDK mints for its OWN verdicts - ``sdk:`` for the
#: built-in governance layers (sdk:canary_leak, sdk:session_tainted, ...) and
#: ``backend:`` for external-policy-backend verdicts. Reserved: an operator-
#: or server-supplied rule claiming either prefix is invalid, because a forged
#: ``sdk:*`` rule would be indistinguishable from the SDK's own governance
#: verdicts on the audit record. Pinned by the ``reserved_rule_id_rejected``
#: case in conformance/fixtures/eval_semantics.json (parity with the TS
#: RESERVED_RULE_ID_PREFIXES).
RESERVED_RULE_ID_PREFIXES = ("sdk:", "backend:")


def _valid_rule(raw: Any) -> bool:
    if not isinstance(raw, dict):
        return False
    # mode is optional; when present it must be a known value. A typo'd
    # mode must invalidate the rule (EV-12), never silently ENFORCE a
    # rule the author meant to shadow.
    if raw.get("mode") is not None and raw.get("mode") not in ("enforce", "shadow"):
        return False
    return (
        isinstance(raw.get("id"), str) and raw["id"] != ""
        # A rule cannot claim the SDK's own verdict namespace (see
        # RESERVED_RULE_ID_PREFIXES above).
        and not raw["id"].startswith(RESERVED_RULE_ID_PREFIXES)
        and isinstance(raw.get("name"), str)
        and isinstance(raw.get("enabled"), bool)
        and raw.get("action") in _VALID_ACTIONS
        and raw.get("type") in _VALID_TYPES
        and isinstance(raw.get("conditions"), dict)
    )


def _parse_escrow_map(raw: Any) -> Optional[Dict[str, Dict[str, Any]]]:
    """Validate and narrow the ``quota_escrow`` field of a /policies response
    into a ``{rule_id: {share, epoch}}`` map (ADR-7, parity with the TS
    parseEscrowMap). Entries whose share/epoch are not finite non-negative
    numbers are dropped rather than trusted — the SDK never fabricates or
    over-trusts share. Returns None when the field is absent or not an object,
    which clears escrow (fall back to per-process)."""
    if not isinstance(raw, dict):
        return None
    out: Dict[str, Dict[str, Any]] = {}
    for rule_id, v in raw.items():
        if not isinstance(v, dict):
            continue
        share = v.get("share")
        epoch = v.get("epoch")
        if (
            isinstance(share, (int, float)) and not isinstance(share, bool)
            and share >= 0
            and isinstance(epoch, (int, float)) and not isinstance(epoch, bool)
        ):
            out[rule_id] = {"share": share, "epoch": epoch}
    return out


def _signal_rejected_rules(config: ResolvedConfig, rules_raw: list, valid: list) -> None:
    """Rejected-rule signal (EV-12): a rule the validator discards is
    silently UNENFORCED, the worst failure mode a governance SDK can
    have. Log the ids loudly and put ONE policy_flag event on the audit
    record per distinct rejected set (not per poll). Parity with the TS
    poll's sdk:rule_rejected signal."""
    valid_ids = {r.get("id") for r in valid if isinstance(r, dict)}
    rejected_ids = [
        (r.get("id") if isinstance(r, dict) and isinstance(r.get("id"), str) else "(missing id)")
        for r in rules_raw
        if not (isinstance(r, dict) and r.get("id") in valid_ids and _valid_rule(r))
    ]
    logging.getLogger("obsvr").warning(
        f"Policy poll: {len(rejected_ids)} rule(s) REJECTED by the "
        f"validator and NOT enforced: {', '.join(rejected_ids)}"
    )
    signature = "|".join(sorted(rejected_ids))
    with _sync_lock:
        if _sync.get("rejected_signature") == signature:
            return
        _sync["rejected_signature"] = signature
    try:
        from .events import emit_event
        from .rules import PolicyRule, derive_policy_version
        applied_hash = derive_policy_version([
            PolicyRule(
                id=r["id"], name=r["name"], enabled=r["enabled"],
                action=r["action"], type=r["type"],
                conditions=r.get("conditions", {}),
                applies_to=r.get("applies_to"), mode=r.get("mode"),
            )
            for r in valid
        ])
        emit_event(
            config,
            provider="unknown",
            model="none",
            operation="policy.rule_rejected",
            source="obsvr_sdk",
            prompt="",
            response="",
            success=True,
            latency_ms=0,
            compliance={
                "event_type": "policy_flag",
                "policy_version": applied_hash,
                "action_taken": "allowed",
                "action_reason": "policy_violation",
                "action_source": "builtin",
                "redacted_types": [],
                "blocked_types": [],
                "rule_id": "sdk:rule_rejected",
                "policy_reason": (
                    "Rules rejected by SDK validator (not enforced): "
                    + ", ".join(rejected_ids)
                )[:256],
            },
        )
    except Exception:
        pass  # signal is best-effort


def poll_once(config: ResolvedConfig) -> None:
    """One /policies refresh. Updates rules, grants, and sync health."""
    from .rules import derive_policy_version
    from .policy import get_detector_error_count
    from .sender import get_sender_stats
    # Fleet status (E10/E11/E33): self-report version, capabilities,
    # applied rules hash, degraded state, and delivery counters; ingest
    # coalesces into the per-key registry behind the dashboard fleet view
    # (parity with TS poll).
    degraded = is_enforcement_degraded(config)
    stats = get_sender_stats()
    dropped = (
        stats.get("dropped_overflow", 0)
        + stats.get("dropped_permanent", 0)
        + stats.get("dropped_retry_exhausted", 0)
    )
    # `dropped` aggregates the never-delivered buckets; server-refused events
    # ride their own key so the fleet view can tell "we never got it" apart
    # from "we got it and said no" (same key name and order as the TS poll).
    counters = (
        f"enqueued={stats.get('enqueued', 0)},sent={stats.get('sent', 0)},"
        f"retries={stats.get('retries', 0)},dropped={dropped}"
        f",dropped_rejected={stats.get('dropped_rejected', 0)}"
        # Enforcement loss, not delivery loss: a detector layer that raised and
        # was resolved by the guard. Its own key for the same reason
        # dropped_rejected has one - these are different operational stories.
        f",detector_errors={get_detector_error_count()}"
    )
    # Escrow report (ADR-7): how much of each rule's granted share this instance
    # spent since the last grant, tagged with the epoch it was granted under (a
    # stale report against an old epoch is ignored by the allocator).
    # Snapshotted BEFORE applying this poll's response, because a fresh grant
    # resets the per-epoch consumption counter. Header sent only when an escrow
    # grant is in effect — backward compatible otherwise (parity with TS).
    consumed = snapshot_consumption()
    headers = {
        "X-API-Key": config.api_key,
        "X-Obsvr-Sdk": f"python/{SDK_VERSION}",
        "X-Obsvr-Instance-Id": _SDK_INSTANCE_ID,
        "X-Obsvr-Capabilities": SDK_CAPABILITIES,
        "X-Obsvr-Rules-Hash": derive_policy_version(
            getattr(config, "policy_rules", None) or []
        ),
        "X-Obsvr-Degraded": "true" if degraded.get("degraded") else "false",
        "X-Obsvr-Counters": counters,
    }
    if consumed:
        headers["X-Obsvr-Quota-Consumed"] = json.dumps(
            consumed, sort_keys=True, separators=(",", ":")
        )
    try:
        # Inside the guard: with no ingest_url configured the URL is unusable,
        # and that must count as a sync failure like an unreachable server
        # rather than an exception that kills the polling thread (parity with
        # the TS poll, whose fetch rejects on the same input).
        req = Request(
            f"{config.ingest_url}/policies",
            headers=headers,
            method="GET",
        )
        resp = urlopen(req, timeout=config.timeout)
        body = json.loads(resp.read().decode("utf-8"))
    except HTTPError as err:
        with _sync_lock:
            if err.code in (401, 403):
                _sync["remote_disabled"] = True
            _sync["failures"] += 1
        return
    except Exception:
        with _sync_lock:
            _sync["failures"] += 1
        return

    rules_raw = body.get("rules")
    if not isinstance(rules_raw, list):
        with _sync_lock:
            _sync["failures"] += 1
        return

    from .rules import PolicyRule  # local import avoids a cycle at module load

    valid = [r for r in rules_raw if _valid_rule(r)]
    if len(valid) != len(rules_raw):
        _signal_rejected_rules(config, rules_raw, valid)
    else:
        with _sync_lock:
            _sync["rejected_signature"] = ""
    config.policy_rules = [
        PolicyRule(
            id=r["id"],
            name=r["name"],
            enabled=r["enabled"],
            action=r["action"],
            type=r["type"],
            conditions=r["conditions"],
            applies_to=r.get("applies_to"),
            mode=r.get("mode"),
        )
        for r in valid
    ]

    approvals_raw = body.get("approvals")
    if isinstance(approvals_raw, list):
        with _grants_lock:
            _grants.clear()
            _grants.extend(
                a for a in approvals_raw
                if isinstance(a, dict)
                and isinstance(a.get("rule_id"), str)
                and isinstance(a.get("expires_at"), str)
            )

    # Fleet-quota escrow grants (ADR-7) ride along on the same poll. Applied
    # AFTER the consumption snapshot above so the just-reported grant's
    # consumption is not reset before it is reported. An absent field / absent
    # rule clears escrow for that rule (falls back to the per-process meter).
    apply_escrow_response(_parse_escrow_map(body.get("quota_escrow")))

    with _sync_lock:
        _sync["last_success"] = time.time()
        _sync["failures"] = 0
        _sync["remote_disabled"] = False


def start_policy_polling(config: ResolvedConfig, interval_s: float) -> None:
    """Start (or restart) the polling daemon with an immediate first poll."""
    global _poll_thread
    stop_policy_polling()
    _poll_stop.clear()
    with _sync_lock:
        _sync["started_at"] = time.time()

    def _loop() -> None:
        poll_once(config)
        while not _poll_stop.wait(interval_s):
            poll_once(config)

    _poll_thread = threading.Thread(target=_loop, name="obsvr-policy-poll", daemon=True)
    _poll_thread.start()


def stop_policy_polling() -> None:
    _poll_stop.set()


def is_enforcement_degraded(config: ResolvedConfig) -> Dict[str, Any]:
    """Whether policy enforcement can currently be trusted.

    Returns {"degraded": bool, "reason": str | None}. remote_disabled (paused
    project / revoked key) always degrades; staleness degrades only with
    fail_mode="closed".
    """
    with _sync_lock:
        if _sync["remote_disabled"]:
            return {"degraded": True, "reason": "project_paused_or_key_revoked"}
        if config.fail_mode != "closed":
            return {"degraded": False, "reason": None}
        interval = getattr(config, "policy_refresh_interval_s", 30.0)
        if interval <= 0:
            return {"degraded": False, "reason": None}
        budget = getattr(config, "policy_staleness_budget_s", None) or max(3 * interval, 90.0)
        reference = _sync["last_success"] or _sync["started_at"]
        if reference is None:
            return {"degraded": False, "reason": None}
        if time.time() - reference > budget:
            reason = (
                "policy_sync_never_succeeded"
                if _sync["last_success"] is None
                else "policy_sync_stale"
            )
            return {"degraded": True, "reason": reason}
        return {"degraded": False, "reason": None}


# ── Approvals (human-in-the-loop) ────────────────────────────────────────────

def _parse_iso_utc(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp to an aware UTC datetime, or None if absent/
    unparseable. Accepts a trailing 'Z' and explicit offsets (offset-correct,
    unlike a lexical string compare); naive timestamps are assumed UTC."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def update_approvals(next_grants: Any) -> None:
    """Replace the grant set. The /policies poll does this inline; this is the
    same operation as a named entry point, so the grant store has one way in
    that tests and callers can both use (TS parity: updateApprovals)."""
    with _grants_lock:
        _grants.clear()
        if isinstance(next_grants, list):
            _grants.extend(g for g in next_grants if isinstance(g, dict))


def _reset_approvals() -> None:
    """@internal test hook - clears the grant store (TS parity: _resetApprovals)."""
    with _grants_lock:
        _grants.clear()


def has_approval(
    rule_id: str,
    user_id: Optional[str] = None,
    rule_hash: Optional[str] = None,
    action_hash: Optional[str] = None,
) -> bool:
    """Whether an unexpired grant covers this claim (twin of TS hasApproval).

    Each pin only narrows: when BOTH the grant and the call carry a value they
    must match; when either side is silent the check does not apply. That is
    what lets a grant issuer adopt the bindings one at a time without every
    outstanding grant going void on upgrade - and it is why an unbound grant is
    exactly as strong as the issuer made it, no stronger.

    ``rule_hash`` voids a grant once the rule is edited: an approval for
    yesterday's rule must never satisfy today's stricter one. ``action_hash``
    voids a grant spent on a different call: one human approving a $50
    transfer must not leave a grant that satisfies a $5,000,000 one just
    because both trip the same rule.
    """
    now = datetime.now(timezone.utc)
    with _grants_lock:
        for g in _grants:
            if g.get("rule_id") != rule_id:
                continue
            # Compare actual instants, not ISO strings: a lexical compare mishandles
            # timezone offsets (a "+09:00" grant sorts as later than an equal-instant
            # "Z" grant) and fractional seconds. A missing/unparseable expiry is
            # treated as expired (fail-closed on a security grant).
            exp = _parse_iso_utc(g.get("expires_at"))
            if exp is None or exp <= now:
                continue
            if g.get("user_id") and g.get("user_id") != user_id:
                continue
            if g.get("rule_hash") and rule_hash and g.get("rule_hash") != rule_hash:
                continue
            if g.get("action_hash") and action_hash and g.get("action_hash") != action_hash:
                continue
            return True
    return False


def revalidate_approval(claim: Dict[str, Any]) -> bool:
    """Re-check a claim that was satisfied earlier in the same call.

    The pre-call pipeline can spend real time between deciding and executing -
    a customer hook has a two-second budget, an external policy backend has its
    own - and a grant that expires inside that window would otherwise let a
    call proceed on an authorization that is no longer live. This runs after
    every layer that can delay the call and before the outbound request, so the
    remaining gap is the SDK's own final assembly rather than a hook timeout.

    It cannot close the gap entirely: nothing in an in-process library can make
    the check and the provider's receipt of the request simultaneous. What it
    removes is the part of the window measured in seconds. Twin:
    ``revalidateApproval`` in policy/approvals.ts.
    """
    return has_approval(
        claim.get("rule_id") or "",
        claim.get("user_id"),
        claim.get("rule_hash"),
        claim.get("action_hash"),
    )


def request_approval(
    config: ResolvedConfig,
    rule_id: str,
    rule_name: Optional[str] = None,
    operation: Optional[str] = None,
    user_id: Optional[str] = None,
    rule_hash: Optional[str] = None,
    action_hash: Optional[str] = None,
) -> None:
    """File an approval request with ingest (fire-and-forget thread).

    ``action_hash`` names the exact call a human is being asked to authorize,
    so the grant that comes back can be bound to it rather than to "anything
    that trips this rule".
    """
    if not config.ingest_url:
        return

    def _send() -> None:
        try:
            data = json.dumps({
                "rule_id": rule_id,
                "rule_name": rule_name,
                "operation": operation,
                "user_id": user_id,
                "rule_hash": rule_hash,
                "action_hash": action_hash,
            }).encode("utf-8")
            req = Request(
                f"{config.ingest_url}/approvals/request",
                data=data,
                headers={"Content-Type": "application/json", "X-API-Key": config.api_key},
                method="POST",
            )
            urlopen(req, timeout=config.timeout)
        except Exception:
            pass  # best-effort

    threading.Thread(target=_send, name="obsvr-approval-req", daemon=True).start()


def _reset_remote() -> None:
    """Reset state (tests only)."""
    stop_policy_polling()
    with _sync_lock:
        _sync["started_at"] = None
        _sync["last_success"] = None
        _sync["remote_disabled"] = False
        _sync["failures"] = 0
    with _grants_lock:
        _grants.clear()
    apply_escrow_response(None)  # clear any fleet-quota escrow grants
