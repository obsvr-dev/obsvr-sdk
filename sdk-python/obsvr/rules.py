"""Structured policy rules engine - parity with sdk-typescript/src/policy/rules.ts.

Rule types (same set as TS): keyword, regex, topic_deny, topic_allow, pii,
action_gate, namespace_isolation, cross_tenant_block, destructive_op_gate,
source_grounding, environment_gate, quota.

Context-dependent types (action_gate etc.) evaluate only when a
PolicyEvalContext-shaped dict is passed; without context they never match,
which keeps text-only callers fully backward compatible (same as TS).
"""
import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .escrow import has_escrow, peek_escrow_share, spend_escrow_share
from .normalize import normalize_for_matching
from .reason_codes import ReasonCode, rule_type_to_reason_code
from .safe_regex import safe_regex_search


@dataclass
class PolicyRule:
    id: str
    name: str
    enabled: bool
    action: str  # 'block' | 'redact' | 'flag'
    type: str    # 'keyword' | 'regex' | 'topic_deny' | 'topic_allow' | 'pii' | ...
    # NB: 'pii' is a valid, hashed policy type but has no rule-engine branch — PII is
    # enforced by the builtin scanner (policy.run_builtin_pii_scan). Kept for parity
    # with the TS SDK and the shared conformance fixtures (rules_hash parity).
    conditions: Dict[str, Any] = field(default_factory=dict)
    applies_to: Optional[str] = None  # 'prompt' | 'response' | 'both' | None
    # "shadow" rules never affect the decision; they only record what they
    # would have done (EV-20/21). None == "enforce".
    mode: Optional[str] = None


# ── Conflict-resolution semantics for the enabled rule set ──────────────────
#
# "first_match" is the engine's original contract: rules evaluate in document
# order and the first rule that renders an outcome decides, so a matched
# topic_allow pre-empts every rule after it (EV-6/EV-8). "deny_wins" is the
# versioned opt-in: every enforcing rule is evaluated, and the collected
# outcomes resolve by action strength -- a refusal anywhere in the set
# prevails over a redaction, a redaction over a flag, a flag over a permit --
# with a deterministic tie-break, so the verdict is identical for every
# ordering of the same rules. Undeclared (None) evaluates as first_match; a
# DECLARED mode is additionally committed into policy_version (see
# derive_policy_version), which is what makes the opt-in auditable.
RULE_RESOLUTION_FIRST_MATCH = "first_match"
RULE_RESOLUTION_DENY_WINS = "deny_wins"
RULE_RESOLUTION_MODES = (RULE_RESOLUTION_FIRST_MATCH, RULE_RESOLUTION_DENY_WINS)


def ensure_rule_resolution(resolution: Optional[str]) -> Optional[str]:
    """Validate a ruleset's declared conflict-resolution mode.

    None (undeclared) and the known modes pass through; anything else raises
    ValueError. Same posture as the per-rule ``mode`` validator (EV-12): an
    unknown value must invalidate LOUDLY at the boundary that parses it,
    never silently evaluate under semantics the author did not choose -- a
    typo'd declaration that quietly fell back to first-match would reopen
    the exact ordering hazard the opt-in exists to close.
    """
    if resolution is not None and resolution not in RULE_RESOLUTION_MODES:
        raise ValueError(
            "unknown rule resolution %r: expected one of %r, or None for the "
            "default %r" % (resolution, RULE_RESOLUTION_MODES, RULE_RESOLUTION_FIRST_MATCH)
        )
    return resolution


def evaluate_policy_rules(
    rules: List[PolicyRule],
    text: str,
    target: str = "prompt",
    context: Optional[Dict[str, Any]] = None,
    check_only: bool = False,
    fail_mode: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate rules against text (+ optional context).

    Context keys (all optional, parity with TS PolicyEvalContext):
      action_name, amount, caller_namespace, target_namespace,
      current_environment, source_documents, metadata.
    check_only (EV-22): identical decision logic, but no quota
    consumption. Used by shadow evaluation and explain().
    fail_mode: the operator's failure posture, for the one case this engine
    can hit an enforcement layer that cannot run -- a quota scope the bounded
    store had no slot for. None behaves as "open", the SDK-wide default.
    Returns PolicyDecisionResult dict.
    """
    # The unmetered record is collected here and attached to whatever verdict
    # comes out, including one produced by a LATER rule: the fact "this call's
    # quota rule did not run" is true of the call regardless of what decided
    # it. Parity with TS evaluatePolicyRules.
    unmetered: Dict[str, Any] = {}
    result = _evaluate_rules(rules, text, target, context, check_only, fail_mode, unmetered)
    if unmetered.get("record") is not None:
        result = {**result, "quota_unmetered": unmetered["record"]}
    return result


def _evaluate_rules(
    rules: List[PolicyRule],
    text: str,
    target: str = "prompt",
    context: Optional[Dict[str, Any]] = None,
    check_only: bool = False,
    fail_mode: Optional[str] = None,
    unmetered: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if unmetered is None:
        unmetered = {}
    # §6: normalize once, up front, so every text-matching rule sees the same
    # confusable/zero-width-folded copy. Matching-only: the engine returns a
    # decision + rule_id, never modified text, so stored/forwarded content is
    # untouched. Identity on plain ASCII, so existing behavior is unchanged.
    text = normalize_for_matching(text)
    for rule in rules:
        if not rule.enabled:
            continue
        # Shadow rules are inert in active evaluation (EV-20); they run
        # only through evaluate_shadow_rules after the active decision.
        if getattr(rule, "mode", None) == "shadow":
            continue

        applies = rule.applies_to
        if applies and applies != "both" and applies != target:
            continue

        matched = False

        if rule.type == "keyword":
            keywords = rule.conditions.get("keywords", [])
            lower = text.lower()
            matched = any(kw.lower() in lower for kw in keywords)

        elif rule.type == "regex":
            pattern = rule.conditions.get("pattern")
            if pattern:
                # ReDoS guard: customer-supplied patterns are validated for
                # catastrophic-backtracking shapes and run on bounded input.
                # Rejected patterns are treated as no-match (never raise).
                matched = safe_regex_search(pattern, text)

        elif rule.type == "topic_deny":
            topics = rule.conditions.get("topics", [])
            lower = text.lower()
            matched = any(t.lower() in lower for t in topics)

        elif rule.type == "topic_allow":
            topics = rule.conditions.get("topics", [])
            lower = text.lower()
            matched = any(t.lower() in lower for t in topics)

        elif rule.type == "action_gate":
            matched = _evaluate_action_gate(rule, text, context)

        elif rule.type in ("namespace_isolation", "cross_tenant_block"):
            matched = _evaluate_namespace_mismatch(context)

        elif rule.type == "destructive_op_gate":
            matched = _evaluate_destructive_op_gate(rule, text, context)

        elif rule.type == "source_grounding":
            matched = _evaluate_source_grounding(rule, text, context)

        elif rule.type == "environment_gate":
            matched = _evaluate_environment_gate(rule, context)

        elif rule.type == "model_gate":
            matched = _evaluate_model_gate(rule, context)
        elif rule.type == "protocol_facet":
            matched = _evaluate_protocol_facet(rule, text)

        elif rule.type == "quota":
            limit = rule.conditions.get("quota_limit")
            window_ms = rule.conditions.get("quota_window_ms")
            scope = rule.conditions.get("quota_scope")
            if not limit or not window_ms or not scope:
                continue
            # Phase-aware consumption (parity with TS rules.ts): a rule in scope
            # for both phases meters and enforces on the REQUEST (prompt) phase
            # only — the response pass of the SAME call must never burn a second
            # unit AND must never re-block (its allowance was already decided
            # pre-call). Only rules explicitly scoped to the response act here.
            if target == "response" and rule.applies_to != "response":
                continue
            meta = (context or {}).get("metadata") or {}
            unit = rule.conditions.get("quota_unit") or "requests"
            scope_value = quota_scope_value(scope, meta, meta.get("user_id"), context)
            if unit == "tokens":
                # Tokens are only known post-call, so the pre-call check never
                # consumes; wrap.py records usage after the call. Parity with TS.
                quota = check_token_budget(scope, scope_value, int(limit), int(window_ms))
            elif has_escrow(rule.id):
                # Fleet-quota escrow (ADR-7) is in effect for this rule: spend
                # this instance's server-granted LOCAL share instead of the
                # per-process meter — zero network on the call path. The
                # /policies poll refills the share and reports consumption. An
                # exhausted share blocks with the same quota_exceeded verdict
                # shape. check_only (shadow/explain, EV-22) peeks without spending.
                quota = peek_escrow_share(rule.id) if check_only else spend_escrow_share(rule.id)
            else:
                # No escrow grant for this rule: fall back to today's
                # per-process meter (backward compatible with servers that
                # never send escrow).
                quota = increment_quota(
                    scope, scope_value, int(limit), int(window_ms),
                    record=not check_only,
                )
            # The bounded meter had no counter slot for this scope, so this
            # rule was NOT enforced on this call. Resolve it the way every
            # other enforcement layer that cannot run resolves -- by fail_mode
            # (policy.py record_detector_failure: every internal failure
            # resolves by fail_mode EXCEPT the floor class, and a quota rule is
            # not floor class). Declaring it is not optional either way: an
            # allowed call whose quota rule never ran is byte-identical on the
            # wire to one that was counted and found under limit, and an
            # auditor replaying it would read a rule that was in force and
            # never exceeded.
            #
            # Why fail_mode rather than always allowing: "closed" means "never
            # fail open", and an unmeterable scope is precisely a case where
            # the SDK cannot say whether the limit holds. It does cost
            # availability -- a caller who can mint scope values can saturate
            # the store and have new identities refused -- but that is the
            # trade the operator selected, and under "open" that same flood
            # buys the flooder UNMETERED quota, which is the worse outcome for
            # someone who asked for fail-closed. "open" stays the default.
            if quota.get("metered") is False:
                fail_closed = fail_mode == "closed"
                unmetered["record"] = {
                    "rule_id": rule.id,
                    "scope": scope,
                    "unit": unit,
                    "resolution": "closed" if fail_closed else "open",
                }
                if fail_closed:
                    return {
                        "decision": "block",
                        "rule_id": rule.id,
                        "reason_code": ReasonCode.QUOTA_UNMETERED.value,
                        "reason": (
                            f"Quota rule '{rule.id}' could not be metered: the quota store "
                            f"has no counter slot for scope '{scope}'. Blocked because "
                            f"fail_mode is 'closed'"
                        ),
                    }
                continue
            if not quota["allowed"]:
                decision = "allow" if rule.action == "flag" else rule.action
                return {
                    "decision": decision,
                    "rule_id": rule.id,
                    "reason_code": ReasonCode.QUOTA_EXCEEDED.value,
                    "reason": (
                        f"Quota exceeded: {quota['remaining']} remaining of "
                        f"{limit} per {window_ms}ms window"
                    ),
                }
            continue

        if not matched:
            continue

        if rule.type == "topic_allow":
            return {
                "decision": "allow",
                "rule_id": rule.id,
                "reason_code": ReasonCode.PERMITTED.value,
                "reason": rule.name,
            }

        if rule.action == "block":
            # Human-in-the-loop: a require_approval rule passes when an
            # unexpired grant covers it; otherwise it blocks and marks the
            # result so the caller files an approval request.
            if rule.conditions.get("require_approval") is True:
                from .approval_action import safe_approval_action_hash
                from .remote import has_approval
                ctx = context or {}
                meta = ctx.get("metadata") or {}
                user_id = meta.get("user_id")
                # Pin the approval to THIS rule definition: a grant minted
                # under an older version of the rule (different hash) is void.
                rule_hash = derive_rule_hash(rule)
                # ...and to THIS action, so a grant issued for one call cannot
                # be spent on a different call that trips the same rule.
                action_hash = safe_approval_action_hash(
                    rule_id=rule.id,
                    rule_hash=rule_hash,
                    action_name=ctx.get("action_name"),
                    amount=ctx.get("amount"),
                    caller_namespace=ctx.get("caller_namespace"),
                    target_namespace=ctx.get("target_namespace"),
                    user_id=user_id,
                )
                claim = {
                    "rule_id": rule.id,
                    "user_id": user_id,
                    "rule_hash": rule_hash,
                    "action_hash": action_hash,
                }
                if has_approval(rule.id, user_id, rule_hash, action_hash):
                    return {
                        "decision": "allow",
                        "rule_id": rule.id,
                        "reason_code": ReasonCode.APPROVAL_GRANTED.value,
                        "reason": f"approved: {rule.name}",
                        "rule_hash": rule_hash,
                        # Carried so the caller can re-check the grant after
                        # the layers that can delay the call.
                        "approval_granted": claim,
                    }
                result: Dict[str, Any] = {
                    "decision": "block",
                    "rule_id": rule.id,
                    "reason_code": ReasonCode.APPROVAL_REQUIRED.value,
                    "reason": f"approval_required: {rule.name}",
                    "approval_required": True,
                    "rule_hash": rule_hash,
                }
                if action_hash is not None:
                    result["action_hash"] = action_hash
                return result
            return {
                "decision": "block",
                "rule_id": rule.id,
                "reason_code": rule_type_to_reason_code(rule.type),
                "reason": rule.name,
            }

        if rule.action == "redact":
            return {
                "decision": "redact",
                "rule_id": rule.id,
                "reason_code": rule_type_to_reason_code(rule.type),
                "reason": rule.name,
            }

        # flag: reason_code classifies WHY the rule engaged; the decision
        # field stays authoritative (a flag matches but allows).
        return {
            "decision": "allow",
            "rule_id": rule.id,
            "reason_code": rule_type_to_reason_code(rule.type),
            "reason": rule.name,
        }

    return {"decision": "allow", "reason_code": ReasonCode.PERMITTED.value}


# ── Context-dependent evaluators (parity with TS) ───────────────────────────

def _evaluate_action_gate(
    rule: PolicyRule, text: str, context: Optional[Dict[str, Any]]
) -> bool:
    """FinTech: matches action types, numeric thresholds, and time windows."""
    conditions = rule.conditions
    ctx = context or {}

    action_types = conditions.get("action_types")
    if action_types:
        action_name = (ctx.get("action_name") or text).lower()
        if not any(at.lower() in action_name for at in action_types):
            return False

    threshold = conditions.get("threshold")
    if threshold:
        actual = _resolve_threshold_field(threshold.get("field", ""), ctx)
        if actual is None:
            return False
        if not _compare_threshold(actual, threshold.get("operator", ""), threshold.get("value")):
            return False

    time_window = conditions.get("time_window")
    if time_window:
        import datetime
        allow_hours = time_window.get("allow_hours") or [0, 24]
        start, end = allow_hours[0], allow_hours[1]
        tz_name = time_window.get("timezone")
        now_hour = None
        if tz_name:
            try:
                from zoneinfo import ZoneInfo
                now_hour = datetime.datetime.now(ZoneInfo(tz_name)).hour
            except Exception:
                now_hour = None
        if now_hour is None:
            now_hour = datetime.datetime.now().hour
        if start <= end:
            if start <= now_hour < end:
                return False  # within window = allowed
        else:  # wraps midnight, e.g. [22, 6]
            if now_hour >= start or now_hour < end:
                return False
        return True

    return True


def _evaluate_namespace_mismatch(context: Optional[Dict[str, Any]]) -> bool:
    """namespace_isolation / cross_tenant_block: caller vs target namespace."""
    if not context:
        return False
    caller = context.get("caller_namespace")
    target = context.get("target_namespace")
    # Both absent: the call is not namespaced, so the isolation rule does not
    # apply. An ASYMMETRIC context (one side missing) is how an attacker nulls a
    # namespace to defeat isolation, so fail closed (parity with the TS twin).
    if not caller and not target:
        return False
    if not caller or not target:
        return True
    return caller != target


def _evaluate_destructive_op_gate(
    rule: PolicyRule, text: str, context: Optional[Dict[str, Any]]
) -> bool:
    ops = rule.conditions.get("destructive_operations")
    if not ops:
        return False
    lower = text.lower()
    action_name = ((context or {}).get("action_name") or "").lower()
    return any(op.lower() in lower or op.lower() in action_name for op in ops)


def _evaluate_source_grounding(
    rule: PolicyRule, text: str, context: Optional[Dict[str, Any]]
) -> bool:
    min_ratio = rule.conditions.get("min_grounding_ratio")
    if min_ratio is None:
        return False
    sources = (context or {}).get("source_documents")
    if not sources:
        return True  # no sources = ungrounded
    return compute_grounding_score(text, sources) < min_ratio


def _evaluate_environment_gate(
    rule: PolicyRule, context: Optional[Dict[str, Any]]
) -> bool:
    targets = rule.conditions.get("target_environments")
    if not targets:
        return False
    current = (context or {}).get("current_environment")
    if not current:
        return False
    return current in targets


def _evaluate_protocol_facet(rule: PolicyRule, text: str) -> bool:
    """protocol_facet - match PARSED protocol structure, not raw characters.

    FAILS CLOSED. Text the decomposer cannot speak about returns
    ``parsed: False``, and that MATCHES - the rule's action applies. This is
    the opposite of every other rule type here, and deliberately so: a facet
    rule exists because "the verb is DROP" is a stronger question than a
    pattern match, and a statement an attacker made unparseable would otherwise
    be the bypass. Parity with TS evaluateProtocolFacet.
    """
    from .protocol_facets import extract_sql_facets, read_facet

    facet = rule.conditions.get("facet")
    if not isinstance(facet, str) or not facet:
        return False
    if not facet.startswith("sql."):
        return False  # only SQL facets exist today
    facets = extract_sql_facets(text)
    if not facets.get("parsed"):
        return True  # fail closed: cannot evaluate is a match
    values = [v.lower() for v in read_facet(facets, facet)]

    in_list = rule.conditions.get("facet_in")
    if in_list:
        wanted = {str(v).lower() for v in in_list}
        if any(v in wanted for v in values):
            return True
    not_in_list = rule.conditions.get("facet_not_in")
    if not_in_list and values:
        allowed = {str(v).lower() for v in not_in_list}
        if any(v not in allowed for v in values):
            return True
    return False


def _evaluate_model_gate(
    rule: PolicyRule, context: Optional[Dict[str, Any]]
) -> bool:
    """Model/provider allowlist gate (parity with TS evaluateModelGate).

    Matches (i.e. the rule fires) when the call's model is denied, is not in
    the allowlist, or its provider is not in the provider allowlist.
    Case-insensitive; allowlist entries match by exact value or prefix.
    """
    ctx = context or {}
    conds = rule.conditions
    model = str(ctx.get("model") or "").lower()
    provider = str(ctx.get("provider") or "").lower()

    def _matches(entries: List[str], value: str) -> bool:
        return any(value == e.lower() or value.startswith(e.lower()) for e in entries)

    denied = conds.get("denied_models")
    allowed = conds.get("allowed_models")
    allowed_providers = conds.get("allowed_providers")
    if denied and model and _matches(denied, model):
        return True
    if allowed and model and not _matches(allowed, model):
        return True
    if (
        allowed_providers
        and provider
        and provider not in [p.lower() for p in allowed_providers]
    ):
        return True
    return False


def _resolve_threshold_field(
    field_name: str, context: Dict[str, Any]
) -> Optional[float]:
    if field_name == "amount":
        v = context.get("amount")
        return float(v) if isinstance(v, (int, float)) else None
    meta = context.get("metadata") or {}
    v = meta.get(field_name)
    return float(v) if isinstance(v, (int, float)) else None


def _compare_threshold(actual: float, operator: str, value: Any) -> bool:
    if not isinstance(value, (int, float)):
        return False
    if operator == ">":
        return actual > value
    if operator == "<":
        return actual < value
    if operator == ">=":
        return actual >= value
    if operator == "<=":
        return actual <= value
    if operator == "==":
        return actual == value
    return False


def compute_grounding_score(output: str, sources: List[str]) -> float:
    """Fraction of output words (len > 3) found in the source docs (TS parity)."""
    words = [w for w in output.lower().split() if len(w) > 3]
    if not words:
        return 1.0
    source_text = " ".join(sources).lower()
    grounded = [w for w in words if w in source_text]
    return len(grounded) / len(words)


# ── In-memory quota store (parity with sdk-typescript/src/governance/quota.ts) ─────────
# Per-process fixed windows. Same caveat as TS: by default N workers = N x the
# budget. Fleet-quota escrow (ADR-7, obsvr/escrow.py) closes that gap for
# request-unit rules the server escrows on the /policies poll — this meter is
# the fallback for rules the server does not escrow. Server-side limits at
# ingest remain authoritative.
#
# Memory bound: both meters cap how many distinct scopes they track, and past
# the cap they refuse new scopes rather than evicting live counters — see
# _make_room for why a quota store makes that call differently from the taint
# latch.

import threading as _threading
import time as _time

_quota_store: Dict[str, Dict[str, float]] = {}
_token_store: Dict[str, Dict[str, float]] = {}
_quota_lock = _threading.Lock()

# Distinct scopes either meter can track. Both stores are process-global and
# keyed by a CALLER-SUPPLIED scope value -- quota_scope "user_id" is one entry
# per distinct end user -- so without a cap they grow for the life of the
# process. Bounded like the other process-global stores (session taint, tool
# pins, canaries).
MAX_QUOTA_SCOPES = 10_000

# ``min(window_start + window_ms)`` per meter, or inf when empty. Only ever a
# LOWER bound: inserts lower it, and deletions can leave it pointing at an
# entry that is gone. Stale-low is the safe direction -- it costs one sweep
# that finds nothing, and can never skip a sweep while something is expired.
_earliest_expiry: Dict[str, float] = {"requests": float("inf"), "tokens": float("inf")}

# True while a saturation episode is being warned about; reset when it clears.
_quota_warned = False


def _meter_name(store: Dict[str, Dict[str, float]]) -> str:
    return "requests" if store is _quota_store else "tokens"


def _sweep_expired(store: Dict[str, Dict[str, float]], now: float) -> None:
    """Drop every entry whose own window has elapsed and re-derive the bound.
    Caller holds ``_quota_lock``."""
    global _quota_warned
    earliest = float("inf")
    for k in list(store):
        expires_at = store[k]["window_start"] + store[k]["window_ms"]
        if expires_at <= now:
            del store[k]
        elif expires_at < earliest:
            earliest = expires_at
    _earliest_expiry[_meter_name(store)] = earliest
    # A recovered meter must be able to warn again if it saturates a second
    # time: one warning per episode, not one per process.
    if len(store) < MAX_QUOTA_SCOPES:
        _quota_warned = False


def _saturated_now(store: Dict[str, Dict[str, float]], now: float) -> bool:
    """Is this meter full of LIVE windows right now? Caller holds the lock.

    The ``_earliest_expiry`` bound is what makes this cheap. Once full, the
    naive check re-scans all MAX_QUOTA_SCOPES entries on every new scope and
    deletes nothing while every window is live -- a per-call O(n) scan on the
    in-process hot path, triggered by exactly the flood the cap exists to
    survive. When ``now`` has not reached the earliest possible expiry, no
    entry CAN be expired, so the scan is skipped and the answer is O(1).
    """
    if len(store) < MAX_QUOTA_SCOPES:
        return False
    if now < _earliest_expiry[_meter_name(store)]:
        return True
    _sweep_expired(store, now)
    return len(store) >= MAX_QUOTA_SCOPES


def _track_expiry(store: Dict[str, Dict[str, float]], now: float, window_ms: int) -> None:
    """Record a newly opened window against the meter's expiry bound."""
    name = _meter_name(store)
    expires_at = now + window_ms
    if expires_at < _earliest_expiry[name]:
        _earliest_expiry[name] = expires_at


def _make_room(store: Dict[str, Dict[str, float]], now: float) -> bool:
    """Make room for a NEW key, or report that there is none. Caller holds
    ``_quota_lock``.

    Eviction policy -- expired windows only, never a live one. Expiry is judged
    against the window stored ON the entry, so an entry that goes is one the
    next touch would have overwritten with a fresh counter anyway: dropping it
    changes no decision. An entry still
    inside its window IS the enforcement state, and dropping it would reset
    that scope's counter to zero. Since scope values are caller-supplied, a
    caller able to mint them could then flood the store with fresh keys to
    evict a live counter -- their own, or a victim's -- and buy a full fresh
    quota. That is a rate-limit bypass, so this store refuses instead, the same
    call tool_pinning.py and canary.py make where eviction would silently
    disable the control. (session_taint.py does evict oldest-first: a taint
    latch is advisory-leaning and an ancient session is the least valuable
    thing it holds. A quota counter is not advisory.)

    A refused scope is UNMETERED, and the verdict says so (``metered`` False)
    rather than being indistinguishable from a scope that was counted and
    found under limit. What happens next is NOT decided here: the rules engine
    resolves it by fail_mode, the same way every other enforcement layer that
    cannot run resolves (policy.py record_detector_failure), and declares it on
    the call's own event either way. A meter that quietly stops metering is the
    enforcement-side twin of a dropped event that leaves no gap marker.
    """
    global _quota_warned
    if not _saturated_now(store, now):
        return True
    if not _quota_warned:
        _quota_warned = True
        import logging

        logging.getLogger("obsvr").warning(
            "quota store is full (%d scopes with live windows); NEW scopes are "
            "NOT metered until a window elapses. Counters already tracked are "
            "unaffected. Each affected call declares this on its own event; "
            "fail_mode decides whether it proceeds.",
            MAX_QUOTA_SCOPES,
        )
    return False


def quota_store_size() -> Dict[str, int]:
    """Scopes currently tracked by each meter (diagnostics, tests)."""
    with _quota_lock:
        return {"requests": len(_quota_store), "tokens": len(_token_store)}


def quota_store_saturated() -> bool:
    """Is either meter full of live windows RIGHT NOW -- i.e. would a new scope
    be refused if one arrived this instant?

    Deliberately a current-state question, not a latch. "This process once
    refused a scope, possibly hours ago and for one call" and "new scopes are
    going unmetered as of now" call for different responses, and a flag that
    never clears can only answer the first while looking like it answers the
    second. Saturation is transient: it ends on its own the moment a tracked
    window elapses.
    """
    now = _time.time() * 1000
    with _quota_lock:
        return _saturated_now(_quota_store, now) or _saturated_now(_token_store, now)


def quota_scope_value(
    scope: str,
    metadata: Optional[Dict[str, Any]],
    user_id: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
) -> str:
    """Resolve the bucket key for a quota rule's scope. 'project' meters the
    whole project; any other scope buckets by that metadata key, falling back
    to the same key at the TOP level of the eval context (callers such as the
    proxy wrapper may spread identity fields there rather than under metadata
    — parity with TS rules.ts, which resolves metadata[scope] ?? context[scope]
    ?? 'default' so a scoped rule never silently meters the 'default' bucket),
    then to user_id for a user_id-scoped rule (token-recording path parity
    with TS recordTokenUsageForRules). None-checks mirror TS ?? semantics."""
    if scope == "project":
        return "project"
    meta = metadata or {}
    value = meta.get(scope)
    if value is None and context is not None:
        value = context.get(scope)
    if value is None and scope == "user_id":
        value = user_id
    if value is None:
        value = "default"
    return str(value)


def check_token_budget(
    scope: str, scope_value: str, limit: int, window_ms: int
) -> Dict[str, Any]:
    """Pre-call token-budget check (parity with TS checkTokenBudget). Tokens are
    only known post-call, so this does NOT increment — it enforces against
    tokens consumed by PRIOR calls in the window. Budgets are approximate
    cutoffs, per-process (server-side limits at ingest are authoritative)."""
    key = f"tokens:{scope}:{scope_value}"
    now = _time.time() * 1000
    with _quota_lock:
        entry = _token_store.get(key)
        if entry is None or (now - entry["window_start"]) >= window_ms:
            # An expired entry reuses its own slot, so an already-tracked scope
            # is never turned away; only a NEW scope can be refused.
            if entry is None and not _make_room(_token_store, now):
                # metered False: the caller must not read this as "counted and
                # under budget". Parity with TS `unmetered`.
                return {
                    "allowed": True,
                    "remaining": limit,
                    "reset_at": now + window_ms,
                    "metered": False,
                }
            entry = {"count": 0.0, "window_start": now, "window_ms": float(window_ms)}
            _token_store[key] = entry
            _track_expiry(_token_store, now, window_ms)
        return {
            "allowed": entry["count"] < limit,
            "remaining": max(0, int(limit - entry["count"])),
            "reset_at": entry["window_start"] + window_ms,
            "metered": True,
        }


def record_token_usage(
    scope: str, scope_value: str, tokens: int, window_ms: int
) -> None:
    """Post-call: add tokens consumed by a completed call to a scope's budget
    (parity with TS recordTokenUsage). Call with the provider-reported
    total_tokens."""
    if not isinstance(tokens, (int, float)) or tokens <= 0:
        return
    key = f"tokens:{scope}:{scope_value}"
    now = _time.time() * 1000
    with _quota_lock:
        entry = _token_store.get(key)
        if entry is None or (now - entry["window_start"]) >= window_ms:
            if entry is None and not _make_room(_token_store, now):
                return
            entry = {"count": 0.0, "window_start": now, "window_ms": float(window_ms)}
            _token_store[key] = entry
            _track_expiry(_token_store, now, window_ms)
        entry["count"] += tokens


def increment_quota(
    scope: str, scope_value: str, limit: int, window_ms: int, record: bool = True
) -> Dict[str, Any]:
    """Check-and-increment a fixed-window quota counter.

    record=False checks without consuming (shadow/explain, EV-22)."""
    key = f"{scope}:{scope_value}"
    now = _time.time() * 1000
    with _quota_lock:
        entry = _quota_store.get(key)
        if entry is None or (now - entry["window_start"]) >= window_ms:
            if entry is None and not _make_room(_quota_store, now):
                # metered False: the caller must not read this as "counted and
                # under limit". Parity with TS `unmetered`.
                return {
                    "allowed": True,
                    "remaining": limit,
                    "reset_at": now + window_ms,
                    "metered": False,
                }
            entry = {"count": 0.0, "window_start": now, "window_ms": float(window_ms)}
            _quota_store[key] = entry
            _track_expiry(_quota_store, now, window_ms)
        if entry["count"] >= limit:
            return {
                "allowed": False,
                "remaining": 0,
                "reset_at": entry["window_start"] + window_ms,
                "metered": True,
            }
        if record:
            entry["count"] += 1
        return {
            "allowed": True,
            "remaining": int(limit - entry["count"]),
            "reset_at": entry["window_start"] + window_ms,
            "metered": True,
        }


def _reset_quota() -> None:
    """Test helper."""
    global _quota_warned
    with _quota_lock:
        _quota_store.clear()
        _token_store.clear()
        _earliest_expiry["requests"] = float("inf")
        _earliest_expiry["tokens"] = float("inf")
        _quota_warned = False


def _canonical_rule(r: PolicyRule) -> Dict[str, Any]:
    """Canonical projection: governance-relevant fields only, so cosmetic
    or unknown fields never change the hash. None-valued keys omitted."""
    projected: Dict[str, Any] = {
        "action": r.action,
        "conditions": r.conditions if r.conditions is not None else {},
        "enabled": r.enabled,
        "id": r.id,
        "name": r.name,
        "type": r.type,
    }
    applies_to = getattr(r, "applies_to", None)
    if applies_to is not None:
        projected["applies_to"] = applies_to
    # "shadow" is a material behavior change (rule not enforced), so it is
    # part of the canonical definition; the default "enforce" is omitted so
    # pre-shadow hashes stay stable.
    if getattr(r, "mode", None) == "shadow":
        projected["mode"] = "shadow"
    return projected


_INF = float("inf")
_MAX_SAFE_INT = 2 ** 53 - 1  # JS Number.MAX_SAFE_INTEGER
_SURROGATE = re.compile("[\ud800-\udfff]")


def _js_number(f: float) -> str:
    """Format a float exactly as ECMAScript ``Number::toString(10)`` does,
    which is what ``JSON.stringify`` — and therefore the TS ``stableStringify``
    — emits.

    ``json.dumps`` and ``JSON.stringify`` disagree on legal JSON numbers, and
    a differential property test (scripts/check-canonical-json-parity.mjs)
    finds it in roughly a third of randomly generated documents. Python's
    ``repr`` and JS's algorithm both produce the SHORTEST round-tripping
    decimal, so the digits always agree; only the presentation differs, in
    four ways, all of which this closes:

      whole-valued floats   1.0     -> "1"        (Python: "1.0")
      negative zero        -0.0     -> "0"        (Python: "-0.0")
      exponent threshold    1e16    -> "10000000000000000"   (Python: "1e+16")
                            3e-5    -> "0.00003"             (Python: "3e-05")
      exponent padding      1e-7    -> "1e-7"                (Python: "1e-07")

    What this does NOT close, because no formatter can: an int whose magnitude
    exceeds 2**53 is already a different VALUE in JS, which rounded it while
    parsing. Ints are therefore left exact rather than pushed through float —
    see the divergence note in conformance/known-divergences.md.
    """
    if f != f or f in (_INF, -_INF):
        # JSON.stringify emits null for non-finite numbers; json.dumps emits
        # the non-standard NaN / Infinity literals.
        return "null"
    if f == 0:
        return "0"  # also normalizes -0.0, which JS prints as "0"
    sign = "-" if f < 0 else ""
    mantissa, _, exponent = repr(abs(f)).partition("e")
    exp = int(exponent) if exponent else 0
    int_part, _, frac_part = mantissa.partition(".")
    raw = int_part + frac_part
    stripped = raw.lstrip("0")
    # n is the decimal point's position in `digits`: value = 0.digits x 10**n.
    n = len(int_part) + exp - (len(raw) - len(stripped))
    digits = stripped.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    e = n - 1
    body = digits if k == 1 else digits[0] + "." + digits[1:]
    return sign + body + "e" + ("+" if e >= 0 else "-") + str(abs(e))


def _js_string(s: str) -> str:
    """JSON string literal identical to ``JSON.stringify``'s.

    ``json.dumps(ensure_ascii=False)` already agrees on every escape (the
    \\b \\t \\n \\f \\r shortcuts, \\u00xx for the other C0 controls, raw
    non-ASCII) except one: an UNPAIRED surrogate. JS escapes it; Python emits
    it raw, and the raw form has no UTF-8 encoding at all, so hashing the
    result raises instead of producing a hash. Any surrogate still present
    after decoding is unpaired by construction — the JSON decoder has already
    combined the valid pairs into astral characters.
    """
    out = json.dumps(s, ensure_ascii=False)
    if _SURROGATE.search(out):
        out = _SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group()), out)
    return out


def _utf16_order(s: str) -> bytes:
    """Sort key reproducing JS's ``Array.prototype.sort`` on object keys, which
    compares UTF-16 CODE UNITS. Python's ``sorted`` compares code points, and
    the two orders differ once an astral character meets a BMP character above
    U+E000: JS sees the astral character's leading surrogate (U+D800..U+DBFF)
    and sorts it FIRST, Python sees U+10000+ and sorts it LAST. Big-endian
    UTF-16 bytes compare in code-unit order, which is what JS does."""
    return s.encode("utf-16-be", errors="surrogatepass")


def _canonical_json(value: Any) -> str:
    """Recursively key-sorted, compact, non-ASCII-preserving JSON.
    Byte-identical to the TS SDK's stableStringify. This is the canonical
    form both SDKs hash; changing it is a cross-language breaking change
    (update the shared fixture and the TS twin together).

    Was a single ``json.dumps(sort_keys=True, separators=(",", ":"),
    ensure_ascii=False)``. That call agrees with ``JSON.stringify`` on strings,
    ordinary integers and simple decimals, and disagrees on whole-valued
    floats, negative zero, exponent form, unpaired surrogates, and the sort
    order of astral object keys — see _js_number / _js_string / _utf16_order.
    Every case this now formats differently from the old call is a case the two
    SDKs previously hashed DIFFERENTLY, so no rules hash the two agreed on has
    changed; the pinned conformance vectors are unmoved.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return _js_number(value)
    if isinstance(value, int):
        if -_MAX_SAFE_INT <= value <= _MAX_SAFE_INT:
            return str(value)
        # Past 2**53 JS has ALREADY lost the value — its parser rounded the
        # literal to the nearest float64 before any serializer ran, so
        # 9007199254740993 and ...92 are one number over there. Matching that
        # rounding is a deliberate loss of precision Python did not have to
        # take, and it is still the right one: the alternative is the same
        # policy stamping two different policy_versions depending on which
        # SDK polled it, which is a false signal of policy change on every
        # audit event in a mixed fleet. The collision it accepts in exchange
        # needs two rule sets differing ONLY in an integer above 2**53, and
        # it exists in the TS SDK either way.
        try:
            return _js_number(float(value))
        except OverflowError:
            # Beyond float64 range entirely; JS parses the literal as Infinity
            # and JSON.stringify writes null.
            return "null"
    if isinstance(value, str):
        return _js_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_order)
        return (
            "{"
            + ",".join("%s:%s" % (_js_string(k), _canonical_json(value[k])) for k in keys)
            + "}"
        )
    # Anything else (Decimal, datetime, a dataclass) was never canonicalizable
    # by the old json.dumps either; raise the same way it did.
    raise TypeError("Object of type %s is not JSON serializable" % type(value).__name__)


def _version_document(enabled: List[PolicyRule], resolution: str) -> Dict[str, Any]:
    """Hash document for a ruleset that DECLARES its conflict-resolution
    mode. The declaration rides inside the hashed document, so the same rules
    under different semantics can never share a policy_version. Projections
    are kept in evaluation order under first_match, because there position
    decides; under deny_wins they are sorted by id, because resolution is
    order-insensitive by construction and a pure reordering keeps the same
    version -- the truthful signal that no decision changed."""
    if resolution == RULE_RESOLUTION_DENY_WINS:
        ordered = sorted(enabled, key=lambda r: _utf16_order(r.id))
    else:
        ordered = list(enabled)
    return {"resolution": resolution, "rules": [_canonical_rule(r) for r in ordered]}


def derive_policy_version(
    rules: List[PolicyRule], resolution: Optional[str] = None
) -> str:
    """Canonical rules hash of the enabled rule set: 16-hex-char SHA-256
    prefix over the canonical projections sorted by id in UTF-16 CODE-UNIT
    order -- the order JS sorts in, not Python's codepoint order.
    Returns "none" when no rules are enabled. Stamped on every audit
    event as policy_version; must match the TS SDK byte for byte
    (pinned by the shared fixture).

    ``resolution`` is the ruleset's DECLARED conflict-resolution mode. A
    declared mode is committed INTO the hash, and the hash then commits to
    exactly what can change a decision under that mode: first_match hashes
    the projections in evaluation order, because list position decides
    there; deny_wins hashes them sorted by id, because its resolution is
    order-insensitive by construction. Two rulesets that can decide
    differently therefore stamp different policy_version values -- the same
    rules under the two modes differ, and the same rules in two orders
    differ under first_match.

    Undeclared (None) keeps the historical bytes -- order-insensitive over
    enabled rules, exactly what every deployed fleet, the poll header and
    the pinned fixture already stamp -- even though first-match evaluation
    reads list order. Changing those bytes would restamp every deployed
    policy on upgrade: a false policy-change signal fleet-wide, and a
    cross-SDK hash mismatch for the whole mixed-fleet rollout window, which
    the fixture grades a release blocker. Order-commitment is therefore
    bound to the declared, versioned semantics: declaring ``resolution`` is
    what buys an order-committed policy_version.

    Guarded at the function, like ``redact_for_storage``, because there is one
    correct answer at all of its call sites and most are on live host paths -
    the wrapper's per-call stamp, the integrations, MCP, the poll header, the
    policy log. It reads the same rule objects the matcher does, so a malformed
    rule raises HERE, before any detector span is entered.

    Always open: the policy version is a provenance field, not a control. It
    records which rules a decision ran under; it never decides anything, so a
    version that cannot be computed must not block a call. "unknown" is the
    honest value and is distinguishable from the legitimate "none".

    Twin: sdk-typescript/src/policy/rules.ts (``derivePolicyVersion``).
    """
    try:
        ensure_rule_resolution(resolution)
        if not rules:
            return "none"
        enabled = [r for r in rules if r.enabled]
        if not enabled:
            return "none"
        if resolution is None:
            # _utf16_order, not the default codepoint order. The two agree on
            # everything except an ASTRAL rule id meeting a BMP id above U+E000,
            # where JS sees the leading surrogate and sorts it FIRST while Python
            # sees U+10000+ and sorts it LAST. The projections are then hashed in
            # that order, so the two SDKs stamped DIFFERENT policy_version on
            # identical policy -- and policy_version is inside the chain preimage
            # under format 3, which makes a wrong value durably wrong rather than
            # merely wrong. The helper existed for exactly this and was wired only
            # to object keys.
            ordered = sorted(enabled, key=lambda r: _utf16_order(r.id))
            data = _canonical_json([_canonical_rule(r) for r in ordered])
        else:
            data = _canonical_json(_version_document(enabled, resolution))
        return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]
    except Exception as _version_exc:  # noqa: BLE001 - deliberate catch-all
        from .policy import record_check_only_failure

        record_check_only_failure("policy_rules", _version_exc)
        return "unknown"


def derive_rule_hash(rule: PolicyRule) -> str:
    """Hash of ONE rule's canonical definition. Approvals are pinned to
    this: an approval granted while a rule had hash H is void once the
    rule is edited, so a stale approval can never satisfy a stricter
    rule. 16-hex-char SHA-256 prefix."""
    data = _canonical_json(_canonical_rule(rule))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def _as_policy_rule(r: Any) -> PolicyRule:
    """Coerce a floor rule to a PolicyRule instance. The TS SDK accepts plain
    objects for policyFloor (object spread), config.py types policy_floor as
    List[Any], and the TS docs use object literals — so a Python caller
    mirroring them may pass dicts. Without coercion the dataclasses.replace()
    in the floor functions raises TypeError, and under failMode=open a raised
    floor eval could be swallowed, silently un-enforcing a security baseline
    (fail-OPEN). Coerce so the floor stays fail-CLOSED and at TS parity.
    Already-PolicyRule instances pass through unchanged, so the conformance
    fixtures (which build dataclasses) hash byte-identically."""
    if isinstance(r, PolicyRule):
        return r
    if isinstance(r, dict):
        allowed = {f.name for f in dataclasses.fields(PolicyRule)}
        return PolicyRule(**{k: v for k, v in r.items() if k in allowed})
    raise TypeError(
        f"policy_floor entries must be a PolicyRule or dict, got {type(r).__name__}"
    )


def evaluate_floor(
    floor_rules: Optional[List[Any]],
    text: str,
    target: str = "prompt",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Anti-tamper policy floor: evaluate operator-declared FLOOR rules that
    cannot be silently disabled or downgraded. Every floor rule is coerced to
    enabled=True, mode="enforce" before evaluation, so flipping a floor rule
    off or to shadow cannot make it inert. Evaluated as its OWN pass BEFORE
    the customer rules (the engine is first-match-in-order; a customer
    topic_allow would otherwise pre-empt a floor block). Byte-identical to the
    TS evaluateFloor."""
    if not floor_rules:
        return {"decision": "allow", "reason_code": ReasonCode.PERMITTED.value}
    enforced = [
        dataclasses.replace(_as_policy_rule(r), enabled=True, mode="enforce")
        for r in floor_rules
    ]
    # The floor always resolves closed, fail_mode or not -- the same rule
    # policy.py applies to the floor class: a floor is the operator's
    # non-overridable baseline, so a floor rule that CANNOT RUN is the
    # strongest form of "cannot guarantee". A floor quota the meter has no slot
    # for therefore blocks, where the same rule in policy_rules follows
    # fail_mode. Parity with TS evaluate_floor.
    return evaluate_policy_rules(enforced, text, target, context, fail_mode="closed")


def derive_floor_version(floor_rules: Optional[List[Any]]) -> str:
    """Hash of the FLOOR definition (its own version, SEPARATE from
    derive_policy_version so it never perturbs the frozen rules-hash vectors).
    Stamped on events when a floor is active. "none" when empty. Byte-identical
    to the TS derive_floor_version."""
    if not floor_rules:
        return "none"
    coerced = sorted(
        (
            _canonical_rule(
                dataclasses.replace(_as_policy_rule(r), enabled=True, mode="enforce")
            )
            for r in floor_rules
        ),
        # Same UTF-16 code-unit order as derive_policy_version, for the same
        # reason: the floor hash rides every event under an active floor.
        key=lambda d: _utf16_order(str(d["id"])),
    )
    data = _canonical_json(coerced)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def evaluate_shadow_rules(
    rules: List[PolicyRule],
    text: str,
    target: str = "prompt",
    context: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Evaluate ONLY the shadow-mode rules, after the active decision is
    final. Same semantics as active evaluation but check-only (no quota
    consumption, EV-20/22); the result is a would-have record
    {rule_id, would, reason}, never a decision. None when nothing matched.
    Parity with TS evaluateShadowRules."""
    shadow_rules = [r for r in rules if r.enabled and getattr(r, "mode", None) == "shadow"]
    if not shadow_rules:
        return None
    import dataclasses
    active_shaped = [dataclasses.replace(r, mode=None) for r in shadow_rules]
    # No fail_mode here, deliberately: a shadow rule is defined as never
    # decision-affecting, and this surface is structurally always open (the
    # same reasoning record_check_only_failure states). Honouring fail_mode
    # would let a check-only unit block a call, which is the one thing shadow
    # mode promises it cannot do -- so an unmeterable shadow quota stays a
    # would-have record. Parity with TS evaluateShadowRules.
    result = evaluate_policy_rules(active_shaped, text, target, context, check_only=True)
    rule_id = result.get("rule_id")
    if not rule_id:
        return None
    fired = next((r for r in shadow_rules if r.id == rule_id), None)
    # A matched topic_allow means "would have allowed": not worth recording.
    if fired is not None and fired.type == "topic_allow":
        return None
    decision = result.get("decision")
    would = "block" if decision == "block" else "redact" if decision == "redact" else "flag"
    return {
        "rule_id": rule_id,
        "would": would,
        "reason_code": ReasonCode.SHADOW_WOULD_BLOCK.value,
        "reason": result.get("reason") or "",
    }
