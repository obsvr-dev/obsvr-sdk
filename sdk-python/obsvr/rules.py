"""Structured policy rules engine - parity with sdk/src/policy/rules.ts.

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


def evaluate_policy_rules(
    rules: List[PolicyRule],
    text: str,
    target: str = "prompt",
    context: Optional[Dict[str, Any]] = None,
    check_only: bool = False,
) -> Dict[str, Any]:
    """Evaluate rules against text (+ optional context).

    Context keys (all optional, parity with TS PolicyEvalContext):
      action_name, amount, caller_namespace, target_namespace,
      current_environment, source_documents, metadata.
    check_only (EV-22): identical decision logic, but no quota
    consumption. Used by shadow evaluation and explain().
    Returns PolicyDecisionResult dict.
    """
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
                from .remote import has_approval
                meta = (context or {}).get("metadata") or {}
                user_id = meta.get("user_id")
                # Pin the approval to THIS rule definition: a grant minted
                # under an older version of the rule (different hash) is void.
                rule_hash = derive_rule_hash(rule)
                if has_approval(rule.id, user_id, rule_hash):
                    return {
                        "decision": "allow",
                        "rule_id": rule.id,
                        "reason_code": ReasonCode.APPROVAL_GRANTED.value,
                        "reason": f"approved: {rule.name}",
                    }
                return {
                    "decision": "block",
                    "rule_id": rule.id,
                    "reason_code": ReasonCode.APPROVAL_REQUIRED.value,
                    "reason": f"approval_required: {rule.name}",
                    "approval_required": True,
                    "rule_hash": rule_hash,
                }
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


# ── In-memory quota store (parity with sdk/src/governance/quota.ts) ─────────
# Per-process fixed windows. Same caveat as TS: by default N workers = N x the
# budget. Fleet-quota escrow (ADR-7, obsvr/escrow.py) closes that gap for
# request-unit rules the server escrows on the /policies poll — this meter is
# the fallback for rules the server does not escrow. Server-side limits at
# ingest remain authoritative.

import threading as _threading
import time as _time

_quota_store: Dict[str, Dict[str, float]] = {}
_token_store: Dict[str, Dict[str, float]] = {}
_quota_lock = _threading.Lock()


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
            entry = {"count": 0.0, "window_start": now}
            _token_store[key] = entry
        return {
            "allowed": entry["count"] < limit,
            "remaining": max(0, int(limit - entry["count"])),
            "reset_at": entry["window_start"] + window_ms,
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
            entry = {"count": 0.0, "window_start": now}
            _token_store[key] = entry
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
            entry = {"count": 0.0, "window_start": now}
            _quota_store[key] = entry
        if entry["count"] >= limit:
            return {
                "allowed": False,
                "remaining": 0,
                "reset_at": entry["window_start"] + window_ms,
            }
        if record:
            entry["count"] += 1
        return {
            "allowed": True,
            "remaining": int(limit - entry["count"]),
            "reset_at": entry["window_start"] + window_ms,
        }


def _reset_quota() -> None:
    """Test helper."""
    with _quota_lock:
        _quota_store.clear()
        _token_store.clear()


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


def _canonical_json(value: Any) -> str:
    """Recursively key-sorted, compact, non-ASCII-preserving JSON.
    Byte-identical to the TS SDK's stableStringify. This is the canonical
    form both SDKs hash; changing it is a cross-language breaking change
    (update the shared fixture and the TS twin together)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def derive_policy_version(rules: List[PolicyRule]) -> str:
    """Canonical rules hash of the enabled rule set: 16-hex-char SHA-256
    prefix over the canonical projections sorted by id (codepoint order).
    Returns "none" when no rules are enabled. Stamped on every audit
    event as policy_version; must match the TS SDK byte for byte
    (pinned by the shared fixture)."""
    if not rules:
        return "none"
    enabled = sorted([r for r in rules if r.enabled], key=lambda r: r.id)
    if not enabled:
        return "none"
    data = _canonical_json([_canonical_rule(r) for r in enabled])
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


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
    return evaluate_policy_rules(enforced, text, target, context)


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
        key=lambda d: str(d["id"]),
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
