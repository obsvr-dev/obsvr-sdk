"""Built-in PII scanner + per-type policy resolution.

EXACT parity with sdk/src/policy/hook.ts:
  - same pattern set (labels, regexes, placeholders, confidence, category)
  - same Luhn validation for credit cards
  - same confidence-based overlap suppression over positioned spans
  - same BUILTIN_SEVERITY defaults
  - same resolution order: rules[type] -> default -> builtin -> detect_only
  - same compliance semantics (incl. customer hook override behavior)

Patterns are compiled with re.ASCII so \\d, \\w, \\s and \\b match exactly what
JavaScript's ASCII character classes match. Without it, Python's Unicode-aware
classes would accept e.g. Arabic-Indic digits that the TS twin never matches,
and the shared conformance fixture (conformance/fixtures/pii_scan.json) would
pin divergent behavior. Fullwidth digits still detect on both sides because
matching runs on the NFKC-normalized copy (§6).
"""

import bisect
import concurrent.futures
import re
import time
import unicodedata
from typing import Any, Callable, Dict, List, Optional, Tuple, TypedDict

from .config import ResolvedConfig
from .deobfuscate import (
    escalate_view_only_action,
    redact_for_storage,
    run_configured_pii_scan,
)
from .normalize import nfkc_with_source_map, normalize_for_matching, strip_invisible_chars

# Whole-text placeholder for a stored response the policy FLOOR redacted. A
# floor rule match (keyword/regex/topic) has no locatable span, so the stored
# copy is replaced wholesale rather than span-redacted. Byte-identical to the
# TS twin (core.FLOOR_REDACTION_PLACEHOLDER) so cross-SDK stored copies agree.
FLOOR_REDACTION_PLACEHOLDER = "[REDACTED:policy_floor]"


class PolicyDecisionResult(TypedDict, total=False):
    decision: str  # "allow" | "block" | "redact"
    rule_id: Optional[str]
    reason: Optional[str]
    policy_version: Optional[str]


def _luhn_check(digits: str) -> bool:
    """Validate a number string with the Luhn algorithm (parity with TS
    luhnCheck). Filters false-positive credit-card matches."""
    cleaned = re.sub(r"\D", "", digits, flags=re.ASCII)
    if len(cleaned) < 13 or len(cleaned) > 19:
        return False
    total = 0
    alt = False
    for ch in reversed(cleaned):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


# Ordered exactly like TS BUILTIN_PII_PATTERNS (hook.ts) — order is behavior:
# redaction applies patterns in sequence, so the shared fixture pins it.
BUILTIN_PII_PATTERNS: List[Dict[str, Any]] = [
    # --- PII ---
    {
        "label": "email",
        "pattern": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", re.ASCII),
        "placeholder": "[REDACTED_EMAIL]",
        "confidence": 0.9,
        "category": "pii",
    },
    {
        "label": "ssn",
        "pattern": re.compile(r"\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b", re.ASCII),
        "placeholder": "[REDACTED_SSN]",
        "confidence": 0.85,
        "category": "pii",
    },
    {
        # separator-less SSN gated on adjacent SSN context (no lookbehind,
        # TS-parity safe). Closes the "remove the dashes to evade" bypass without
        # flagging bare 9-digit runs (order ids, timestamps).
        "label": "ssn",
        "pattern": re.compile(
            r"\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|#))?)\b\s{0,8}[:#]?\s{0,8}\d{9}\b",
            re.I | re.ASCII,
        ),
        "placeholder": "[REDACTED_SSN]",
        "confidence": 0.8,
        "category": "pii",
    },
    {
        "label": "credit_card",
        "pattern": re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b", re.ASCII),
        "placeholder": "[REDACTED_CC]",
        "confidence": 0.9,
        "category": "pii",
        "validate": _luhn_check,
    },
    {
        "label": "phone",
        "pattern": re.compile(
            r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b", re.ASCII
        ),
        "placeholder": "[REDACTED_PHONE]",
        "confidence": 0.75,
        "category": "pii",
    },
    {
        "label": "ip_address",
        "pattern": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            re.ASCII,
        ),
        "placeholder": "[REDACTED_IP]",
        "confidence": 0.8,
        "category": "pii",
    },
    {
        "label": "uuid",
        "pattern": re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            re.ASCII,
        ),
        "placeholder": "[REDACTED_UUID]",
        "confidence": 0.5,
        "category": "pii",
    },
    # --- Secrets ---
    {
        "label": "jwt",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b", re.ASCII),
        "placeholder": "[REDACTED_JWT]",
        "confidence": 0.95,
        "category": "secret",
    },
    {
        "label": "api_key",
        "pattern": re.compile(r"\b(?:sk-|pk-)[A-Za-z0-9\-_]{10,}\b", re.ASCII),
        "placeholder": "[REDACTED_API_KEY]",
        "confidence": 0.9,
        "category": "secret",
    },
    {
        "label": "api_key",
        "pattern": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", re.ASCII),
        "placeholder": "[REDACTED_API_KEY]",
        "confidence": 0.95,
        "category": "secret",
    },
    {
        "label": "api_key",
        "pattern": re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b", re.ASCII),
        "placeholder": "[REDACTED_API_KEY]",
        "confidence": 0.95,
        "category": "secret",
    },
    {
        "label": "aws_access_key",
        "pattern": re.compile(
            r"\b(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b",
            re.ASCII,
        ),
        "placeholder": "[REDACTED_AWS_KEY]",
        "confidence": 0.95,
        "category": "secret",
    },
    {
        "label": "private_key",
        "pattern": re.compile(r"-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----", re.ASCII),
        "placeholder": "[REDACTED_PRIVATE_KEY]",
        "confidence": 0.95,
        "category": "secret",
    },
    {
        "label": "github_token",
        "pattern": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{34,}\b", re.ASCII),
        "placeholder": "[REDACTED_GITHUB_TOKEN]",
        "confidence": 0.95,
        "category": "secret",
    },
    {
        "label": "slack_webhook",
        "pattern": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", re.ASCII
        ),
        "placeholder": "[REDACTED_SLACK_WEBHOOK]",
        "confidence": 0.95,
        "category": "secret",
    },
    # --- Security (prompt injection) ---
    {
        "label": "prompt_injection",
        "pattern": re.compile(
            r"(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|your|the|system)\s*(?:instructions?|rules?|prompts?|guidelines?|constraints?|programming|training)",
            re.IGNORECASE | re.ASCII,
        ),
        "placeholder": "[BLOCKED_INJECTION]",
        "confidence": 0.85,
        "category": "security",
    },
    {
        "label": "prompt_injection",
        "pattern": re.compile(
            r"(?:reveal|show|display|print|output|repeat|echo|tell\s+me|give\s+me|what\s+(?:is|are))\s+(?:your|the)\s+(?:system|initial|original|hidden|secret|internal)\s*(?:prompt|instructions?|rules?|message|configuration|directives?)",
            re.IGNORECASE | re.ASCII,
        ),
        "placeholder": "[BLOCKED_INJECTION]",
        "confidence": 0.9,
        "category": "security",
    },
    {
        "label": "prompt_injection",
        "pattern": re.compile(
            r"(?:you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\s+(?:DAN|an?\s+unrestricted|an?\s+uncensored|an?\s+unfiltered|a\s+jailbroken|Developer\s*Mode|god\s*mode)",
            re.IGNORECASE | re.ASCII,
        ),
        "placeholder": "[BLOCKED_INJECTION]",
        "confidence": 0.9,
        "category": "security",
    },
    {
        "label": "prompt_injection",
        "pattern": re.compile(
            r"(?:enable|activate|enter|switch\s+to|turn\s+on)\s+(?:developer|debug|admin|god|unrestricted|jailbreak|sudo)\s*(?:mode|access)",
            re.IGNORECASE | re.ASCII,
        ),
        "placeholder": "[BLOCKED_INJECTION]",
        "confidence": 0.85,
        "category": "security",
    },
]

from .pii_types import BUILTIN_SEVERITY

DEFAULT_COMPLIANCE: Dict[str, Any] = {
    "event_type": "llm_call",
    "policy_version": "v1",
    "action_taken": "allowed",
    "action_reason": "none",
    "action_source": "unknown",
    "redacted_types": [],
    "blocked_types": [],
}


def _collect_matches(text: str) -> List[Dict[str, Any]]:
    """Collect all pattern matches with position and confidence info (parity
    with TS collectMatches). validate() failures are discarded."""
    matches: List[Dict[str, Any]] = []
    for entry in BUILTIN_PII_PATTERNS:
        validate: Optional[Callable[[str], bool]] = entry.get("validate")
        for m in entry["pattern"].finditer(text):
            if validate is not None and not validate(m.group(0)):
                continue
            matches.append(
                {
                    "label": entry["label"],
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": entry["confidence"],
                    "category": entry["category"],
                }
            )
    return matches


def _suppress_overlaps(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove overlapping matches, keeping the highest-confidence span when two
    overlap (parity with TS suppressOverlaps: greedy by confidence descending —
    stable for equal confidence — over a start-sorted, overlap-free kept set)."""
    by_confidence = sorted(matches, key=lambda m: -m["confidence"])
    kept: List[Dict[str, Any]] = []  # invariant: sorted by start, non-overlapping
    starts: List[int] = []
    for match in by_confidence:
        idx = bisect.bisect_left(starts, match["start"])
        prev = kept[idx - 1] if idx > 0 else None
        nxt = kept[idx] if idx < len(kept) else None
        overlaps_prev = prev is not None and match["start"] < prev["end"] and match["end"] > prev["start"]
        overlaps_next = nxt is not None and match["start"] < nxt["end"] and match["end"] > nxt["start"]
        if not overlaps_prev and not overlaps_next:
            kept.insert(idx, match)
            starts.insert(idx, match["start"])
    return kept


def run_builtin_pii_scan(text: str) -> Dict[str, Any]:
    """Scan text with the built-in patterns: confidence scoring, Luhn validation
    for credit cards, and overlap suppression — exact parity with TS
    runBuiltinPiiScan. detected_types are unique labels in span (start) order.

    §6: matches against the NFKC/zero-width/confusable-normalized copy so a
    lookalike or zero-width-joined payload cannot dodge the PII / secret /
    injection patterns. Matching-only -- the caller's stored text is untouched
    (redact_builtin_pii runs on the original), so only DETECTION is affected.
    """
    raw = _collect_matches(normalize_for_matching(text))
    filtered = _suppress_overlaps(raw)
    detected_types = list(dict.fromkeys(m["label"] for m in filtered))
    return {"pii_detected": len(detected_types) > 0, "detected_types": detected_types}


def redact_builtin_pii(text: Optional[str]) -> str:
    """Replace all PII matches with typed placeholders. Strips invisible
    (zero-width / bidi) chars first so PII that detection caught on the
    normalized text is actually scrubbed rather than forwarded intact.
    None-safe: a missing value redacts to "" (callers may pass an absent last
    user message), never a TypeError."""
    if not text:
        return ""
    result = strip_invisible_chars(text)
    # Fast path: when the text has no NFKC-changing compatibility forms (the
    # common ASCII case), folding surfaces nothing the patterns don't already
    # match, so redact directly and skip building any per-codepoint offset map.
    # Keeps redaction at its prior cost; fold-aware matching runs only for text
    # that actually contains fullwidth / ligature / compatibility characters.
    has_compat_forms = result != unicodedata.normalize("NFKC", result)
    for entry in BUILTIN_PII_PATTERNS:
        if has_compat_forms:
            result = _redact_pattern_fold_aware(result, entry)
        else:
            result = _sub_validated(entry, result)
    return result


def _sub_validated(entry: Dict[str, Any], text: str) -> str:
    """pattern.sub with per-match validate() (parity with TS redactBuiltinPii:
    a match failing validation — e.g. a non-Luhn card number — is left intact)."""
    validate: Optional[Callable[[str], bool]] = entry.get("validate")
    if validate is None:
        return entry["pattern"].sub(entry["placeholder"], text)
    return entry["pattern"].sub(
        lambda m: entry["placeholder"] if validate(m.group(0)) else m.group(0), text
    )


def _redact_pattern_fold_aware(base: str, entry: Dict[str, Any]) -> str:
    """Apply one PII pattern, matching on the NFKC-folded view but replacing the
    span in ``base``. Keeps redaction in step with detection (which normalizes)
    for compatibility forms (fullwidth digits, ligatures) while leaving every
    non-PII character in ``base`` untouched. Plain ASCII takes the identity fast
    path, exactly the prior ``pattern.sub`` behavior."""
    pattern = entry["pattern"]
    placeholder = entry["placeholder"]
    validate: Optional[Callable[[str], bool]] = entry.get("validate")
    normalized, map_start, map_end = nfkc_with_source_map(base)
    if normalized == base:
        return _sub_validated(entry, base)
    spans: List[Tuple[int, int]] = []
    for m in pattern.finditer(normalized):
        if m.start() == m.end():
            continue
        if validate is not None and not validate(m.group(0)):
            continue
        spans.append((map_start[m.start()], map_end[m.end() - 1]))
    if not spans:
        return base
    out = base
    for s, e in reversed(spans):
        out = out[:s] + placeholder + out[e:]
    return out


def resolve_pii_policy(
    detected_types: List[str],
    policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolution order per type: rules[type] -> default -> builtin -> detect_only.

    Final action is the most severe: block > redact > detect_only.
    """
    blocked_types: List[str] = []
    redacted_types: List[str] = []
    rules = (policy or {}).get("rules") or {}
    default = (policy or {}).get("default")

    for pii_type in detected_types:
        action = rules.get(pii_type)
        if action is None:
            action = default
        if action is None:
            action = BUILTIN_SEVERITY.get(pii_type)
        if action is None:
            action = "detect_only"

        if action == "block":
            blocked_types.append(pii_type)
        elif action == "redact":
            redacted_types.append(pii_type)
        # detect_only: neither list

    if blocked_types:
        action = "block"
    elif redacted_types:
        action = "redact"
    else:
        action = "detect_only"

    return {
        "action": action,
        "blocked_types": blocked_types,
        "redacted_types": redacted_types,
    }


# ============================================================================
# Pre-call / observe-only policy application (parity with integrations/core.ts)
# ============================================================================


def apply_pre_call_policy(
    prompt_text: str,
    config: ResolvedConfig,
    provider: str = "unknown",
    operation: str = "",
    tenant_id: str = None,
    metadata: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
    scan_text: Optional[str] = None,
) -> Dict[str, Any]:
    """Compliance boundary before an LLM call (real enforcement).

    ``prompt_text`` is the FULL prompt — it is what gets stored/redacted.
    ``scan_text`` is the text the PII / rules DECISION scans AND what
    multi-turn injection scores; callers pass the last user message so each
    turn is governed once, when it arrives, and the multi-turn gate
    accumulates per-turn deltas (parity with the TS wrapper — scoring the
    joined history would re-count early turns on every call and inflate the
    decayed score into a false trip). Defaults to ``prompt_text`` when not
    provided.

    Returns {"decision", "compliance", "redacted_prompt"}.
    """
    scan = scan_text if scan_text is not None else prompt_text
    # Resolve tenant config if provided
    if tenant_id is not None:
        from .config import get_tenant_config
        config = get_tenant_config(tenant_id)

    action_taken = "allowed"
    action_reason = "none"
    action_source = "unknown"
    redacted_types: List[str] = []
    blocked_types: List[str] = []
    hook_rule_id: Optional[str] = None
    hook_reason: Optional[str] = None
    hook_policy_version: Optional[str] = None
    gate_rule_id: Optional[str] = None
    gate_reason: Optional[str] = None

    # 0. Enforcement-integrity gate: blocks when the project is paused / the
    #    key is revoked (kill switch), or when fail_mode="closed" and policy
    #    sync has gone stale beyond the staleness budget.
    from .remote import is_enforcement_degraded
    degraded = is_enforcement_degraded(config)
    if degraded["degraded"]:
        action_taken = "blocked"
        action_reason = "policy_violation"
        # "policy_rules": parity with BOTH TS paths (wrapper + integrations
        # core), which label integrity-gate blocks policy_rules so evidence
        # attributes them to the policy machinery, not the PII scanner.
        action_source = "policy_rules"
        gate_rule_id = f"sdk:{degraded['reason']}"
        gate_reason = (
            "Project paused or API key revoked (SDK kill switch)"
            if degraded["reason"] == "project_paused_or_key_revoked"
            else f"Policy sync unavailable with fail_mode=closed ({degraded['reason']})"
        )

    # 0.5 Session taint latch: a session compromised on an earlier turn has its
    #     later egress escalated. ENFORCE runs on PRIOR taint; SET happens at
    #     this call's detection points below (TS parity: core.ts / wrapper.ts).
    from .session_taint import (
        resolve_session_taint,
        derive_session_key,
        evaluate_session_taint,
        mark_tainted,
        touch_taint,
        session_taint_size,
    )
    taint_cfg = resolve_session_taint(config)
    taint_key = derive_session_key(metadata)
    taint_rule_id: Optional[str] = None
    taint_reason: Optional[str] = None
    if taint_cfg and session_taint_size() > 0 and action_taken != "blocked":
        verdict = evaluate_session_taint(taint_key, taint_cfg)
        if verdict["enforcement"] != "none":
            touch_taint(taint_key, time.monotonic())  # LRU: keep victim alive
            taint_rule_id = "sdk:session_tainted"
            taint_reason = (
                "Session previously compromised (%s); egress escalated"
                % verdict["reason"]
            )
            if verdict["enforcement"] == "block":
                action_taken = "blocked"
                action_reason = "policy_violation"
                action_source = "policy_rules"
            elif action_reason == "none":
                action_reason = "policy_violation"
                action_source = "policy_rules"

    # 0.75 Canary-leak scan (unsuppressible). A planted honeytoken appearing in
    #      the OUTBOUND text (tool-call arguments, or a user turn echoing a
    #      leaked token) is a CRITICAL exfiltration signal -- block before it
    #      reaches the provider/tool, and DO NOT let the customer hook downgrade
    #      it (canary_floor). Scans ``scan`` (the user/tool-args decision text,
    #      never the app's planted system prompt), only when a canary is minted.
    canary_floor = False
    canary_telemetry: Optional[Dict[str, Any]] = None
    canary_rule_id: Optional[str] = None
    canary_reason: Optional[str] = None
    from .canary import canary_registry_size
    if canary_registry_size() > 0 and action_taken != "blocked":
        from .canary import scan_for_canary, canary_leak_telemetry
        leak = scan_for_canary(scan)
        if leak["leaked"]:
            action_taken = "blocked"
            action_reason = "policy_violation"
            action_source = "builtin"
            canary_floor = True
            ids = ", ".join(h["id"] for h in leak["hits"])
            canary_rule_id = "sdk:canary_leak"
            canary_reason = f"Canary token leaked in request ({ids})"
            canary_telemetry = canary_leak_telemetry(leak["hits"], "request")
            if taint_cfg:
                mark_tainted(taint_key, "canary_leak", time.monotonic())

    # 1. Built-in PII scan (note: empty-dict policy still enables it).
    #    Presidio NLP results merge with the regex scan when configured,
    #    matching the TS SDK (regex always runs; Presidio adds NLP types).
    #    With deobfuscation enabled the scanner also sees decoded/stripped
    #    views (server-side normalizer mirror); ``via`` records which view surfaced a
    #    hit the raw text hid.
    pii_scan_via: Optional[str] = None
    if config.pii_policy is not None and action_taken != "blocked":
        pii = run_configured_pii_scan(scan, getattr(config, "deobfuscation", None))
        pii_scan_via = pii.get("via")
        detected_types = list(pii["detected_types"])
        if getattr(config, "presidio_analyzer_url", None):
            from .presidio import presidio_scan
            nlp = presidio_scan(scan, config.presidio_analyzer_url)
            for t in nlp["detected_types"]:
                if t not in detected_types:
                    detected_types.append(t)
        if detected_types:
            action_reason = "pii_detected"
            action_source = (
                "builtin+presidio"
                if getattr(config, "presidio_analyzer_url", None)
                else "builtin"
            )
            # A detected prompt-injection taints the session.
            if taint_cfg and "prompt_injection" in detected_types:
                mark_tainted(taint_key, "prompt_injection", time.monotonic())
            resolved = resolve_pii_policy(detected_types, config.pii_policy)
            # A view-only hit has no locatable span in the raw text, so
            # "redact" would no-op while the record claims "redacted" —
            # escalate to block (parity with the TS wrapper/core).
            pii_action = escalate_view_only_action(resolved["action"], pii_scan_via)
            if pii_action == "block":
                action_taken = "blocked"
                blocked_types = resolved["blocked_types"]
                redacted_types = resolved["redacted_types"]
            elif pii_action == "redact":
                action_taken = "redacted"
                redacted_types = resolved["redacted_types"]
            # detect_only: reason/source set; action stays "allowed"

    # 1.2. Multi-turn injection scoring - catches payloads split across turns
    #      that no single message would trip. Session keyed by metadata
    #      user_id (falls back to a process-wide bucket); score decays with
    #      a half-life so normal traffic never accumulates.
    mti = getattr(config, "multi_turn_injection", None)
    if mti and mti.get("enabled") and action_taken != "blocked":
        from .injection_session import score_turn
        meta = metadata or {}
        session_key = str(meta.get("user_id") or meta.get("session_id") or meta.get("tenant_id") or "global")
        # Score THIS turn's new text (``scan`` = last user message when the
        # caller provides it), never the joined history — parity with the TS
        # wrapper's per-turn-delta scoring; re-scoring earlier turns on every
        # call would inflate the decayed score into a false trip.
        # RAW scan only -- deliberately NOT the deobfuscation-aware scan. The
        # gate below fires on ``tripped and not had_full`` ("a full match is
        # already handled by the single-turn scan"), but the single-turn scan
        # only enforces when pii_policy is configured. A view-aware had_full
        # here let an ENCODED injection suppress the accumulation block while
        # nothing else enforced it -- enabling deobfuscation weakened this
        # gate (caught by adversarial review). With pii_policy set, the
        # view-aware step-1 scan above already blocks encoded injections.
        had_full = "prompt_injection" in run_builtin_pii_scan(scan)["detected_types"]
        mt = score_turn(
            session_key,
            scan,
            had_full,
            threshold=float(mti.get("threshold", 1.0)),
            half_life_s=float(mti.get("half_life_s", 600.0)),
        )
        # Full matches are already handled by the single-turn scan; the
        # multi-turn gate exists for the accumulation case.
        if mt["tripped"] and not had_full:
            gate_rule_id = "sdk:multi_turn_injection"
            gate_reason = (
                f"Multi-turn injection score {mt['score']:.2f} reached threshold over "
                f"{mt['turns']} turn(s); this turn's signals: {', '.join(mt['signals']) or 'none'}"
            )
            # Accumulated injection taints the session (later egress escalated).
            if taint_cfg:
                mark_tainted(taint_key, "multi_turn_injection", time.monotonic())
            if mti.get("action", "block") == "block":
                action_taken = "blocked"
                action_reason = "policy_violation"
                # "policy_rules": parity with the TS wrapper and integrations
                # core (rule_id sdk:multi_turn_injection names the gate).
                action_source = "policy_rules"
            else:
                # flag: annotate without changing the action (TS parity).
                if action_reason == "none":
                    action_reason = "policy_violation"
                action_source = "policy_rules"

    # 1.4. Anti-tamper policy FLOOR (before customer rules; floor rules always
    #      enforce, and a floor block is excluded from the hook-override
    #      branches below). Lives in its own config field so a remote sync
    #      replacing policy_rules can never delete it. TS parity: core.ts 1.4.
    floor_block = False
    floor_rule_id: Optional[str] = None
    floor_reason: Optional[str] = None
    floor_override_ignored: Optional[Dict[str, Any]] = None
    floor_active = bool(getattr(config, "policy_floor", None))
    if floor_active and action_taken != "blocked":
        from .rules import evaluate_floor
        floor_result = evaluate_floor(
            config.policy_floor,
            scan,
            "prompt",
            # SAME context the customer-rules pass below builds, so a rule
            # promoted INTO the floor evaluates identically (incl.
            # current_environment for environment_gate floor rules) — the floor
            # must never be weaker than the same rule as a customer rule.
            {
                "metadata": metadata or {},
                "model": model,
                "provider": provider,
                "current_environment": getattr(config, "environment", None),
            },
        )
        if floor_result.get("decision") in ("block", "redact"):
            # A floor 'redact' FAILS CLOSED to a block (parity with TS wrapper,
            # core.ts, and the governance surface): there is no span-level
            # redaction for an arbitrary floor-rule match, so blocking is the
            # only way the non-overridable baseline can guarantee the matched
            # content is not forwarded. floor_block=True so the hook-override
            # exclusion + floor_override_ignored record cover the redact case.
            floor_block = True
            floor_rule_id = floor_result.get("rule_id")
            floor_reason = floor_result.get("reason") or "Blocked by policy floor"
            action_taken = "blocked"
            action_reason = "policy_violation"
            action_source = "policy_rules"

    # 1.5. Structured policy rules
    rules_rule_id: Optional[str] = floor_rule_id or gate_rule_id
    rules_reason: Optional[str] = floor_reason or gate_reason
    if getattr(config, 'policy_rules', None) and action_taken != "blocked":
        from .rules import evaluate_policy_rules
        rules_result = evaluate_policy_rules(
            config.policy_rules,
            scan,
            context={
                "metadata": metadata or {},
                "model": model,
                "provider": provider,
                "current_environment": getattr(config, "environment", None),
            },
        )
        rules_decision = rules_result.get("decision", "allow")
        rules_rule_id = rules_result.get("rule_id")
        rules_reason = rules_result.get("reason")
        if rules_decision == "block" and action_taken != "blocked":
            action_taken = "blocked"
            action_reason = "policy_violation"
            # Parity with TS (EV-15): structured-rule outcomes are labeled
            # "policy_rules", never "builtin", so evidence names the
            # determining step correctly.
            action_source = "policy_rules"
            # Human-in-the-loop: file an approval request so the dashboard
            # queue can grant a time-boxed pass; retries pass once granted.
            if rules_result.get("approval_required"):
                from .remote import request_approval
                request_approval(
                    config,
                    rule_id=rules_result.get("rule_id") or "",
                    rule_name=rules_result.get("reason"),
                    operation=operation,
                    user_id=(metadata or {}).get("user_id"),
                    rule_hash=rules_result.get("rule_hash"),
                )
        elif rules_decision == "redact" and action_taken != "redacted":
            action_taken = "redacted"
            action_reason = "policy_violation"
            action_source = "policy_rules"

    # 2. Customer hook. Runs after builtin policy, EXCEPT when the
    #    enforcement-integrity gate is degraded (project paused / key revoked /
    #    fail-closed staleness): a gate block is NOT customer-overridable (EV-3).
    #    Mirrors the TS wrapper (`!degraded.degraded` guard in wrapper.ts) so the
    #    dashboard kill switch cannot be defeated by a hook returning "allow".
    # Hook disposition for the decision record (ADR-2): configured-but-not-run
    # is "skipped"; outcomes overwrite it below.
    hook_disposition = "not_configured" if config.on_pre_call is None else "skipped"
    if config.on_pre_call is not None and not degraded["degraded"]:
        pre_event = {
            "provider": provider,
            "operation": operation,
            "environment": config.environment,
            "prompt": prompt_text,
        }
        timeout_s = getattr(config, 'hook_timeout_ms', 2000) / 1000.0
        # NOT a `with` block: the context manager's __exit__ does
        # shutdown(wait=True) and JOINS a hung hook thread, so the timeout
        # would no longer bound wall clock (a 50ms budget could stall for the
        # hook's full runtime). shutdown(wait=False) abandons the worker
        # instead — the non-daemon thread keeps running the hook and may
        # delay process exit until it returns, but the governed call itself
        # stays bounded by hook_timeout_ms.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = ex.submit(config.on_pre_call, pre_event)
            try:
                hook_result = future.result(timeout=timeout_s)
                # handle PolicyDecisionResult dict or bare string
                if isinstance(hook_result, dict):
                    hook_decision = hook_result.get("decision", "allow")
                    hook_rule_id = hook_result.get("rule_id")
                    hook_reason = hook_result.get("reason")
                    hook_policy_version = hook_result.get("policy_version")
                else:
                    hook_decision = hook_result if hook_result else "allow"
                    hook_rule_id = None
                    hook_reason = None
                    hook_policy_version = None
                hook_disposition = (
                    hook_decision if hook_decision in ("block", "redact") else "allow"
                )
            except concurrent.futures.TimeoutError:
                # fail_closed: a hook that cannot render a verdict is not
                # approval. Parity with the TS SDK failMode semantics.
                fail_closed = getattr(config, "fail_mode", "open") == "closed"
                hook_disposition = "timeout"
                hook_decision = "block" if fail_closed else "allow"
                hook_rule_id = None
                hook_reason = "hook_timeout (fail_closed)" if fail_closed else None
                hook_policy_version = None
                # Never downgrade a builtin/rules block: a hook that can't render
                # a verdict is not an approval (fail-open applies to the hook's
                # own contribution, not to overriding other enforcement).
                if action_taken != "blocked":
                    action_taken = "hook_timeout"
                    action_source = "customer_hook"
        except Exception:
            fail_closed = getattr(config, "fail_mode", "open") == "closed"
            hook_disposition = "error"
            hook_decision = "block" if fail_closed else "allow"
            hook_rule_id = None
            hook_reason = "hook_error (fail_closed)" if fail_closed else None
            hook_policy_version = None
            # Same as timeout: a hook error must not un-block a builtin/rules block.
            if action_taken != "blocked":
                action_taken = "hook_error"
                action_source = "customer_hook"
        finally:
            ex.shutdown(wait=False)

        # fail_closed promotes a hook timeout/error to a hard block. The
        # event_type stays derivable from action_taken == "blocked" below,
        # while policy_reason preserves the "(fail_closed)" cause.
        if action_taken in ("hook_error", "hook_timeout") and hook_decision == "block":
            action_taken = "blocked"
            action_reason = "policy_violation"
            action_source = "customer_hook"

        if action_taken not in ("hook_error", "hook_timeout"):
            if hook_decision == "block":
                action_taken = "blocked"
                action_reason = "policy_violation"
                action_source = "customer_hook"
            elif (
                hook_decision == "allow"
                and hook_disposition == "allow"
                and action_taken == "blocked"
                and not canary_floor
            ):
                if floor_block:
                    # The hook tried to un-block a FLOOR rule. Refused +
                    # recorded on the tamper-evident event; the block stands.
                    floor_override_ignored = {
                        "rule_id": floor_rule_id,
                        "attempted": "allow",
                    }
                else:
                    # Only an EXPLICIT hook allow overrides a builtin block
                    # (logged transparently). A fail-open timeout/error default
                    # must NOT un-block builtin PII/rules enforcement. A
                    # canary-leak block is unsuppressible (canary_floor).
                    action_taken = "allowed"
                    action_reason = "customer_override"
                    action_source = "customer_hook"
            elif (
                hook_decision == "redact"
                and action_taken != "redacted"
                and not canary_floor
                and floor_block
            ):
                floor_override_ignored = {"rule_id": floor_rule_id, "attempted": "redact"}
            elif hook_decision == "redact" and action_taken != "redacted" and not canary_floor:
                if pii_scan_via is not None:
                    # View-only detection: no locatable span, so a "redacted"
                    # outcome would be a false record (and would downgrade the
                    # escalated builtin block). Same clamp as
                    # escalate_view_only_action: block instead.
                    action_taken = "blocked"
                    action_reason = "policy_violation"
                    action_source = "customer_hook"
                else:
                    action_taken = "redacted"
                    action_reason = "policy_violation"
                    action_source = "customer_hook"
                    redacted_types = ["all"]  # customer-driven; exact types unknown

    from .rules import derive_policy_version
    policy_ver = derive_policy_version(getattr(config, 'policy_rules', None) or [])

    # 2.5. Inbound external policy backend (ADR-4): consult the customer's
    #      OPA/Cedar engine and merge DENY-WINS with the local decision (a deny
    #      from EITHER side blocks). Only when not already blocked — a local
    #      block cannot be downgraded, so the deny-wins outcome is already
    #      settled and a network round-trip would be pure overhead. A backend
    #      error/timeout is a DENY (fail-closed) unless the backend is in
    #      observe-only shadow mode. The backend's identity + effective-policy
    #      hash are recorded on the event for provenance.
    external_backend_record = None
    backend_rule_id: Optional[str] = None
    backend_reason: Optional[str] = None
    backend_cfg = getattr(config, "external_policy_backend", None)
    if backend_cfg and action_taken != "blocked":
        from .decision_record import sha256_hex
        from .external_backend import build_backend_input, run_external_backend_step
        local_decision = "redact" if action_taken == "redacted" else "allow"
        meta_b = metadata or {}
        try:
            step = run_external_backend_step(
                backend_cfg,
                local_decision,
                build_backend_input(
                    operation=operation,
                    provider=provider,
                    model=model or "",
                    environment=getattr(config, "environment", None),
                    user_id=meta_b.get("user_id") if isinstance(meta_b.get("user_id"), str) else None,
                    service_name=(
                        getattr(config, "default_service_name", None)
                        if isinstance(getattr(config, "default_service_name", None), str)
                        else None
                    ),
                    tenant_id=tenant_id if isinstance(tenant_id, str) else None,
                    local_decision=local_decision,
                    rules_hash=policy_ver,
                    prompt_sha256=sha256_hex(scan),
                ),
            )
            external_backend_record = step["record"]
            if step["blocked_by_backend"]:
                action_taken = "blocked"
                action_reason = "policy_violation"
                action_source = "external_backend"
                backend_rule_id = f"backend:{backend_cfg['type']}"
                reasons = step["record"].get("reasons") or []
                backend_reason = (
                    "; ".join(reasons)
                    if reasons
                    else f"Denied by external {backend_cfg['type']} policy backend"
                )
        except Exception:
            # run_external_backend_step maps every failure to an outcome; this
            # is defensive. Fail closed unless the backend is observe-only.
            if not backend_cfg.get("shadow"):
                action_taken = "blocked"
                action_reason = "policy_violation"
                action_source = "external_backend"
                backend_rule_id = f"backend:{backend_cfg['type']}"
                backend_reason = (
                    f"Denied by external {backend_cfg['type']} policy backend "
                    "(evaluation error, fail-closed)"
                )

    # Shadow rules (EV-20/21): evaluated AFTER the active decision is
    # final, check-only, recorded on the event, never decision-affecting.
    shadow_outcome = None
    if getattr(config, "policy_rules", None):
        from .rules import evaluate_shadow_rules
        shadow_outcome = evaluate_shadow_rules(
            config.policy_rules, prompt_text, context={"metadata": metadata or {}}
        )

    # Canonical decision record (ADR-2): commit exactly what this decision ran
    # over. ``scan`` is the text the pipeline evaluated (pre-redaction).
    from .decision_record import (
        ENGINE_VERSION,
        build_decision_input,
        compute_decision_input_hash,
    )
    meta = metadata or {}
    decision_doc = build_decision_input(
        rules_hash=policy_ver,
        degraded=degraded["degraded"],
        degraded_reason=degraded.get("reason"),
        target="request",
        evaluated_text=scan,
        user_id=meta.get("user_id") if isinstance(meta.get("user_id"), str) else None,
        service_name=(
            getattr(config, "default_service_name", None)
            if isinstance(getattr(config, "default_service_name", None), str)
            else None
        ),
        tenant_id=tenant_id if isinstance(tenant_id, str) else None,
        hook=hook_disposition,
    )

    compliance = {
        "event_type": "blocked_call" if action_taken == "blocked" else "llm_call",
        "policy_version": policy_ver,
        "action_taken": action_taken,
        "action_reason": action_reason,
        "action_source": action_source,
        "redacted_types": redacted_types,
        "blocked_types": blocked_types,
        # Canary wins (unsuppressible), then the rest; taint is the escalation
        # reason when nothing more specific fired.
        "rule_id": canary_rule_id or backend_rule_id or hook_rule_id or rules_rule_id or taint_rule_id,
        "policy_reason": canary_reason or backend_reason or hook_reason or rules_reason or taint_reason,
        "shadow_outcome": shadow_outcome,
        # Additive decision-record fields (never part of the chain preimage)
        "decision_input_hash": compute_decision_input_hash(decision_doc),
        "engine_version": ENGINE_VERSION,
        # External policy backend provenance (ADR-4, additive)
        "external_backend": external_backend_record,
    }

    if action_taken == "blocked":
        decision = "block"
    elif action_taken == "redacted":
        decision = "redact"
    else:
        decision = "allow"

    # Presidio anonymizer produces the redacted copy when configured
    # (typed placeholders for NLP entities); regex redaction is the fallback.
    redacted_prompt = None
    if canary_floor:
        # A canary leak stores a whole-text placeholder (the surface carries
        # the raw token / an encoded copy -- never persist the secret).
        from .canary import CANARY_REDACTION_PLACEHOLDER
        redacted_prompt = CANARY_REDACTION_PLACEHOLDER
    elif (
        action_taken == "redacted"
        and getattr(config, "presidio_analyzer_url", None)
        and getattr(config, "presidio_anonymizer_url", None)
    ):
        from .presidio import presidio_redact_text
        redacted_prompt = presidio_redact_text(
            prompt_text, config.presidio_analyzer_url, config.presidio_anonymizer_url
        )
    if redacted_prompt is None:
        # View-only detections have no locatable span, so the stored copy
        # becomes a whole-text placeholder (redact_for_storage); with via
        # absent this is exactly the prior redact_builtin_pii output.
        redacted_prompt = redact_for_storage(prompt_text, pii_scan_via)

    result = {
        "decision": decision,
        "compliance": compliance,
        "redacted_prompt": redacted_prompt,
    }
    if pii_scan_via is not None:
        # Server-side normalizer mirror (security_normalized): which view defeated the
        # obfuscation. Key only present on view-only hits (TS parity).
        result["security_normalized"] = pii_scan_via
    if canary_telemetry is not None:
        # CRITICAL canary evidence for the caller to stamp on the event
        # (obsvr_telemetry). Never the raw token.
        result["canary_telemetry"] = canary_telemetry
    if floor_active:
        from .rules import derive_floor_version
        floor_tel: Dict[str, Any] = {
            "floor_version": derive_floor_version(config.policy_floor)
        }
        if floor_override_ignored is not None:
            floor_tel["floor_override_ignored"] = floor_override_ignored
        result["floor_telemetry"] = floor_tel
    return result


def blocked_prompt_for_storage(
    prompt_text: str,
    compliance: Dict[str, Any],
    via: Optional[str] = None,
) -> str:
    """Redacted form when PII triggered the block, else a placeholder.

    ``via`` is ``security_normalized`` from the pre-call result, when the
    caller has one: a view-only detection has no locatable span, so the
    stored prompt becomes a whole-text placeholder instead of a
    silently-intact "redacted" copy. Additive — omitting it preserves the
    prior behavior exactly.
    """
    if compliance.get("action_reason") == "pii_detected":
        return redact_for_storage(prompt_text, via)
    return "[BLOCKED_BY_POLICY]"


def blocked_user_input_for_storage(user_text: str, policy: Dict[str, Any]) -> str:
    """The ``user_input`` stored on a blocked pre-call event. On a canary-leak
    block the raw token must NEVER persist (redact_for_storage ->
    redact_builtin_pii does not know the canary format), so the stored copy is
    the canary placeholder; otherwise the view-aware redaction. TS parity:
    blockedUserInputForStorage.
    """
    if policy.get("canary_telemetry") is not None:
        from .canary import CANARY_REDACTION_PLACEHOLDER
        return CANARY_REDACTION_PLACEHOLDER
    return redact_for_storage(user_text, policy.get("security_normalized"))


def _observe_compliance(config: ResolvedConfig) -> Dict[str, Any]:
    """DEFAULT_COMPLIANCE copy with the REAL rules hash stamped: even
    observe-only paths must pin the policy state they ran under."""
    from .rules import derive_policy_version
    compliance = dict(DEFAULT_COMPLIANCE)
    compliance["policy_version"] = derive_policy_version(
        getattr(config, "policy_rules", None) or []
    )
    return compliance


def apply_observe_policy(prompt_text: str, config: ResolvedConfig) -> Dict[str, Any]:
    """Observe-only policy for framework callbacks: the request already
    went to the LLM, so policy applies to the *stored* copy.
    "block" is downgraded to redact-in-event with action_reason pii_detected.
    """
    if config.pii_policy is None:
        return {"should_redact_stored": False, "compliance": _observe_compliance(config)}
    scan = run_configured_pii_scan(prompt_text, getattr(config, "deobfuscation", None))
    if not scan["pii_detected"]:
        return {"should_redact_stored": False, "compliance": _observe_compliance(config)}
    via = scan.get("via")
    resolved = resolve_pii_policy(scan["detected_types"], config.pii_policy)
    if resolved["action"] == "detect_only":
        compliance = _observe_compliance(config)
        compliance["action_reason"] = "pii_detected"
        compliance["action_source"] = "builtin"
        result = {"should_redact_stored": False, "compliance": compliance}
        if via is not None:
            result["stored_redaction_via"] = via
        return result
    # redact OR block (downgraded): redact the stored copy. A view-only hit
    # (stored_redaction_via) has no locatable span — callers MUST redact
    # stored copies with redact_for_storage(text, via), never span redaction.
    compliance = _observe_compliance(config)
    compliance["action_taken"] = "redacted"
    compliance["action_reason"] = "pii_detected"
    compliance["action_source"] = "builtin"
    compliance["redacted_types"] = resolved["redacted_types"] + resolved["blocked_types"]
    result = {"should_redact_stored": True, "compliance": compliance}
    if via is not None:
        result["stored_redaction_via"] = via
    return result


# ============================================================================
# Post-call policy application
# ============================================================================


def apply_post_call_policy(
    response_text: str,
    event: dict,
    config: "ResolvedConfig",
) -> dict:
    """Post-call policy: scan response text + run onPostCall hook.

    Returns {"decision", "redacted_response"?, "compliance"}.
    decision: "pass" | "flag" | "redact_response"
    """
    decision = "pass"
    rule_id = None
    reason = None

    # 0. Anti-tamper policy FLOOR on the RESPONSE (applies_to 'response'|'both').
    #    Evaluated first and re-asserted at the end (below) so it is
    #    unsuppressible: neither the customer rules nor the onPostCall hook
    #    (which can otherwise downgrade redact_response -> flag) may weaken it.
    #    The response already came back and cannot be un-sent, so a floor match
    #    fails closed to redact_response. Twin: TS applyPostCallPolicy step 0.
    floor_response_lock = False
    floor_response_rule_id = None
    floor_response_reason = None
    if getattr(config, "policy_floor", None):
        from .rules import evaluate_floor
        floor_ctx = {
            "metadata": {
                **(event.get("metadata") or {}),
                **({"user_id": event.get("user_id")} if event.get("user_id") else {}),
                **({"service_name": event.get("service_name")} if event.get("service_name") else {}),
                **({"tenant_id": event.get("tenant_id")} if event.get("tenant_id") else {}),
            }
        }
        floor_result = evaluate_floor(config.policy_floor, response_text, "response", floor_ctx)
        if floor_result.get("decision") in ("block", "redact"):
            decision = "redact_response"
            rule_id = floor_result.get("rule_id")
            reason = floor_result.get("reason")
            floor_response_lock = True
            floor_response_rule_id = floor_result.get("rule_id")
            floor_response_reason = floor_result.get("reason")

    # 1. Evaluate policy rules against response
    if getattr(config, 'policy_rules', None):
        from .rules import evaluate_policy_rules
        rules_result = evaluate_policy_rules(config.policy_rules, response_text, "response")
        rules_decision = rules_result.get("decision", "allow")
        if rules_decision in ("block", "redact"):
            decision = "redact_response"
        rule_id = rules_result.get("rule_id")
        reason = rules_result.get("reason")

    # 2. onPostCall hook (timeout + error handling)
    on_post_call = getattr(config, 'on_post_call', None)
    if on_post_call is not None:
        timeout_s = getattr(config, 'hook_timeout_ms', 2000) / 1000.0
        # No `with` block: same rationale as the pre-call hook above — the
        # context manager would JOIN a hung hook thread and void the timeout;
        # shutdown(wait=False) abandons the (non-daemon) worker thread, which
        # may delay process exit until the hook returns.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            future = ex.submit(on_post_call, response_text, event)
            try:
                hook_result = future.result(timeout=timeout_s)
                if isinstance(hook_result, dict):
                    hd = hook_result.get("decision", "pass")
                else:
                    hd = hook_result or "pass"
                if hd in ("redact_response", "flag"):
                    decision = hd
                    rule_id = (hook_result.get("rule_id") if isinstance(hook_result, dict) else None) or rule_id
                    reason = (hook_result.get("reason") if isinstance(hook_result, dict) else None) or reason
            except concurrent.futures.TimeoutError:
                pass  # keep existing decision
        except Exception:
            pass  # hook error: keep existing decision
        finally:
            ex.shutdown(wait=False)

    # 3. Built-in response-side PII scan (the response twin of the pre-call
    # Step 1 scan; mirror of the TS applyPostCallPolicy step 3). Only when a
    # pii_policy is configured. On the response side "block" cannot un-send
    # the request, so block and redact both redact the STORED copy;
    # detect_only records the finding.
    response_pii: Optional[Dict[str, Any]] = None
    stored_redaction_via: Optional[str] = None
    if getattr(config, "pii_policy", None) and response_text:
        scan = run_configured_pii_scan(response_text, getattr(config, "deobfuscation", None))
        if scan.get("pii_detected"):
            detected_types = scan.get("detected_types", [])
            resolved = resolve_pii_policy(detected_types, config.pii_policy)
            must_redact = resolved.get("action") in ("block", "redact")
            response_pii = {
                "detected": True,
                "types": detected_types,
                "action": "redacted" if must_redact else "detected_only",
            }
            if scan.get("via") is not None:
                # Server-side normalizer mirror: which view surfaced the hit (TS parity —
                # key only present on view-only hits).
                response_pii["via"] = scan["via"]
            if must_redact:
                decision = "redact_response"
                if not reason:
                    reason = "pii_detected_in_response"
                # View-only hit: the stored copy must become a whole-text
                # placeholder (span redaction cannot locate an encoded payload).
                stored_redaction_via = scan.get("via")

    # 4. Canary-leak scan on the RESPONSE (the primary leak surface: a planted
    # system-prompt/context token surfacing in the model's output). Evidential
    # -- the response already came back, so this forces redact_response and
    # stores a placeholder (never the raw token) + CRITICAL telemetry. Only
    # when a canary has been minted.
    canary_telemetry: Optional[Dict[str, Any]] = None
    canary_leaked = False
    from .canary import canary_registry_size
    if canary_registry_size() > 0 and response_text:
        from .canary import scan_for_canary, canary_leak_telemetry
        leak = scan_for_canary(response_text)
        if leak["leaked"]:
            canary_leaked = True
            decision = "redact_response"
            canary_telemetry = canary_leak_telemetry(leak["hits"], "response")
            if not rule_id:
                rule_id = "sdk:canary_leak"
            ids = ", ".join(h["id"] for h in leak["hits"])
            reason = f"Canary token leaked in response ({ids})"

    # Re-assert the floor (unsuppressible): nothing above may downgrade a
    # floor-forced response redaction. Keep floor attribution unless a canary
    # also leaked (canary is likewise critical and carries its own telemetry).
    if floor_response_lock:
        decision = "redact_response"
        if not canary_leaked:
            rule_id = floor_response_rule_id
            reason = floor_response_reason

    compliance: Dict[str, Any] = {}
    if decision == "flag":
        compliance["event_type"] = "policy_flag"
    if rule_id:
        compliance["rule_id"] = rule_id
    if reason:
        compliance["policy_reason"] = reason

    redacted_response = None
    if decision == "redact_response":
        if canary_leaked:
            from .canary import CANARY_REDACTION_PLACEHOLDER
            redacted_response = CANARY_REDACTION_PLACEHOLDER
        elif floor_response_lock:
            # A floor rule match has no locatable span, so store a whole-text
            # placeholder rather than span-redact (which would leave the matched
            # content intact). Byte-identical to TS FLOOR_REDACTION_PLACEHOLDER.
            redacted_response = FLOOR_REDACTION_PLACEHOLDER
        else:
            redacted_response = redact_for_storage(response_text, stored_redaction_via)

    result: Dict[str, Any] = {
        "decision": decision,
        "redacted_response": redacted_response,
        "compliance": compliance,
    }
    if response_pii is not None:
        result["response_pii"] = response_pii
    if canary_telemetry is not None:
        result["canary_telemetry"] = canary_telemetry
    return result


# ============================================================================
# Check-only explanation (EV-22)
# ============================================================================

def explain(
    prompt_text: str,
    metadata: Optional[Dict[str, Any]] = None,
    target: str = "prompt",
    config: Optional[ResolvedConfig] = None,
) -> Dict[str, Any]:
    """Check-only policy explanation (twin of the TS SDK's explain()).

    Runs the same built-in PII scan and structured-rule evaluation a real
    call would, but consumes no quota, advances no injection-session
    state, files no approval requests, and emits no audit events.
    Customer hooks are not invoked. Safe for tests, dashboards, and CI.
    """
    from .config import try_get_config
    cfg = config or try_get_config()
    if cfg is None:
        raise RuntimeError(
            "Governance not initialized. Call obsvr.init() first or pass config."
        )
    from .rules import (
        derive_policy_version,
        evaluate_policy_rules,
        evaluate_shadow_rules,
    )
    rules = getattr(cfg, "policy_rules", None) or []
    ctx = {"metadata": metadata or {}}
    result: Dict[str, Any] = {
        "decision": "allow",
        "rule_id": None,
        "reason": None,
        "rules_hash": derive_policy_version(rules),
        "pii": {"detected": False, "types": []},
        "shadow_outcome": None,
        "not_evaluated": ["customer_hook", "multi_turn_injection"],
    }

    scan = run_configured_pii_scan(prompt_text, getattr(cfg, "deobfuscation", None))
    result["pii"] = {
        "detected": scan["pii_detected"],
        "types": scan["detected_types"],
    }
    if scan.get("via") is not None:
        result["pii"]["via"] = scan["via"]
    if scan["pii_detected"] and cfg.pii_policy is not None:
        resolved = resolve_pii_policy(scan["detected_types"], cfg.pii_policy)
        # Mirror the live pipeline: a view-only redact resolution escalates
        # to block (no locatable span), so explain() predicts the real outcome.
        pii_action = escalate_view_only_action(resolved["action"], scan.get("via"))
        if pii_action == "block":
            result["decision"] = "block"
            result["reason"] = "PII detected: " + ", ".join(scan["detected_types"])
            if scan.get("via") is not None:
                result["reason"] += " (via %s)" % scan["via"]
        elif pii_action == "redact":
            result["decision"] = "redact"
            result["reason"] = "PII would be redacted: " + ", ".join(scan["detected_types"])

    if result["decision"] != "block" and rules:
        rr = evaluate_policy_rules(rules, prompt_text, target, ctx, check_only=True)
        if rr.get("decision") in ("block", "redact"):
            result["decision"] = rr["decision"]
            result["rule_id"] = rr.get("rule_id")
            result["reason"] = rr.get("reason")
        elif rr.get("rule_id") and not result["rule_id"]:
            result["rule_id"] = rr.get("rule_id")
            result["reason"] = rr.get("reason")

    result["shadow_outcome"] = evaluate_shadow_rules(rules, prompt_text, target, ctx)
    return result
