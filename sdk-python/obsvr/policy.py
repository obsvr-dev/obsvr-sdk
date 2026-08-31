"""Built-in PII scanner + per-type policy resolution.

EXACT parity with sdk-typescript/src/policy/hook.ts:
  - same pattern set (labels, regexes, placeholders, confidence, category)
  - same Luhn validation for credit cards
  - same confidence-based overlap suppression over positioned spans
  - same BUILTIN_SEVERITY defaults
  - same resolution order: rules[type] -> default -> builtin -> detect_only
  - same compliance semantics (including monotonic customer-hook behavior)

Patterns are compiled with re.ASCII so \\d, \\w, \\s and \\b match exactly what
JavaScript's ASCII character classes match. Without it, Python's Unicode-aware
classes would accept e.g. Arabic-Indic digits that the TS twin never matches,
and the shared conformance fixture (conformance/fixtures/pii_scan.json) would
pin divergent behavior. Fullwidth digits still detect on both sides because
matching runs on the NFKC-normalized copy (§6).
"""

import bisect
import concurrent.futures
import json
import logging
import re
import time
import unicodedata
from typing import Any, Callable, Dict, List, Optional, Tuple, TypedDict

from .config import ResolvedConfig
from .reason_codes import ReasonCode
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

# Stored-copy marker for content NOTHING scanned, because the scanner that
# would have vetted it raised. Deliberately NOT a "[REDACTED..." token: every
# other placeholder in this SDK means "a scan ran and removed something", and
# an auditor who cannot tell that apart from "we never looked" has to treat
# every redaction as possibly the second. Different word, no prefix collision.
UNSCANNED_PLACEHOLDER = "[UNSCANNED:detector_error]"


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

from .pii_types import BUILTIN_SEVERITY, PII_TYPES

DEFAULT_COMPLIANCE: Dict[str, Any] = {
    "event_type": "llm_call",
    "policy_version": "v1",
    "action_taken": "allowed",
    "action_reason": "none",
    "action_source": "unknown",
    "redacted_types": [],
    "blocked_types": [],
}


# Opening delimiter -> the closing delimiter that ends the same quotation.
#
# Deliberately tiny and literal (parity with TS QUOTE_PAIRS). This is NOT a
# parser and must never become one: the moment it starts inferring whether text
# is "inside a code block" or "part of a string literal" it is a second
# detector, with a second detector's false-negative surface, guarding the first
# one. Five pairs, exact characters, no state.
QUOTE_PAIRS: Dict[str, str] = {
    '"': '"',
    "'": "'",
    "`": "`",
    "“": "”",  # " "
    "‘": "’",  # ' '
}


def _is_quoted_span(text: str, start: int, end: int) -> bool:
    """Is ``[start, end)`` immediately enclosed by a matching delimiter pair?

    Text that QUOTES an attack phrase is not performing one. A bug report, a
    test fixture, a policy document and a support ticket all reproduce the exact
    strings a real attack uses, and rewriting them to ``[BLOCKED_INJECTION]``
    makes the ledger commit to content the model never saw -- the evidence is
    corrupted to record a detection that, read literally, did not happen.

    Strict adjacency, on purpose. The character before the span must open, and
    the character after it must close the same pair. No whitespace skipping, no
    scanning outward for the nearest quote: every relaxation classifies MORE
    text as quoted, and being wrong in that direction is what lets a real attack
    ride through downgraded. Being wrong the other way only leaves the
    pre-existing behaviour in place.

    So this recognizes a quotation only when it holds the matched span and
    nothing else. Two shapes are therefore missed and still redacted, both
    deliberately:

    - punctuation inside the quotation -- ``"ignore all previous instructions."``
      puts a ``.`` between the span and the closing delimiter;
    - a quotation wider than the pattern's match -- ``"you are DAN and can do
      anything"`` matches only ``you are DAN``, so the delimiters are not
      adjacent.

    Both leave the pre-existing behaviour in place rather than introducing a new
    way to be wrong. Widening either one is a change here and nowhere else, if
    the under-recognition ever costs more than the risk of scanning outward.

    Byte-identical to TS ``isQuotedSpan``.
    """
    if start <= 0 or end >= len(text):
        return False
    closing = QUOTE_PAIRS.get(text[start - 1])
    return closing is not None and text[end] == closing


def _collect_matches(text: str) -> List[Dict[str, Any]]:
    """Collect all pattern matches with position and confidence info (parity
    with TS collectMatches). validate() failures are discarded.

    ``quoted`` is resolved here, against the very string being matched, so the
    verdict never has to be carried across a normalization boundary -- see
    ``run_builtin_pii_scan`` and ``redact_builtin_pii``, which operate on
    different strings and each resolve it locally.
    """
    matches: List[Dict[str, Any]] = []
    for entry in BUILTIN_PII_PATTERNS:
        validate: Optional[Callable[[str], bool]] = entry.get("validate")
        category = entry["category"]
        for m in entry["pattern"].finditer(text):
            if validate is not None and not validate(m.group(0)):
                continue
            matches.append(
                {
                    "label": entry["label"],
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": entry["confidence"],
                    "category": category,
                    # Security patterns only. A quoted API key is still an API key.
                    "quoted": category == "security"
                    and _is_quoted_span(text, m.start(), m.end()),
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

    ``quoted`` is resolved against THIS string -- the normalized copy the
    patterns actually matched -- and never handed to redaction, which normalizes
    differently and would land the verdict on the wrong span.
    """
    raw = _collect_matches(normalize_for_matching(text))
    filtered = _suppress_overlaps(raw)
    detected_types = list(dict.fromkeys(m["label"] for m in filtered))
    # Additive: ``pii_detected`` and ``detected_types`` are unchanged, so a
    # quoted injection still reports as a detection. ``matches`` is what lets a
    # caller DOWNGRADE it (see the multi-turn call site) rather than lose it.
    matches = [
        {"label": m["label"], "confidence": m["confidence"], "quoted": m["quoted"]}
        for m in filtered
    ]
    return {
        "pii_detected": len(detected_types) > 0,
        "detected_types": detected_types,
        "matches": matches,
    }


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
        # Security patterns take a span-collecting path in both branches because
        # they need each match's offsets to test its delimiters. PII and secret
        # patterns keep their original code paths byte-for-byte -- a quoted
        # credential is still a leaked credential and must still be scrubbed.
        if entry["category"] == "security":
            if has_compat_forms:
                result = _redact_pattern_fold_aware(result, entry, _is_quoted_span)
            else:
                result = _redact_pattern_plain(result, entry, _is_quoted_span)
        elif has_compat_forms:
            result = _redact_pattern_fold_aware(result, entry)
        else:
            result = _sub_validated(entry, result)
    return result


def _redact_pattern_plain(
    base: str,
    entry: Dict[str, Any],
    skip_span: Callable[[str, int, int], bool],
) -> str:
    """Splice placeholders into ``base`` for every match of ``entry``, skipping
    spans that ``skip_span`` vetoes.

    Used when ``base`` carries no NFKC-changing character, so ``base`` IS its
    own folded view: match offsets index it directly and no source map is
    needed. That is the same string ``nfkc_with_source_map`` would hand back
    unchanged, so the delimiters this sees are the delimiters detection saw.
    Parity with TS redactPatternPlain.
    """
    pattern = entry["pattern"]
    placeholder = entry["placeholder"]
    validate: Optional[Callable[[str], bool]] = entry.get("validate")
    spans: List[Tuple[int, int]] = []
    for m in pattern.finditer(base):
        if m.start() == m.end():
            continue
        if validate is not None and not validate(m.group(0)):
            continue
        if skip_span(base, m.start(), m.end()):
            continue
        spans.append((m.start(), m.end()))
    if not spans:
        return base
    out = base
    for s, e in reversed(spans):
        out = out[:s] + placeholder + out[e:]
    return out


def _sub_validated(entry: Dict[str, Any], text: str) -> str:
    """pattern.sub with per-match validate() (parity with TS redactBuiltinPii:
    a match failing validation — e.g. a non-Luhn card number — is left intact)."""
    validate: Optional[Callable[[str], bool]] = entry.get("validate")
    if validate is None:
        return entry["pattern"].sub(entry["placeholder"], text)
    return entry["pattern"].sub(
        lambda m: entry["placeholder"] if validate(m.group(0)) else m.group(0), text
    )


def _redact_pattern_fold_aware(
    base: str,
    entry: Dict[str, Any],
    skip_span: Optional[Callable[[str, int, int], bool]] = None,
) -> str:
    """Apply one PII pattern, matching on the NFKC-folded view but replacing the
    span in ``base``. Keeps redaction in step with detection (which normalizes)
    for compatibility forms (fullwidth digits, ligatures) while leaving every
    non-PII character in ``base`` untouched. Plain ASCII takes the identity fast
    path, exactly the prior ``pattern.sub`` behavior.

    ``skip_span``, when supplied, vetoes replacement of a span. It is consulted
    on the FOLDED view in FOLDED coordinates -- the same coordinate space the
    match was found in -- and the existing source map then carries the surviving
    spans back to ``base`` exactly as before. Nothing new crosses the boundary:
    the verdict is decided before the map is applied, never transported across
    it. Only the security patterns pass one."""
    pattern = entry["pattern"]
    placeholder = entry["placeholder"]
    validate: Optional[Callable[[str], bool]] = entry.get("validate")
    normalized, map_start, map_end = nfkc_with_source_map(base)
    # ``skip_span`` needs per-match offsets, which ``pattern.sub`` does not
    # expose, so it always takes the span-collecting path below. That path is
    # correct for an identity map too -- it just costs a little more than sub().
    if normalized == base and skip_span is None:
        return _sub_validated(entry, base)
    spans: List[Tuple[int, int]] = []
    for m in pattern.finditer(normalized):
        if m.start() == m.end():
            continue
        if validate is not None and not validate(m.group(0)):
            continue
        # Decide quoted-ness in folded coordinates, BEFORE the map is applied.
        if skip_span is not None and skip_span(normalized, m.start(), m.end()):
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


#: Layers whose disposition failMode cannot move. A floor is the operator's
#: non-overridable baseline, so a floor that CANNOT RUN is the strongest form
#: of "cannot guarantee" - it fails closed, exactly as a floor redact that
#: cannot be guaranteed already fails closed to a block. Canary is the same
#: class: a leak block is unsuppressible, so an unusable canary scan must not
#: quietly wave the call through.
_FLOOR_CLASS_LAYERS = frozenset({"policy_floor", "canary"})

#: Count of detector exceptions swallowed by the guard. Its own bucket,
#: reported on the fleet poll: a lost enforcement layer and an undelivered
#: event are different operational stories, so it is never folded into the
#: delivery drop counters.
_detector_errors = 0


def get_detector_error_count() -> int:
    """Detector exceptions this process has resolved (fleet-poll counter)."""
    return _detector_errors


def _reset_detector_errors() -> None:
    """Reset the counter (tests only)."""
    global _detector_errors
    _detector_errors = 0


def record_check_only_failure(layer: str, exc: BaseException) -> None:
    """Count and log a failure on a surface that is STRUCTURALLY always open,
    so the log does not assert a resolution the caller will not apply.

    ``record_detector_failure`` reports "resolving closed / the call was
    BLOCKED" whenever fail_mode says so. That message is wrong for a unit that
    cannot block by construction: a shadow rule runs after the active decision
    is final and is defined as never decision-affecting, and the policy-version
    hash is a provenance field. Honouring fail_mode at either would let a
    check-only unit stop a call, which is the one thing shadow mode promises it
    cannot do.

    Twin: sdk-typescript/src/policy/detector-guard.ts (``recordCheckOnlyFailure``).
    """
    global _detector_errors
    _detector_errors += 1
    logging.getLogger("obsvr").error(
        "obsvr detector layer '%s' failed on a check-only surface (%s). "
        "The call is UNAFFECTED - this unit never decides anything - and only "
        "its own output was lost. This is an SDK defect - please report it.",
        layer or "unknown",
        f"{type(exc).__name__}: {exc}"[:200],
    )


def apply_outbound_redaction(
    redact: Callable[[], None], layer: str = "builtin_pii_scan"
) -> Optional[Dict[str, Any]]:
    """Apply a redaction to OUTBOUND content, reporting failure instead of raising.

    This is the enforcement-APPLICATION phase, and it is deliberately not the
    pre-call rule. Pre-call resolves by fail_mode because a DETECTION failure
    means the SDK does not know whether sensitive content is present, and
    proceeding is a bounded risk. Here the scan already ran, already found
    something, and policy already said remove it: the uncertainty is resolved
    against us, so failing open would transmit to a third party exactly the
    content the SDK was told to strip.

    So it fails CLOSED regardless of fail_mode, on the same reasoning the floor
    already uses one step away - a floor redact that cannot be guaranteed blocks
    because the SDK must never forward content it cannot guarantee was redacted.
    That rule is about the act of forwarding, not about the rule being a floor.

    The in-place redactors walk message structures field by field, so a raise
    mid-walk leaves a PARTIALLY redacted request. Forwarding that is the worst
    of the three outcomes: it still carries unredacted content while looking, to
    every downstream reader, like a redaction that succeeded.

    Returns None when the redaction completed, or a failure descriptor the
    caller must turn into a block. Callers must also drop any "redacted" claim
    from the event: a record asserting a redaction that did not happen is worse
    than none, because it tells an auditor the content was cleaned.

    Twin: sdk-typescript/src/policy/detector-guard.ts (``applyOutboundRedaction``).
    """
    global _detector_errors
    try:
        redact()
        return None
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all
        _detector_errors += 1
        detail = f"{type(exc).__name__}: {exc}"[:200]
        logging.getLogger("obsvr").error(
            "obsvr detector layer '%s' failed while APPLYING a redaction (%s); "
            "resolving closed. The call was BLOCKED - the SDK does not forward "
            "content it cannot guarantee was redacted. This is an SDK defect - "
            "please report it.",
            layer or "unknown",
            detail,
        )
        return {
            "rule_id": "sdk:detector_error",
            "policy_reason": (
                f"Redaction could not be applied: detector layer "
                f"'{layer or 'unknown'}' raised {detail}; blocked rather than "
                f"forwarded unredacted"
            )[:256],
            "detector_failure": {
                "layer": layer or "unknown",
                "error": detail,
                "resolution": "closed",
                "floor_class": layer in _FLOOR_CLASS_LAYERS,
                "phase": "enforcement_application",
            },
        }


class RedactionNotApplied(Exception):
    """A type policy named for removal is still present after redaction.

    Raised into :func:`apply_outbound_redaction`, which resolves it the way
    every unappliable redaction resolves: closed, with the ``redacted`` claim
    stripped from the event rather than asserted over content still in the call.
    """


def redact_arguments(value: Any, redact: Callable[[Optional[str]], str]) -> Any:
    """Redact every string inside a call's ARGUMENTS, structure preserved.

    :func:`apply_outbound_redaction` has always been available to the model-call
    path, where the payload is text and the redacted copy can simply replace it.
    The tool-shaped boundaries — the generic tool governor, the MCP
    ``tools/call`` gate, the PydanticAI toolset — could not use it, because a
    tool takes ARGUMENTS and the pipeline's redacted copy of the scanned text
    cannot be handed back to a callable. So each of them took
    ``redacted_prompt``, used it as the EVENT's prompt, and let the call proceed
    with the values it came in with: the signed record said
    ``action_taken: "redacted"`` while the tool wrote the raw value to a file, a
    row, or a third-party API. This is the missing half, in one place, because
    three boundaries drifting from ``wrap()`` independently is how the defect
    arose.

    Arguments are not flat text: a declared parameter can be a dict, a list, or
    a nested mixture, and the callee has to receive the same SHAPE it would have
    received unredacted or the redaction breaks the caller. Only ``str`` leaves
    change; every other scalar comes back as it was, and containers are rebuilt
    rather than mutated so the caller's own objects are never written through.

    Dict KEYS are left alone deliberately. A key is a parameter or field name
    the schema chose, not user content, and rewriting one would hand the callee
    an argument it does not accept.
    """
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_arguments(item, redact) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_arguments(item, redact) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_arguments(item, redact) for item in value)
    return value


def assert_redaction_applied(
    payload: Any, compliance: Optional[Dict[str, Any]]
) -> None:
    """Confirm the rewritten arguments no longer carry what was to be removed.

    CHECK THE OUTCOME, NOT THE INTENT. Everything upstream of this is the SDK
    describing its own behaviour; this re-scans the values the callee is about
    to be handed and refuses if a type the policy named is still in them. It is
    the difference between "a redaction was requested" and "the content is
    gone", and only the second one is worth recording.

    Scoped to the types the verdict CLAIMS to have removed, so a detection the
    policy resolved as detect-only is not turned into a block.
    """
    expected = list((compliance or {}).get("redacted_types") or [])
    if not expected:
        return
    if isinstance(payload, str):
        text = payload
    else:
        try:
            text = json.dumps(payload if payload is not None else {}, default=str)
        except Exception:  # noqa: BLE001 - an unserializable payload
            text = str(payload)
    remaining = set(run_builtin_pii_scan(text)["detected_types"])
    survived = sorted(name for name in expected if name in remaining)
    if survived:
        raise RedactionNotApplied("redaction did not remove " + ", ".join(survived))


def outbound_redaction_blocked_compliance(
    base: Dict[str, Any], failed: Dict[str, Any]
) -> Dict[str, Any]:
    """Compliance for a call blocked because its redaction could not be APPLIED.

    Derived from the policy's own compliance so the version and provenance
    fields survive, with every "redacted" claim stripped. The types the scan
    found move to ``blocked_types``, which is what they now are - the reason the
    call was refused rather than a list of things removed.

    Twin: sdk-typescript/src/integrations/core.ts (``outboundRedactionBlockedCompliance``).
    """
    merged = dict(base)
    merged.update(
        {
            "event_type": "blocked_call",
            "action_taken": "blocked",
            "action_reason": "policy_violation",
            "redacted_types": [],
            "blocked_types": list(
                dict.fromkeys(
                    list(base.get("blocked_types") or [])
                    + list(base.get("redacted_types") or [])
                )
            ),
            "rule_id": failed["rule_id"],
            "policy_reason": failed["policy_reason"],
            "detector_failure": failed["detector_failure"],
        }
    )
    return merged


#: PII types the built-in regex tier has NO pattern for, so only the Presidio
#: analyzer can locate them. Derived from the pattern table rather than
#: listed, because a list would drift the first time a pattern is added.
NLP_ONLY_PII_TYPES = frozenset(PII_TYPES) - {p["label"] for p in BUILTIN_PII_PATTERNS}


def outbound_redactor(
    config: ResolvedConfig, redacted_types: Optional[List[str]] = None
) -> Callable[[str], str]:
    """The redactor that rewrites what actually leaves the process.

    The regex tier alone was used here while ``presidio_redact_text`` produced
    the STORED copy, so with Presidio configured and one of the six NLP-only
    types resolving to ``redact``, the audit record said ``redacted`` and the
    name or address went to the provider intact — the record describing a
    removal from a payload that still carried it.

    Presidio is asked only when a type it alone can find is in play. That keeps
    a flaky sidecar from failing calls the regex tier could have redacted
    completely, and it keeps the extra round trip off the common path. When it
    IS in play and does not answer, this raises: the caller runs it through
    ``apply_outbound_redaction``, which blocks. That is the applied-redaction
    rule — falling back to a tier with no pattern for the type would forward
    exactly the content policy said to remove.
    """
    analyzer = getattr(config, "presidio_analyzer_url", None)
    anonymizer = getattr(config, "presidio_anonymizer_url", None)
    if not (analyzer and anonymizer):
        return redact_builtin_pii
    if redacted_types is not None and not (set(redacted_types) & NLP_ONLY_PII_TYPES):
        return redact_builtin_pii

    from .presidio import presidio_redact_text

    def _redact(text: str) -> str:
        out = presidio_redact_text(text, analyzer, anonymizer)
        if out is None:
            raise RuntimeError(
                "the Presidio anonymizer did not answer; an NLP-only PII type "
                "cannot be removed by the regex tier"
            )
        # Both tiers, in order: Presidio locates the NLP entities and the
        # regex table catches the structured ones it does not model.
        return redact_builtin_pii(out)

    return _redact


def safe_policy_version(config: ResolvedConfig) -> str:
    """Derive the policy version for a failure record WITHOUT trusting the
    inputs that just failed.

    The version is a hash over the same rules a detector may have choked on, so
    a resolver that recomputed it naively raises out of its own except block -
    turning the guard back into the unguarded propagation it exists to replace.
    Same lesson as the stored-copy fallback: nothing on the failure path may
    re-run the code that failed and assume it works this time.

    Twin: sdk-typescript/src/policy/detector-guard.ts (`safePolicyVersion`).
    """
    try:
        from .rules import derive_policy_version

        return derive_policy_version(
            getattr(config, "policy_rules", None) or [],
            getattr(config, "rule_resolution", None),
        )
    except Exception:  # noqa: BLE001 - the failure path must not fail
        return "unknown"


def record_detector_failure(
    layer: str, exc: BaseException, config: ResolvedConfig
) -> bool:
    """Count and log one detector failure; return True if it resolves CLOSED.

    The single resolution point for the rule: every internal failure resolves
    by fail_mode, EXCEPT two classes fail_mode does not speak for — the floor,
    which is by definition the thing fail_mode cannot move, and a rule that is
    not a rule (see rules.MalformedPolicyRule). Both the pre-call guard and the
    response-scan guard come here, so the rule exists once rather than per call
    site.
    """
    from .rules import MalformedPolicyRule

    global _detector_errors
    _detector_errors += 1

    fail_closed = (
        layer in _FLOOR_CLASS_LAYERS
        or isinstance(exc, MalformedPolicyRule)
        or getattr(config, "fail_mode", "open") == "closed"
    )
    logging.getLogger("obsvr").error(
        "obsvr detector layer %r failed (%s: %s); resolving %s. The call was %s. "
        "This is an SDK defect - please report it.",
        layer or "unknown",
        type(exc).__name__,
        exc,
        "closed" if fail_closed else "open",
        "BLOCKED" if fail_closed else "allowed with this layer's enforcement lost",
    )
    return fail_closed


def _resolve_post_call_detector_failure(
    layer: str, exc: BaseException, config: ResolvedConfig
) -> Dict[str, Any]:
    """Resolve an exception raised by a RESPONSE-phase detector layer.

    Never raises and never withholds the response: the provider has already
    answered, blocking cannot undo that, and the SDK's published contract is
    that a response-side control never mutates the value returned to the
    caller. The floor class is included in that - "closed" is simply not an
    available action once the answer exists.

    What DOES fail closed is the stored audit copy. The scan that would have
    redacted it is the thing that just failed, so persisting the raw response
    into an evidence record would be storing content nothing vetted. It is
    replaced with a marker that cannot be confused with a real redaction.
    """
    record_detector_failure(layer, exc, config)
    from .decision_record import engine_version_for

    return {
        # "flag", never "redact_response": the caller's value is untouched.
        "decision": "flag",
        "redacted_response": UNSCANNED_PLACEHOLDER,
        "compliance": {
            "event_type": "policy_flag",
            "policy_version": safe_policy_version(config),
            "action_taken": "allowed",
            "action_reason": "none",
            "action_source": "builtin",
            "redacted_types": [],
            "blocked_types": [],
            "rule_id": "sdk:detector_error",
            "policy_reason": (
                f"Response-phase detector layer '{layer or 'unknown'}' raised "
                f"{type(exc).__name__}; response delivered unchanged, stored copy withheld"
            )[:256],
            "shadow_outcome": None,
            "decision_input_hash": None,
            "engine_version": engine_version_for(getattr(config, "rule_resolution", None)),
            "external_backend": None,
            "detector_failure": {
                "layer": layer or "unknown",
                "error": f"{type(exc).__name__}: {exc}"[:200],
                "resolution": "open",
                "floor_class": layer in _FLOOR_CLASS_LAYERS,
                "phase": "response",
                # Queryable without string-matching content.
                "stored_unscanned": True,
            },
        },
    }


def _resolve_detector_failure(
    layer: str,
    exc: BaseException,
    config: ResolvedConfig,
    prompt_text: str,
) -> Dict[str, Any]:
    """The one place a detector exception becomes a decision.

    Never re-raises: an SDK defect must not surface as an unhandled error in
    the calling application. The failure resolves by fail_mode for the
    scanning layers and CLOSED for the floor class, is recorded on this call's
    own event (no second event, and no new action_taken value - that is a
    closed wire enum), and is counted so an operator can see that a layer's
    enforcement was lost rather than infer it from silence.
    """
    fail_closed = record_detector_failure(layer, exc, config)
    floor_class = layer in _FLOOR_CLASS_LAYERS
    detail = f"{type(exc).__name__}: {exc}"

    reason = (
        f"Detector layer '{layer or 'unknown'}' raised {type(exc).__name__}; "
        + (
            "resolved closed (floor class cannot fail open)"
            if floor_class
            else ("resolved closed (fail_mode)" if fail_closed else "resolved open, enforcement lost for this call")
        )
    )

    from .decision_record import engine_version_for

    compliance: Dict[str, Any] = {
        "event_type": "blocked_call" if fail_closed else "policy_flag",
        "policy_version": safe_policy_version(config),
        # NOT a new action_taken value: that field is a closed wire enum.
        "action_taken": "blocked" if fail_closed else "allowed",
        "action_reason": "policy_violation" if fail_closed else "none",
        "action_source": "builtin",
        "redacted_types": [],
        "blocked_types": [],
        "rule_id": "sdk:detector_error",
        "policy_reason": reason[:256],
        "shadow_outcome": None,
        "decision_input_hash": None,
        "engine_version": engine_version_for(getattr(config, "rule_resolution", None)),
        "external_backend": None,
        # Mirrored onto metadata.obsvr_telemetry by the event builder, the
        # same route the external-backend provenance takes.
        "detector_failure": {
            "layer": layer or "unknown",
            "error": detail[:200],
            "resolution": "closed" if fail_closed else "open",
            "floor_class": floor_class,
            "phase": "pre_call",
        },
    }

    # The scan that would have produced a redacted copy is the thing that just
    # failed, so redaction is attempted but never trusted to succeed.
    try:
        redacted_prompt = redact_for_storage(prompt_text, None)
    except Exception:
        redacted_prompt = "[REDACTED:detector_error]"

    return {
        "decision": "block" if fail_closed else "allow",
        "compliance": compliance,
        "redacted_prompt": redacted_prompt,
    }


def _monitor_conversion_applies(
    config: ResolvedConfig,
    degraded: Dict[str, Any],
    canary_floor: bool,
) -> bool:
    """Whether monitor mode may convert THIS final block into an allow.

    Monitor mode is one conversion point after the decision is final: the
    whole pipeline still runs, every event still emits, and the would-be
    verdict rides ``shadow_outcome``. Two classes are carved out and enforce
    in both modes:

    - **Layer 0** (enforcement-integrity gate: kill switch / fail-closed
      staleness). A monitor mode that suppressed it would be a one-flag
      defeat of a revoked key. The carve-out is re-derived HERE, from the
      gate itself, rather than trusted from the caller's snapshot — so even
      a stale or tampered ``degraded`` argument cannot extend monitor mode
      to a paused project.
    - **Canary leaks** (the unsuppressible 0.75 layer). A planted honeytoken
      in outbound content is an exfiltration in flight; observing it out the
      door is not monitoring, it is the leak.
    """
    if getattr(config, "enforcement_mode", "enforce") != "monitor":
        return False
    if canary_floor:
        return False
    if degraded.get("degraded"):
        return False
    # Re-derive the layer-0 verdict at the moment of conversion.
    from .remote import is_enforcement_degraded
    if is_enforcement_degraded(config)["degraded"]:
        return False
    return True


def destructive_source_label(source: Optional[str]) -> str:
    """How a denied capability got into the destructive set, in words an
    operator reading the audit trail can act on. "The server told us this about
    itself" and "I wrote this name down" are different facts and lead to
    different next steps, so the record distinguishes them. Twin:
    ``destructiveSourceLabel`` in integrations/core.ts.
    """
    return "tool descriptor hint" if source == "descriptor_hint" else "operator list"


def apply_pre_call_policy(
    prompt_text: str,
    config: ResolvedConfig,
    provider: str = "unknown",
    operation: str = "",
    tenant_id: str = None,
    metadata: Optional[Dict[str, Any]] = None,
    model: Optional[str] = None,
    scan_text: Optional[str] = None,
    turn_text: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_declared_destructive: bool = False,
) -> Dict[str, Any]:
    """Compliance boundary before an LLM call (real enforcement).

    ``prompt_text`` is the FULL prompt — it is what gets stored/redacted.
    ``scan_text`` is the complete provider-bound text the PII, floor, and
    structured-rule decision evaluates. ``turn_text`` is the newest user/tool
    turn used only by canary and multi-turn accumulation, so earlier history is
    not re-counted on every call. Both default to ``prompt_text``.

    Returns {"decision", "compliance", "redacted_prompt"}.
    """
    scan = scan_text if scan_text is not None else prompt_text
    turn = turn_text if turn_text is not None else scan
    # Resolve tenant config if provided
    if tenant_id is not None:
        from .config import get_tenant_config
        config = get_tenant_config(tenant_id)

    # Fold the ambient use_subject() scope into the ENFORCING metadata, once,
    # before any layer reads it. Every user-scoped control below keys on this
    # dict — require_principal (0.4), the session-taint latch, the quota
    # bucket, the decision-input hash — and the signed record resolves its
    # own user_id with the same nullish precedence (events.build_audit_event).
    # Without this fold the two channels disagreed: an ambient-only principal
    # was attributed on the record but invisible to enforcement, so
    # require_principal refused a call whose signed event named the very
    # principal it claimed was absent — a record contradicting its own reason.
    # Explicit metadata always wins; the ambient only fills what is absent or
    # None. In particular, an explicitly supplied empty string MUST survive:
    # require_principal treats it as unattributed, while replacing it with an
    # ambient subject would turn a refusal into a permit. This matches the
    # signed channel's nullish precedence and tools._identity_meta.
    # A fresh dict, never the caller's — this is the enforcing view, not a
    # mutation of what the caller passed. No ambient scope active ⇒ identical
    # to before, byte for byte.
    from .subject import get_current_subject
    _ambient_subject = get_current_subject() or {}
    if _ambient_subject:
        metadata = dict(metadata or {})
        for _idk in ("user_id", "tenant_id", "service_name"):
            if metadata.get(_idk) is None and _ambient_subject.get(_idk) is not None:
                metadata[_idk] = _ambient_subject[_idk]

    action_taken = "allowed"
    action_reason = "none"
    action_source = "unknown"
    redacted_types: List[str] = []
    blocked_types: List[str] = []
    #: What the scan FOUND, before policy resolved what to do about it.
    #:
    #: ``action_reason`` is set from the raw detection while ``redacted_types``
    #: and ``blocked_types`` are only filled by the block and redact branches,
    #: so every type that resolves to detect_only produces
    #: ``reason_code: PII_DETECTED`` with both lists EMPTY — a verdict carrying
    #: no evidence of what it saw. An operator grepping for PII_DETECTED got a
    #: hit with nothing in it to act on, which teaches them to ignore the
    #: signal. This carries the finding so a detect-only verdict says what it
    #: detected. Additive and emitted only when non-empty, so an event with no
    #: detection is unchanged.
    detected_types_found: List[str] = []
    hook_rule_id: Optional[str] = None
    hook_reason: Optional[str] = None
    hook_reason_code: Optional[str] = None
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

    # --- guarded detector section -------------------------------------
    # One enclosing guard for the seven in-process detector layers below.
    # `_layer` names whichever one is executing so the handler can resolve
    # the floor class differently from the scanning layers; the customer
    # hook and the external backend sit OUTSIDE it because they already
    # carry their own guards and dispositions, and so does the
    # enforcement-integrity gate above.
    _layer = ""
    try:
        # Explicit classification from a detector layer (taint, PII/injection,
        # multi-turn) when one blocked. Lowest precedence of the explicit
        # codes: when a detector blocked, floor/rules never ran and a hook
        # block clears it (TS parity).
        detector_reason_code: Optional[str] = None
        # 0.4 Required principal (opt-in): an unattributed call is refused
        #     before any scanning layer runs — the refusal is about
        #     attribution, not content. Runs after the enforcement-integrity
        #     gate so a paused project keeps its own verdict and rule id, and
        #     reads the enforcing channel (metadata) that every user-scoped
        #     control keys on. Only a non-blank string is attributable. Monitor mode converts
        #     this block like any non-integrity block: rolling the flag out
        #     in monitor first is the intended adoption path.
        from .subject import has_meaningful_principal
        if (
            action_taken != "blocked"
            and getattr(config, "require_principal", False)
            and not has_meaningful_principal((metadata or {}).get("user_id"))
        ):
            action_taken = "blocked"
            action_reason = "policy_violation"
            action_source = "policy_rules"
            gate_rule_id = "sdk:principal_required"
            gate_reason = (
                "require_principal is set and the call carries no user_id "
                "on the enforcing metadata"
            )
            detector_reason_code = ReasonCode.PRINCIPAL_REQUIRED.value
        _layer = "session_taint"
        # 0.5 Session taint latch: a session compromised on an earlier turn has its
        #     later egress escalated. ENFORCE runs on PRIOR taint; SET happens at
        #     this call's detection points below (TS parity: core.ts / wrapper.ts).
        from .session_taint import (
            resolve_session_taint,
            derive_session_key,
            evaluate_tool_taint_gate,
            mark_tainted,
            touch_taint,
            session_taint_size,
        )
        taint_cfg = resolve_session_taint(config)
        taint_key = derive_session_key(metadata)
        taint_rule_id: Optional[str] = None
        taint_reason: Optional[str] = None
        if taint_cfg and session_taint_size() > 0 and action_taken != "blocked":
            # Tool-aware when the caller is a tool boundary: a tainted session
            # in flag mode still loses its DESTRUCTIVE capabilities - the
            # composition that stops indirect injection without bricking the
            # session (TS parity). The set is the operator's destructive_tools
            # union whatever the tool's own descriptor declared at discovery.
            verdict = evaluate_tool_taint_gate(
                taint_key, taint_cfg, tool_name or "", tool_declared_destructive is True
            )
            if verdict["enforcement"] != "none":
                touch_taint(taint_key, time.monotonic())  # LRU: keep victim alive
                taint_rule_id = "sdk:session_tainted"
                taint_reason = (
                    "Session previously compromised (%s); destructive capability '%s' denied (%s)"
                    % (
                        verdict["reason"],
                        tool_name,
                        destructive_source_label(verdict.get("destructive_source")),
                    )
                    if verdict.get("destructive")
                    else "Session previously compromised (%s); egress escalated"
                    % verdict["reason"]
                )
                if verdict["enforcement"] == "block":
                    action_taken = "blocked"
                    action_reason = "policy_violation"
                    action_source = "policy_rules"
                    # A taint-gated refusal of outbound egress (TS parity).
                    detector_reason_code = ReasonCode.TRANSMISSION_BLOCKED.value
                elif action_reason == "none":
                    action_reason = "policy_violation"
                    action_source = "policy_rules"

        _layer = "canary"
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
            leak = scan_for_canary(turn)
            if leak["leaked"]:
                from .source_lineage import mark_current_lineage_tainted
                mark_current_lineage_tainted(
                    kind="canary_leak",
                    reason="canary_leak",
                    detector="obsvr-canary",
                )
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

        _layer = "builtin_pii_scan"
        # 1. Built-in content scan (note: empty-dict PII policy still enables
        #    it). Session taint owns its prompt-injection latch independently
        #    of PII policy, so enabling the latch also enables this single scan.
        #    PII verdicts/telemetry and Presidio remain gated by pii_policy.
        #    With deobfuscation enabled the scanner also sees decoded/stripped
        #    views (server-side normalizer mirror); ``via`` records which view surfaced a
        #    hit the raw text hid.
        pii_scan_via: Optional[str] = None
        if (config.pii_policy is not None or taint_cfg) and action_taken != "blocked":
            pii = run_configured_pii_scan(scan, getattr(config, "deobfuscation", None))
            if config.pii_policy is not None:
                pii_scan_via = pii.get("via")
            detected_types = list(pii["detected_types"])
            presidio_answered = False
            if (
                config.pii_policy is not None
                and getattr(config, "presidio_analyzer_url", None)
            ):
                from .presidio import presidio_scan
                nlp = presidio_scan(scan, config.presidio_analyzer_url)
                presidio_answered = bool(nlp.get("answered"))
                for t in nlp["detected_types"]:
                    if t not in detected_types:
                        detected_types.append(t)

            # SET is independent of PII resolution and affects later turns
            # only. With pii_policy configured this reuses the exact same scan,
            # so there is no duplicate work or telemetry.
            if "prompt_injection" in detected_types:
                from .source_lineage import mark_current_lineage_tainted
                mark_current_lineage_tainted(
                    kind="prompt_injection",
                    reason="prompt_injection",
                    detector="obsvr-builtin-injection",
                )
                if taint_cfg:
                    mark_tainted(taint_key, "prompt_injection", time.monotonic())

            if config.pii_policy is not None and detected_types:
                action_reason = "pii_detected"
                detected_types_found = list(detected_types)
                # Attributed to what ANSWERED, not to what was configured. A
                # 500ms budget means a cold sidecar or a GC pause routinely
                # contributes nothing, and this field used to credit it anyway
                # — naming a detector on the record as having participated in a
                # verdict it never saw.
                action_source = "builtin+presidio" if presidio_answered else "builtin"
                resolved = resolve_pii_policy(detected_types, config.pii_policy)
                # A view-only hit has no locatable span in the raw text, so
                # "redact" would no-op while the record claims "redacted" —
                # escalate to block (parity with the TS wrapper/core).
                pii_action = escalate_view_only_action(resolved["action"], pii_scan_via)
                if pii_action == "block":
                    action_taken = "blocked"
                    blocked_types = resolved["blocked_types"]
                    redacted_types = resolved["redacted_types"]
                    # The prompt_injection label rides the PII pipeline, but a
                    # block it drove is an injection finding, not a PII finding
                    # (TS parity).
                    detector_reason_code = (
                        ReasonCode.INJECTION_DETECTED.value
                        if "prompt_injection" in resolved["blocked_types"]
                        else ReasonCode.PII_DETECTED.value
                    )
                elif pii_action == "redact":
                    action_taken = "redacted"
                    redacted_types = resolved["redacted_types"]
                # detect_only: reason/source set; action stays "allowed"

        _layer = "multi_turn_injection"
        # 1.2. Multi-turn injection scoring - catches payloads split across turns
        #      that no single message would trip. Session keyed by metadata
        #      user_id (falls back to a process-wide bucket); score decays with
        #      a half-life, so traffic matching NO weak signal never accumulates
        #      at all and traffic spaced well beyond the half-life stays bounded
        #      near one turn's weight. Traffic that repeatedly matches even ONE
        #      weak signal at conversational spacing DOES cross the threshold —
        #      measured at the shipped defaults (threshold 1.0, half-life 600s),
        #      benign phrasings tripped at turn 3 at 10s spacing and still at
        #      turn 7 at 300s. The half-life bounds accumulation; it does not
        #      prevent it, and the header used to say it did.
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
            # A QUOTED injection phrase is a weak signal, not a full match: text
            # that quotes an attack (a bug report, a fixture, a policy doc) is
            # not performing one. The detection is untouched -- the scan still
            # reports ``prompt_injection`` and the event still fires -- but it
            # no longer counts as the single-turn full match that scores 1.0 and
            # lets turn 1 trip on its own. The phrase still accrues weak-signal
            # score in score_turn, so an attacker who wraps a payload in quotes
            # gets a quieter line in the log and nothing else.
            _inj_scan = run_builtin_pii_scan(turn)
            had_full = any(
                m["label"] == "prompt_injection" and not m["quoted"]
                for m in _inj_scan["matches"]
            )
            mt = score_turn(
                session_key,
                turn,
                had_full,
                threshold=float(mti.get("threshold", 1.0)),
                half_life_s=float(mti.get("half_life_s", 600.0)),
            )
            # Full matches are already handled by the single-turn scan; the
            # multi-turn gate exists for the accumulation case.
            if mt["tripped"] and not had_full:
                from .injection_session import format_multi_turn_reason
                gate_rule_id = "sdk:multi_turn_injection"
                # No score in the stored reason - a persisted continuous
                # margin is an evasion oracle (see format_multi_turn_reason).
                gate_reason = format_multi_turn_reason(mt["turns"], mt["signals"])
                # Accumulated injection taints the session (later egress escalated).
                if taint_cfg:
                    mark_tainted(taint_key, "multi_turn_injection", time.monotonic())
                if mti.get("action", "block") == "block":
                    action_taken = "blocked"
                    action_reason = "policy_violation"
                    # "policy_rules": parity with the TS wrapper and integrations
                    # core (rule_id sdk:multi_turn_injection names the gate).
                    action_source = "policy_rules"
                    # Accumulated multi-turn injection IS an injection finding.
                    detector_reason_code = ReasonCode.INJECTION_DETECTED.value
                else:
                    # flag: annotate without changing the action (TS parity).
                    if action_reason == "none":
                        action_reason = "policy_violation"
                    action_source = "policy_rules"

        _layer = "policy_floor"
        # 1.4. Anti-tamper policy FLOOR (before customer rules; floor rules always
        #      enforce, and an attempted hook downgrade is recorded below).
        #      Lives in its own config field so a remote sync
        #      replacing the SERVER rule set can never delete it. TS parity: core.ts 1.4.
        floor_block = False
        floor_rule_id: Optional[str] = None
        floor_reason: Optional[str] = None
        floor_reason_code: Optional[str] = None
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
                # content is not forwarded. floor_block=True so the
                # floor_override_ignored record covers the redact case.
                floor_block = True
                floor_rule_id = floor_result.get("rule_id")
                floor_reason = floor_result.get("reason") or "Blocked by policy floor"
                floor_reason_code = floor_result.get("reason_code")
                action_taken = "blocked"
                action_reason = "policy_violation"
                action_source = "policy_rules"

        _layer = "policy_rules"
        # 1.5. Structured policy rules
        rules_rule_id: Optional[str] = floor_rule_id or gate_rule_id
        rules_reason: Optional[str] = floor_reason or gate_reason
        # The fine-grained code from whichever structured evaluation decided —
        # floor first, customer rules when they run. Survives to the event and
        # the raised error; never re-collapsed to a coarse category downstream.
        rules_reason_code: Optional[str] = floor_reason_code
        quota_unmetered: Optional[Dict[str, Any]] = None
        # The approval claim a live grant satisfied, re-checked at the end of
        # the pipeline after every layer that can delay the call.
        approval_claim: Optional[Dict[str, Any]] = None
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
                fail_mode=getattr(config, "fail_mode", None),
                resolution=getattr(config, "rule_resolution", None),
            )
            rules_decision = rules_result.get("decision", "allow")
            rules_rule_id = rules_result.get("rule_id")
            rules_reason = rules_result.get("reason")
            # A no-match PERMITTED (no rule engaged) must not erase an earlier
            # layer's classification (a detect-only PII finding, a taint flag).
            if rules_decision != "allow" or rules_result.get("rule_id"):
                rules_reason_code = rules_result.get("reason_code")
            # A quota rule the bounded meter could not count is declared on
            # this call's own event, on the same reserved channel
            # detector_failure and canary evidence take. Without it an
            # unenforced quota rule is indistinguishable from one that was
            # counted and found under limit. Parity with TS.
            quota_unmetered = rules_result.get("quota_unmetered")
            approval_claim = rules_result.get("approval_granted")
            if rules_decision == "block" and action_taken != "blocked":
                # Saved so the blocking approval wait below can lift the block
                # without inventing a state: on approval the pipeline resumes
                # exactly where it stood before this rule fired.
                pre_block_state = (action_taken, action_reason, action_source)
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
                        # Names the exact call a human is being asked to
                        # authorize, so the grant can be bound to it rather
                        # than to "anything that trips this rule".
                        action_hash=rules_result.get("action_hash"),
                    )
                    # Blocking wait (opt-in, approval_wait_ms > 0): HOLD this
                    # call while the grant channel is polled, instead of
                    # refusing and passing on a retry. The wait runs in the
                    # calling thread on human timescales; the pre-call hook's
                    # hook_timeout_ms budget is untouched. Skipped in monitor
                    # mode — a verdict there is recorded, not enforced, so
                    # there is nothing to hold the call for. Only an explicit
                    # "approved" lifts the block: timeout, degradation, and
                    # any wait-internal failure all leave it standing.
                    wait_ms = getattr(config, "approval_wait_ms", 0) or 0
                    if (
                        wait_ms > 0
                        and getattr(config, "enforcement_mode", "enforce") != "monitor"
                    ):
                        wait_claim = {
                            "rule_id": rules_result.get("rule_id"),
                            "user_id": (metadata or {}).get("user_id"),
                            "rule_hash": rules_result.get("rule_hash"),
                            "action_hash": rules_result.get("action_hash"),
                        }
                        try:
                            from .remote import await_approval
                            poll_ms = getattr(config, "approval_poll_ms", 5000) or 5000
                            wait_verdict = await_approval(
                                config,
                                wait_claim,
                                timeout_s=wait_ms / 1000.0,
                                poll_s=poll_ms / 1000.0,
                            )
                        except Exception:  # noqa: BLE001 - the block must stand
                            wait_verdict = "unavailable"
                        if wait_verdict == "approved":
                            # The grant landed while the call was held. Lift
                            # the block and hand the claim to the end-of-
                            # pipeline re-validation below, so a grant that
                            # expires or is revoked between here and the
                            # outbound request is caught before it is spent.
                            action_taken, action_reason, action_source = pre_block_state
                            approval_claim = wait_claim
                            rules_reason_code = ReasonCode.APPROVAL_GRANTED.value
                            rules_reason = "approval_granted_after_wait: %s" % (
                                rules_result.get("rule_id")
                            )
                        elif wait_verdict == "timeout":
                            # Its own registry code: a hold that expired is a
                            # different fact from "refused; ask and retry".
                            # The reason asserts only what is true in both
                            # worlds — the grant channel carries no verdicts,
                            # so an explicit denial and no decision at all
                            # both surface here, and the record says so
                            # rather than claiming nobody answered
                            # (SECURITY.md, "The approval-status contract").
                            rules_reason_code = ReasonCode.APPROVAL_TIMEOUT.value
                            rules_reason = (
                                "approval_wait_timeout: no covering grant "
                                "within %dms; denial and no-decision are "
                                "indistinguishable on the grant channel (%s)"
                                % (wait_ms, rules_result.get("reason"))
                            )
                        else:
                            # Degraded mid-wait (kill switch / staleness) or a
                            # wait-internal failure: the APPROVAL_REQUIRED
                            # block stands, with the abort on the record.
                            rules_reason = "%s (approval_wait_aborted: %s)" % (
                                rules_result.get("reason"),
                                wait_verdict,
                            )
            elif rules_decision == "redact" and action_taken != "redacted":
                action_taken = "redacted"
                action_reason = "policy_violation"
                action_source = "policy_rules"

    except Exception as _detector_exc:  # noqa: BLE001 - deliberate catch-all
        return _resolve_detector_failure(_layer, _detector_exc, config, prompt_text)

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
            # A timeout resolved closed is its own classification (TS parity);
            # an error resolved closed derives HOOK_BLOCKED from the source.
            hook_reason_code = (
                ReasonCode.HOOK_TIMEOUT.value if hook_disposition == "timeout" else None
            )
            rules_reason_code = None
            detector_reason_code = None

        if action_taken not in ("hook_error", "hook_timeout"):
            if hook_decision == "block":
                action_taken = "blocked"
                action_reason = "policy_violation"
                action_source = "customer_hook"
                # An earlier layer's code no longer describes this decision;
                # HOOK_BLOCKED derives from the source at event build.
                hook_reason_code = (
                    ReasonCode.HOOK_TIMEOUT.value if hook_disposition == "timeout" else None
                )
                rules_reason_code = None
                detector_reason_code = None
            elif (
                hook_decision == "allow"
                and hook_disposition == "allow"
                and action_taken == "blocked"
                and floor_block
            ):
                # Enforcement is monotonic: a hook may add a restriction, but
                # an allow verdict never erases a block already rendered by
                # PII, policy rules, taint, protocol facets, or another
                # detector. Floor override attempts retain their stronger,
                # explicit audit record because the floor is a separately
                # sealed operator boundary.
                floor_override_ignored = {
                    "rule_id": floor_rule_id,
                    "attempted": "allow",
                }
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
    policy_ver = derive_policy_version(
        getattr(config, 'policy_rules', None) or [],
        getattr(config, "rule_resolution", None),
    )

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

        # Check-only, and structurally always open: a shadow rule is defined as
        # never decision-affecting (it runs AFTER the active decision is final),
        # so a defect in one must not change the outcome in EITHER direction.
        # fail_mode is deliberately not consulted - honoring "closed" here would
        # let a shadow rule block a call, which is the one thing shadow mode
        # promises it cannot do. The loss is recorded; the outcome stays None.
        try:
            shadow_outcome = evaluate_shadow_rules(
                config.policy_rules, prompt_text, context={"metadata": metadata or {}}
            )
        except Exception as _shadow_exc:  # noqa: BLE001 - deliberate catch-all
            record_check_only_failure("policy_rules", _shadow_exc)
            shadow_outcome = None

    # Re-check a spent approval grant. Everything above can take real time -
    # the customer hook has a two-second budget by default and an external
    # policy backend has its own - and a grant that expired inside that window
    # authorized nothing by the time the call goes out. The remaining gap is
    # this function's own return path, which is microseconds; an in-process
    # library cannot make the check and the provider's receipt of the request
    # simultaneous, and this does not pretend to. TS parity: the same position
    # in wrapper.ts and integrations/core.ts.
    if approval_claim and action_taken != "blocked":
        from .remote import revalidate_approval
        if not revalidate_approval(approval_claim):
            action_taken = "blocked"
            action_reason = "policy_violation"
            action_source = "policy_rules"
            rules_reason_code = ReasonCode.APPROVAL_REQUIRED.value
            rules_rule_id = approval_claim.get("rule_id")
            rules_reason = (
                "approval_expired_before_execution: %s" % approval_claim.get("rule_id")
            )

    # Canonical decision record (ADR-2): commit exactly what this decision ran
    # over. ``scan`` is the text the pipeline evaluated (pre-redaction).
    from .decision_record import (
        build_decision_input,
        compute_decision_input_hash,
        engine_version_for,
    )
    engine_ver = engine_version_for(getattr(config, "rule_resolution", None))
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
        engine_version=engine_ver,
    )

    # Same precedence as rule_id below; anything still unresolved derives in
    # the event builder exactly the way the raised error derives, so the
    # record and the exception cannot disagree.
    from .errors import _resolve_reason_code
    explicit_reason_code = hook_reason_code or rules_reason_code or detector_reason_code
    resolved_reason_code = explicit_reason_code or (
        ReasonCode.PERMITTED.value
        if action_reason == "none"
        else _resolve_reason_code(action_reason, action_source, None)
    )

    # Canary wins (unsuppressible), then the rest; taint is the escalation
    # reason when nothing more specific fired.
    resolved_rule_id = (
        canary_rule_id or backend_rule_id or hook_rule_id or rules_rule_id or taint_rule_id
    )
    resolved_policy_reason = (
        canary_reason or backend_reason or hook_reason or rules_reason or taint_reason
    )

    # Monitor mode: the single conversion point, after the decision is final
    # and before it is returned. A block becomes an allow while
    # shadow_outcome — the field documented as never decision-affecting —
    # carries the would-be verdict with the same rule_id and reason_code an
    # enforcing run would put on the blocked event. Everything else on the
    # record keeps the deciding layer's classification (action_reason,
    # action_source, blocked_types), which is also what exempts the event
    # from allowed-call sampling: the evidence is never dropped. Layer 0 and
    # canary leaks are carved out in _monitor_conversion_applies.
    if action_taken == "blocked" and _monitor_conversion_applies(
        config, degraded, canary_floor
    ):
        shadow_outcome = {
            "rule_id": resolved_rule_id,
            "would": "block",
            "reason_code": resolved_reason_code,
            "reason": resolved_policy_reason or "",
        }
        action_taken = "allowed"

    compliance = {
        "event_type": "blocked_call" if action_taken == "blocked" else "llm_call",
        "policy_version": policy_ver,
        "action_taken": action_taken,
        "action_reason": action_reason,
        "reason_code": resolved_reason_code,
        "action_source": action_source,
        "redacted_types": redacted_types,
        "blocked_types": blocked_types,
        "rule_id": resolved_rule_id,
        "policy_reason": resolved_policy_reason,
        "shadow_outcome": shadow_outcome,
        # Additive decision-record fields (never part of the chain preimage)
        "decision_input_hash": compute_decision_input_hash(decision_doc),
        "engine_version": engine_ver,
        # External policy backend provenance (ADR-4, additive)
        "external_backend": external_backend_record,
    }
    # Mirrored onto metadata.obsvr_telemetry by the event builder, the same
    # route detector_failure takes and for the same reason: an enforcement
    # layer that did not run has to say so on the record.
    if quota_unmetered is not None:
        compliance["quota_unmetered"] = quota_unmetered

    # The evidence behind a detection verdict. Emitted only when the scan found
    # something, so an event with no detection keeps exactly the shape it had.
    if detected_types_found:
        compliance["detected_types"] = detected_types_found

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
    compliance["action_taken"] = "not_evaluated"
    compliance["policy_not_evaluated"] = {
        "surface": "observe_only_integration",
        "gate": "pre_call_policy",
        "reason": "callback_observed_after_operation",
    }
    compliance["policy_version"] = derive_policy_version(
        getattr(config, "policy_rules", None) or [],
        getattr(config, "rule_resolution", None),
    )
    return compliance


def apply_observe_policy(prompt_text: str, config: ResolvedConfig) -> Dict[str, Any]:
    """Observe-only policy for framework callbacks: the request already
    went to the LLM, so policy can only change the stored copy. The outbound
    verdict remains not_evaluated and storage provenance is recorded separately.
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
    # redact OR block: redact the stored copy without claiming the already-sent
    # provider request was changed. A view-only hit
    # (stored_redaction_via) has no locatable span — callers MUST redact
    # stored copies with redact_for_storage(text, via), never span redaction.
    compliance = _observe_compliance(config)
    compliance["action_taken"] = "not_evaluated"
    compliance["action_reason"] = "pii_detected"
    compliance["action_source"] = "builtin"
    compliance["policy_not_evaluated"] = {
        "surface": "observe_only_integration",
        "gate": "pre_call_policy",
        "reason": "callback_observed_after_operation",
    }
    compliance["stored_redaction_telemetry"] = {
        "stored_redaction_scope": "observe_only",
        "stored_redaction_types": resolved["redacted_types"] + resolved["blocked_types"],
        "stored_redaction_outbound_unmodified": True,
        "stored_redaction_requested_action": resolved["action"],
    }
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

    # --- guarded detector section (response phase) ---------------------
    # Same layers as the pre-call pipeline, so the same guard - but the
    # provider has ALREADY answered. Blocking cannot undo the response, and
    # the published contract says a response-side control never withholds it
    # from the application. So this phase never raises and never withholds:
    # it fails closed only on the STORED copy, the one thing still in our
    # hands, under a marker that cannot be mistaken for a real redaction.
    _post_layer = ""
    try:
        _post_layer = "policy_floor"
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

        _post_layer = "policy_rules"
        # 1. Evaluate policy rules against response
        if getattr(config, 'policy_rules', None):
            from .rules import evaluate_policy_rules
            rules_result = evaluate_policy_rules(
                config.policy_rules,
                response_text,
                "response",
                resolution=getattr(config, "rule_resolution", None),
            )
            rules_decision = rules_result.get("decision", "allow")
            if rules_decision in ("block", "redact"):
                decision = "redact_response"
            rule_id = rules_result.get("rule_id")
            reason = rules_result.get("reason")

        # 2. onPostCall hook (timeout + error handling). Budgeted from
        #    post_call_timeout_ms, its own declared key — the pre-call hook's
        #    hook_timeout_ms budgets the pre-call hook only (parity with the
        #    TS integrations core, which reads postCallTimeoutMs here).
        on_post_call = getattr(config, 'on_post_call', None)
        if on_post_call is not None:
            timeout_s = getattr(config, 'post_call_timeout_ms', 2000) / 1000.0
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

        _post_layer = "builtin_pii_scan"
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

        _post_layer = "canary"
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

    except Exception as _post_exc:  # noqa: BLE001 - deliberate catch-all
        return _resolve_post_call_detector_failure(_post_layer, _post_exc, config)

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
        evaluate_policy_rules,
        evaluate_shadow_rules,
    )
    rules = getattr(cfg, "policy_rules", None) or []
    ctx = {"metadata": metadata or {}}
    result: Dict[str, Any] = {
        "decision": "allow",
        "rule_id": None,
        "reason": None,
        "rules_hash": safe_policy_version(cfg),
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
        rr = evaluate_policy_rules(
            rules,
            prompt_text,
            target,
            ctx,
            check_only=True,
            resolution=getattr(cfg, "rule_resolution", None),
        )
        if rr.get("decision") in ("block", "redact"):
            result["decision"] = rr["decision"]
            result["rule_id"] = rr.get("rule_id")
            result["reason"] = rr.get("reason")
        elif rr.get("rule_id") and not result["rule_id"]:
            result["rule_id"] = rr.get("rule_id")
            result["reason"] = rr.get("reason")

    # Same rule on the check-only surface: explain() predicts, it never
    # enforces, so a lost shadow evaluation is reported as unevaluated rather
    # than raised at whoever called explain().
    try:
        result["shadow_outcome"] = evaluate_shadow_rules(rules, prompt_text, target, ctx)
    except Exception as _shadow_exc:  # noqa: BLE001 - deliberate catch-all
        record_check_only_failure("policy_rules", _shadow_exc)
        result["shadow_outcome"] = None
        if "policy_rules" not in result["not_evaluated"]:
            result["not_evaluated"].append("policy_rules")
    return result
