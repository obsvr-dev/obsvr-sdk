/**
 * Policy Hook
 *
 * Pre-call intercept point that runs before the LLM call and before
 * the audit event is emitted. Provides a governance foundation for
 * blocking, redacting, or allowing requests.
 *
 * @packageDocumentation
 */

import type { AuditEvent } from '../proxy/types.js';
import type { ReasonCode } from '../governance/reason-codes.js';
import { BUILTIN_SEVERITY as BUILTIN_SEVERITY_MAP } from './pii-types.js';
import { normalizeForMatching, stripInvisibleChars, nfkcWithSourceMap } from './normalize.js';

/**
 * Decision returned by a policy hook.
 * - allow  : keep a call allowed when no earlier layer blocked it; never
 *            erase an existing PII, policy-rule, taint, or protocol block
 * - block  : throw an error before calling the LLM
 * - redact : strip prompt/response content before the call proceeds
 */
export type PolicyDecision = 'allow' | 'block' | 'redact';

/**
 * Structured result returned by a policy hook.
 * Backward-compatible: bare PolicyDecision strings are auto-wrapped.
 */
export interface PolicyDecisionResult {
  decision: PolicyDecision;
  rule_id?: string;
  /**
   * Closed-vocabulary reason code (governance/reason-codes.ts ReasonCode).
   * Additive to `reason`: the code is the stable, machine-groupable
   * classification of the verdict; `reason` remains the free-form human
   * detail. Present on every result the structured rules engine returns.
   */
  reason_code?: ReasonCode;
  reason?: string;
  policy_version?: string;
  /** Set when a require_approval rule blocked: the caller should file an approval request. */
  approval_required?: boolean;
  /** Canonical hash of the fired rule's definition (approval pinning). */
  rule_hash?: string;
  /**
   * Digest of the action a require_approval rule blocked on, so the approval
   * request the caller files names the exact call a human is being asked to
   * authorize rather than only the rule it tripped.
   */
  action_hash?: string;
  /**
   * The claim a live grant satisfied, carried so the caller can RE-check it
   * immediately before the outbound call. The pre-call pipeline can spend
   * seconds after this decision (a customer hook, an external backend), and a
   * grant that expires inside that window must not still be spending.
   */
  approval_granted?: {
    ruleId: string;
    userId?: string;
    ruleHash?: string;
    actionHash?: string;
  };
  /**
   * Set when a quota rule could not be metered on this call because the
   * bounded store had no counter slot for the scope. Present on BOTH
   * resolutions — the caller stamps it on the event either way, so an
   * unenforced quota rule is never indistinguishable from one that passed.
   */
  quota_unmetered?: QuotaUnmetered;
  /** Corrective instruction on a steer refusal. The call is still blocked. */
  steering?: { outcome: 'MODIFY'; guidance: string };
}

/**
 * The declared record of a quota rule that went unenforced.
 *
 * Rides `metadata.obsvr_telemetry.quota_unmetered` on the call's own event,
 * the same channel `detector_failure` and `canary_leak` take, rather than
 * minting a new `action_taken` (a closed wire enum) or a second event (which
 * would break the one-event-per-call correspondence).
 *
 * Carries the scope NAME ("user_id"), never the scope VALUE. The value is an
 * end-user identifier, and the event already carries it in metadata — that is
 * where it came from. Copying it here would put an identifier on a second
 * channel for no added information.
 */
export interface QuotaUnmetered {
  rule_id: string;
  /** quota_scope the rule meters by, e.g. "user_id" or "project". */
  scope: string;
  /** "requests" or "tokens". */
  unit: string;
  /** How failMode resolved it: "open" allowed the call, "closed" blocked it. */
  resolution: 'open' | 'closed';
}

/** Result returned by a post-call hook */
export interface PostCallDecisionResult {
  decision: 'pass' | 'flag' | 'redact_response';
  rule_id?: string;
  reason?: string;
}

/** Post-call hook receives response text + the partial event */
export interface PostCallHook {
  (responseText: string, event: Partial<AuditEvent>): PostCallDecisionResult | Promise<PostCallDecisionResult>;
}

/** Normalize bare string to PostCallDecisionResult */
export function normalizePostCallDecision(
  result: PostCallDecisionResult | string,
): PostCallDecisionResult {
  if (typeof result === 'string') {
    return { decision: result as 'pass' | 'flag' | 'redact_response' };
  }
  return result;
}

/** Coerce a bare decision string or PolicyDecisionResult to PolicyDecisionResult */
export function normalizePolicyDecision(
  result: PolicyDecision | PolicyDecisionResult,
): PolicyDecisionResult {
  if (typeof result === 'string') return { decision: result };
  return result;
}

/**
 * A policy hook receives a partial audit event (built from the request
 * before the LLM is called) and returns a PolicyDecision synchronously
 * or asynchronously.
 */
export interface PolicyHook {
  (event: Partial<AuditEvent>): PolicyDecision | PolicyDecisionResult | Promise<PolicyDecision | PolicyDecisionResult>;
}

/**
 * Evaluate the policy hook against a pre-call event.
 *
 * Returns the decision.  Throws if the hook itself throws - callers
 * should decide whether to surface that or fall back to 'allow'.
 *
 * Overloads:
 * - 2-arg (no timeoutMs): returns PolicyDecision (backward-compatible string)
 * - 3-arg (with timeoutMs): returns PolicyDecisionResult | 'hook_timeout'
 */
export async function evaluatePolicyHook(
  hook: PolicyHook,
  event: Partial<AuditEvent>,
): Promise<PolicyDecision>;
export async function evaluatePolicyHook(
  hook: PolicyHook,
  event: Partial<AuditEvent>,
  timeoutMs: number,
): Promise<PolicyDecisionResult | 'hook_timeout'>;
export async function evaluatePolicyHook(
  hook: PolicyHook,
  event: Partial<AuditEvent>,
  timeoutMs?: number,
): Promise<PolicyDecision | PolicyDecisionResult | 'hook_timeout'> {
  let raw: PolicyDecision | PolicyDecisionResult | 'hook_timeout';
  if (timeoutMs != null && timeoutMs > 0) {
    raw = await hookWithTimeout(hook, event, timeoutMs);
  } else {
    raw = await hook(event);
  }
  if (raw === 'hook_timeout') return raw;
  const normalized = normalizePolicyDecision(raw);
  // When called without timeout (2-arg), return bare string for backward compat
  if (timeoutMs === undefined) return normalized.decision;
  return normalized;
}

/**
 * Wrap a policy hook with a timeout. If the hook doesn't resolve within
 * timeoutMs milliseconds, returns "hook_timeout" as the decision.
 */
async function hookWithTimeout(
  hook: PolicyHook,
  event: Partial<AuditEvent>,
  timeoutMs: number,
): Promise<PolicyDecision | PolicyDecisionResult | 'hook_timeout'> {
  let timer: ReturnType<typeof setTimeout>;
  const timeoutPromise = new Promise<'hook_timeout'>((resolve) => {
    timer = setTimeout(() => resolve('hook_timeout'), timeoutMs);
  });
  try {
    return await Promise.race([hook(event), timeoutPromise]);
  } finally {
    clearTimeout(timer!);
  }
}

// ============================================================================
// Built-in PII Scanner
// ============================================================================

/**
 * Structured PII pattern with confidence scoring and optional validation.
 */
interface PiiPattern {
  label: string;
  pattern: RegExp;
  placeholder: string;
  confidence: number;
  category: 'pii' | 'secret' | 'security';
  validate?: (match: string) => boolean;
}

/**
 * A single span-based PII match with position and confidence.
 */
interface PiiMatch {
  label: string;
  start: number;
  end: number;
  confidence: number;
  category: 'pii' | 'secret' | 'security';
  /**
   * The span sits inside a quote / backtick pair — see `isQuotedSpan`. Only
   * ever true for `category: 'security'`; a quoted credential is still a
   * leaked credential, so PII and secret matches are never marked.
   */
  quoted: boolean;
}

// ============================================================================
// Luhn Algorithm (standard mod-10 checksum)
// ============================================================================

/**
 * Validate a number string using the Luhn algorithm.
 * Used to filter false-positive credit card matches.
 */
function luhnCheck(digits: string): boolean {
  const cleaned = digits.replace(/\D/g, '');
  if (cleaned.length < 13 || cleaned.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let n = parseInt(cleaned[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/**
 * Built-in patterns covering PII, secrets, and prompt injection.
 * Each entry includes confidence scoring and optional validation:
 * Luhn-validated structured PII patterns plus expanded secret and
 * prompt-injection detectors.
 */
const BUILTIN_PII_PATTERNS: PiiPattern[] = [
  // --- PII ---
  {
    label: 'email',
    pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/,
    placeholder: '[REDACTED_EMAIL]',
    confidence: 0.9,
    category: 'pii',
  },
  {
    label: 'ssn',
    pattern: /\b\d{3}[-.\s]\d{2}[-.\s]\d{4}\b/,
    placeholder: '[REDACTED_SSN]',
    confidence: 0.85,
    category: 'pii',
  },
  {
    // separator-less SSN, gated on adjacent SSN context so a bare 9-digit
    // run (order id, timestamp, ...) is NOT a false positive. Closes the "remove
    // the dashes to evade the block" bypass. No lookbehind (Python-parity safe);
    // the whole "ssn 123456789" phrase is replaced with the placeholder.
    label: 'ssn',
    pattern: /\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|#))?)\b\s{0,8}[:#]?\s{0,8}\d{9}\b/i,
    placeholder: '[REDACTED_SSN]',
    confidence: 0.8,
    category: 'pii',
  },
  {
    label: 'credit_card',
    pattern: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b/,
    placeholder: '[REDACTED_CC]',
    confidence: 0.9,
    category: 'pii',
    validate: luhnCheck,
  },
  {
    label: 'phone',
    pattern: /\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/,
    placeholder: '[REDACTED_PHONE]',
    confidence: 0.75,
    category: 'pii',
  },
  {
    label: 'ip_address',
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/,
    placeholder: '[REDACTED_IP]',
    confidence: 0.8,
    category: 'pii',
  },
  {
    label: 'uuid',
    pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/,
    placeholder: '[REDACTED_UUID]',
    confidence: 0.5,
    category: 'pii',
  },

  // --- Secrets ---
  {
    label: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b/,
    placeholder: '[REDACTED_JWT]',
    confidence: 0.95,
    category: 'secret',
  },
  {
    label: 'api_key',
    pattern: /\b(?:sk-|pk-)[A-Za-z0-9\-_]{10,}\b/,
    placeholder: '[REDACTED_API_KEY]',
    confidence: 0.9,
    category: 'secret',
  },
  {
    label: 'api_key',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/,
    placeholder: '[REDACTED_API_KEY]',
    confidence: 0.95,
    category: 'secret',
  },
  {
    label: 'api_key',
    pattern: /\bAIza[A-Za-z0-9_-]{30,}\b/,
    placeholder: '[REDACTED_API_KEY]',
    confidence: 0.95,
    category: 'secret',
  },
  {
    label: 'aws_access_key',
    pattern: /\b(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b/,
    placeholder: '[REDACTED_AWS_KEY]',
    confidence: 0.95,
    category: 'secret',
  },
  {
    label: 'private_key',
    pattern: /-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----/,
    placeholder: '[REDACTED_PRIVATE_KEY]',
    confidence: 0.95,
    category: 'secret',
  },
  {
    label: 'github_token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{34,}\b/,
    placeholder: '[REDACTED_GITHUB_TOKEN]',
    confidence: 0.95,
    category: 'secret',
  },
  {
    label: 'slack_webhook',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/,
    placeholder: '[REDACTED_SLACK_WEBHOOK]',
    confidence: 0.95,
    category: 'secret',
  },

  // --- Security (prompt injection) ---
  {
    label: 'prompt_injection',
    pattern: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|your|the|system)\s*(?:instructions?|rules?|prompts?|guidelines?|constraints?|programming|training)/i,
    placeholder: '[BLOCKED_INJECTION]',
    confidence: 0.85,
    category: 'security',
  },
  {
    label: 'prompt_injection',
    pattern: /(?:reveal|show|display|print|output|repeat|echo|tell\s+me|give\s+me|what\s+(?:is|are))\s+(?:your|the)\s+(?:system|initial|original|hidden|secret|internal)\s*(?:prompt|instructions?|rules?|message|configuration|directives?)/i,
    placeholder: '[BLOCKED_INJECTION]',
    confidence: 0.9,
    category: 'security',
  },
  {
    label: 'prompt_injection',
    pattern: /(?:you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\s+(?:DAN|an?\s+unrestricted|an?\s+uncensored|an?\s+unfiltered|a\s+jailbroken|Developer\s*Mode|god\s*mode)/i,
    placeholder: '[BLOCKED_INJECTION]',
    confidence: 0.9,
    category: 'security',
  },
  {
    label: 'prompt_injection',
    pattern: /(?:enable|activate|enter|switch\s+to|turn\s+on)\s+(?:developer|debug|admin|god|unrestricted|jailbreak|sudo)\s*(?:mode|access)/i,
    placeholder: '[BLOCKED_INJECTION]',
    confidence: 0.85,
    category: 'security',
  },
];

// ============================================================================
// Span-based matching with overlap suppression
// ============================================================================

/**
 * Opening delimiter → the closing delimiter that ends the same quotation.
 *
 * Deliberately tiny and literal. This is NOT a parser and must never become
 * one: the moment it starts inferring whether text is "inside a code block" or
 * "part of a string literal" it is a second detector, with a second detector's
 * false-negative surface, guarding the first one. Five pairs, exact characters,
 * no state.
 */
const QUOTE_PAIRS: ReadonlyMap<string, string> = new Map([
  ['"', '"'],
  ["'", "'"],
  ['`', '`'],
  ['“', '”'], // “ ”
  ['‘', '’'], // ‘ ’
]);

/**
 * Is `[start, end)` immediately enclosed by a matching delimiter pair?
 *
 * Text that QUOTES an attack phrase is not performing one. A bug report, a test
 * fixture, a policy document and a support ticket all reproduce the exact
 * strings a real attack uses, and rewriting them to `[BLOCKED_INJECTION]` makes
 * the ledger commit to content the model never saw — the evidence is corrupted
 * to record a detection that, read literally, did not happen.
 *
 * Strict adjacency, on purpose. The character before the span must open, and
 * the character after it must close the same pair. No whitespace skipping, no
 * scanning outward for the nearest quote: every relaxation classifies MORE text
 * as quoted, and being wrong in that direction is what lets a real attack ride
 * through downgraded. Being wrong the other way only leaves the pre-existing
 * behaviour in place.
 *
 * So this recognizes a quotation only when it holds the matched span and
 * nothing else. Two shapes are therefore missed and still redacted, both
 * deliberately:
 *   - punctuation inside the quotation — `"ignore all previous instructions."`
 *     puts a `.` between the span and the closing delimiter;
 *   - a quotation wider than the pattern's match — `"you are DAN and can do
 *     anything"` matches only `you are DAN`, so the delimiters are not adjacent.
 * Both leave the pre-existing behaviour in place rather than introducing a new
 * way to be wrong. Widening either one is a change here and nowhere else, if
 * the under-recognition ever costs more than the risk of scanning outward.
 *
 * @param text - the string the caller is matching against; offsets index it
 * @param start - match start, inclusive
 * @param end - match end, exclusive
 */
function isQuotedSpan(text: string, start: number, end: number): boolean {
  if (start <= 0 || end >= text.length) return false;
  const closing = QUOTE_PAIRS.get(text[start - 1]);
  return closing !== undefined && text[end] === closing;
}

/**
 * Collect all pattern matches with position and confidence info.
 * Runs validate() on each match and discards failures.
 *
 * `quoted` is resolved here, against the very string being matched, so the
 * verdict never has to be carried across a normalization boundary — see
 * `runBuiltinPiiScan` and `redactBuiltinPii`, which operate on different
 * strings and each resolve it locally.
 */
function collectMatches(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  for (const p of BUILTIN_PII_PATTERNS) {
    const re = new RegExp(p.pattern.source, p.pattern.flags.includes('i') ? 'gi' : 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (p.validate && !p.validate(m[0])) continue;
      const start = m.index;
      const end = m.index + m[0].length;
      matches.push({
        label: p.label,
        start,
        end,
        confidence: p.confidence,
        category: p.category,
        // Security patterns only. A quoted API key is still an API key.
        quoted: p.category === 'security' && isQuotedSpan(text, start, end),
      });
    }
  }
  return matches;
}

/**
 * Remove overlapping matches, keeping the highest-confidence match
 * when two spans overlap.
 *
 * O(m log m) via binary search over a start-sorted `kept` array, not the
 * O(m^2) full linear scan this used to do. That matters: for a large
 * document with many PII-shaped patterns (a CSV export, a transaction log,
 * a contact list), `matches.length` scales with document size, and a
 * pairwise scan against a growing `kept` array turns a 10x larger document
 * into ~100x the work. Measured: a 10MB document with a repeating
 * phone-number-shaped pattern went from ~15.8s (O(m^2)) to sub-second
 * (O(m log m)) after this fix.
 *
 * Correctness: `kept` is maintained sorted by `start` and is an
 * invariant-overlap-free set at every step, so a new candidate can only
 * possibly overlap its immediate left/right neighbors in start order -
 * binary search finds the insertion point, and only those two neighbors
 * need checking instead of the entire kept set.
 */
function suppressOverlaps(matches: PiiMatch[]): PiiMatch[] {
  const byConfidence = [...matches].sort((a, b) => b.confidence - a.confidence);
  const kept: PiiMatch[] = []; // invariant: sorted by `start`, mutually non-overlapping

  const findInsertionIndex = (start: number): number => {
    let lo = 0;
    let hi = kept.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (kept[mid].start < start) lo = mid + 1;
      else hi = mid;
    }
    return lo;
  };

  for (const match of byConfidence) {
    const idx = findInsertionIndex(match.start);
    const prev = idx > 0 ? kept[idx - 1] : undefined;
    const next = idx < kept.length ? kept[idx] : undefined;
    const overlapsPrev = !!prev && match.start < prev.end && match.end > prev.start;
    const overlapsNext = !!next && match.start < next.end && match.end > next.start;
    if (!overlapsPrev && !overlapsNext) {
      kept.splice(idx, 0, match);
    }
  }
  return kept;
}

/**
 * Scan text for PII using built-in regex patterns with confidence scoring,
 * Luhn validation for credit cards, and overlap suppression.
 *
 * Return shape is identical to the previous version - no breaking change.
 */
export function runBuiltinPiiScan(
  text: string,
): {
  pii_detected: boolean;
  detected_types: string[];
  matches: Array<{ label: string; confidence: number; quoted: boolean }>;
} {
  // §6: match against the NFKC/zero-width/confusable-normalized copy so a
  // lookalike or zero-width-joined payload cannot dodge the PII / secret /
  // injection patterns. Matching-only — the caller's stored text is untouched
  // (redactBuiltinPii runs on the original), so only DETECTION is affected.
  //
  // `quoted` is resolved against THIS string — the normalized copy the patterns
  // actually matched — and never handed to redaction, which normalizes
  // differently and would land the verdict on the wrong span.
  const raw = collectMatches(normalizeForMatching(text));
  const filtered = suppressOverlaps(raw);
  const types = [...new Set(filtered.map(m => m.label))];
  // Additive: `pii_detected` and `detected_types` are unchanged, so a quoted
  // injection still reports as a detection. `matches` is what lets a caller
  // DOWNGRADE it (see the multi-turn call sites) rather than lose it.
  const matches = filtered.map(m => ({
    label: m.label,
    confidence: m.confidence,
    quoted: m.quoted,
  }));
  return { pii_detected: types.length > 0, detected_types: types, matches };
}

/**
 * Replace all PII matches with typed placeholders.
 * Respects per-pattern validation (e.g. Luhn check for credit cards)
 * so non-validated matches are left intact.
 */
export function redactBuiltinPii(text: string): string {
  if (!text) return text;
  // Strip invisible (zero-width / bidi) chars first so PII that detection caught
  // on the NORMALIZED text (e.g. a zero-width-split SSN) is actually scrubbed
  // here rather than forwarded intact while the event says "redacted".
  let result = stripInvisibleChars(text);
  // Fast path: when the text has no NFKC-changing compatibility forms (the
  // common ASCII case), folding would surface nothing the ASCII patterns don't
  // already match, so redact directly and skip building any per-codepoint offset
  // map. This keeps redaction at its prior cost — the fold-aware path (and its
  // ~codepoint-count `.normalize()` calls) runs only for text that actually
  // contains fullwidth / ligature / compatibility characters.
  const hasCompatForms = result !== result.normalize("NFKC");
  for (const p of BUILTIN_PII_PATTERNS) {
    // Security patterns take a span-collecting path in both branches because
    // they need each match's offsets to test its delimiters. PII and secret
    // patterns keep their original code paths byte-for-byte — a quoted
    // credential is still a leaked credential and must still be scrubbed.
    if (p.category === "security") {
      result = hasCompatForms
        ? redactPatternFoldAware(result, p, isQuotedSpan)
        : redactPatternPlain(result, p, isQuotedSpan);
    } else if (hasCompatForms) {
      result = redactPatternFoldAware(result, p);
    } else {
      const re = new RegExp(p.pattern.source, p.pattern.flags.includes("i") ? "gi" : "g");
      result = result.replace(re, (match) => (p.validate && !p.validate(match) ? match : p.placeholder));
    }
  }
  return result;
}

/**
 * Splice placeholders into `base` for every match of `p`, skipping spans that
 * `skipSpan` vetoes.
 *
 * Used when `base` carries no NFKC-changing character, so `base` IS its own
 * folded view: match offsets index it directly and no source map is needed.
 * That is the same string `nfkcWithSourceMap` would hand back unchanged, so the
 * delimiters this sees are the delimiters detection saw.
 */
function redactPatternPlain(
  base: string,
  p: { pattern: RegExp; placeholder: string; validate?: (m: string) => boolean },
  skipSpan: (text: string, start: number, end: number) => boolean,
): string {
  const flags = p.pattern.flags.includes("i") ? "gi" : "g";
  const re = new RegExp(p.pattern.source, flags);
  const spans: Array<[number, number]> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(base)) !== null) {
    if (m[0] === "") {
      re.lastIndex++;
      continue;
    }
    if (p.validate && !p.validate(m[0])) continue;
    const start = m.index;
    const end = m.index + m[0].length;
    if (skipSpan(base, start, end)) continue;
    spans.push([start, end]);
  }
  if (spans.length === 0) return base;
  let out = base;
  for (let k = spans.length - 1; k >= 0; k--) {
    const [s, e] = spans[k];
    out = out.slice(0, s) + p.placeholder + out.slice(e);
  }
  return out;
}

/**
 * Apply one PII pattern to `base`, matching on the NFKC-folded view but
 * replacing the corresponding span in `base`. This closes the fullwidth-PII
 * leak: JS's `\d`/ASCII character classes never match compatibility forms
 * (fullwidth `５５５`, etc.),
 * so a fullwidth-digit phone/SSN was DETECTED (detection normalizes) yet left
 * intact by redaction and forwarded to the provider while the audit said
 * "redacted". Folding only the LOCATE step — and scrubbing the original span —
 * keeps every non-PII character (including legitimate fullwidth/CJK text) exactly
 * as the user sent it. Plain ASCII takes the identity fast path below, so
 * existing behavior is unchanged byte-for-byte.
 *
 * `skipSpan`, when supplied, vetoes replacement of a span. It is consulted on
 * the FOLDED view in FOLDED coordinates — the same coordinate space the match
 * was found in — and the existing source map then carries the surviving spans
 * back to `base` exactly as before. Nothing new crosses the boundary: the
 * verdict is decided before the map is applied, never transported across it.
 * Only the security patterns pass one.
 */
function redactPatternFoldAware(
  base: string,
  p: { pattern: RegExp; placeholder: string; validate?: (m: string) => boolean },
  skipSpan?: (text: string, start: number, end: number) => boolean,
): string {
  const flags = p.pattern.flags.includes("i") ? "gi" : "g";
  const { normalized, mapStart, mapEnd } = nfkcWithSourceMap(base);
  // `skipSpan` needs per-match offsets, which `String.replace` does not expose,
  // so it always takes the span-collecting path below. That path is correct for
  // an identity map too — it just costs a little more than `replace`.
  if (normalized === base && !skipSpan) {
    // Fast path: no compatibility chars — match and replace directly on `base`,
    // identical to the prior implementation.
    const re = new RegExp(p.pattern.source, flags);
    return base.replace(re, (match) => (p.validate && !p.validate(match) ? match : p.placeholder));
  }
  // Slow path: collect match spans in folded coordinates, map each back to a
  // source [start, end) span, then splice placeholders into `base` right-to-left
  // so earlier offsets stay valid.
  const re = new RegExp(p.pattern.source, flags);
  const spans: Array<[number, number]> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(normalized)) !== null) {
    if (m[0] === "") {
      re.lastIndex++;
      continue;
    }
    if (p.validate && !p.validate(m[0])) continue;
    // Decide quoted-ness in folded coordinates, BEFORE the map is applied.
    if (skipSpan && skipSpan(normalized, m.index, m.index + m[0].length)) continue;
    const s = mapStart[m.index];
    const e = mapEnd[m.index + m[0].length - 1];
    spans.push([s, e]);
  }
  if (spans.length === 0) return base;
  let out = base;
  for (let k = spans.length - 1; k >= 0; k--) {
    const [s, e] = spans[k];
    out = out.slice(0, s) + p.placeholder + out.slice(e);
  }
  return out;
}

// ============================================================================
// Per-type PII policy resolution
// ============================================================================

type PiiPolicyAction = "block" | "redact" | "detect_only";

/**
 * Built-in severity defaults used when no rule or default is configured.
 * Re-exported from the shared pii-types module for backward compatibility.
 */
export const BUILTIN_SEVERITY: Record<string, PiiPolicyAction> = BUILTIN_SEVERITY_MAP;

/**
 * Resolve the overall PII policy action for a set of detected types.
 *
 * Resolution order per type (most specific wins):
 *   policy.rules[type] → policy.default → BUILTIN_SEVERITY[type] → "detect_only"
 *
 * Final action is the most severe across all types:
 *   block > redact > detect_only
 */
export function resolvePiiPolicy(
  detectedTypes: string[],
  policy?: {
    default?: PiiPolicyAction;
    rules?: Partial<Record<string, PiiPolicyAction>>;
  },
): { action: PiiPolicyAction; blockedTypes: string[]; redactedTypes: string[] } {
  const blockedTypes: string[] = [];
  const redactedTypes: string[] = [];

  for (const type of detectedTypes) {
    const action: PiiPolicyAction =
      policy?.rules?.[type] ??
      policy?.default ??
      BUILTIN_SEVERITY[type] ??
      "detect_only";

    if (action === "block") {
      blockedTypes.push(type);
    } else if (action === "redact") {
      redactedTypes.push(type);
    }
    // detect_only: neither list gets the type
  }

  const action: PiiPolicyAction =
    blockedTypes.length > 0
      ? "block"
      : redactedTypes.length > 0
        ? "redact"
        : "detect_only";

  return { action, blockedTypes, redactedTypes };
}
