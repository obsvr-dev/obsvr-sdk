/**
 * The stored-content net: the last thing that touches an event's content
 * fields before they are signed and shipped.
 *
 * It exists because SCAN SCOPE and STORAGE SCOPE are different questions and
 * this SDK answers them differently. A policy decision is made on the last
 * user turn only — deliberately, so a PII value quoted three turns ago does
 * not block today's call. But the event stores the WHOLE concatenated prompt:
 * system instructions, earlier user turns, assistant replies, tool results.
 * So every byte the decision pipeline never looked at still lands in the
 * audit record verbatim unless something else vets it. Nothing did, on the
 * `wrap()` path, in either direction: a honeytoken planted in a system prompt
 * (the site `canary.ts` endorses) was stored raw, and PII in a system prompt
 * was stored raw under every configuration of block / redact / flag.
 *
 * Two nets, one chokepoint, both scoped to the STORED copy:
 *
 *   1. `scrubCanaryForStorage` — a minted honeytoken must never come to rest
 *      in an audit record, on any path, whatever the verdict was. This is the
 *      one absolute `canary.ts` states about storage, so it runs whenever the
 *      registry is non-empty and is not conditional on any policy setting.
 *
 *   2. `redactUnscannedForStorage` — makes "earlier turns and system prompts
 *      are still stored (and redacted if configured)" true. It runs ONLY over
 *      content the decision scan did not already cover, ONLY when a PII policy
 *      configures at least one type to `block` or `redact`, and ONLY on the
 *      stored copy.
 *
 * What net 2 deliberately does NOT do, because doing it would trade a storage
 * defect for a worse one:
 *
 *   - It does not change the verdict. The call is decided exactly where it was
 *     decided before; widening enforcement to every role is a separate,
 *     breaking decision and is not smuggled in here.
 *   - It does not fire for a `detect_only`-only policy. `detect_only` exists so
 *     an operator can baseline what actually flows before enforcing, and
 *     scrubbing the record would destroy the only thing that mode produces.
 *   - It does not run when the stored text is the scanned text. Single-turn
 *     calls — the common case — pay nothing, which is what keeps this off the
 *     latency budget A-28c is about.
 *   - It records that it fired. A redacted stored prompt beside
 *     `action_taken: "allowed"` would otherwise read as "the payload was
 *     stopped", which is false: the request went to the provider unmodified.
 *     The telemetry says so in as many words.
 */

import {
  CANARY_REDACTION_PLACEHOLDER,
  canaryLeakTelemetry,
  canaryRegistrySize,
  scanForCanary,
  type CanaryHit,
} from "./canary.js";
import { UNSCANNED_PLACEHOLDER } from "./detector-guard.js";
import {
  redactForStorage,
  runConfiguredPiiScan,
  type DeobfuscationView,
} from "./deobfuscate.js";
import { resolvePiiPolicy } from "./hook.js";

/** The `pii_policy` shape, as `resolvePiiPolicy` reads it. */
type PiiPolicyConfig = Parameters<typeof resolvePiiPolicy>[1];

/** The three content fields every emitted event carries. */
export interface StoredContent {
  prompt: string;
  response: string;
  /** Absent on paths that record no distinct user-input copy. */
  userInput?: string;
}

export interface CanaryScrubResult {
  content: StoredContent;
  /** Leak evidence (ids / hash prefixes — never the token). Absent when clean. */
  telemetry?: Record<string, unknown>;
  /** True when the scan itself threw; content was withheld rather than persisted unvetted. */
  scanFailed: boolean;
}

/**
 * Replace any content field carrying a live canary token with the placeholder.
 *
 * Runs on every emitted event on every path, so it must never raise into a
 * host that has not otherwise touched the policy engine. It builds a stored
 * record rather than deciding a call, so a scan failure resolves the
 * response-phase way: withhold the stored copy instead of persisting text no
 * canary scan ever vetted.
 *
 * `onScanFailure` is the caller's detector-failure recorder; it is passed in
 * rather than imported so this module stays free of config plumbing.
 */
export function scrubCanaryForStorage(
  content: StoredContent,
  onScanFailure: (err: unknown) => void,
): CanaryScrubResult {
  let minted: number;
  try {
    minted = canaryRegistrySize();
  } catch (err) {
    // Inside the guard for the same reason the scan is: this is the emit path
    // of an already-decided call, and nothing here may raise into the host.
    onScanFailure(err);
    return { content, scanFailed: true };
  }
  if (minted === 0) {
    return { content, scanFailed: false };
  }

  const hits: CanaryHit[] = [];
  let leakSurface: string | undefined;
  const scrub = (v: string, surface: string): string => {
    const leak = scanForCanary(v);
    if (leak.leaked) {
      hits.push(...leak.hits);
      if (leakSurface === undefined) leakSurface = surface;
      return CANARY_REDACTION_PLACEHOLDER;
    }
    return v;
  };

  let prompt = content.prompt;
  let response = content.response;
  let userInput = content.userInput;
  try {
    prompt = scrub(prompt, "prompt");
    response = scrub(response, "response");
    if (userInput !== undefined) userInput = scrub(userInput, "user_input");
  } catch (err) {
    onScanFailure(err);
    return {
      content: {
        prompt: UNSCANNED_PLACEHOLDER,
        response: response ? UNSCANNED_PLACEHOLDER : response,
        ...(userInput !== undefined ? { userInput: UNSCANNED_PLACEHOLDER } : {}),
      },
      scanFailed: true,
    };
  }

  return {
    content: {
      prompt,
      response,
      ...(userInput !== undefined ? { userInput } : {}),
    },
    ...(hits.length > 0
      ? { telemetry: canaryLeakTelemetry(hits, leakSurface ?? "response") }
      : {}),
    scanFailed: false,
  };
}

export interface UnscannedRedactionResult {
  /** The stored prompt, redacted iff the net fired. */
  prompt: string;
  /**
   * Evidence that the net fired, for `metadata.obsvr_telemetry`. Absent when
   * it did not. Names the types found outside the decision scan and states
   * plainly that the outbound request was NOT modified — a redacted stored
   * prompt beside an `allowed` verdict must not read as prevention.
   */
  telemetry?: Record<string, unknown>;
}

/**
 * Redact the stored prompt when it carries enforced PII the decision scan
 * never saw.
 *
 * `storedText` is what the event would otherwise persist (the full multi-role
 * prompt). `scannedText` is what the decision pipeline actually evaluated.
 * When they are the same string the decision already covered everything and
 * this is a no-op — that is the fast path for single-turn calls.
 */
export function redactUnscannedForStorage(
  storedText: string,
  scannedText: string,
  config: {
    pii_policy?: PiiPolicyConfig;
    deobfuscation?: { enabled?: boolean };
  },
  onScanFailure: (err: unknown) => void,
): UnscannedRedactionResult {
  // Gated exactly the way the decision scan is gated (`if (config.pii_policy)`),
  // so "configured" means the same thing in both places. An empty object IS a
  // configuration — it selects the built-in severities, under which `ssn` and
  // the other credential types already resolve to block.
  if (!config.pii_policy) return { prompt: storedText };
  if (!storedText || storedText === scannedText) return { prompt: storedText };

  // ONE span around every step that can raise, not just the scan. This runs on
  // the emit path of an already-decided call, so an exception escaping here
  // would reach the host from a function whose entire job is to build a stored
  // field — the failure mode the detector-guard contract exists to forbid. The
  // resolution is the stored-copy one and it fails CLOSED: withhold the text
  // rather than persist content nothing vetted.
  try {
    const scan = runConfiguredPiiScan(storedText, config.deobfuscation);
    const detected: string[] = scan.detected_types;
    const via: DeobfuscationView["method"] | undefined = scan.via;

    // Only the types the operator asked to be acted on, resolved by the SDK's
    // OWN resolver rather than by a second reading of the policy object. The
    // order is rules[type] -> default -> built-in severity -> detect_only, and
    // getting that wrong here would either miss the common configuration
    // (`pii_policy: {}`, which relies entirely on the built-in severities) or
    // scrub a `detect_only` record an operator is deliberately baselining.
    const resolved = resolvePiiPolicy(detected, config.pii_policy);
    const actionable = [...resolved.blockedTypes, ...resolved.redactedTypes];
    if (actionable.length === 0) return { prompt: storedText };

    return {
      prompt: redactForStorage(storedText, via),
      telemetry: {
        // The stored copy was scrubbed; the request was not. Saying only the
        // first half would let a reader infer an enforcement that never happened.
        stored_redaction_scope: "unscanned_roles",
        stored_redaction_types: actionable.sort(),
        stored_redaction_outbound_unmodified: true,
        ...(via !== undefined ? { stored_redaction_via: via } : {}),
      },
    };
  } catch (err) {
    onScanFailure(err);
    return {
      prompt: UNSCANNED_PLACEHOLDER,
      telemetry: {
        stored_redaction_scan_failed: true,
        stored_redaction_scope: "unscanned_roles",
      },
    };
  }
}
