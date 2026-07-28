/**
 * Canonical decision records (ADR-2 tier-1).
 *
 * At decision time the enforcement pipeline builds a small canonical JSON
 * document — the decision-input document, schema `obsvr-decision-input-v1` —
 * describing exactly what the rules engine evaluated: the canonical rules-set
 * hash, the enforcement-integrity (kill-switch/degraded) state, the evaluation
 * target, a digest of the evaluated text, the scope identifiers visible at the
 * boundary, and the customer-hook disposition. Its SHA-256
 * (`decision_input_hash`) plus `engine_version` are stamped on emitted audit
 * events as ADDITIVE fields (never part of the HMAC chain preimage), and the
 * ledger's v7 Merkle leaf seals them.
 *
 * Canonicalization is RFC 8785-style: UTF-8, lexicographically sorted keys,
 * no insignificant whitespace, absent optionals OMITTED (never null). It
 * reuses `stableStringify` — the same helper the cross-language rules hash is
 * pinned on — so both SDKs produce byte-identical documents. Parity is pinned
 * by conformance/fixtures/decision_input.json (twin:
 * sdk-python/obsvr/decision_record.py).
 *
 * @packageDocumentation
 */

import { createHash } from 'crypto';
import { stableStringify } from './rules.js';

/**
 * Cross-language rules-engine semantics version. Bumped when — and only
 * when — evaluation semantics change (a change that can produce a different
 * decision for the same rules + input), in the same commit that updates
 * conformance/fixtures/eval_semantics.json, in BOTH SDKs. Never bumped for
 * additive fields or refactors.
 */
export const RULES_ENGINE_SEMANTICS_VERSION = 1;

/** The engine_version string stamped on events: "obsvr-rules/<N>". */
export const ENGINE_VERSION = `obsvr-rules/${RULES_ENGINE_SEMANTICS_VERSION}`;

/** Schema tag of the canonical decision-input document. */
export const DECISION_INPUT_SCHEMA = 'obsvr-decision-input-v1';

/** Customer-hook disposition recorded in the decision-input document. */
export type HookDisposition =
  | 'not_configured' // no customer hook registered
  | 'skipped' // configured but not run (degraded gate, or trigger condition not met)
  | 'allow'
  | 'block'
  | 'redact'
  | 'timeout'
  | 'error';

/**
 * The canonical decision-input document (v1). All values are strings or
 * booleans; optionals are omitted when absent — a document never contains
 * a JSON null.
 */
export interface DecisionInput {
  schema: typeof DECISION_INPUT_SCHEMA;
  engine_version: string;
  /** Canonical enabled-rules-set hash (= policy_version; "none" when empty). */
  rules_hash: string;
  /** Enforcement-integrity gate state at decision time (kill switch / staleness). */
  degraded: boolean;
  /** Present only when degraded is true. */
  degraded_reason?: string;
  target: 'request' | 'response';
  /** SHA-256 hex of the evaluated text; present when target = "request". */
  prompt_sha256?: string;
  /** SHA-256 hex of the evaluated text; present when target = "response". */
  response_sha256?: string;
  user_id?: string;
  service_name?: string;
  tenant_id?: string;
  hook: HookDisposition;
}

/** SHA-256 lowercase hex over the UTF-8 bytes of `text`. */
export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Inputs to {@link buildDecisionInput}. */
export interface DecisionInputParams {
  rulesHash: string;
  degraded: boolean;
  degradedReason?: string;
  target: 'request' | 'response';
  /**
   * The exact text the decision pipeline evaluated (the scan text — the
   * last-user-message extraction — captured BEFORE any redaction the
   * pipeline applies). Digested, never stored.
   */
  evaluatedText: string;
  userId?: string;
  serviceName?: string;
  tenantId?: string;
  hook: HookDisposition;
}

/**
 * Build the canonical decision-input document. Scope identifiers are
 * included only when they are non-empty strings (what the boundary could
 * actually see); the evaluated text is digested into prompt_sha256 or
 * response_sha256 depending on the target.
 */
export function buildDecisionInput(params: DecisionInputParams): DecisionInput {
  const doc: DecisionInput = {
    schema: DECISION_INPUT_SCHEMA,
    engine_version: ENGINE_VERSION,
    rules_hash: params.rulesHash,
    degraded: params.degraded,
    target: params.target,
    hook: params.hook,
  };
  if (params.degraded && typeof params.degradedReason === 'string' && params.degradedReason.length > 0) {
    doc.degraded_reason = params.degradedReason;
  }
  const digest = sha256Hex(params.evaluatedText);
  if (params.target === 'request') {
    doc.prompt_sha256 = digest;
  } else {
    doc.response_sha256 = digest;
  }
  if (typeof params.userId === 'string' && params.userId.length > 0) doc.user_id = params.userId;
  if (typeof params.serviceName === 'string' && params.serviceName.length > 0) doc.service_name = params.serviceName;
  if (typeof params.tenantId === 'string' && params.tenantId.length > 0) doc.tenant_id = params.tenantId;
  return doc;
}

/**
 * Canonical serialization of a decision-input document: sorted keys, no
 * insignificant whitespace, minimal escaping, undefined keys omitted.
 * Byte-for-byte identical to the Python SDK (pinned by
 * conformance/fixtures/decision_input.json).
 */
export function canonicalizeDecisionInput(doc: DecisionInput): string {
  return stableStringify(doc);
}

/** SHA-256 lowercase hex of the canonical UTF-8 bytes of the document. */
export function computeDecisionInputHash(doc: DecisionInput): string {
  return sha256Hex(canonicalizeDecisionInput(doc));
}
