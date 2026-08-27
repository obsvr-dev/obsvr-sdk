import {
  createHash, createPublicKey, verify as cryptoVerify,
} from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import {
  verifyStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Envelope,
} from './strict-execution-outcome-v2-1.js';
import {
  reconstructStrictPolicyContinuityV21,
  type StrictPolicyContinuityV21,
} from './strict-policy-continuity-v2-1.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import {
  strictReceiptV21KeyId,
} from './strict-receipt-v2-1.js';
import {
  verifyStrictReceiptV21Chain,
  type StrictReceiptV21TrustOptions,
} from './strict-receipt-v2-1-verify.js';

export const STRICT_EVIDENCE_BUNDLE_V21_SCHEMA = 'obsvr-strict-evidence-bundle-v2-1' as const;
export const STRICT_EVIDENCE_BUNDLE_V21_ENVELOPE_SCHEMA =
  'obsvr-strict-evidence-bundle-envelope-v2-1' as const;
const BODY_DOMAIN = 'obsvr-strict-evidence-bundle/body/2.1';
const SIGNATURE_DOMAIN = 'obsvr-strict-evidence-bundle/signature/2.1';
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const MAX_ITEMS = 4096;

export interface StrictEvidenceCoverageV21 {
  sequence: number;
  receipt_hash: string;
  record_type: 'decision' | 'resolution';
  execution_authorized: boolean;
  execution_status: 'not_authorized' | 'missing' | 'succeeded' | 'failed' | 'uncertain';
  outcome_hash?: string;
}

export interface StrictEvidenceBundleV21Body {
  schema: typeof STRICT_EVIDENCE_BUNDLE_V21_SCHEMA;
  profile_version: '2.1';
  tenant_id: string;
  session_id: string;
  first_sequence: number;
  last_sequence: number;
  head_receipt_hash: string;
  complete: boolean;
  receipts: StrictReceiptV21Envelope[];
  execution_outcomes: StrictExecutionOutcomeV21Envelope[];
  coverage: StrictEvidenceCoverageV21[];
  policy_continuity: StrictPolicyContinuityV21;
}

export interface StrictEvidenceBundleV21Envelope {
  schema: typeof STRICT_EVIDENCE_BUNDLE_V21_ENVELOPE_SCHEMA;
  body: StrictEvidenceBundleV21Body;
  bundle_hash: string;
  signature: { algorithm: 'Ed25519'; key_id: string; value: string };
  public_key_b64: string;
}

export interface StrictEvidenceBundleV21Verification {
  schema_valid: boolean;
  semantic_valid: boolean;
  hash_valid: boolean;
  signature_valid: boolean;
  signer_binding_valid: boolean;
  trusted: boolean;
  complete: boolean;
  errors: string[];
}

export class StrictEvidenceBundleV21Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictEvidenceBundleV21Error'; }
}

function fail(message: string): never { throw new StrictEvidenceBundleV21Error(message); }
function u64(value: number): Buffer {
  const bytes = Buffer.alloc(8); bytes.writeBigUInt64BE(BigInt(value)); return bytes;
}
function domainHash(domain: string, value: unknown): string {
  const canonical = Buffer.from(canonicalJsonForHash(value), 'utf8');
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(domain), Buffer.from([0]), u64(canonical.length), canonical,
  ])).digest('hex');
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length
    && keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}
function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}
function publicKey(value: unknown): Buffer | undefined {
  if (typeof value !== 'string') return undefined;
  try {
    const raw = Buffer.from(value, 'base64');
    return raw.length === 32 && raw.toString('base64') === value ? raw : undefined;
  } catch { return undefined; }
}

export function strictEvidenceBundleV21Hash(body: StrictEvidenceBundleV21Body): string {
  return domainHash(BODY_DOMAIN, body);
}

export function strictEvidenceBundleV21SignaturePreimage(
  keyId: string, bundleHash: string,
): Buffer {
  if (!/^sha256:[0-9a-f]{64}$/.test(keyId) || !HEX64.test(bundleHash)) {
    return fail('invalid evidence bundle signature binding');
  }
  const key = Buffer.from(keyId, 'utf8');
  return Buffer.concat([
    Buffer.from(SIGNATURE_DOMAIN), Buffer.from([0]), u64(key.length), key,
    Buffer.from(bundleHash, 'hex'),
  ]);
}

export function buildStrictEvidenceBundleV21Body(params: {
  receipts: readonly StrictReceiptV21Envelope[];
  execution_outcomes: readonly StrictExecutionOutcomeV21Envelope[];
  trust: StrictReceiptV21TrustOptions;
}): StrictEvidenceBundleV21Body {
  if (!Array.isArray(params.receipts) || params.receipts.length === 0
    || params.receipts.length > MAX_ITEMS) return fail('receipt chain size is unsupported');
  if (!Array.isArray(params.execution_outcomes)
    || params.execution_outcomes.length > MAX_ITEMS) return fail('outcome set size is unsupported');
  const receipts = structuredClone(params.receipts) as StrictReceiptV21Envelope[];
  const chain = verifyStrictReceiptV21Chain(receipts, params.trust);
  if (!chain.valid) return fail(`receipt chain is not trusted: ${chain.errors.join(', ')}`);
  const byHash = new Map(receipts.map((receipt) => [receipt.receipt_hash, receipt]));
  const outcomes = structuredClone(
    params.execution_outcomes,
  ) as StrictExecutionOutcomeV21Envelope[];
  outcomes.sort((left, right) => left.body.decision_sequence - right.body.decision_sequence);
  const outcomeByReceipt = new Map<string, StrictExecutionOutcomeV21Envelope>();
  for (const outcome of outcomes) {
    const receiptHash = outcome?.body?.decision_receipt_hash;
    const receipt = byHash.get(receiptHash);
    if (!receipt) return fail('execution outcome references a receipt outside the bundle');
    if (outcomeByReceipt.has(receiptHash)) return fail('receipt has duplicate execution outcomes');
    if (!verifyStrictExecutionOutcomeV21(outcome, receipt, params.trust).trusted) {
      return fail('execution outcome is not trusted');
    }
    outcomeByReceipt.set(receiptHash, outcome);
  }
  const coverage: StrictEvidenceCoverageV21[] = receipts.map((receipt) => {
    const outcome = outcomeByReceipt.get(receipt.receipt_hash);
    return {
      sequence: receipt.body.sequence,
      receipt_hash: receipt.receipt_hash,
      record_type: receipt.body.record_type,
      execution_authorized: receipt.body.execution_authorized,
      execution_status: receipt.body.execution_authorized
        ? outcome?.body.status ?? 'missing' : 'not_authorized',
      ...(outcome ? { outcome_hash: outcome.outcome_hash } : {}),
    };
  });
  const complete = coverage.every((item) => item.execution_status !== 'missing');
  const policyContinuity = reconstructStrictPolicyContinuityV21(receipts, params.trust);
  return {
    schema: STRICT_EVIDENCE_BUNDLE_V21_SCHEMA, profile_version: '2.1',
    tenant_id: receipts[0].body.tenant_id, session_id: receipts[0].body.session_id,
    first_sequence: receipts[0].body.sequence,
    last_sequence: receipts.at(-1)!.body.sequence,
    head_receipt_hash: receipts.at(-1)!.receipt_hash,
    complete, receipts, execution_outcomes: outcomes, coverage,
    policy_continuity: policyContinuity,
  };
}

export function createStrictEvidenceBundleV21(params: {
  receipts: readonly StrictReceiptV21Envelope[];
  execution_outcomes: readonly StrictExecutionOutcomeV21Envelope[];
  trust: StrictReceiptV21TrustOptions;
  signer: DeviceSigner;
}): StrictEvidenceBundleV21Envelope {
  const body = buildStrictEvidenceBundleV21Body(params);
  const last = body.receipts.at(-1)!;
  const keyId = strictReceiptV21KeyId(params.signer.rawPublicKey);
  if (keyId !== last.signature.key_id
    || params.signer.publicKeyB64 !== last.public_key_b64) {
    return fail('evidence bundle signer must match the head receipt signer');
  }
  const bundleHash = strictEvidenceBundleV21Hash(body);
  const preimage = strictEvidenceBundleV21SignaturePreimage(keyId, bundleHash);
  const signature = params.signer.signBytes(preimage);
  if (!HEX128.test(signature)) return fail('signer returned an invalid Ed25519 signature');
  const rawKey = Buffer.from(params.signer.rawPublicKey);
  if (params.signer.publicKeyB64 !== rawKey.toString('base64')) {
    return fail('signer publicKeyB64 does not match rawPublicKey');
  }
  const verified = cryptoVerify(null, preimage,
    createPublicKey({ key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' }),
    Buffer.from(signature, 'hex'));
  if (!verified) return fail('signer signature failed self-verification');
  return { schema: STRICT_EVIDENCE_BUNDLE_V21_ENVELOPE_SCHEMA, body,
    bundle_hash: bundleHash, signature: { algorithm: 'Ed25519', key_id: keyId,
      value: signature }, public_key_b64: params.signer.publicKeyB64 };
}

export function verifyStrictEvidenceBundleV21(
  value: unknown, trust: StrictReceiptV21TrustOptions,
): StrictEvidenceBundleV21Verification {
  const errors: string[] = []; const envelope = record(value);
  const body = record(envelope?.body); const signature = record(envelope?.signature);
  const schemaValid = Boolean(envelope && body && signature
    && exact(envelope, ['schema', 'body', 'bundle_hash', 'signature', 'public_key_b64'])
    && envelope.schema === STRICT_EVIDENCE_BUNDLE_V21_ENVELOPE_SCHEMA
    && typeof envelope.bundle_hash === 'string' && HEX64.test(envelope.bundle_hash)
    && exact(signature, ['algorithm', 'key_id', 'value'])
    && signature.algorithm === 'Ed25519'
    && typeof signature.key_id === 'string' && KEY_ID.test(signature.key_id)
    && typeof signature.value === 'string' && HEX128.test(signature.value)
    && publicKey(envelope.public_key_b64) !== undefined);
  if (!schemaValid) errors.push('bundle_schema_invalid');
  let rebuilt: StrictEvidenceBundleV21Body | undefined;
  try {
    rebuilt = buildStrictEvidenceBundleV21Body({
      receipts: body?.receipts as StrictReceiptV21Envelope[],
      execution_outcomes: body?.execution_outcomes as StrictExecutionOutcomeV21Envelope[],
      trust,
    });
  } catch { errors.push('bundle_components_untrusted'); }
  const semanticValid = Boolean(rebuilt
    && canonicalJsonForHash(rebuilt) === canonicalJsonForHash(body));
  if (!semanticValid) errors.push('bundle_semantic_invalid');
  const hashValid = Boolean(rebuilt && typeof envelope?.bundle_hash === 'string'
    && strictEvidenceBundleV21Hash(rebuilt) === envelope.bundle_hash);
  if (!hashValid) errors.push('bundle_hash_invalid');
  const rawKey = publicKey(envelope?.public_key_b64);
  let signatureValid = false;
  try {
    if (rawKey && signature && typeof signature.key_id === 'string'
      && typeof signature.value === 'string' && typeof envelope?.bundle_hash === 'string') {
      signatureValid = cryptoVerify(null,
        strictEvidenceBundleV21SignaturePreimage(signature.key_id, envelope.bundle_hash),
        createPublicKey({ key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' }),
        Buffer.from(signature.value, 'hex'));
    }
  } catch { signatureValid = false; }
  if (!signatureValid) errors.push('bundle_signature_invalid');
  const head = rebuilt?.receipts.at(-1);
  const signerBindingValid = Boolean(rawKey && head && signature
    && strictReceiptV21KeyId(rawKey) === signature.key_id
    && signature.key_id === head.signature.key_id
    && envelope?.public_key_b64 === head.public_key_b64);
  if (!signerBindingValid) errors.push('bundle_signer_mismatch');
  const trusted = schemaValid && semanticValid && hashValid
    && signatureValid && signerBindingValid;
  return { schema_valid: schemaValid, semantic_valid: semanticValid,
    hash_valid: hashValid, signature_valid: signatureValid,
    signer_binding_valid: signerBindingValid, trusted,
    complete: trusted ? rebuilt!.complete : false, errors };
}
