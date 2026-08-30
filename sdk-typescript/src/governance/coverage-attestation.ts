import { createHash } from 'node:crypto';
import {
  integrationBindings,
  type BindingEntry,
  type EnforcementDepth,
} from '../binding-report.js';
import {
  deriveDeviceKeyId,
  verifyDeviceSig,
  type DeviceSigner,
} from '../proxy/device-identity.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { compareCodePoints } from './strict-canonical.js';

export const COVERAGE_ATTESTATION_SCHEMA = 'obsvr-coverage-attestation-v1' as const;
export const COVERAGE_ATTESTATION_ENVELOPE_SCHEMA =
  'obsvr-coverage-attestation-envelope-v1' as const;
export const COVERAGE_ATTESTATION_DOMAIN = 'obsvr-coverage-attestation/1' as const;

const MAX_ITEMS = 256;
const MAX_TEXT_BYTES = 256;
const HASH_RE = /^[0-9a-f]{64}$/;
const DEPTH_RANK: Record<EnforcementDepth, number> = {
  unknown: 0,
  observe: 1,
  enforce: 2,
};
const BODY_FIELDS = [
  'schema',
  'attestation_id',
  'workload_id',
  'environment',
  'sdk_language',
  'sdk_version',
  'generated_at_ms',
  'valid_until_ms',
  'required',
  'bindings',
  'policy_pack_hashes',
  'coverage_complete',
  'failures',
] as const;

export type CoverageFailureReason =
  | 'missing'
  | 'unbound'
  | 'insufficient_depth';

export interface CoverageRequirementInput {
  integration: string;
  minimum_depth: Exclude<EnforcementDepth, 'unknown'>;
  symbols?: string[];
}

export interface CoverageAttestationInput {
  attestation_id: string;
  workload_id: string;
  environment: string;
  sdk_language: 'typescript' | 'python';
  sdk_version: string;
  generated_at_ms: number;
  valid_until_ms: number;
  required: CoverageRequirementInput[];
  policy_pack_hashes: string[];
}

export interface CoverageBinding {
  integration: string;
  symbol: string;
  bound: boolean;
  enforcement_depth: EnforcementDepth;
  integration_version?: string;
  initialized_at_ms?: number;
  exclusions: string[];
  error_type?: string;
  error?: string;
}

export interface CoverageFailure {
  integration: string;
  symbol: string;
  reason: CoverageFailureReason;
  required_depth: Exclude<EnforcementDepth, 'unknown'>;
  actual_depth: EnforcementDepth | 'missing';
}

export interface CoverageAttestationBody {
  schema: typeof COVERAGE_ATTESTATION_SCHEMA;
  attestation_id: string;
  workload_id: string;
  environment: string;
  sdk_language: 'typescript' | 'python';
  sdk_version: string;
  generated_at_ms: number;
  valid_until_ms: number;
  required: Array<Required<CoverageRequirementInput>>;
  bindings: CoverageBinding[];
  policy_pack_hashes: string[];
  coverage_complete: boolean;
  failures: CoverageFailure[];
}

export interface CoverageAttestationEnvelope {
  schema: typeof COVERAGE_ATTESTATION_ENVELOPE_SCHEMA;
  body: CoverageAttestationBody;
  body_hash: string;
  key_id: string;
  signature: string;
}

export interface CoverageAttestationVerification {
  valid: boolean;
  reason: 'valid' | 'invalid_body' | 'body_hash_mismatch' | 'foreign_key' | 'invalid_signature';
  body_hash?: string;
}

export class CoverageAttestationValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CoverageAttestationValidationError';
  }
}

function fail(message: string): never {
  throw new CoverageAttestationValidationError(message);
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') fail(`${field} must be nonblank`);
  const normalized = value.trim();
  if (Buffer.byteLength(normalized, 'utf8') > MAX_TEXT_BYTES) {
    fail(`${field} exceeds ${MAX_TEXT_BYTES} UTF-8 bytes`);
  }
  return normalized;
}

function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
  return value;
}

function uniqueTexts(values: unknown, field: string): string[] {
  if (!Array.isArray(values) || values.length > MAX_ITEMS) {
    fail(`${field} must be an array with at most ${MAX_ITEMS} items`);
  }
  return [...new Set(values.map((value, index) => text(value, `${field}[${index}]`)))]
    .sort(compareCodePoints);
}

function hashes(values: unknown, field: string): string[] {
  const items = uniqueTexts(values, field);
  for (const item of items) if (!HASH_RE.test(item)) fail(`${field} contains an invalid hash`);
  return items;
}

function normalizedRequirements(values: unknown): Array<Required<CoverageRequirementInput>> {
  if (!Array.isArray(values) || values.length > MAX_ITEMS) {
    fail(`required must be an array with at most ${MAX_ITEMS} items`);
  }
  const requirements: Array<Required<CoverageRequirementInput>> = values.map((candidate, index) => {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return fail(`required[${index}] must be an object`);
    }
    const value = candidate as Record<string, unknown>;
    const unknown = Object.keys(value).filter(
      (key) => !['integration', 'minimum_depth', 'symbols'].includes(key),
    );
    if (unknown.length > 0) fail(`required[${index}] contains unsupported field: ${unknown[0]}`);
    if (value.minimum_depth !== 'observe' && value.minimum_depth !== 'enforce') {
      fail(`required[${index}].minimum_depth is invalid`);
    }
    return {
      integration: text(value.integration, `required[${index}].integration`),
      minimum_depth: value.minimum_depth as 'observe' | 'enforce',
      symbols: uniqueTexts(value.symbols ?? [], `required[${index}].symbols`),
    };
  });
  requirements.sort((left, right) => compareCodePoints(
    `${left.integration}\0${left.minimum_depth}\0${left.symbols.join('\0')}`,
    `${right.integration}\0${right.minimum_depth}\0${right.symbols.join('\0')}`,
  ));
  const keys = requirements.map((item) => canonicalJsonForHash(item));
  if (new Set(keys).size !== keys.length) fail('required contains duplicate requirements');
  return requirements;
}

function normalizedBinding(
  integration: string,
  symbol: string,
  entry: BindingEntry,
): CoverageBinding {
  const depth = entry.enforcementDepth ?? 'unknown';
  const binding: CoverageBinding = {
    integration: text(integration, 'binding.integration'),
    symbol: text(symbol, 'binding.symbol'),
    bound: entry.bound === true,
    enforcement_depth: depth in DEPTH_RANK ? depth : 'unknown',
    exclusions: uniqueTexts(entry.exclusions ?? [], 'binding.exclusions'),
  };
  if (entry.integrationVersion !== undefined) {
    binding.integration_version = text(entry.integrationVersion, 'binding.integration_version');
  }
  if (entry.initializedAtMs !== undefined) {
    binding.initialized_at_ms = integer(entry.initializedAtMs, 'binding.initialized_at_ms');
  }
  if (entry.errorType !== undefined) binding.error_type = text(entry.errorType, 'binding.error_type');
  if (entry.error !== undefined) binding.error = text(entry.error, 'binding.error');
  return binding;
}

function flattenBindings(
  snapshot: Record<string, Record<string, BindingEntry>>,
): CoverageBinding[] {
  const flattened: CoverageBinding[] = [];
  for (const [integration, symbols] of Object.entries(snapshot)) {
    for (const [symbol, entry] of Object.entries(symbols)) {
      flattened.push(normalizedBinding(integration, symbol, entry));
    }
  }
  if (flattened.length > MAX_ITEMS) fail(`bindings exceeds ${MAX_ITEMS} items`);
  return flattened.sort((left, right) => compareCodePoints(
    `${left.integration}\0${left.symbol}`,
    `${right.integration}\0${right.symbol}`,
  ));
}

function coverageFailures(
  required: Array<Required<CoverageRequirementInput>>,
  bindings: CoverageBinding[],
): CoverageFailure[] {
  const failures: CoverageFailure[] = [];
  for (const requirement of required) {
    const candidates = bindings.filter((binding) =>
      binding.integration === requirement.integration &&
      (requirement.symbols.length === 0 || requirement.symbols.includes(binding.symbol)),
    );
    const symbols = requirement.symbols.length > 0
      ? requirement.symbols
      : candidates.length > 0
        ? [...new Set(candidates.map((binding) => binding.symbol))]
        : [''];
    for (const symbol of symbols) {
      const binding = candidates.find((candidate) => candidate.symbol === symbol);
      if (!binding) {
        failures.push({
          integration: requirement.integration,
          symbol,
          reason: 'missing',
          required_depth: requirement.minimum_depth,
          actual_depth: 'missing',
        });
      } else if (!binding.bound) {
        failures.push({
          integration: requirement.integration,
          symbol,
          reason: 'unbound',
          required_depth: requirement.minimum_depth,
          actual_depth: binding.enforcement_depth,
        });
      } else if (DEPTH_RANK[binding.enforcement_depth] < DEPTH_RANK[requirement.minimum_depth]) {
        failures.push({
          integration: requirement.integration,
          symbol,
          reason: 'insufficient_depth',
          required_depth: requirement.minimum_depth,
          actual_depth: binding.enforcement_depth,
        });
      }
    }
  }
  return failures.sort((left, right) => compareCodePoints(
    `${left.integration}\0${left.symbol}\0${left.reason}`,
    `${right.integration}\0${right.symbol}\0${right.reason}`,
  ));
}

/** Raised when the current process does not meet its exact coverage contract. */
export class CoverageRequirementsError extends Error {
  readonly failures: CoverageFailure[];

  constructor(failures: CoverageFailure[]) {
    super(
      `Required obsvr coverage is not active: ${failures.map((failure) =>
        `${failure.integration}:${failure.symbol || '*'} ${failure.reason} ` +
        `(required ${failure.required_depth}, actual ${failure.actual_depth})`,
      ).join(', ')}`,
    );
    this.name = 'CoverageRequirementsError';
    this.failures = failures.map((failure) => ({ ...failure }));
  }
}

/** Resolve exact symbol and enforcement-depth requirements against live bindings. */
export function coverageRequirementFailures(
  required: CoverageRequirementInput[],
  snapshot = integrationBindings(),
): CoverageFailure[] {
  return coverageFailures(normalizedRequirements(required), flattenBindings(snapshot));
}

/** Refuse startup when a required path is absent, unbound, or too shallow. */
export function assertCoverageRequirements(
  required: CoverageRequirementInput[],
  snapshot = integrationBindings(),
): void {
  const failures = coverageRequirementFailures(required, snapshot);
  if (failures.length > 0) throw new CoverageRequirementsError(failures);
}

export function buildCoverageAttestationBody(
  input: CoverageAttestationInput,
  snapshot = integrationBindings(),
): CoverageAttestationBody {
  const generatedAt = integer(input.generated_at_ms, 'generated_at_ms');
  const validUntil = integer(input.valid_until_ms, 'valid_until_ms');
  if (validUntil <= generatedAt) fail('valid_until_ms must be after generated_at_ms');
  const required = normalizedRequirements(input.required);
  const bindings = flattenBindings(snapshot);
  const failures = coverageFailures(required, bindings);
  return {
    schema: COVERAGE_ATTESTATION_SCHEMA,
    attestation_id: text(input.attestation_id, 'attestation_id'),
    workload_id: text(input.workload_id, 'workload_id'),
    environment: text(input.environment, 'environment'),
    sdk_language: input.sdk_language === 'typescript' || input.sdk_language === 'python'
      ? input.sdk_language
      : fail('sdk_language is invalid'),
    sdk_version: text(input.sdk_version, 'sdk_version'),
    generated_at_ms: generatedAt,
    valid_until_ms: validUntil,
    required,
    bindings,
    policy_pack_hashes: hashes(input.policy_pack_hashes, 'policy_pack_hashes'),
    coverage_complete: failures.length === 0,
    failures,
  };
}

export function canonicalizeCoverageAttestationBody(body: CoverageAttestationBody): string {
  if (!body || typeof body !== 'object' || Array.isArray(body)) fail('body must be an object');
  const actualFields = Object.keys(body).sort(compareCodePoints);
  const expectedFields = [...BODY_FIELDS].sort(compareCodePoints);
  if (canonicalJsonForHash(actualFields) !== canonicalJsonForHash(expectedFields)) {
    fail('body fields do not match the coverage attestation schema');
  }
  if (body.schema !== COVERAGE_ATTESTATION_SCHEMA) fail('body schema is invalid');
  const snapshot: Record<string, Record<string, BindingEntry>> = {};
  for (const binding of body.bindings) {
    snapshot[binding.integration] ??= {};
    snapshot[binding.integration][binding.symbol] = {
      bound: binding.bound,
      enforcementDepth: binding.enforcement_depth,
      ...(binding.integration_version ? { integrationVersion: binding.integration_version } : {}),
      ...(binding.initialized_at_ms === undefined ? {} : { initializedAtMs: binding.initialized_at_ms }),
      exclusions: binding.exclusions,
      ...(binding.error_type ? { errorType: binding.error_type } : {}),
      ...(binding.error ? { error: binding.error } : {}),
    };
  }
  const rebuilt = buildCoverageAttestationBody(body, snapshot);
  if (canonicalJsonForHash(body) !== canonicalJsonForHash(rebuilt)) {
    fail('body contains noncanonical or inconsistent derived fields');
  }
  return canonicalJsonForHash(rebuilt);
}

export function coverageAttestationBodyHash(body: CoverageAttestationBody): string {
  return createHash('sha256').update(canonicalizeCoverageAttestationBody(body), 'utf8').digest('hex');
}

function signaturePayload(body: CoverageAttestationBody): string {
  return `${COVERAGE_ATTESTATION_DOMAIN}\0${canonicalizeCoverageAttestationBody(body)}`;
}

export function signCoverageAttestation(
  input: CoverageAttestationInput,
  signer: DeviceSigner,
  snapshot = integrationBindings(),
): CoverageAttestationEnvelope {
  const body = buildCoverageAttestationBody(input, snapshot);
  return {
    schema: COVERAGE_ATTESTATION_ENVELOPE_SCHEMA,
    body,
    body_hash: coverageAttestationBodyHash(body),
    key_id: signer.keyId,
    signature: signer.signPayload(signaturePayload(body)),
  };
}

export function verifyCoverageAttestation(
  envelope: CoverageAttestationEnvelope,
  rawPublicKey: Buffer,
): CoverageAttestationVerification {
  let bodyHash: string;
  try {
    if (envelope.schema !== COVERAGE_ATTESTATION_ENVELOPE_SCHEMA) throw new Error();
    bodyHash = coverageAttestationBodyHash(envelope.body);
  } catch {
    return { valid: false, reason: 'invalid_body' };
  }
  if (bodyHash !== envelope.body_hash) {
    return { valid: false, reason: 'body_hash_mismatch', body_hash: bodyHash };
  }
  if (deriveDeviceKeyId(rawPublicKey) !== envelope.key_id) {
    return { valid: false, reason: 'foreign_key', body_hash: bodyHash };
  }
  if (!verifyDeviceSig(
    rawPublicKey,
    envelope.key_id,
    signaturePayload(envelope.body),
    envelope.signature,
  )) {
    return { valid: false, reason: 'invalid_signature', body_hash: bodyHash };
  }
  return { valid: true, reason: 'valid', body_hash: bodyHash };
}
