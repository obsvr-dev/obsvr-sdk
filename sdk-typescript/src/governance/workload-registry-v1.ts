import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { deriveDeviceKeyId, verifyDeviceSig, type DeviceSigner } from '../proxy/device-identity.js';
import { compareCodePoints } from './strict-canonical.js';

export const WORKLOAD_REGISTRATION_V1_SCHEMA = 'obsvr-workload-registration-v1' as const;
export const WORKLOAD_REGISTRATION_ENVELOPE_V1_SCHEMA = 'obsvr-workload-registration-envelope-v1' as const;
const HASH_RE = /^[0-9a-f]{64}$/;

export interface WorkloadRegistrationV1Input {
  workload_id: string; owner_ref_hash: string; environment: string; deployment_id: string;
  autonomy: 'assistive' | 'supervised' | 'autonomous';
  entry_points: string[]; capabilities: string[]; providers: string[]; models: string[];
  tools: string[]; mcp_servers: string[]; data_zones: string[]; external_side_effects: string[];
  required_approvals: string[]; policy_pack_hashes: string[]; coverage_attestation_hash: string;
  registered_at_ms: number;
}

export class WorkloadRegistryV1ValidationError extends Error {
  constructor(message: string) { super(message); this.name = 'WorkloadRegistryV1ValidationError'; }
}
function fail(message: string): never { throw new WorkloadRegistryV1ValidationError(message); }
function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value.trim(), 'utf8') > 256) fail(`${field} must be nonblank and at most 256 UTF-8 bytes`);
  return value.trim();
}
function hash(value: unknown, field: string): string { if (typeof value !== 'string' || !HASH_RE.test(value)) fail(`${field} must be a lowercase SHA-256 hash`); return value; }
function texts(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.length > 256) fail(`${field} must contain at most 256 items`);
  return [...new Set(value.map((item, i) => text(item, `${field}[${i}]`)))].sort(compareCodePoints);
}
function hashes(value: unknown, field: string): string[] { return texts(value, field).map((item) => hash(item, field)); }

export function buildWorkloadRegistrationV1(input: WorkloadRegistrationV1Input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('registration must be an object');
  const raw = input as unknown as Record<string, unknown>;
  const allowed = ['schema', 'workload_id', 'owner_ref_hash', 'environment', 'deployment_id', 'autonomy', 'entry_points', 'capabilities', 'providers', 'models', 'tools', 'mcp_servers', 'data_zones', 'external_side_effects', 'required_approvals', 'policy_pack_hashes', 'coverage_attestation_hash', 'registered_at_ms'];
  const unknown = Object.keys(raw).filter((key) => !allowed.includes(key)).sort(compareCodePoints);
  if (unknown.length) fail(`registration contains unsupported field: ${unknown[0]}`);
  if (raw.schema !== undefined && raw.schema !== WORKLOAD_REGISTRATION_V1_SCHEMA) fail('registration schema is invalid');
  if (!['assistive', 'supervised', 'autonomous'].includes(String(raw.autonomy))) fail('autonomy is invalid');
  if (typeof raw.registered_at_ms !== 'number' || !Number.isSafeInteger(raw.registered_at_ms) || raw.registered_at_ms < 0) fail('registered_at_ms must be a nonnegative safe integer');
  const result = {
    schema: WORKLOAD_REGISTRATION_V1_SCHEMA,
    workload_id: text(raw.workload_id, 'workload_id'), owner_ref_hash: hash(raw.owner_ref_hash, 'owner_ref_hash'),
    environment: text(raw.environment, 'environment'), deployment_id: text(raw.deployment_id, 'deployment_id'),
    autonomy: raw.autonomy as WorkloadRegistrationV1Input['autonomy'],
    entry_points: texts(raw.entry_points, 'entry_points'), capabilities: texts(raw.capabilities, 'capabilities'),
    providers: texts(raw.providers, 'providers'), models: texts(raw.models, 'models'), tools: texts(raw.tools, 'tools'),
    mcp_servers: texts(raw.mcp_servers, 'mcp_servers'), data_zones: texts(raw.data_zones, 'data_zones'),
    external_side_effects: texts(raw.external_side_effects, 'external_side_effects'),
    required_approvals: texts(raw.required_approvals, 'required_approvals'),
    policy_pack_hashes: hashes(raw.policy_pack_hashes, 'policy_pack_hashes'),
    coverage_attestation_hash: hash(raw.coverage_attestation_hash, 'coverage_attestation_hash'),
    registered_at_ms: raw.registered_at_ms,
  };
  if (result.entry_points.length === 0 || result.capabilities.length === 0 || result.policy_pack_hashes.length === 0) fail('entry_points, capabilities, and policy_pack_hashes must be nonempty');
  return result;
}

export function workloadRegistrationV1Hash(input: WorkloadRegistrationV1Input): string {
  return createHash('sha256').update(`obsvr-workload-registration/1\0${canonicalJsonForHash(buildWorkloadRegistrationV1(input))}`, 'utf8').digest('hex');
}

export function signWorkloadRegistrationV1(input: WorkloadRegistrationV1Input, signer: DeviceSigner) {
  const body = buildWorkloadRegistrationV1(input); const bodyHash = workloadRegistrationV1Hash(body);
  return { schema: WORKLOAD_REGISTRATION_ENVELOPE_V1_SCHEMA, body, body_hash: bodyHash, key_id: signer.keyId, signature: signer.signPayload(`obsvr-workload-registration-signature/1\0${bodyHash}`) };
}

export function verifyWorkloadRegistrationV1(envelope: unknown, rawPublicKey: Buffer): boolean {
  try {
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) return false;
    const value = envelope as Record<string, unknown>;
    if (value.schema !== WORKLOAD_REGISTRATION_ENVELOPE_V1_SCHEMA || value.key_id !== deriveDeviceKeyId(rawPublicKey) || typeof value.signature !== 'string') return false;
    const body = buildWorkloadRegistrationV1(value.body as WorkloadRegistrationV1Input);
    const bodyHash = workloadRegistrationV1Hash(body);
    return value.body_hash === bodyHash && verifyDeviceSig(rawPublicKey, value.key_id as string, `obsvr-workload-registration-signature/1\0${bodyHash}`, value.signature);
  } catch { return false; }
}

export class WorkloadRegistryV1 {
  private readonly entries = new Map<string, ReturnType<typeof signWorkloadRegistrationV1>>();
  register(envelope: ReturnType<typeof signWorkloadRegistrationV1>, rawPublicKey: Buffer): void {
    if (!verifyWorkloadRegistrationV1(envelope, rawPublicKey)) fail('registration signature is invalid');
    const key = `${envelope.body.workload_id}\0${envelope.body.environment}\0${envelope.body.deployment_id}`;
    this.entries.set(key, envelope);
  }
  snapshot() { return [...this.entries.values()].sort((a, b) => compareCodePoints(a.body_hash, b.body_hash)); }
}
