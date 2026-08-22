import { sha256Hex } from '../policy/decision-record.js';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { compareCodePoints } from './strict-canonical.js';

export const STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA =
  'obsvr-strict-identity-evidence-v2-1' as const;
export const STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE = '2.1' as const;
export const STRICT_IDENTITY_EVIDENCE_V2_1_HASH_DOMAIN =
  'obsvr-strict-identity-evidence/2.1' as const;

const HASH = /^[0-9a-f]{64}$/;
const KEY_ID = /^sha256:[0-9a-f]{64}$/;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const PRINCIPAL_TYPES = new Set(['human', 'service', 'agent', 'workload', 'unknown']);
const MAX_SET_ITEMS = 64;
const MAX_DELEGATION_HOPS = 16;
const MAX_CANONICAL_BYTES = 65_536;
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;
const TRUSTED = new WeakSet<object>();

export type StrictPrincipalTypeV21 =
  'human' | 'service' | 'agent' | 'workload' | 'unknown';

export interface StrictDelegationHopV21 {
  hop: number;
  delegation_id_hash: string;
  delegator_ref_hash: string;
  delegatee_ref_hash: string;
  granted_scopes: string[];
  issued_at_ms: number;
  expires_at_ms: number;
}

export interface StrictIdentityEvidenceV21Input {
  schema: typeof STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA;
  profile_version: typeof STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE;
  relationship: 'direct' | 'delegated';
  receipt_time_ms: number;
  requester: {
    requester_ref_hash: string;
    principal_type: StrictPrincipalTypeV21;
    role_ids: string[];
    privilege_scopes: string[];
  };
  initiator: {
    agent_ref_hash: string;
    key_id: string;
    role_ids: string[];
    privilege_scopes: string[];
  };
  delegation_chain: StrictDelegationHopV21[];
}

export type StrictIdentityEvidenceV21Document = StrictIdentityEvidenceV21Input;

export interface TrustedStrictIdentityEvidenceV21 {
  readonly schema: typeof STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA;
  readonly profile_version: typeof STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE;
}

export interface StrictIdentityEvidenceV21Authority {
  issue(input: StrictIdentityEvidenceV21Input): TrustedStrictIdentityEvidenceV21;
}

export class StrictIdentityEvidenceV21ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictIdentityEvidenceV21ValidationError';
  }
}

function fail(message: string): never { throw new StrictIdentityEvidenceV21ValidationError(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const known = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !known.has(key)).sort(compareCodePoints);
  if (unknown.length > 0) fail(`${field} contains unsupported field: ${unknown[0]}`);
}
function hex(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${field} must be 64 lowercase hex characters`);
  return value;
}
function safeId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !SAFE_ID.test(value)) {
    fail(`${field} must be a 1-128 byte safe ASCII identifier`);
  }
  return value;
}
function safeSet(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) fail(`${field} must be an array`);
  if (value.length > MAX_SET_ITEMS) fail(`${field} exceeds ${MAX_SET_ITEMS} items`);
  const values = value.map((entry, index) => safeId(entry, `${field}[${index}]`));
  values.sort(compareCodePoints);
  return values.filter((entry, index) => index === 0 || entry !== values[index - 1]);
}
function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0
    || value > MAX_SAFE_INTEGER) fail(`${field} must be a nonnegative safe integer`);
  return value;
}
function subset(child: readonly string[], parent: readonly string[]): boolean {
  const allowed = new Set(parent);
  return child.every((scope) => allowed.has(scope));
}

function delegationHop(value: unknown, index: number, receiptTime: number): StrictDelegationHopV21 {
  const field = `delegation_chain[${index}]`;
  const hop = record(value, field);
  exact(hop, ['hop', 'delegation_id_hash', 'delegator_ref_hash', 'delegatee_ref_hash',
    'granted_scopes', 'issued_at_ms', 'expires_at_ms'], field);
  const normalized: StrictDelegationHopV21 = {
    hop: integer(hop.hop, `${field}.hop`),
    delegation_id_hash: hex(hop.delegation_id_hash, `${field}.delegation_id_hash`),
    delegator_ref_hash: hex(hop.delegator_ref_hash, `${field}.delegator_ref_hash`),
    delegatee_ref_hash: hex(hop.delegatee_ref_hash, `${field}.delegatee_ref_hash`),
    granted_scopes: safeSet(hop.granted_scopes, `${field}.granted_scopes`),
    issued_at_ms: integer(hop.issued_at_ms, `${field}.issued_at_ms`),
    expires_at_ms: integer(hop.expires_at_ms, `${field}.expires_at_ms`),
  };
  if (normalized.hop !== index) fail(`${field}.hop must equal ${index}`);
  if (normalized.issued_at_ms > receiptTime || receiptTime >= normalized.expires_at_ms) {
    fail(`${field} is not valid at receipt_time_ms`);
  }
  return normalized;
}

export function buildStrictIdentityEvidenceV21(
  input: StrictIdentityEvidenceV21Input,
): StrictIdentityEvidenceV21Document {
  const root = record(input, 'identity evidence');
  exact(root, ['schema', 'profile_version', 'relationship', 'receipt_time_ms',
    'requester', 'initiator', 'delegation_chain'], 'identity evidence');
  if (root.schema !== STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA) {
    fail(`schema must be ${STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA}`);
  }
  if (root.profile_version !== STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE) {
    fail(`profile_version must be ${STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE}`);
  }
  if (root.relationship !== 'direct' && root.relationship !== 'delegated') {
    fail('relationship must be direct or delegated');
  }
  const receiptTime = integer(root.receipt_time_ms, 'receipt_time_ms');
  const requester = record(root.requester, 'requester');
  exact(requester, ['requester_ref_hash', 'principal_type', 'role_ids',
    'privilege_scopes'], 'requester');
  if (typeof requester.principal_type !== 'string'
    || !PRINCIPAL_TYPES.has(requester.principal_type)) fail('requester.principal_type is unsupported');
  const normalizedRequester = {
    requester_ref_hash: hex(requester.requester_ref_hash, 'requester.requester_ref_hash'),
    principal_type: requester.principal_type as StrictPrincipalTypeV21,
    role_ids: safeSet(requester.role_ids, 'requester.role_ids'),
    privilege_scopes: safeSet(requester.privilege_scopes, 'requester.privilege_scopes'),
  };
  const initiator = record(root.initiator, 'initiator');
  exact(initiator, ['agent_ref_hash', 'key_id', 'role_ids', 'privilege_scopes'], 'initiator');
  if (typeof initiator.key_id !== 'string' || !KEY_ID.test(initiator.key_id)) {
    fail('initiator.key_id must be sha256 followed by 64 lowercase hex characters');
  }
  const normalizedInitiator = {
    agent_ref_hash: hex(initiator.agent_ref_hash, 'initiator.agent_ref_hash'),
    key_id: initiator.key_id,
    role_ids: safeSet(initiator.role_ids, 'initiator.role_ids'),
    privilege_scopes: safeSet(initiator.privilege_scopes, 'initiator.privilege_scopes'),
  };
  if (!Array.isArray(root.delegation_chain)) fail('delegation_chain must be an array');
  if (root.delegation_chain.length > MAX_DELEGATION_HOPS) {
    fail(`delegation_chain exceeds ${MAX_DELEGATION_HOPS} items`);
  }
  const chain = root.delegation_chain.map((hop, index) => delegationHop(hop, index, receiptTime));
  const delegationIds = new Set<string>();
  for (const hop of chain) {
    if (delegationIds.has(hop.delegation_id_hash)) fail('delegation_chain contains duplicate delegation_id_hash');
    delegationIds.add(hop.delegation_id_hash);
  }
  if (root.relationship === 'direct') {
    if (chain.length !== 0) fail('direct relationship requires an empty delegation_chain');
    if (normalizedRequester.requester_ref_hash !== normalizedInitiator.agent_ref_hash) {
      fail('direct relationship requires requester and initiator to match');
    }
    if (!subset(normalizedInitiator.privilege_scopes, normalizedRequester.privilege_scopes)) {
      fail('initiator privilege_scopes exceed requester privilege_scopes');
    }
  } else {
    if (chain.length === 0) fail('delegated relationship requires delegation_chain');
    if (chain[0].delegator_ref_hash !== normalizedRequester.requester_ref_hash) {
      fail('delegation_chain must start at requester');
    }
    if (chain[chain.length - 1].delegatee_ref_hash !== normalizedInitiator.agent_ref_hash) {
      fail('delegation_chain must end at initiator');
    }
    if (!subset(chain[0].granted_scopes, normalizedRequester.privilege_scopes)) {
      fail('first delegation grants scopes outside requester privilege_scopes');
    }
    for (let index = 1; index < chain.length; index += 1) {
      if (chain[index - 1].delegatee_ref_hash !== chain[index].delegator_ref_hash) {
        fail(`delegation_chain[${index}] does not continue the prior hop`);
      }
      if (!subset(chain[index].granted_scopes, chain[index - 1].granted_scopes)) {
        fail(`delegation_chain[${index}] expands granted_scopes`);
      }
    }
    if (!subset(normalizedInitiator.privilege_scopes, chain[chain.length - 1].granted_scopes)) {
      fail('initiator privilege_scopes exceed delegated scopes');
    }
  }
  const document: StrictIdentityEvidenceV21Document = {
    schema: STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
    profile_version: STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
    relationship: root.relationship,
    receipt_time_ms: receiptTime,
    requester: normalizedRequester,
    initiator: normalizedInitiator,
    delegation_chain: chain,
  };
  if (Buffer.byteLength(canonicalJsonForHash(document), 'utf8') > MAX_CANONICAL_BYTES) {
    fail(`canonical identity evidence exceeds ${MAX_CANONICAL_BYTES} UTF-8 bytes`);
  }
  return document;
}

export function canonicalizeStrictIdentityEvidenceV21(input: StrictIdentityEvidenceV21Input): string {
  return canonicalJsonForHash(buildStrictIdentityEvidenceV21(input));
}

export function strictIdentityEvidenceV21Hash(input: StrictIdentityEvidenceV21Input): string {
  return sha256Hex(`${STRICT_IDENTITY_EVIDENCE_V2_1_HASH_DOMAIN}\0${canonicalizeStrictIdentityEvidenceV21(input)}`);
}

export function createStrictIdentityEvidenceV21Authority(): StrictIdentityEvidenceV21Authority {
  return Object.freeze({
    issue(input: StrictIdentityEvidenceV21Input): TrustedStrictIdentityEvidenceV21 {
      const canonical = canonicalizeStrictIdentityEvidenceV21(input);
      const evidence = Object.freeze({
        schema: STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
        profile_version: STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
        canonical,
      });
      TRUSTED.add(evidence);
      return evidence;
    },
  });
}

export function trustedStrictIdentityEvidenceV21Document(
  evidence: TrustedStrictIdentityEvidenceV21,
): StrictIdentityEvidenceV21Document {
  if (evidence === null || typeof evidence !== 'object' || !TRUSTED.has(evidence)) {
    fail('identity evidence was not issued by a trusted authority');
  }
  const canonical = (evidence as unknown as { canonical: string }).canonical;
  return buildStrictIdentityEvidenceV21(JSON.parse(canonical) as StrictIdentityEvidenceV21Input);
}
