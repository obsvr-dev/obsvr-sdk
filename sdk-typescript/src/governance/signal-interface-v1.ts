import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { compareCodePoints } from './strict-canonical.js';

export const SIGNAL_DECLARATION_V1_SCHEMA = 'obsvr-signal-declaration-v1' as const;
export const SIGNAL_OBSERVATION_V1_SCHEMA = 'obsvr-signal-observation-v1' as const;
export const SIGNAL_RESOLUTION_V1_SCHEMA = 'obsvr-signal-resolution-v1' as const;
const HASH_RE = /^[0-9a-f]{64}$/;
export interface SignalDeclarationV1Input { signal_id: string; version: string; determinism: 'deterministic' | 'probabilistic'; locality: 'local' | 'remote'; timeout_ms: number; cache_ttl_ms: number; failure_disposition: 'deny' | 'defer' | 'ignore'; }
export interface SignalObservationV1Input { signal_id: string; version: string; input_hash: string; status: 'matched' | 'not_matched' | 'error' | 'timeout'; labels: string[]; score_bps?: number; provenance_hash: string; evaluated_at_ms: number; latency_ms: number; cache_state: 'hit' | 'miss' | 'not_cacheable'; }

export class SignalInterfaceV1ValidationError extends Error { constructor(message: string) { super(message); this.name = 'SignalInterfaceV1ValidationError'; } }
function fail(message: string): never { throw new SignalInterfaceV1ValidationError(message); }
function text(value: unknown, field: string): string { if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value.trim(), 'utf8') > 256) fail(`${field} must be nonblank and at most 256 UTF-8 bytes`); return value.trim(); }
function hash(value: unknown, field: string): string { if (typeof value !== 'string' || !HASH_RE.test(value)) fail(`${field} must be a lowercase SHA-256 hash`); return value; }
function integer(value: unknown, field: string, max = Number.MAX_SAFE_INTEGER): number { if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > max) fail(`${field} must be a nonnegative safe integer no greater than ${max}`); return value; }

export function buildSignalDeclarationV1(input: SignalDeclarationV1Input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('declaration must be an object'); const raw = input as unknown as Record<string, unknown>;
  const unknown = Object.keys(raw).filter((key) => !['schema', 'signal_id', 'version', 'determinism', 'locality', 'timeout_ms', 'cache_ttl_ms', 'failure_disposition'].includes(key)).sort(compareCodePoints); if (unknown.length) fail(`declaration contains unsupported field: ${unknown[0]}`);
  if (raw.schema !== undefined && raw.schema !== SIGNAL_DECLARATION_V1_SCHEMA) fail('declaration schema is invalid');
  if (!['deterministic', 'probabilistic'].includes(String(raw.determinism)) || !['local', 'remote'].includes(String(raw.locality)) || !['deny', 'defer', 'ignore'].includes(String(raw.failure_disposition))) fail('declaration enum is invalid');
  const timeout = integer(raw.timeout_ms, 'timeout_ms', 300_000); if (timeout === 0) fail('timeout_ms must be greater than zero');
  return { schema: SIGNAL_DECLARATION_V1_SCHEMA, signal_id: text(raw.signal_id, 'signal_id'), version: text(raw.version, 'version'), determinism: raw.determinism as SignalDeclarationV1Input['determinism'], locality: raw.locality as SignalDeclarationV1Input['locality'], timeout_ms: timeout, cache_ttl_ms: integer(raw.cache_ttl_ms, 'cache_ttl_ms', 86_400_000), failure_disposition: raw.failure_disposition as SignalDeclarationV1Input['failure_disposition'], authoritative_allow: false as const };
}

export function buildSignalObservationV1(input: SignalObservationV1Input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('observation must be an object'); const raw = input as unknown as Record<string, unknown>;
  const unknown = Object.keys(raw).filter((key) => !['schema', 'signal_id', 'version', 'input_hash', 'status', 'labels', 'score_bps', 'provenance_hash', 'evaluated_at_ms', 'latency_ms', 'cache_state'].includes(key)).sort(compareCodePoints); if (unknown.length) fail(`observation contains unsupported field: ${unknown[0]}`);
  if (raw.schema !== undefined && raw.schema !== SIGNAL_OBSERVATION_V1_SCHEMA) fail('observation schema is invalid');
  if (!['matched', 'not_matched', 'error', 'timeout'].includes(String(raw.status)) || !['hit', 'miss', 'not_cacheable'].includes(String(raw.cache_state))) fail('observation enum is invalid');
  if (!Array.isArray(raw.labels) || raw.labels.length > 128) fail('labels must contain at most 128 items'); const labels = [...new Set(raw.labels.map((item, i) => text(item, `labels[${i}]`)))].sort(compareCodePoints);
  const result: Record<string, unknown> = { schema: SIGNAL_OBSERVATION_V1_SCHEMA, signal_id: text(raw.signal_id, 'signal_id'), version: text(raw.version, 'version'), input_hash: hash(raw.input_hash, 'input_hash'), status: raw.status, labels, provenance_hash: hash(raw.provenance_hash, 'provenance_hash'), evaluated_at_ms: integer(raw.evaluated_at_ms, 'evaluated_at_ms'), latency_ms: integer(raw.latency_ms, 'latency_ms'), cache_state: raw.cache_state };
  if (raw.score_bps !== undefined) result.score_bps = integer(raw.score_bps, 'score_bps', 10_000); return result;
}

export function resolveSignalV1(declarationInput: SignalDeclarationV1Input, observationInput: SignalObservationV1Input) {
  const declaration = buildSignalDeclarationV1(declarationInput); const observation = buildSignalObservationV1(observationInput);
  if (declaration.signal_id !== observation.signal_id || declaration.version !== observation.version) fail('observation does not match declaration');
  const failure = observation.status === 'error' || observation.status === 'timeout';
  const requiredOutcome = failure && declaration.failure_disposition !== 'ignore' ? declaration.failure_disposition.toUpperCase() : null;
  const body = { schema: SIGNAL_RESOLUTION_V1_SCHEMA, declaration, observation, fact: { matched: observation.status === 'matched', labels: observation.labels, ...(observation.score_bps !== undefined ? { score_bps: observation.score_bps } : {}) }, required_outcome: requiredOutcome, authoritative_allow: false as const };
  return { ...body, resolution_hash: createHash('sha256').update(`obsvr-signal-resolution/1\0${canonicalJsonForHash(body)}`, 'utf8').digest('hex') };
}

export function signalResolutionToOtelAttributesV1(resolution: ReturnType<typeof resolveSignalV1>) { return { 'obsvr.signal.schema': resolution.schema, 'obsvr.signal.id': resolution.declaration.signal_id, 'obsvr.signal.version': resolution.declaration.version, 'obsvr.signal.determinism': resolution.declaration.determinism, 'obsvr.signal.locality': resolution.declaration.locality, 'obsvr.signal.status': resolution.observation.status, 'obsvr.signal.provenance_hash': resolution.observation.provenance_hash, 'obsvr.signal.resolution_hash': resolution.resolution_hash, 'obsvr.signal.latency_ms': resolution.observation.latency_ms, 'obsvr.signal.authoritative_allow': false }; }
export function signalResolutionToOpaInputV1(resolution: ReturnType<typeof resolveSignalV1>) { return { obsvr_signal: { id: resolution.declaration.signal_id, version: resolution.declaration.version, matched: resolution.fact.matched, labels: resolution.fact.labels, score_bps: resolution.fact.score_bps ?? null, provenance_hash: resolution.observation.provenance_hash, required_outcome: resolution.required_outcome, authoritative_allow: false, resolution_hash: resolution.resolution_hash } }; }
export function signalResolutionToCedarContextV1(resolution: ReturnType<typeof resolveSignalV1>) { return { obsvrSignalId: resolution.declaration.signal_id, obsvrSignalVersion: resolution.declaration.version, obsvrSignalMatched: resolution.fact.matched, obsvrSignalLabels: resolution.fact.labels, obsvrSignalScoreBps: resolution.fact.score_bps ?? 0, obsvrSignalProvenanceHash: resolution.observation.provenance_hash, obsvrSignalRequiredOutcome: resolution.required_outcome ?? '', obsvrSignalAuthoritativeAllow: false, obsvrSignalResolutionHash: resolution.resolution_hash }; }
