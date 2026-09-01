import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import { postPinnedBytes, type PinnedHttpResponse } from '../utils/pinned-http.js';
import {
  assertBackendUrlStatic,
  resolveBackendUrlAllowed,
  type AllowedBackendTarget,
  type Resolver,
} from '../utils/ssrf.js';
import {
  verifyCoverageAttestation,
  type CoverageAttestationEnvelope,
} from './coverage-attestation.js';
import {
  verifyWorkloadRegistrationV1,
} from './workload-registry-v1.js';

const MAX_REQUEST_BYTES = 1_048_576;
const MAX_RESPONSE_BYTES = 65_536;
const MAX_TIMEOUT_MS = 60_000;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const TRUST = new Set(['pinned', 'self_presented']);

export type WorkloadRegistrationV1Envelope = ReturnType<
  typeof import('./workload-registry-v1.js').signWorkloadRegistrationV1
>;

export interface DeploymentProofPublishOptions {
  ingest_url: string;
  api_key: string;
  signer: DeviceSigner;
  timeout_ms?: number;
  max_response_bytes?: number;
  /** Explicit test seam. Production uses a DNS-pinned fresh socket. */
  trusted_fetch?: typeof fetch;
  /** Explicit test seam that still receives the approved DNS snapshot. */
  trusted_pinned_transport?: DeploymentProofPinnedTransport;
  resolver?: Resolver;
}

export type DeploymentProofPinnedTransport = (
  target: AllowedBackendTarget,
  body: string,
  headers: Readonly<Record<string, string>>,
  signal: AbortSignal,
  maxResponseBytes: number,
) => Promise<PinnedHttpResponse>;

export type DeploymentProofPublishResult =
  | {
      disposition: 'accepted';
      kind: 'coverage' | 'workload';
      body_hash: string;
      trust: 'pinned' | 'self_presented';
    }
  | {
      disposition: 'rejected';
      kind: 'coverage' | 'workload';
      body_hash: string;
      http_status: number;
      error: string;
    }
  | {
      disposition: 'uncertain';
      kind: 'coverage' | 'workload';
      body_hash: string;
      reason: 'redirect' | 'transport_error' | 'invalid_response';
    };

export interface DeploymentProofPublishSequence {
  coverage: DeploymentProofPublishResult;
  workload?: DeploymentProofPublishResult | {
    disposition: 'not_attempted';
    kind: 'workload';
    body_hash: string;
    reason: 'coverage_not_accepted';
  };
}

export class DeploymentProofPublishError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DeploymentProofPublishError';
  }
}

function positiveInteger(value: number | undefined, fallback: number, maximum: number, field: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0 || resolved > maximum) {
    throw new DeploymentProofPublishError(`${field} is outside its supported positive range`);
  }
  return resolved;
}

function nonblank(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new DeploymentProofPublishError(`${field} must be a nonblank string`);
  }
  return value;
}

function endpoint(value: string, path: string): { url: string; allowLoopback: boolean } {
  const raw = nonblank(value, 'ingest_url');
  let host = '';
  try { host = new URL(raw).hostname.replace(/^\[|\]$/g, '').toLowerCase(); } catch { /* guarded below */ }
  const allowLoopback = LOCAL_HOSTS.has(host);
  let parsed: URL;
  try {
    parsed = assertBackendUrlStatic(raw, { allowPrivateNetwork: allowLoopback });
  } catch {
    throw new DeploymentProofPublishError('ingest_url failed static security validation');
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new DeploymentProofPublishError(
      'ingest_url must be an absolute HTTP(S) URL without credentials, query, or fragment',
    );
  }
  if (parsed.protocol === 'http:' && !allowLoopback) {
    throw new DeploymentProofPublishError('ingest_url must use HTTPS unless it targets loopback');
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/, '')}${path}`;
  return { url: parsed.toString(), allowLoopback };
}

function parsedObject(bytes: Uint8Array | undefined): Record<string, unknown> | undefined {
  if (bytes === undefined || bytes.byteLength === 0) return undefined;
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    return value !== null && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown>
      : undefined;
  } catch {
    return undefined;
  }
}

function withinAbortBudget<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error('deployment proof timeout budget exhausted'));
  return new Promise<T>((resolve, reject) => {
    const aborted = () => reject(new Error('deployment proof timeout budget exhausted'));
    signal.addEventListener('abort', aborted, { once: true });
    operation.then(
      (value) => { signal.removeEventListener('abort', aborted); resolve(value); },
      (error: unknown) => { signal.removeEventListener('abort', aborted); reject(error); },
    );
  });
}

async function readBounded(response: Response, limit: number): Promise<Uint8Array | undefined> {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^[0-9]+$/.test(declared) || Number(declared) > limit)) return undefined;
  const bytes = new Uint8Array(await response.arrayBuffer());
  return bytes.byteLength <= limit ? bytes : undefined;
}

function accepted(
  kind: 'coverage' | 'workload',
  response: Record<string, unknown> | undefined,
  envelope: CoverageAttestationEnvelope | WorkloadRegistrationV1Envelope,
): DeploymentProofPublishResult | undefined {
  if (response?.ok !== true || response.body_hash !== envelope.body_hash
    || typeof response.trust !== 'string' || !TRUST.has(response.trust)) return undefined;
  if (kind === 'coverage' && typeof response.coverage_complete !== 'boolean') return undefined;
  if (kind === 'workload'
    && (response.workload_id !== envelope.body.workload_id
      || response.deployment_id !== (envelope as WorkloadRegistrationV1Envelope).body.deployment_id)) {
    return undefined;
  }
  return {
    disposition: 'accepted', kind, body_hash: envelope.body_hash,
    trust: response.trust as 'pinned' | 'self_presented',
  };
}

async function publish(
  kind: 'coverage' | 'workload',
  path: string,
  envelope: CoverageAttestationEnvelope | WorkloadRegistrationV1Envelope,
  options: DeploymentProofPublishOptions,
): Promise<DeploymentProofPublishResult> {
  const location = endpoint(options.ingest_url, path);
  const apiKey = nonblank(options.api_key, 'api_key');
  const timeoutMs = positiveInteger(options.timeout_ms, 5_000, MAX_TIMEOUT_MS, 'timeout_ms');
  const maxResponseBytes = positiveInteger(
    options.max_response_bytes, MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES, 'max_response_bytes',
  );
  if (options.trusted_fetch !== undefined && typeof options.trusted_fetch !== 'function') {
    throw new DeploymentProofPublishError('trusted_fetch must be a function');
  }
  if (options.trusted_pinned_transport !== undefined
    && typeof options.trusted_pinned_transport !== 'function') {
    throw new DeploymentProofPublishError('trusted_pinned_transport must be a function');
  }
  let body: string;
  try { body = canonicalJsonForHash(envelope); } catch {
    throw new DeploymentProofPublishError(`${kind} envelope cannot be serialized canonically`);
  }
  if (Buffer.byteLength(body, 'utf8') > MAX_REQUEST_BYTES) {
    throw new DeploymentProofPublishError(`${kind} envelope exceeds the supported request size`);
  }
  const headers = {
    'Content-Type': 'application/json',
    'X-API-Key': apiKey,
    'X-Obsvr-Device-Public-Key': options.signer.publicKeyB64,
    'Idempotency-Key': envelope.body_hash,
  };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: PinnedHttpResponse;
  try {
    if (options.trusted_fetch !== undefined) {
      const fetched = await options.trusted_fetch(location.url, {
        method: 'POST', redirect: 'manual', headers, body, signal: controller.signal,
      });
      response = { status: fetched.status, body: await readBounded(fetched, maxResponseBytes) };
    } else {
      const target = await withinAbortBudget(resolveBackendUrlAllowed(
        location.url, { allowPrivateNetwork: location.allowLoopback }, options.resolver,
      ), controller.signal);
      const transport = options.trusted_pinned_transport ?? postPinnedBytes;
      response = await transport(target, body, headers, controller.signal, maxResponseBytes);
    }
  } catch {
    return { disposition: 'uncertain', kind, body_hash: envelope.body_hash, reason: 'transport_error' };
  } finally {
    clearTimeout(timer);
  }
  if (response.status >= 300 && response.status < 400) {
    return { disposition: 'uncertain', kind, body_hash: envelope.body_hash, reason: 'redirect' };
  }
  const parsed = parsedObject(response.body);
  if (response.status >= 200 && response.status < 300) {
    return accepted(kind, parsed, envelope) ?? {
      disposition: 'uncertain', kind, body_hash: envelope.body_hash, reason: 'invalid_response',
    };
  }
  if (parsed?.ok === false && typeof parsed.error === 'string' && parsed.error !== '') {
    return {
      disposition: 'rejected', kind, body_hash: envelope.body_hash,
      http_status: response.status, error: parsed.error,
    };
  }
  return { disposition: 'uncertain', kind, body_hash: envelope.body_hash, reason: 'invalid_response' };
}

export async function publishCoverageAttestation(
  envelope: CoverageAttestationEnvelope,
  options: DeploymentProofPublishOptions,
): Promise<DeploymentProofPublishResult> {
  const verification = verifyCoverageAttestation(envelope, options.signer.rawPublicKey);
  if (!verification.valid) {
    throw new DeploymentProofPublishError(`coverage envelope is invalid: ${verification.reason}`);
  }
  return publish('coverage', '/coverage/attestations', envelope, options);
}

export async function publishWorkloadRegistration(
  envelope: WorkloadRegistrationV1Envelope,
  options: DeploymentProofPublishOptions,
): Promise<DeploymentProofPublishResult> {
  if (!verifyWorkloadRegistrationV1(envelope, options.signer.rawPublicKey)) {
    throw new DeploymentProofPublishError('workload envelope is invalid');
  }
  return publish('workload', '/workloads/registrations', envelope, options);
}

/** Publish coverage first; a workload is never sent without accepted exact coverage. */
export async function publishDeploymentProofs(
  coverage: CoverageAttestationEnvelope,
  workload: WorkloadRegistrationV1Envelope | undefined,
  options: DeploymentProofPublishOptions,
): Promise<DeploymentProofPublishSequence> {
  if (workload !== undefined
    && (workload.body.coverage_attestation_hash !== coverage.body_hash
      || workload.body.workload_id !== coverage.body.workload_id
      || workload.body.environment !== coverage.body.environment
      || workload.key_id !== coverage.key_id)) {
    throw new DeploymentProofPublishError(
      'workload registration must bind the same coverage hash, workload, environment, and signer',
    );
  }
  const coverageResult = await publishCoverageAttestation(coverage, options);
  if (workload === undefined) return { coverage: coverageResult };
  if (coverageResult.disposition !== 'accepted') {
    return {
      coverage: coverageResult,
      workload: {
        disposition: 'not_attempted', kind: 'workload', body_hash: workload.body_hash,
        reason: 'coverage_not_accepted',
      },
    };
  }
  return {
    coverage: coverageResult,
    workload: await publishWorkloadRegistration(workload, options),
  };
}
