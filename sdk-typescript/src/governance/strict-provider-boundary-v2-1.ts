import { randomUUID } from 'node:crypto';
import { actionTargetHash } from './action-context-v2.js';
import {
  bindStrictV21JsonArguments,
  assertStrictReceiptRuntimeV21,
  runTrustedStrictReceiptRuntimeV21,
  type StrictReceiptRuntimeV21,
  type StrictRuntimeV21Result,
} from './strict-receipt-runtime-v2-1.js';
import { readBaseUrl } from '../proxy/provider-attribution.js';
import { assertBackendUrlStatic } from '../utils/ssrf.js';

export interface StrictProviderCallV21 {
  provider: string;
  operation: string;
  model?: string;
  target: string;
  data_classifications: string[];
}

export interface StrictProviderContextV21 {
  active_intents: string[];
  requested_scopes: string[];
  run_id: string;
  thread_id?: string;
}

export interface StrictProviderBoundaryV21Options {
  runtime: StrictReceiptRuntimeV21;
  context: (call: Readonly<StrictProviderCallV21>) => StrictProviderContextV21;
}

export interface StrictProviderBoundaryV21Capability {
  readonly profile_version: '2.1';
}

type Binding = Readonly<StrictProviderBoundaryV21Options>;
const capabilities = new WeakMap<object, Binding>();

export type StrictProviderBoundaryV21Code =
  | 'unsupported_surface'
  | 'context_unavailable'
  | 'runtime_unavailable'
  | 'not_authorized'
  | 'admission_not_confirmed';

export class ObsvrStrictProviderBoundaryV21Error extends Error {
  constructor(
    public readonly code: StrictProviderBoundaryV21Code,
    public readonly receipt_hash?: string,
  ) {
    super(`obsvr strict provider boundary: ${code}${receipt_hash ? ` (${receipt_hash})` : ''}`);
    this.name = 'ObsvrStrictProviderBoundaryV21Error';
  }
}

export function createStrictProviderBoundaryV21(
  options: StrictProviderBoundaryV21Options,
): StrictProviderBoundaryV21Capability {
  try {
    assertStrictReceiptRuntimeV21(options?.runtime);
  } catch {
    throw new ObsvrStrictProviderBoundaryV21Error('runtime_unavailable');
  }
  if (typeof options.context !== 'function') {
    throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  }
  const capability = Object.freeze({ profile_version: '2.1' as const });
  capabilities.set(capability, Object.freeze({ ...options }));
  return capability;
}

export function assertStrictProviderBoundaryV21(
  value: unknown,
): asserts value is StrictProviderBoundaryV21Capability {
  if (!value || typeof value !== 'object' || !capabilities.has(value)) {
    throw new ObsvrStrictProviderBoundaryV21Error('runtime_unavailable');
  }
}

export function strictProviderSurfaceUnsupportedV21(): never {
  throw new ObsvrStrictProviderBoundaryV21Error('unsupported_surface');
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1']);
const TRUSTED_PROVIDER_HOSTS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.groq.com',
]);

function normalizedHostname(value: string): string {
  return value.replace(/^\[|\]$/g, '').toLowerCase();
}

function readStrictProviderBaseUrl(client: unknown): string | undefined {
  const direct = readBaseUrl(client);
  if (direct) return direct;
  try {
    const root = client as {
      apiClient?: {
        customBaseUrl?: unknown;
        clientOptions?: { httpOptions?: { baseUrl?: unknown } };
      };
    };
    const custom = root.apiClient?.customBaseUrl;
    if (typeof custom === 'string' && custom) return custom;
    const configured = root.apiClient?.clientOptions?.httpOptions?.baseUrl;
    return typeof configured === 'string' && configured ? configured : undefined;
  } catch {
    return undefined;
  }
}

export function strictProviderTargetV21(client: unknown): string {
  const baseUrl = readStrictProviderBaseUrl(client);
  if (!baseUrl) throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  const rawPath = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/i.exec(baseUrl)?.[1] ?? '/';
  if (rawPath.split('/').some((segment) => {
    try {
      const decoded = decodeURIComponent(segment);
      return decoded === '.' || decoded === '..';
    } catch {
      return true;
    }
  })) throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  let url: URL;
  try {
    const candidate = new URL(baseUrl);
    const loopback = LOOPBACK.has(normalizedHostname(candidate.hostname));
    url = assertBackendUrlStatic(baseUrl, { allowPrivateNetwork: loopback });
  }
  catch { throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable'); }
  const hostname = normalizedHostname(url.hostname);
  if (!LOOPBACK.has(hostname) && !TRUSTED_PROVIDER_HOSTS.has(hostname)) {
    throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  }
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(hostname))) {
    throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  }
  const path = url.pathname === '/' ? '/' : (url.pathname.replace(/\/+$/, '') || '/');
  return `${url.protocol}//${url.host}${path}`;
}

export async function executeStrictProviderCallV21<R>(
  capability: StrictProviderBoundaryV21Capability,
  call: StrictProviderCallV21,
  invocation: unknown[],
  invoke: (invocation: unknown[]) => Promise<R> | R,
): Promise<R> {
  assertStrictProviderBoundaryV21(capability);
  const binding = capabilities.get(capability as object) as Binding;
  const trustedCall = Object.freeze(structuredClone(call));
  let context: StrictProviderContextV21;
  try {
    context = structuredClone(binding.context(trustedCall));
  } catch {
    throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  }
  const actionId = randomUUID();
  let original;
  try {
    original = bindStrictV21JsonArguments(invocation);
  } catch {
    throw new ObsvrStrictProviderBoundaryV21Error('context_unavailable');
  }
  let result: StrictRuntimeV21Result<R>;
  try {
    result = await runTrustedStrictReceiptRuntimeV21(binding.runtime, {
      decision: {
        action_id: actionId,
        active_intents: context.active_intents,
        current_action: {
          kind: 'model_call',
          name: call.operation,
          arguments_hash: original.arguments_hash,
          target_hash: actionTargetHash(call.target),
          data_classifications: call.data_classifications,
          requested_scopes: [...new Set([
            ...(Array.isArray(context.requested_scopes) ? context.requested_scopes : []),
            'model:invoke',
          ])].sort(),
        },
        run_id: context.run_id,
        ...(context.thread_id === undefined ? {} : { thread_id: context.thread_id }),
      },
      action: {
        runtime_action_id: actionId,
        original_arguments: original,
        invoke,
      },
    });
  } catch {
    throw new ObsvrStrictProviderBoundaryV21Error('runtime_unavailable');
  }
  if (result.status === 'executed') return result.value;
  if (result.status === 'invocation_failed') throw result.error;
  if (result.status === 'nonexecuted' && result.reason === 'not_authorized') {
    throw new ObsvrStrictProviderBoundaryV21Error('not_authorized', result.receipt_hash);
  }
  throw new ObsvrStrictProviderBoundaryV21Error(
    'admission_not_confirmed', result.receipt_hash,
  );
}
