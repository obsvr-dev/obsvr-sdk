import { randomUUID } from 'node:crypto';
import { actionTargetHash } from './action-context-v2.js';
import { deepFreezeStrictV21 } from './strict-receipt-runtime-v2-1-bindings.js';
import {
  assertStrictReceiptRuntimeV21,
  bindStrictV21JsonArguments,
  runTrustedStrictReceiptRuntimeV21,
  type StrictReceiptRuntimeV21,
  type StrictRuntimeV21Result,
} from './strict-receipt-runtime-v2-1.js';
import type {
  StrictRuntimeFailureClassificationV21,
} from './strict-receipt-runtime-v2-1-outcomes.js';

export interface StrictActionV21 {
  kind: string;
  name: string;
  target: string;
  data_classifications: string[];
  requested_scopes: string[];
}

export interface StrictActionContextV21 {
  active_intents: string[];
  run_id: string;
  thread_id?: string;
}

export interface StrictActionBoundaryV21Options {
  runtime: StrictReceiptRuntimeV21;
  context: (action: Readonly<StrictActionV21>) => StrictActionContextV21;
}

export interface StrictActionExecutionV21<R> {
  result_projection?: (value: R) => unknown;
  classify_error?: (error: unknown) => StrictRuntimeFailureClassificationV21;
}

export interface StrictActionBoundaryV21Capability {
  readonly profile_version: '2.1';
}

export type StrictActionBoundaryV21Code =
  | 'context_unavailable'
  | 'runtime_unavailable'
  | 'not_authorized'
  | 'admission_not_confirmed';

export class ObsvrStrictActionBoundaryV21Error extends Error {
  constructor(
    public readonly code: StrictActionBoundaryV21Code,
    public readonly receipt_hash?: string,
  ) {
    super(`obsvr strict action boundary: ${code}${receipt_hash ? ` (${receipt_hash})` : ''}`);
    this.name = 'ObsvrStrictActionBoundaryV21Error';
  }
}

type Binding = Readonly<StrictActionBoundaryV21Options>;
const capabilities = new WeakMap<object, Binding>();

export function createStrictActionBoundaryV21(
  options: StrictActionBoundaryV21Options,
): StrictActionBoundaryV21Capability {
  try {
    assertStrictReceiptRuntimeV21(options?.runtime);
  } catch {
    throw new ObsvrStrictActionBoundaryV21Error('runtime_unavailable');
  }
  if (typeof options.context !== 'function') {
    throw new ObsvrStrictActionBoundaryV21Error('context_unavailable');
  }
  const capability = Object.freeze({ profile_version: '2.1' as const });
  capabilities.set(capability, Object.freeze({ ...options }));
  return capability;
}

export function assertStrictActionBoundaryV21(
  value: unknown,
): asserts value is StrictActionBoundaryV21Capability {
  if (!value || typeof value !== 'object' || !capabilities.has(value)) {
    throw new ObsvrStrictActionBoundaryV21Error('runtime_unavailable');
  }
}

export async function executeStrictActionV21<A, R>(
  capability: StrictActionBoundaryV21Capability,
  action: StrictActionV21,
  invocation: A,
  invoke: (invocation: A) => Promise<R> | R,
  execution: StrictActionExecutionV21<R> = {},
): Promise<R> {
  assertStrictActionBoundaryV21(capability);
  const binding = capabilities.get(capability as object) as Binding;
  let trustedAction: StrictActionV21;
  let context: StrictActionContextV21;
  let original;
  let targetHash: string;
  try {
    trustedAction = deepFreezeStrictV21(structuredClone(action));
    context = structuredClone(binding.context(structuredClone(trustedAction)));
    original = bindStrictV21JsonArguments(invocation);
    targetHash = actionTargetHash(trustedAction.target);
  } catch {
    throw new ObsvrStrictActionBoundaryV21Error('context_unavailable');
  }
  if (typeof invoke !== 'function') {
    throw new ObsvrStrictActionBoundaryV21Error('context_unavailable');
  }
  const actionId = randomUUID();
  let result: StrictRuntimeV21Result<R>;
  try {
    result = await runTrustedStrictReceiptRuntimeV21(binding.runtime, {
      decision: {
        action_id: actionId,
        active_intents: context.active_intents,
        current_action: {
          kind: trustedAction.kind,
          name: trustedAction.name,
          arguments_hash: original.arguments_hash,
          target_hash: targetHash,
          data_classifications: trustedAction.data_classifications,
          requested_scopes: trustedAction.requested_scopes,
        },
        run_id: context.run_id,
        ...(context.thread_id === undefined ? {} : { thread_id: context.thread_id }),
      },
      action: {
        runtime_action_id: actionId,
        original_arguments: original,
        invoke,
        ...(execution.result_projection
          ? { result_projection: execution.result_projection }
          : {}),
        ...(execution.classify_error ? { classify_error: execution.classify_error } : {}),
      },
    });
  } catch {
    throw new ObsvrStrictActionBoundaryV21Error('runtime_unavailable');
  }
  if (result.status === 'executed') return result.value;
  if (result.status === 'invocation_failed') throw result.error;
  if (result.status === 'nonexecuted' && result.reason === 'not_authorized') {
    throw new ObsvrStrictActionBoundaryV21Error('not_authorized', result.receipt_hash);
  }
  throw new ObsvrStrictActionBoundaryV21Error(
    'admission_not_confirmed', result.receipt_hash,
  );
}
