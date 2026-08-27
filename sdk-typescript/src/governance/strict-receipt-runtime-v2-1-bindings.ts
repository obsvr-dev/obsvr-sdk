import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import type {
  StrictV21BoundArguments,
  StrictV21RuntimeAction,
} from './strict-receipt-runtime-v2-1-types.js';

const boundArguments = new WeakSet<object>();

function clone<T>(value: T): T { return structuredClone(value); }
export function deepFreezeStrictV21<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    Object.values(value as Record<string, unknown>).forEach(deepFreezeStrictV21);
    Object.freeze(value);
  }
  return value;
}

export function bindStrictV21JsonArguments<T>(value: T): StrictV21BoundArguments<T> {
  const snapshot = deepFreezeStrictV21(clone(value));
  const hash = createHash('sha256').update(canonicalJsonForHash(snapshot)).digest('hex');
  const result = Object.freeze({ arguments_hash: hash, value: snapshot });
  boundArguments.add(result);
  return result;
}

export function readStrictV21ExecutionArguments<A, R>(
  action: StrictV21RuntimeAction<A, R>,
  receipt: StrictReceiptV21Envelope,
): { ok: true; value: A } | { ok: false } {
  const modified = receipt.body.outcome === 'MODIFY';
  const bound = modified ? action.effective_arguments : action.original_arguments;
  const expected = modified
    ? receipt.body.action.effective_arguments_hash : receipt.body.action.arguments_hash;
  if (!bound || !boundArguments.has(bound) || bound.arguments_hash !== expected) return { ok: false };
  return { ok: true, value: bound.value };
}
