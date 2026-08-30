import { recordBinding } from '../binding-report.js';
import {
  obsvrGovernTool,
  type GovernToolOptions,
} from '../integrations/tools.js';

const GOVERNED_FUNCTION_MARKER = Symbol.for('obsvr.governedFunction');
const MAX_ACTION_NAME_BYTES = 256;

type AnyFunction = (...args: never[]) => unknown;

export type GovernedFunction<F extends AnyFunction> = (
  ...args: Parameters<F>
) => Promise<Awaited<ReturnType<F>>>;

export interface GovernFnOptions extends GovernToolOptions {
  /** Stable action identifier used by policy, evidence, and coverage reports. */
  name?: string;
  /** Application boundary represented by the callable. */
  surface?: 'action' | 'workflow';
  /** Operator-defined consequence class, for example `external_write`. */
  consequence?: string;
  /** Human-readable descriptor sealed with the governed tool descriptor. */
  description?: string;
}

function boundedText(value: unknown, field: string, required = false): string | undefined {
  if (value === undefined && !required) return undefined;
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${field} must be a nonblank string`);
  }
  const normalized = value.trim();
  if (Buffer.byteLength(normalized, 'utf8') > MAX_ACTION_NAME_BYTES) {
    throw new TypeError(`${field} exceeds ${MAX_ACTION_NAME_BYTES} UTF-8 bytes`);
  }
  return normalized;
}

/**
 * Govern any application callable at its invocation boundary.
 *
 * The returned function is always async because it reuses the complete
 * pre-call tool pipeline, including approval waits and external policy. A deny
 * rejects before `fn` is entered. A redact verdict rewrites the arguments the
 * function receives, or fails closed when the rewrite cannot be proven.
 *
 * Keeping another reference to `fn` is a bypass. The coverage binding records
 * that exclusion rather than presenting this wrapper as process-wide control.
 */
export function governFn<F extends AnyFunction>(
  fn: F,
  options: GovernFnOptions = {},
): GovernedFunction<F> {
  if (typeof fn !== 'function') throw new TypeError('fn must be callable');
  const marked = fn as F & { [GOVERNED_FUNCTION_MARKER]?: boolean };
  if (marked[GOVERNED_FUNCTION_MARKER] === true) {
    return fn as unknown as GovernedFunction<F>;
  }

  const name = boundedText(options.name ?? fn.name, 'name', true) as string;
  const surface = options.surface ?? 'action';
  if (surface !== 'action' && surface !== 'workflow') {
    throw new TypeError('surface must be action or workflow');
  }
  const consequence = boundedText(options.consequence, 'consequence');
  const description = boundedText(options.description, 'description');
  const actionMetadata = Object.freeze({
    surface,
    name,
    ...(consequence === undefined ? {} : { consequence }),
  });

  const governed = obsvrGovernTool({
    name,
    ...(description === undefined ? {} : { description }),
    execute: async (payload: { args: Parameters<F> }) => fn(...payload.args),
  }, {
    source: options.source ?? 'obsvr_govern_fn',
    region: options.region,
    service_name: options.service_name,
    user_id: options.user_id,
    metadata: {
      ...(options.metadata ?? {}),
      obsvr_action: actionMetadata,
    },
    name,
  });

  const wrapped = (async (...args: Parameters<F>) => governed.execute({ args })) as GovernedFunction<F> & {
    [GOVERNED_FUNCTION_MARKER]?: boolean;
  };
  Object.defineProperty(wrapped, GOVERNED_FUNCTION_MARKER, {
    value: true,
    enumerable: false,
    configurable: false,
  });
  Object.defineProperty(wrapped, 'name', {
    value: fn.name || name,
    configurable: true,
  });

  recordBinding('govern_fn', name, undefined, {
    enforcementDepth: 'enforce',
    initializedAtMs: Date.now(),
    exclusions: ['calls through retained raw function aliases'],
  });
  return wrapped;
}
