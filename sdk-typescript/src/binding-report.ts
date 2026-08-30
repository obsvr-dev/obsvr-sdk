/**
 * Why an optional integration failed to bind, instead of only that it did.
 *
 * Integrations that resolve an optional upstream package do so behind a
 * guard and fall back (or skip) so the SDK never hard-depends on a framework
 * the caller has not installed. That part is deliberate. What the guard must
 * not do is discard the failure, because three completely different
 * situations then look identical from the caller's side:
 *
 *   - the package is not installed at all (normal; nothing to fix),
 *   - the package is installed but a symbol was RENAMED upstream (an obsvr
 *     defect; the integration is silently inert while the manifest
 *     advertises support),
 *   - the package is installed and resolvable but broken (upstream's
 *     problem; the manifest should say so).
 *
 * Only the middle one is obsvr's to fix, and a bare boolean cannot tell them
 * apart. The report is a plain object of primitive values - no dependency,
 * no new transport, nothing emitted anywhere. It is read on demand through
 * `integrationBindings()` / `unboundSymbols()` on the package surface.
 *
 * Twin: sdk-python/obsvr/binding_report.py (`obsvr.integration_bindings()`).
 */

export interface BindingEntry {
  bound: boolean;
  errorType?: string;
  error?: string;
}

export interface UnboundSymbol {
  integration: string;
  symbol: string;
  errorType?: string;
  error?: string;
}

export interface RequiredBindingFailure extends UnboundSymbol {
  reason: "missing" | "unbound";
}

/** Raised when a deployment-declared integration is not completely bound. */
export class RequiredBindingsError extends Error {
  readonly failures: RequiredBindingFailure[];

  constructor(failures: RequiredBindingFailure[]) {
    const summary = failures
      .map((failure) =>
        failure.reason === "missing"
          ? `${failure.integration} was never bound`
          : `${failure.integration}:${failure.symbol} is unbound`,
      )
      .join(", ");
    super(`Required obsvr bindings are not active: ${summary}`);
    this.name = "RequiredBindingsError";
    this.failures = failures.map((failure) => ({ ...failure }));
  }
}

const bindings = new Map<string, Map<string, BindingEntry>>();

/**
 * Record that `symbol` bound for `integration`, or why it did not.
 *
 * Never throws: a diagnostic that can break an integration's resolve path is
 * worse than no diagnostic. The message is truncated because a resolution
 * error can carry a full search-path listing and this is a summary, not a
 * log.
 */
export function recordBinding(
  integration: string,
  symbol: string,
  error?: unknown,
): void {
  try {
    const entry: BindingEntry = { bound: error === undefined };
    if (error !== undefined) {
      // Each field is captured separately: an error whose message getter
      // throws must still be RECORDED as a failure. Losing the whole entry
      // because the message could not be rendered would put us back where
      // this started, with a bind that failed and left no trace.
      try {
        entry.errorType =
          error instanceof Error ? error.constructor.name : typeof error;
      } catch {
        entry.errorType = "Unknown";
      }
      try {
        entry.error = String(
          error instanceof Error ? error.message : error,
        ).slice(0, 300);
      } catch {
        entry.error = "<error message could not be rendered>";
      }
    }
    let symbols = bindings.get(integration);
    if (!symbols) {
      symbols = new Map();
      bindings.set(integration, symbols);
    }
    symbols.set(symbol, entry);
  } catch {
    // Deliberately swallowed - see the docblock.
  }
}

/**
 * Every recorded bind, keyed by integration then symbol.
 *
 * Only integrations whose resolve path has actually run appear - module-load
 * binds record at import, call-time binds (an install function probing its
 * framework) record when that call runs. An integration nobody touched has
 * nothing to report, and saying otherwise would be a guess.
 */
export function integrationBindings(): Record<
  string,
  Record<string, BindingEntry>
> {
  const out: Record<string, Record<string, BindingEntry>> = {};
  for (const [integration, symbols] of bindings) {
    out[integration] = {};
    for (const [symbol, entry] of symbols) {
      out[integration][symbol] = { ...entry };
    }
  }
  return out;
}

/**
 * The failures only, flattened - the list worth looking at when an
 * integration is registered and quietly doing nothing.
 */
export function unboundSymbols(): UnboundSymbol[] {
  const out: UnboundSymbol[] = [];
  for (const [integration, symbols] of bindings) {
    for (const [symbol, entry] of symbols) {
      if (!entry.bound) {
        out.push({
          integration,
          symbol,
          errorType: entry.errorType,
          error: entry.error,
        });
      }
    }
  }
  return out;
}

/**
 * Resolve deployment requirements against binding paths that have actually run.
 *
 * A missing integration is different from an integration whose upstream symbol
 * failed to resolve, but both are fatal when the caller declared that integration
 * required. Call this after the application's client/tool factory has installed
 * its integrations; startup auto-instrumentation uses the same primitive.
 */
export function requiredBindingFailures(
  required: readonly string[],
): RequiredBindingFailure[] {
  const failures: RequiredBindingFailure[] = [];
  for (const integration of new Set(required)) {
    if (typeof integration !== "string" || integration.trim() === "") {
      throw new TypeError("required bindings must be non-empty integration names");
    }
    const name = integration.trim();
    const symbols = bindings.get(name);
    if (!symbols || symbols.size === 0) {
      failures.push({ integration: name, symbol: "", reason: "missing" });
      continue;
    }
    for (const [symbol, entry] of symbols) {
      if (!entry.bound) {
        failures.push({
          integration: name,
          symbol,
          reason: "unbound",
          errorType: entry.errorType,
          error: entry.error,
        });
      }
    }
  }
  return failures;
}

/** Refuse startup when any deployment-declared integration is not fully bound. */
export function assertRequiredBindings(required: readonly string[]): void {
  const failures = requiredBindingFailures(required);
  if (failures.length > 0) throw new RequiredBindingsError(failures);
}

/** Test seam. */
export function _resetBindings(): void {
  bindings.clear();
}
