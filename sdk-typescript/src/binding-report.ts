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

/** Test seam. */
export function _resetBindings(): void {
  bindings.clear();
}
