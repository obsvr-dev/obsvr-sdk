/**
 * Span primitive (DASHBOARD_TELEMETRY.md, Milestone 3): a generic node in the
 * execution graph. This is a FOUNDATIONAL data model, not a UI feature.
 *
 * Design decisions (see new_changes/DASHBOARD_TELEMETRY_M3.md):
 *  - Generic over feature-specific. A span carries a typed identity
 *    (span_id, parent_span_id, kind, name) plus an OPEN `attributes` bag.
 *    Kind-specific data (tool name, retrieval count, memory op) goes in
 *    attributes under semantic-convention keys, so new node kinds never
 *    require a schema change.
 *  - Deterministic. Parent links come from an explicit, developer-declared
 *    async context (`withSpan`), never inferred by a heuristic. No LLM, no
 *    guessing, on the telemetry path.
 *  - Additive transport. The span envelope rides the event metadata under a
 *    reserved key (`obsvr_span`), exactly like M1 telemetry, so the signed
 *    raw/canonical schema and its conformance fixtures are untouched.
 *
 * @packageDocumentation
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { AuditEvent } from "./types.js";
import { getConfig, isInitialized } from "./config.js";
import { sendAuditAsync, shouldSample } from "./sender/index.js";
import { withRunMetadata } from "./agent-run.js";
import { derivePolicyVersion } from "../policy/rules.js";

/**
 * Node kind. The listed values are the known execution-graph node types; the
 * union stays open (`string & {}`) so a future kind is a value, not a schema
 * change.
 */
export type SpanKind =
  | "llm_call"
  | "tool"
  | "retrieval"
  | "memory"
  | "agent"
  | "chain"
  | "guardrail"
  | "policy_eval"
  | "approval"
  | (string & {});

/** The active span, tracked per async context. */
export interface SpanContext {
  span_id: string;
  trace_id?: string;
  kind: SpanKind;
  name: string;
}

/** What gets stamped onto an event so it becomes a graph node. */
export interface SpanEnvelope {
  span_id: string;
  parent_span_id?: string;
  span_kind: SpanKind;
  span_name: string;
  /** Open, kind-specific attributes (semantic-convention keyed). Collected
   * and stored; only selected keys are ever shown. */
  attributes?: Record<string, string | number | boolean>;
}

const storage = new AsyncLocalStorage<SpanContext>();

export function generateSpanId(): string {
  return randomUUID();
}

/** The enclosing span for the current async context, if any. */
export function currentSpan(): SpanContext | undefined {
  return storage.getStore();
}

export function currentSpanId(): string | undefined {
  return storage.getStore()?.span_id;
}

/**
 * Run `fn` inside a new span context. Any governed call made within `fn`
 * (directly or in awaited descendants) links to this span as its parent.
 * Deterministic: the parent is this explicit scope, never inferred.
 *
 * Trace grouping: the scope carries a `trace_id` so every span emitted within
 * it (and every governed call the caller tags with the same id) groups into one
 * trace. Precedence: an explicit `opts.trace_id` wins, else the enclosing
 * scope's trace_id is inherited, else this root scope establishes the trace and
 * its own span_id becomes the trace_id. Pass `opts.trace_id` set to your run /
 * conversation id to align child spans with the governed calls in that run.
 *
 * @example
 *   await obsvr.withSpan("plan_step", "agent", async () => {
 *     await openai.chat.completions.create(...); // parent_span_id = plan_step
 *   }, { trace_id: runId });
 */
export function withSpan<T>(
  name: string,
  kind: SpanKind,
  fn: () => T,
  opts?: { trace_id?: string },
): T {
  const parent = storage.getStore();
  const span_id = generateSpanId();
  const ctx: SpanContext = {
    span_id,
    trace_id: opts?.trace_id ?? parent?.trace_id ?? span_id,
    kind,
    name,
  };
  return storage.run(ctx, fn);
}

/**
 * Build the span envelope for an event about to be emitted, using the
 * enclosing `withSpan` scope (if any) as the deterministic parent.
 */
export function spanEnvelopeFor(
  kind: SpanKind,
  name: string,
  attributes?: Record<string, string | number | boolean>,
): SpanEnvelope {
  const parent = storage.getStore();
  const env: SpanEnvelope = {
    span_id: generateSpanId(),
    span_kind: kind,
    span_name: name,
  };
  if (parent?.span_id) env.parent_span_id = parent.span_id;
  if (attributes && Object.keys(attributes).length > 0) env.attributes = attributes;
  return env;
}

const RESERVED_SPAN_KEY = "obsvr_span";

/**
 * Merge a span envelope into an event's metadata under the reserved key.
 * Never overwrites caller-provided metadata keys.
 */
export function withSpanMetadata(
  metadata: Record<string, unknown> | undefined,
  envelope: SpanEnvelope,
): Record<string, unknown> | undefined {
  return { ...(metadata ?? {}), [RESERVED_SPAN_KEY]: envelope };
}

/**
 * Emit a standalone execution span as a SIGNED audit event (M3B). The span is
 * evidence: it flows through the same signing / chain / delivery pipeline as
 * every other event, tagged event_class = "execution_span" so the UI shows it
 * in traces rather than the main governance feed. Never throws; respects the
 * disabled flag and sampling. No-op if the SDK is not initialized.
 *
 * Exported (as the options-object `emitSpan` below) for framework
 * integrations whose callback APIs surface start/end pairs rather than a
 * wrappable function — e.g. LangChain retriever callbacks. Integrations must
 * use THIS path so their spans are signed and classed identically to
 * `obsvr.span()` output; emitting execution spans any other way is a
 * parallel-implementation bug.
 */
function emitSpanEvent(
  spanId: string,
  parentId: string | undefined,
  traceId: string | undefined,
  kind: SpanKind,
  name: string,
  ok: boolean,
  attributes: Record<string, string | number | boolean>,
): void {
  let config;
  try {
    if (!isInitialized()) return;
    config = getConfig();
  } catch {
    return;
  }
  if (config.disabled) return;
  if (!shouldSample(config.sample_rate)) return;

  const envelope: SpanEnvelope & { event_class: string } = {
    span_id: spanId,
    span_kind: kind,
    span_name: name,
    event_class: "execution_span",
    attributes,
  };
  if (parentId) envelope.parent_span_id = parentId;

  // Trace grouping: stamp the scope's trace_id into metadata so ingest links
  // this execution span to its run/trace (the timeline and agent-run analytics
  // group on trace_id / agent_run_id). Without it, spans are orphaned nodes.
  const spanMeta: Record<string, unknown> = { [RESERVED_SPAN_KEY]: envelope };
  if (traceId) spanMeta.trace_id = traceId;
  // Ambient agent-run stamping: a span emitted inside an agentRun(...) scope must
  // carry agent_run_id so it joins the run — parity with proxy calls, integration
  // events, and the Python builder (which stamps in build_audit_event). Without
  // this, TS spans were orphaned from runs while identical Python spans grouped.
  // agent-run.ts is a pure leaf, so this import cannot create a cycle.
  const metadata = withRunMetadata(spanMeta) ?? spanMeta;

  const event: AuditEvent = {
    request_id: spanId,
    environment: config.environment,
    region: config.default_region || "unknown",
    provider: "unknown",
    model: "unknown",
    operation: name,
    source: "span",
    prompt: "",
    response: "",
    success: ok,
    status_code: ok ? 200 : 500,
    event_type: "span",
    event_class: "execution_span",
    policy_version: derivePolicyVersion(config.policyRules ?? []),
    action_taken: "allowed",
    action_reason: "none",
    action_source: "unknown",
    redacted_types: [],
    metadata,
  };
  sendAuditAsync(config, event);
}

/**
 * Low-level exported span emitter for start/end-style integration callbacks.
 * Same signed pipeline, same precedence rules as `span()`:
 * trace_id = explicit > enclosing scope > self-root (own span_id).
 */
export function emitSpan(opts: {
  kind: SpanKind;
  name: string;
  ok: boolean;
  span_id?: string;
  parent_span_id?: string;
  trace_id?: string;
  attributes?: Record<string, string | number | boolean>;
}): void {
  const spanId = opts.span_id ?? generateSpanId();
  const traceId = opts.trace_id ?? currentSpan()?.trace_id ?? spanId;
  emitSpanEvent(
    spanId,
    opts.parent_span_id ?? currentSpanId(),
    traceId,
    opts.kind,
    opts.name,
    opts.ok,
    opts.attributes ?? {},
  );
}

/**
 * Run a function as a recorded execution span. Opens a `withSpan` scope (so
 * governed calls and child spans inside it link as children), times it, and
 * emits a signed execution-span event on completion. Works with sync and async
 * functions. Kind-specific detail goes in `attributes` (semantic-convention
 * keyed), never as new fields.
 *
 * @example
 *   const docs = await obsvr.span("vector_search", "retrieval",
 *     () => retriever.search(q), { attributes: { "gen_ai.retrieval.document_count": 5 } });
 */
export function span<T>(
  name: string,
  kind: SpanKind,
  fn: () => T,
  opts?: { attributes?: Record<string, string | number | boolean>; trace_id?: string },
): T {
  const parent = currentSpan();
  const parentId = parent?.span_id;
  const id = generateSpanId();
  // Same trace precedence as withSpan: explicit id, else inherited scope, else
  // this span roots its own single-node trace.
  const traceId = opts?.trace_id ?? parent?.trace_id ?? id;
  const start = Date.now();
  const ctx: SpanContext = { span_id: id, trace_id: traceId, kind, name };
  const finish = (ok: boolean): void => {
    emitSpanEvent(id, parentId, traceId, kind, name, ok, {
      ...(opts?.attributes ?? {}),
      duration_ms: Date.now() - start,
    });
  };
  return storage.run(ctx, () => {
    let result: T;
    try {
      result = fn();
    } catch (e) {
      finish(false);
      throw e;
    }
    if (result && typeof (result as { then?: unknown }).then === "function") {
      return (result as unknown as Promise<unknown>).then(
        (v) => {
          finish(true);
          return v;
        },
        (e) => {
          finish(false);
          throw e;
        },
      ) as unknown as T;
    }
    finish(true);
    return result;
  });
}
