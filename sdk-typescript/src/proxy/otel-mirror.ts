/**
 * Optional OpenTelemetry mirror.
 *
 * When enabled and @opentelemetry/api is installed (it is a peer, never a
 * hard dependency), every audit event is mirrored as an OTel span so teams
 * keep whatever tracing backend they already run while obsvr remains the
 * signed compliance layer. Spans are created retroactively
 * from the event's own timing, attributed with GenAI semantic-convention
 * fields plus obsvr governance outcomes.
 *
 * If the API package is missing, this module logs once and stays inert -
 * consistent with the SDK's no-monkey-patching, plays-well-with-others rule.
 */

import { createRequire } from "node:module";
import type { StrictRuntimeExecutionJournalV21, StrictV21CheckpointStore } from "../governance/strict-receipt-runtime-v2-1-types.js";
import type { AuditEvent, ResolvedConfig } from "./types.js";
import { debugLog } from "../utils/logger.js";

interface OtelSpan {
  setStatus(status: { code: number; message?: string }): void;
  setAttributes?(attributes: Record<string, string | number | boolean>): unknown;
  isRecording?(): boolean;
  end(endTime?: number): void;
}

interface OtelApi {
  trace: {
    getActiveSpan?(): OtelSpan | undefined;
    getTracer(name: string, version?: string): {
      startSpan(
        name: string,
        options?: { startTime?: number; attributes?: Record<string, unknown>; kind?: number },
      ): OtelSpan;
    };
  };
  SpanStatusCode: { OK: number; ERROR: number };
  SpanKind?: { CLIENT: number };
}

let otelApi: OtelApi | null | undefined; // undefined = not yet resolved, null = unavailable
let warned = false;

function resolveOtel(config: ResolvedConfig): OtelApi | null {
  if (otelApi !== undefined) return otelApi;
  try {
    // Dual-mode resolution: CJS gives us require directly; ESM needs
    // createRequire(import.meta.url).
    //
    // `import.meta.url` is read DIRECTLY. It used to be reached through
    // `(0, eval)("import.meta.url")`, which was meant to survive a CJS
    // transform — but indirect eval runs its argument as a SCRIPT in global
    // scope, where `import.meta` is a SyntaxError. In any pure-ESM consumer
    // (`"type": "module"`, which is the modern default and what this package
    // itself ships as) that threw on the first mirrored event, the catch below
    // set otelApi = null, and OTel mirroring was silently disabled for the
    // life of the process. Nothing surfaced it: the unit tests inject the API
    // through _setOtelApi and never exercise this resolution at all, so the
    // path was dead in production while the suite stayed green.
    //
    // Reading it directly is safe here because this package emits ESM
    // (tsconfig module: NodeNext) and the test runner is ESM too
    // (ts-jest/presets/default-esm, extensionsToTreatAsEsm).
    const req =
      typeof require !== "undefined" ? require : createRequire(import.meta.url);
    otelApi = req("@opentelemetry/api") as OtelApi;
  } catch {
    otelApi = null;
    if (!warned) {
      warned = true;
      debugLog(
        config,
        "warn",
        "otel.enabled is set but @opentelemetry/api is not installed - OTel mirroring disabled",
      );
    }
  }
  return otelApi;
}

/**
 * The GenAI usage attributes, present only when the count is actually known.
 *
 * An OTel attribute that is absent means "not recorded"; an attribute set to 0
 * means "recorded, and it was zero". Those are different claims, and a
 * governance span must not make the second one on evidence for the first.
 */
function tokenAttributes(event: AuditEvent): Record<string, number> {
  const attrs: Record<string, number> = {};
  if (typeof event.input_tokens === "number" && Number.isFinite(event.input_tokens)) {
    attrs["gen_ai.usage.input_tokens"] = event.input_tokens;
  }
  if (typeof event.output_tokens === "number" && Number.isFinite(event.output_tokens)) {
    attrs["gen_ai.usage.output_tokens"] = event.output_tokens;
  }
  return attrs;
}

/**
 * Mirror one audit event as a retroactive OTel span. Fire-and-forget:
 * failures never affect the audit path.
 */
export function mirrorToOtel(config: ResolvedConfig, event: AuditEvent): void {
  if (!config.otel?.enabled) return;
  const api = resolveOtel(config);
  if (!api) return;
  try {
    const tracer = api.trace.getTracer(config.otel.tracerName ?? "obsvr-sdk");
    const endTime = event.timestamp_sdk ?? Date.now();
    const startTime = endTime - Math.max(0, event.latency_ms ?? 0);
    const span = tracer.startSpan(`obsvr.${event.operation ?? "llm_call"}`, {
      startTime,
      kind: api.SpanKind?.CLIENT,
      attributes: {
        "gen_ai.system": event.provider ?? "unknown",
        // Current GenAI semantic conventions use provider.name. Keep system
        // during the compatibility window for existing dashboards.
        "gen_ai.provider.name": event.provider ?? "unknown",
        "gen_ai.request.model": event.model ?? "unknown",
        // The two token attributes are OMITTED when the count is unknown, and
        // that is the whole point: a span reporting 0 for a measurement that
        // never happened is the same false record the extractors were changed
        // to stop producing, in a different sink. An absent attribute is how
        // the GenAI semantic conventions say "not recorded"; a zero is a claim.
        //
        // This makes the key set conditional, which is a change to a contract
        // pinned in both languages — conformance/fixtures/otel_attributes.json
        // now states which keys are unconditional and which two depend on the
        // counts being known, and both SDKs' parity tests assert BOTH shapes.
        ...tokenAttributes(event),
        "obsvr.event_type": event.event_type ?? "llm_call",
        "obsvr.action_taken": event.action_taken ?? "allowed",
        "obsvr.action_reason": event.action_reason ?? "none",
        "obsvr.rule_id": event.rule_id ?? "",
        "obsvr.pii_detected": event.action_reason === "pii_detected",
        "obsvr.seq_no": event.seq_no ?? 0,
        "obsvr.sdk_session_id": event.sdk_session_id ?? "",
        "obsvr.environment": event.environment ?? "",
      },
    });
    if (event.success === false || event.action_taken === "blocked") {
      span.setStatus({
        code: api.SpanStatusCode.ERROR,
        message: event.action_taken === "blocked" ? "blocked_by_policy" : (event.error_type ?? "error"),
      });
    } else {
      span.setStatus({ code: api.SpanStatusCode.OK });
    }
    span.end(endTime);
  } catch (e) {
    debugLog(config, "warn", "OTel mirror failed (non-fatal):", e instanceof Error ? e.message : String(e));
  }
}

function strictCheckpointAttributes(
  checkpoint: StrictRuntimeExecutionJournalV21,
): Record<string, string | number | boolean> | undefined {
  if (checkpoint.phase !== "committed" && checkpoint.phase !== "terminal") return undefined;
  const receipt = checkpoint.receipt;
  if (checkpoint.receipt_hash !== receipt.receipt_hash
    || checkpoint.tenant_id !== receipt.body.tenant_id
    || checkpoint.session_id !== receipt.body.session_id) return undefined;
  const policy = receipt.body.evaluation.effective_policy;
  const attributes: Record<string, string | number | boolean> = {
    "obsvr.strict.profile_version": receipt.body.profile_version,
    "obsvr.strict.receipt_hash": receipt.receipt_hash,
    "obsvr.strict.receipt_sequence": receipt.body.sequence,
    "obsvr.strict.record_type": receipt.body.record_type,
    "obsvr.strict.execution_authorized": receipt.body.execution_authorized,
    "obsvr.strict.decision_outcome": receipt.body.outcome,
    "obsvr.strict.policy_version": policy.version,
    "obsvr.strict.policy_artifact_hash": policy.artifact_hash,
    "obsvr.strict.evaluator_manifest_hash": receipt.body.evaluation.evaluator_manifest_hash,
    "obsvr.strict.journal_phase": checkpoint.phase,
  };
  const supported = Object.values(attributes).every((value) => (
    typeof value === "boolean"
    || (typeof value === "string" && value.length > 0)
    || (typeof value === "number" && Number.isSafeInteger(value))
  ));
  if (!supported) return undefined;
  if (checkpoint.terminal_status) {
    attributes["obsvr.strict.terminal_status"] = checkpoint.terminal_status;
  }
  const outcome = checkpoint.execution_outcome;
  if (outcome && /^[0-9a-f]{64}$/.test(outcome.outcome_hash)
    && ["succeeded", "failed", "uncertain"].includes(outcome.body.status)
    && outcome.body.decision_receipt_hash === receipt.receipt_hash
    && outcome.body.decision_sequence === receipt.body.sequence) {
    attributes["obsvr.strict.execution_outcome_hash"] = outcome.outcome_hash;
    attributes["obsvr.strict.execution_status"] = outcome.body.status;
  }
  return attributes;
}

/** Attach durable strict evidence references to the currently recording span. */
export function correlateStrictRuntimeCheckpointV21ToOtel(
  checkpoint: StrictRuntimeExecutionJournalV21,
): boolean {
  try {
    const attributes = strictCheckpointAttributes(checkpoint);
    if (!attributes) return false;
    const span = resolveOtel({ debug: false } as ResolvedConfig)?.trace.getActiveSpan?.();
    if (!span || span.isRecording?.() === false || typeof span.setAttributes !== "function") {
      return false;
    }
    span.setAttributes(attributes);
    return true;
  } catch {
    return false;
  }
}

/**
 * Decorate a durable checkpoint store with best-effort active-span correlation.
 * The underlying save completes first; telemetry failure never changes runtime behavior.
 */
export function withStrictOtelCorrelationV21(
  checkpointStore: StrictV21CheckpointStore,
): StrictV21CheckpointStore {
  if (!checkpointStore || typeof checkpointStore.save !== "function") {
    throw new TypeError("durable checkpoint store is required");
  }
  const save = checkpointStore.save.bind(checkpointStore);
  return Object.freeze({
    save: async (checkpoint: StrictRuntimeExecutionJournalV21): Promise<void> => {
      await save(checkpoint);
      correlateStrictRuntimeCheckpointV21ToOtel(checkpoint);
    },
  });
}

/** @internal test hook */
export function _resetOtelMirror(): void {
  otelApi = undefined;
  warned = false;
}

/** @internal test hook: inject a fake OTel API (attribute-parity tests). */
export function _setOtelApi(api: OtelApi | null): void {
  otelApi = api;
}
