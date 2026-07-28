/**
 * Optional OpenTelemetry mirror.
 *
 * When enabled and @opentelemetry/api is installed (it is a peer, never a
 * hard dependency), every audit event is mirrored as an OTel span so teams
 * keep their existing tracing backend (Grafana, Datadog, Jaeger, ...) while
 * obsvr remains the signed compliance layer. Spans are created retroactively
 * from the event's own timing, attributed with GenAI semantic-convention
 * fields plus obsvr governance outcomes.
 *
 * If the API package is missing, this module logs once and stays inert -
 * consistent with the SDK's no-monkey-patching, plays-well-with-others rule.
 */

import { createRequire } from "node:module";
import type { AuditEvent, ResolvedConfig } from "./types.js";
import { debugLog } from "../utils/logger.js";

interface OtelApi {
  trace: {
    getTracer(name: string, version?: string): {
      startSpan(
        name: string,
        options?: { startTime?: number; attributes?: Record<string, unknown>; kind?: number },
      ): {
        setStatus(status: { code: number; message?: string }): void;
        end(endTime?: number): void;
      };
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
    // createRequire(import.meta.url). import.meta is reached via indirect
    // eval so CJS transforms (jest) can still compile this module.
    const req =
      typeof require !== "undefined"
        ? require
        : createRequire((0, eval)("import.meta.url") as string);
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
        "gen_ai.request.model": event.model ?? "unknown",
        "gen_ai.usage.input_tokens": event.input_tokens ?? 0,
        "gen_ai.usage.output_tokens": event.output_tokens ?? 0,
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

/** @internal test hook */
export function _resetOtelMirror(): void {
  otelApi = undefined;
  warned = false;
}

/** @internal test hook: inject a fake OTel API (attribute-parity tests). */
export function _setOtelApi(api: OtelApi | null): void {
  otelApi = api;
}
