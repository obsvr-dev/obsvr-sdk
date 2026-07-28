/**
 * CloudEvents v1.0 export.
 *
 * An `AuditEvent` is obsvr's own shape and every consumer of it needs an
 * adapter. CloudEvents is the CNCF interchange envelope those consumers
 * already speak, so one serializer removes an adapter from every sink an
 * operator might want to fan events out to — the same argument the OTel span
 * mirror makes for the trace bus, applied to the event bus.
 *
 * This is a pure, additive projection. It runs when an operator asks for it,
 * never on the call path, and it never mutates the event: the envelope carries
 * the audit event verbatim as `data`, so nothing downstream of a CloudEvents
 * sink is working from a lossy copy.
 *
 * ## The mapping, and why each field is what it is
 *
 * | CloudEvents | obsvr |
 * |---|---|
 * | `specversion` | fixed `"1.0"` |
 * | `id` | `seq_no`, else `request_id` — see below |
 * | `source` | `urn:obsvr:session:<sdk_session_id>` |
 * | `type` | `dev.obsvr.audit.<event_type>` |
 * | `subject` | `operation`, when non-empty |
 * | `time` | `timestamp_sdk` as RFC 3339 UTC, when usable |
 * | `datacontenttype` | fixed `"application/json"` |
 * | `dataschema` | fixed `urn:obsvr:schema:audit-event:1` |
 * | `data` | the audit event, unmodified |
 *
 * The spec makes `(source, id)` the deduplication key, and obsvr already has a
 * pair that means exactly that: the chain coordinate `(sdk_session_id,
 * seq_no)`. Mapping one onto the other means a sink that dedupes CloudEvents
 * dedupes on the same identity the ledger does, instead of on a second,
 * differently-shaped notion of "same event". An event carrying no `seq_no`
 * never entered the signed chain, so there is no chain coordinate to use;
 * those fall back to `request_id`, and the uniqueness guarantee is then only
 * as strong as that field. Stating that is better than papering over it with a
 * generated id that would make every re-export look like a new event.
 *
 * `dataschema` is a URN rather than an https URL on purpose: a URL is a promise
 * that something is served there, and nothing is.
 *
 * Two extension attributes are emitted so a sink can route without opening the
 * payload — the actual reason context attributes exist. Extension names are
 * lower-case alphanumerics per the spec, which is why they read as one word.
 *
 * ## Byte-identical across SDKs
 *
 * {@link serializeCloudEvent} produces the canonical string form through the
 * same canonicalizer the tool hashes use, so the two languages emit the same
 * bytes for the same event and the fixture can pin a string rather than a
 * shape. That canonicalizer REFUSES values the two runtimes cannot render
 * identically (integers past 2^53, exponent-notation extremes, non-finite),
 * and so does this: a "byte-identical" claim that quietly is not would be
 * worse than an error. Callers that would rather drop the export than fail
 * should use {@link safeSerializeCloudEvent}.
 *
 * @packageDocumentation
 */

import type { AuditEvent } from "./types.js";
import { canonicalJsonForHash } from "../policy/tool-pinning.js";

/** CloudEvents spec version this serializer emits. */
export const CLOUDEVENTS_SPEC_VERSION = "1.0";

/** Reverse-DNS prefix for the `type` attribute, per the spec's SHOULD. */
export const CLOUDEVENTS_TYPE_PREFIX = "dev.obsvr.audit";

/** Identifies the shape carried in `data`. A URN, because nothing is served. */
export const CLOUDEVENTS_DATA_SCHEMA = "urn:obsvr:schema:audit-event:1";

/** `source` for an event whose SDK session is unknown. */
const UNKNOWN_SESSION_SOURCE = "urn:obsvr:session:unknown";

/** A CloudEvents v1.0 envelope in the JSON event format. */
export interface CloudEvent {
  specversion: typeof CLOUDEVENTS_SPEC_VERSION;
  id: string;
  source: string;
  type: string;
  datacontenttype: string;
  dataschema: string;
  subject?: string;
  time?: string;
  /** Routing extension: the decision this event records. */
  obsvraction?: string;
  /** Routing extension: the deployment environment. */
  obsvrenv?: string;
  data: AuditEvent;
}

/**
 * Milliseconds-since-epoch rendered as RFC 3339 UTC with exactly three
 * fractional digits.
 *
 * Written out rather than delegating to `Date.prototype.toISOString` so the
 * Python twin has something to match that is not "whatever that runtime does":
 * `toISOString` switches to an expanded ±YYYYYY year form outside 0000-9999,
 * and the two languages would then disagree at exactly the inputs nobody
 * tests. Returns undefined for anything the format cannot represent, and the
 * caller omits `time` — an absent optional attribute is honest, a wrong
 * timestamp is not.
 */
export function rfc3339FromEpochMs(ms: unknown): string | undefined {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return undefined;
  const whole = Math.trunc(ms);
  // The range Date represents exactly; beyond it the value is not a time.
  if (Math.abs(whole) > 8.64e15) return undefined;
  const d = new Date(whole);
  if (Number.isNaN(d.getTime())) return undefined;
  const year = d.getUTCFullYear();
  if (year < 0 || year > 9999) return undefined; // no expanded-year form
  const p = (n: number, width = 2): string => String(n).padStart(width, "0");
  return (
    `${p(year, 4)}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}` +
    `T${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}` +
    `.${p(d.getUTCMilliseconds(), 3)}Z`
  );
}

/**
 * Project an audit event onto a CloudEvents v1.0 envelope. Pure: no clock, no
 * I/O, no per-process state, so the same event always yields the same envelope.
 * The event is carried by reference as `data` and is never modified.
 */
export function toCloudEvent(event: AuditEvent): CloudEvent {
  const session = typeof event.sdk_session_id === "string" && event.sdk_session_id.length > 0
    ? event.sdk_session_id
    : undefined;
  const id =
    typeof event.seq_no === "number" && Number.isFinite(event.seq_no)
      ? String(event.seq_no)
      : String(event.request_id ?? "");
  const time = rfc3339FromEpochMs(event.timestamp_sdk);
  const subject = typeof event.operation === "string" && event.operation.length > 0
    ? event.operation
    : undefined;

  return {
    specversion: CLOUDEVENTS_SPEC_VERSION,
    id,
    source: session === undefined ? UNKNOWN_SESSION_SOURCE : `urn:obsvr:session:${session}`,
    type: `${CLOUDEVENTS_TYPE_PREFIX}.${event.event_type}`,
    datacontenttype: "application/json",
    dataschema: CLOUDEVENTS_DATA_SCHEMA,
    ...(subject !== undefined ? { subject } : {}),
    ...(time !== undefined ? { time } : {}),
    ...(event.action_taken !== undefined ? { obsvraction: event.action_taken } : {}),
    ...(event.environment !== undefined ? { obsvrenv: event.environment } : {}),
    data: event,
  };
}

/**
 * The canonical JSON string form of the envelope: sorted keys, no
 * insignificant whitespace, cross-SDK-stable numbers. THIS is the byte
 * contract both languages reproduce, pinned by
 * conformance/fixtures/cloudevents.json.
 *
 * THROWS on event content neither runtime can render identically.
 */
export function serializeCloudEvent(event: AuditEvent): string {
  return canonicalJsonForHash(toCloudEvent(event) as unknown as Record<string, unknown>);
}

/**
 * {@link serializeCloudEvent}, or `undefined` when the event carries content
 * the two runtimes cannot render identically. For a fan-out loop that should
 * skip one event rather than abandon the batch.
 */
export function safeSerializeCloudEvent(event: AuditEvent): string | undefined {
  try {
    return serializeCloudEvent(event);
  } catch {
    return undefined;
  }
}
