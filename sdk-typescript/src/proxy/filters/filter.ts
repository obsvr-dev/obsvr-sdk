/**
 * Field Filtering
 *
 * Extracts audit-specific fields from request arguments and returns
 * cleaned arguments suitable for the LLM provider.
 *
 * Strategy: Only maintain AUDIT_FIELDS - everything else passes through to the LLM.
 * This is future-proof as OpenAI/Anthropic add new parameters.
 *
 * @packageDocumentation
 */

import type { AuditFields, FilterResult } from "../types.js";

/**
 * Fields that are extracted for audit purposes and stripped before
 * sending to the LLM provider.
 *
 * These match the audit backend schema.
 */
const AUDIT_FIELDS = new Set<string>([
  "request_id", // Unique identifier for this request
  "region", // Deployment region
  "source", // Source application identifier
  "metadata", // User-defined metadata (user_id, session_id, etc.)
  // The four below are declared on the exported `AuditFields` type as
  // "customer-provided" and are read onto the event by the wrapper — but they
  // were absent from THIS set, which is the only thing that extracts them. So
  // they were wrong in two directions at once: a caller who typed their args
  // against the public type had the values forwarded VERBATIM to the provider
  // (which rejects an unknown parameter, so the documented shape broke the
  // call), while `auditFields.user_id` and friends were always undefined and
  // the record they were meant to populate carried nothing. The Python twin's
  // `_collect_metadata` states the reasoning this set was missing: the kwarg is
  // "stripped before the request reaches the provider (the provider SDK would
  // reject an unknown parameter)".
  "user_id", // Identity the event is attributed to
  "client_ip", // Network field; see the note on AuditFields
  "user_agent", // Network field
  "service_name", // Emitting service, overrides default_service_name
]);

/**
 * Check if a value is a plain object (not array, null, or other type)
 */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/**
 * Filter a single argument object, extracting audit fields
 */
function filterObject(
  obj: Record<string, unknown>
): { cleaned: Record<string, unknown>; audit: AuditFields } {
  const cleaned: Record<string, unknown> = {};
  const audit: AuditFields = {};

  for (const [key, value] of Object.entries(obj)) {
    if (AUDIT_FIELDS.has(key)) {
      // Extract audit field
      switch (key) {
        case "request_id":
          if (typeof value === "string") {
            audit.request_id = value;
          }
          break;
        case "region":
          if (typeof value === "string") {
            audit.region = value;
          }
          break;
        case "source":
          if (typeof value === "string") {
            audit.source = value;
          }
          break;
        case "metadata":
          if (isPlainObject(value)) {
            audit.metadata = value as Record<string, unknown>;
          }
          break;
        case "user_id":
          // The signed principal: coerce scalars to the one canonical string
          // both offline verifiers recompute identically (String(1.0) === "1",
          // String(true) === "true" — the same strings the Python boundary
          // mints via its ECMAScript-rendering rules). Non-scalars and
          // non-finite numbers are treated as absent rather than sealed as a
          // rendering no other consumer can recompute; user_id is inside the
          // format-3 decision digest, so what is stored here is what is signed.
          if (typeof value === "string") {
            audit.user_id = value;
          } else if (
            typeof value === "boolean" ||
            (typeof value === "number" && Number.isFinite(value))
          ) {
            audit.user_id = String(value);
          }
          break;
        case "client_ip":
          if (typeof value === "string") {
            audit.client_ip = value;
          }
          break;
        case "user_agent":
          if (typeof value === "string") {
            audit.user_agent = value;
          }
          break;
        case "service_name":
          if (typeof value === "string") {
            audit.service_name = value;
          }
          break;
      }
    } else {
      // Pass through to LLM
      cleaned[key] = value;
    }
  }

  return { cleaned, audit };
}

/**
 * Filter request arguments, extracting audit fields from the first object argument
 *
 * Most LLM SDK methods take a single options object as the first argument.
 * This function extracts audit fields from that object.
 *
 * @param args - Arguments passed to the LLM method
 * @returns FilterResult with cleaned args and extracted audit fields
 */
export function filterArgs(args: unknown[]): FilterResult {
  if (args.length === 0) {
    return {
      cleaned_args: [],
      audit_fields: {},
    };
  }

  const firstArg = args[0];

  // Only filter if the first argument is a plain object
  if (!isPlainObject(firstArg)) {
    return {
      cleaned_args: args,
      audit_fields: {},
    };
  }

  const { cleaned, audit } = filterObject(firstArg);

  // Return cleaned args with the filtered first argument
  return {
    cleaned_args: [cleaned, ...args.slice(1)],
    audit_fields: audit,
  };
}

/**
 * Check if any audit fields are present in an object
 */
export function hasAuditFields(obj: unknown): boolean {
  if (!isPlainObject(obj)) {
    return false;
  }

  for (const key of Object.keys(obj)) {
    if (AUDIT_FIELDS.has(key)) {
      return true;
    }
  }

  return false;
}

/**
 * Get the set of audit field names (for testing/documentation)
 */
export function getAuditFieldNames(): string[] {
  return Array.from(AUDIT_FIELDS);
}
