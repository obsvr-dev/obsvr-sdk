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
