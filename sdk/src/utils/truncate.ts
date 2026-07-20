/**
 * Payload Truncation Utility
 *
 * Truncates large payloads to prevent excessive data transmission.
 *
 * @packageDocumentation
 */

const TRUNCATION_MARKER = " [TRUNCATED]";

/**
 * Truncate a string to the specified maximum length
 *
 * @param value - The string to truncate
 * @param maxChars - Maximum allowed characters
 * @returns The truncated string with marker if truncated
 */
export function truncateString(value: string, maxChars: number): string {
  if (value.length <= maxChars) {
    return value;
  }

  // Reserve space for the truncation marker
  const truncateAt = maxChars - TRUNCATION_MARKER.length;
  if (truncateAt <= 0) {
    return TRUNCATION_MARKER.trim();
  }

  return value.slice(0, truncateAt) + TRUNCATION_MARKER;
}

/**
 * Safely convert any value to a string for truncation
 */
export function safeStringify(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  if (value === null || value === undefined) {
    return "";
  }

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Truncate a value, handling both strings and objects
 */
export function truncate(value: unknown, maxChars: number): string {
  const str = safeStringify(value);
  return truncateString(str, maxChars);
}
