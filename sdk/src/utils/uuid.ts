/**
 * UUID generation for audit request ids.
 *
 * Lives in utils rather than beside a feature module because four hot-path
 * modules need it - the wrapper, the integrations core, the policy-change log,
 * and the healthcare industry rules - and none of them should have to import
 * from a module whose other exports they must never reach.
 *
 * @packageDocumentation
 */

import { randomUUID } from "node:crypto";

/**
 * Generate a UUID v4 via node:crypto — works on all supported Node versions
 * (the global Web Crypto `crypto` is not present on every Node 18 build).
 */
export function generateUUID(): string {
  return randomUUID();
}
