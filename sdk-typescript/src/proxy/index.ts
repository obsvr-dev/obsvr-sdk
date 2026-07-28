/**
 * Proxy Module
 *
 * Transparent proxy wrapper for automatic LLM audit tracking.
 *
 * @packageDocumentation
 */

// Main exports
export { init, getConfig, isInitialized, _reset } from "./config.js";
export { wrap } from "./wrapper.js";

// Types
export type {
  LLMAuditInitConfig,
  WrapOptions,
  ResolvedConfig,
  AuditEvent,
  AuditFields,
} from "./types.js";

// Utilities for advanced usage
export { shouldSample, flushQueue, getQueueSize, getDroppedCount } from "./sender/index.js";
export { filterArgs, hasAuditFields, getAuditFieldNames } from "./filters/index.js";
