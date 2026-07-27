/**
 * Sender Module
 *
 * @packageDocumentation
 */

export {
  enqueueAuditEvent,
  sendAuditAsync,
  getQueueSize,
  getDroppedCount,
  getPendingGapCount,
  getSenderStats,
  flushQueue,
  setupExitHandlers,
  _resetSender,
} from "./fire-and-forget.js";

export { shouldSample } from "./sampling.js";
