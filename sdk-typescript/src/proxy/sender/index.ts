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
  getDeliveryStatus,
  configureDurableDelivery,
  flushQueue,
  setupExitHandlers,
  _resetSender,
} from "./fire-and-forget.js";

export { shouldSample, shouldEmitAllowedEvent } from "./sampling.js";
