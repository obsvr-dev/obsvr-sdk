/**
 * Industry policy modules barrel export.
 * @packageDocumentation
 */

// FinTech
export {
  evaluateActionGate,
  resolveThresholdField,
  compareThreshold,
  getCurrentHour,
  classifyFintechRisk,
} from './fintech.js';

// Healthcare
export {
  evaluateNamespaceIsolation,
  hardDeleteEvents,
  buildHardDeleteAuditEvent,
  isWithinNamespace,
} from './healthcare.js';

// SaaS
export {
  evaluateCrossTenantBlock,
  evaluateDestructiveOpGate,
  isDestructiveOperation,
  requiresApproval,
  detectCrossTenantAccess,
  DEFAULT_DESTRUCTIVE_OPS,
} from './saas.js';

// Legal
export {
  evaluateSourceGrounding,
  computeGroundingScore,
  detectUnsupportedAssertions,
  groundingReport,
} from './legal.js';

// DevOps
export {
  evaluateEnvironmentGate,
  LoopDetector,
  createLoopDetector,
  captureStateSnapshot,
  isRestrictedEnvironment,
} from './devops.js';

// Agentic
export {
  DelegationTracker,
  createDelegationTracker,
  hasCircularDelegation,
} from './agentic.js';
export type { DelegationViolation } from './agentic.js';
