/**
 * Industry policy modules barrel export.
 *
 * **These are EVALUATORS AND PRIMITIVES, not shipped policy content.** Nothing
 * in this directory is a ready-made HIPAA, PCI or SOC 2 ruleset, and installing
 * the package does not put one into force. What is here is the machinery a
 * rule of that kind is built out of — a namespace-isolation predicate, a
 * threshold comparator, a cross-tenant check, a destructive-operation
 * classifier — which you compose into `policyRules` yourself, and which decide
 * nothing until you do.
 *
 * The names in this barrel are the reason to say so. `healthcare`, `fintech`
 * and `legal` read as compliance packages, and the module docstrings mention
 * HIPAA by name, so a reader who arrives here through the package's public
 * exports can reasonably form an expectation this code does not meet. It is a
 * misreading no behaviour prevents, and no public document contradicts it,
 * because no public document mentions these modules at all — this export
 * surface IS where they are advertised.
 *
 * **TypeScript only.** The Python package has no equivalent module, so any
 * rule composed from these primitives is not portable to it, and the parity
 * the two SDKs claim elsewhere does not extend here.
 *
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
