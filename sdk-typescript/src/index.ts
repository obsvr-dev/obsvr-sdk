/**
 * LLM Audit SDK
 *
 * Two ways to use this SDK:
 *
 * 1. **Automatic Proxy** (recommended): Wrap your LLM client for transparent audit tracking
 *    ```typescript
 *    import { obsvr } from '@obsvr/sdk';
 *
 *    obsvr.init({ api_key: 'your-api-key' });
 *    const openai = obsvr.wrap(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }));
 *
 *    // Audit fields are stripped before sending to OpenAI
 *    const response = await openai.chat.completions.create({
 *      model: 'gpt-4o',
 *      messages: [{ role: 'user', content: 'Hello!' }],
 *      request_id: 'req_123',       // Goes to audit only
 *      metadata: { user_id: 'u1' }  // Goes to audit only
 *    });
 *    ```
 *
 * @packageDocumentation
 */

// Request-id generation, used by the governed paths and exported because a
// caller supplying its own audit_fields.request_id needs the same shape.
export { generateUUID } from "./utils/uuid.js";

// Span primitive: a generic execution-graph node (M3). withSpan establishes a
// deterministic parent scope; governed calls inside it link to it.
export { span, withSpan, currentSpan, currentSpanId, generateSpanId } from "./proxy/span.js";
export type { SpanKind, SpanEnvelope, SpanContext } from "./proxy/span.js";
export { SPAN_ATTR } from "./proxy/span-attributes.js";
export type { SpanAttrKey } from "./proxy/span-attributes.js";
import { span as _span, withSpan as _withSpan } from "./proxy/span.js";

// Agent-run scope (run lifecycle): forms one Runs-tab row per agentic
// execution, grouping every governed action inside it by agent_run_id.
export { agentRun } from "./integrations/agent-run.js";
export type { AgentRunOptions } from "./integrations/agent-run.js";
export { currentAgentRun, currentAgentRunId, generateRunId } from "./proxy/agent-run.js";
export type { AgentRunContext } from "./proxy/agent-run.js";
import { agentRun as _agentRun } from "./integrations/agent-run.js";

// Import proxy functions
import { init as _init, wrap, getConfig, isInitialized, flushQueue, getQueueSize, getDroppedCount, _reset } from "./proxy/index.js";
import { evaluate as _evaluate, evaluateAction as _evaluateAction } from "./governance/evaluate.js";
import { verifyAuditChain as _verifyAuditChain } from "./governance/verify-chain.js";
import { startPolicyPolling } from "./proxy/config.js";
import type { LLMAuditInitConfig, ObsvrConfig, WrapOptions } from "./proxy/types.js";
import { autoInstrument } from "./auto/index.js";
import {
  claimGoverningInstance,
  duplicateInstanceMessage,
  isGoverningInstance,
} from "./proxy/instance-guard.js";
import { SDK_VERSION } from "./constants.js";
import { governFn as _governFn } from "./governance/govern-fn.js";

// Re-export proxy types
export type { LLMAuditInitConfig, ObsvrConfig, WrapOptions, AuditEvent, AuditFields, AgentPolicy } from "./proxy/types.js";
export { autoGovernanceStatus } from "./auto/index.js";
export type { AutoGovernanceStatus, InterceptorKind } from "./auto/index.js";
export type { PolicyHook, PolicyDecision } from "./policy/hook.js";
export type { PolicyRule, PolicyEvalContext } from "./policy/rules.js";

// Re-export governance modules
export type {
  GovernanceDecision,
  GovernanceResponse,
  EvaluateRequest,
  EvaluateResponse,
  PolicyEvaluationToken,
  QuotaConfig,
  ChainVerificationResult,
  GovernanceServerConfig,
} from "./governance/types.js";
export { ReasonCode, REASON_CODES, RULE_TYPE_TO_REASON_CODE, mapLegacyDecision, ruleTypeToReasonCode } from "./governance/reason-codes.js";
export { issueExecutionToken, verifyExecutionToken } from "./governance/token.js";
export { evaluate, evaluateAction, explain } from "./governance/evaluate.js";
export type { ExplainResult } from "./governance/evaluate.js";
export { evaluateShadowRules, deriveRuleHash, derivePolicyVersion } from "./policy/rules.js";
export type { ShadowOutcome } from "./policy/rules.js";
export { exportToRego } from "./policy/rego-export.js";
export type { RegoExportBundle, DelegatedRule } from "./policy/rego-export.js";
// Inbound external policy backend (ADR-4): OPA/Cedar, merged DENY-WINS with local rules.
export {
  mergeExternalBackendDecision,
  evaluateExternalBackend,
  runExternalBackendStep,
  buildBackendInput,
  backendProvenance,
} from "./policy/external-backend.js";
export type {
  ExternalPolicyBackendConfig,
  ExternalBackendRecord,
  ExternalBackendType,
  BackendOutcome,
  LocalDecision,
  BackendDecisionInput,
  BackendMergeResult,
} from "./policy/external-backend.js";
export { useSubject, getCurrentSubject, parseSubject } from "./proxy/subject.js";
export type { Subject } from "./proxy/subject.js";
export { verifyAuditChain } from "./governance/verify-chain.js";
export { governFn } from "./governance/govern-fn.js";
export type { GovernedFunction, GovernFnOptions } from "./governance/govern-fn.js";
export {
  ACTION_CONTEXT_V2_SCHEMA,
  ACTION_TARGET_HASH_DOMAIN,
  buildActionContextV2,
  canonicalizeActionContextV2,
  actionContextV2Hash,
  actionTargetHash,
  ActionContextV2ValidationError,
} from "./governance/action-context-v2.js";
export {
  REMEDIATION_PLAN_V1_SCHEMA,
  REMEDIATION_RETRY_V1_SCHEMA,
  REMEDIATION_PLAN_HASH_DOMAIN,
  RemediationV1ValidationError,
  buildRemediationPlanV1,
  canonicalizeRemediationPlanV1,
  remediationPlanV1Hash,
  buildRemediationRetryV1,
  remediationRetryV1Hash,
} from "./governance/remediation-v1.js";
export type {
  RemediationRequirementV1Input,
  RemediationPlanV1Input,
  RemediationPlanV1Document,
  SatisfiedRemediationRequirementV1Input,
  RemediationRetryV1Input,
  RemediationRetryV1Document,
} from "./governance/remediation-v1.js";
export type {
  ActionContextV2Input,
  ActionContextV2Document,
  PriorActionV2Input,
} from "./governance/action-context-v2.js";
// Gap markers: a verified chain can still declare events the bounded sender
// queue dropped. `verifyAuditChain` totals them; this identifies which events
// carry the claim, for callers processing their own exports.
export { parseAuditGapPrompt } from "./proxy/audit-gap.js";
export type { AuditGapClaim } from "./proxy/audit-gap.js";
// CloudEvents v1.0 export: an additive projection for CNCF-ecosystem sinks, so
// fanning audit events out does not need a bespoke adapter per consumer.
export {
  toCloudEvent,
  serializeCloudEvent,
  safeSerializeCloudEvent,
  CLOUDEVENTS_SPEC_VERSION,
  CLOUDEVENTS_TYPE_PREFIX,
  CLOUDEVENTS_DATA_SCHEMA,
} from "./proxy/cloudevents.js";
export type { CloudEvent } from "./proxy/cloudevents.js";
// Typed policy-block error: catch this to tell "refused by policy" apart
// from a provider or transport failure without matching on the message.
export {
  ObsvrPolicyError,
  ObsvrUnknownPolicyError,
} from "./policy/policy-error.js";
export type { ObsvrPolicyDecision } from "./policy/policy-error.js";
export { checkQuota, incrementQuota, resetQuota, getQuotaStatus } from "./governance/quota.js";
// Layered call cost: a caller estimate, an operator-declared override, and a
// metered figure from real usage at operator-declared rates - all three kept,
// because the gap between estimate and correction is the auditable part.
export { resolveCallCost, priceTokens } from "./governance/cost.js";
export type { CostPolicyConfig, CostRate, ResolvedCost } from "./governance/cost.js";
export { createGovernanceServer } from "./governance/server.js";
export {
  createStrictActionBoundaryV21,
  executeStrictActionV21,
  ObsvrStrictActionBoundaryV21Error,
} from "./governance/strict-action-boundary-v2-1.js";
export type {
  StrictActionBoundaryV21Capability,
  StrictActionBoundaryV21Options,
  StrictActionContextV21,
  StrictActionExecutionV21,
  StrictActionV21,
} from "./governance/strict-action-boundary-v2-1.js";
export {
  createStrictProviderBoundaryV21,
  ObsvrStrictProviderBoundaryV21Error,
} from "./governance/strict-provider-boundary-v2-1.js";
export type {
  StrictProviderBoundaryV21Capability,
  StrictProviderBoundaryV21Options,
  StrictProviderCallV21,
  StrictProviderContextV21,
} from "./governance/strict-provider-boundary-v2-1.js";
export {
  StrictReceiptRuntimeV21,
  bindStrictV21JsonArguments,
} from "./governance/strict-receipt-runtime-v2-1.js";
export type {
  StrictV21CheckpointStore,
  StrictV21ApprovalRuntimeAction,
  StrictV21BoundArguments,
  StrictV21RuntimeAction,
  StrictRuntimeExecutionJournalV21,
  StrictRuntimeV21Result,
} from "./governance/strict-receipt-runtime-v2-1.js";
export type {
  StrictRuntimeFailureClassificationV21,
} from "./governance/strict-receipt-runtime-v2-1-outcomes.js";
export {
  correlateStrictRuntimeCheckpointV21ToOtel,
  withStrictOtelCorrelationV21,
} from "./proxy/otel-mirror.js";
export {
  finalizeInterruptedStrictRuntimeExecutionV21,
  reconcileStrictRuntimeExecutionV21,
  StrictRuntimeRecoveryV21Error,
} from "./governance/strict-runtime-recovery-v2-1.js";
export type {
  StrictInterruptedExecutionCheckpointStoreV21,
  StrictInterruptedExecutionFinalizerV21Options,
  StrictRuntimeRecoveryV21Result,
} from "./governance/strict-runtime-recovery-v2-1.js";
export {
  STRICT_POLICY_CONTINUITY_V21_SCHEMA,
  StrictPolicyContinuityV21Error,
  reconstructStrictPolicyContinuityV21,
} from "./governance/strict-policy-continuity-v2-1.js";
export type {
  StrictPolicyContinuityV21,
  StrictPolicySnapshotV21,
  StrictPolicyTransitionV21,
} from "./governance/strict-policy-continuity-v2-1.js";
export {
  STRICT_EVIDENCE_BUNDLE_V21_SCHEMA,
  STRICT_EVIDENCE_BUNDLE_V21_ENVELOPE_SCHEMA,
  StrictEvidenceBundleV21Error,
  buildStrictEvidenceBundleV21Body,
  createStrictEvidenceBundleV21,
  strictEvidenceBundleV21Hash,
  verifyStrictEvidenceBundleV21,
} from "./governance/strict-evidence-bundle-v2-1.js";
export type {
  StrictEvidenceBundleV21Body,
  StrictEvidenceBundleV21Envelope,
  StrictEvidenceBundleV21Verification,
  StrictEvidenceCoverageV21,
} from "./governance/strict-evidence-bundle-v2-1.js";
export {
  STRICT_EXECUTION_OUTCOME_V21_SCHEMA,
  STRICT_EXECUTION_OUTCOME_V21_ENVELOPE_SCHEMA,
  StrictExecutionOutcomeV21ValidationError,
  buildStrictExecutionOutcomeV21Body,
  canonicalizeStrictExecutionOutcomeV21Body,
  signStrictExecutionOutcomeV21,
  strictExecutionOutcomeV21Hash,
  strictExecutionOutcomeV21SignaturePreimage,
  strictExecutionResultV21Hash,
  strictExecutionStartV21Hash,
  verifyStrictExecutionOutcomeV21,
} from "./governance/strict-execution-outcome-v2-1.js";
export type {
  StrictExecutionOutcomeV21Body,
  StrictExecutionOutcomeV21Envelope,
  StrictExecutionOutcomeV21Status,
  StrictExecutionOutcomeV21Verification,
  StrictExecutionStartV21,
} from "./governance/strict-execution-outcome-v2-1.js";
export {
  STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA,
  STRICT_EXECUTION_OUTCOME_V21_ENDPOINT,
  STRICT_EXECUTION_OUTCOME_V21_INGEST_SCHEMA,
  STRICT_EXECUTION_OUTCOME_V21_MAX_REQUEST_BYTES,
  StrictExecutionOutcomeV21TransportError,
  assertStrictExecutionOutcomeV21RequestBytes,
  submitStrictExecutionOutcomeV21,
  submitStrictRuntimeTerminalJournalV21,
} from "./governance/strict-execution-outcome-transport-v2-1.js";
export type {
  StrictExecutionOutcomeV21PinnedTransport,
  StrictExecutionOutcomeV21TransportOptions,
  StrictExecutionOutcomeV21TransportResult,
} from "./governance/strict-execution-outcome-transport-v2-1.js";
export {
  StrictReceiptCoordinatorV21,
  createTrustedIntentDecisionProviderV21,
} from "./governance/strict-receipt-coordinator-v2-1.js";
export {
  createTrustedEvaluationEvidenceProviderV21,
} from "./governance/strict-evaluation-evidence-v2-1.js";
export {
  createStrictIdentityEvidenceV21Authority,
} from "./governance/strict-identity-evidence-v2-1.js";
export { loadDeviceSigner } from "./proxy/device-identity.js";

// Re-export MCP client governance (also available as `@obsvr/sdk/mcp`)
export { patchMCP, obsvrGovernMCP } from "./integrations/mcp.js";
export {
  RequiredBindingsError,
  assertRequiredBindings,
  integrationBindings,
  requiredBindingFailures,
  unboundSymbols,
} from "./binding-report.js";
export type {
  BindingEntry,
  BindingMetadata,
  EnforcementDepth,
  RequiredBindingFailure,
  UnboundSymbol,
} from "./binding-report.js";
export {
  COVERAGE_ATTESTATION_ENVELOPE_SCHEMA,
  COVERAGE_ATTESTATION_SCHEMA,
  CoverageAttestationValidationError,
  buildCoverageAttestationBody,
  canonicalizeCoverageAttestationBody,
  coverageAttestationBodyHash,
  signCoverageAttestation,
  verifyCoverageAttestation,
} from "./governance/coverage-attestation.js";
export type {
  CoverageAttestationBody,
  CoverageAttestationEnvelope,
  CoverageAttestationInput,
  CoverageAttestationVerification,
  CoverageBinding,
  CoverageFailure,
  CoverageFailureReason,
  CoverageRequirementInput,
} from "./governance/coverage-attestation.js";

// Framework-agnostic tool governance: wrap any framework's tool (Vercel AI,
// LlamaIndex, LangChain, ...) so its execution is allow/deny-gated, PII-scanned,
// and audited. Works where per-framework tool hooks don't exist or aren't stable.
export { obsvrGovernTool, obsvrGovernTools } from "./integrations/tools.js";
export type { GovernToolOptions } from "./integrations/tools.js";

// The generic OpenAI-compatible wrapper (also available as
// `@obsvr/sdk/openai-compat`). Exported from the root because it is the entry
// point for endpoints that have no named integration of their own; the named
// wrappers built on it (together, azure-openai, cloudflare) stay subpath-only.
// Unlike those, this one takes `provider` and `source` from the caller, so the
// label on the audit event names the endpoint the caller actually reached.
export { wrapOpenAICompatible } from "./integrations/openai-compat.js";
export type { OpenAICompatConfig } from "./integrations/openai-compat.js";

// Canary-leak detection: mint a honeytoken, plant it where only the model
// should see it; if it later surfaces in output/tool-args/tool-results it is
// a CRITICAL leak. Only the token HASH is ever stored or audited.
export { mintCanary, scanForCanary, canaryCandidates } from "./policy/canary.js";
export type { MintedCanary, CanaryHit, CanaryScanResult, CanaryCandidate } from "./policy/canary.js";
export {
  POLICY_CANDIDATE_V1_SCHEMA,
  POLICY_REPLAY_REPORT_V1_SCHEMA,
  POLICY_PROMOTION_V1_SCHEMA,
  PolicyLifecycleV1ValidationError,
  buildPolicyCandidateV1,
  policyCandidateV1Hash,
  replayPolicyCandidateV1,
  decidePolicyPromotionV1,
} from "./governance/policy-lifecycle-v1.js";
export type {
  PolicyCandidateV1Input,
  PolicyReplayCaseV1,
  PolicyPromotionThresholdsV1,
  PolicyStageV1,
  ReplayOutcomeV1,
} from "./governance/policy-lifecycle-v1.js";

// Resolved config accessor (needed by obsvrGovernMCP and custom integrations)
export { getConfig } from "./proxy/index.js";

// Re-export industry modules
export {
  hardDeleteEvents,
  LoopDetector,
  createLoopDetector,
  DelegationTracker,
  createDelegationTracker,
  computeGroundingScore,
  detectUnsupportedAssertions,
  groundingReport,
  isDestructiveOperation,
  detectCrossTenantAccess,
  classifyFintechRisk,
  isRestrictedEnvironment,
  hasCircularDelegation,
} from "./policy/industry/index.js";
export type { DelegationViolation } from "./policy/industry/index.js";

/**
 * Typed passthrough for customer config files.
 *
 * Provides TypeScript autocomplete and a single canonical config shape.
 * Create an `obsvr.config.ts` at your project root:
 *
 * ```ts
 * import { defineConfig } from '@obsvr/sdk';
 * export default defineConfig({
 *   apiKey:    process.env.OBSVR_API_KEY!,
 *   ingestUrl: 'https://ingest.obsvr.co',
 *   providers: ['openai', 'anthropic'],
 * });
 * ```
 */
export function defineConfig(config: ObsvrConfig): ObsvrConfig {
  return config;
}

/**
 * Wrapper around the internal init that also checks interceptor coverage.
 */
/** Identifies THIS copy of the module inside the process. */
const MODULE_INSTANCE_ID = `obsvr-${SDK_VERSION}-${Math.random().toString(36).slice(2)}`;

function initWithAutoInstrumentation(config: LLMAuditInitConfig | ObsvrConfig): void {
  _init(config);

  // Two copies of the SDK in one process would each poll, each wrap, and each
  // emit - duplicate evidence for one call. The first copy to init governs;
  // this one says so once and stands down.
  const claim = claimGoverningInstance(SDK_VERSION, MODULE_INSTANCE_ID);
  if (!claim.governing) {
    console.warn(duplicateInstanceMessage(claim));
    return;
  }

  // After config is resolved, verify interceptor coverage and start policy polling
  // (autoInstrument never patches anything; it only warns on misconfiguration)
  try {
    const resolved = getConfig();
    autoInstrument(resolved);
    const refreshMs = resolved.policyRefreshIntervalMs ?? 30_000;
    if (refreshMs > 0) {
      startPolicyPolling(resolved);
    }
  } catch {
    // If getConfig() fails for any reason, skip auto-instrumentation silently
  }
}

/**
 * Whether this copy of the module governs the process. A copy that yielded to
 * an earlier one passes clients through unwrapped rather than governing them
 * alongside it.
 */
export function isGoverningCopy(): boolean {
  return isGoverningInstance(MODULE_INSTANCE_ID);
}

/**
 * LLM Audit Proxy Singleton
 *
 * Provides automatic audit tracking by wrapping LLM client instances.
 *
 * @example
 * ```typescript
 * import { obsvr } from '@obsvr/sdk';
 * import OpenAI from 'openai';
 *
 * // Initialize once at startup
 * obsvr.init({
 *   api_key: 'tp_live_your_api_key',
 *   environment: 'production',
 *   debug: true
 * });
 *
 * // Wrap your OpenAI client
 * const openai = obsvr.wrap(
 *   new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
 * );
 *
 * // Use normally - audit happens automatically
 * const response = await openai.chat.completions.create({
 *   model: 'gpt-4o',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 *   // These fields go to audit, NOT to OpenAI:
 *   request_id: 'req_123',
 *   region: 'us-east-1',
 *   source: 'web_app',
 *   metadata: { user_id: 'user_123', session_id: 'sess_abc' }
 * });
 * ```
 */
export const obsvr = {
  /**
   * Initialize the LLM Audit proxy SDK
   *
   * Accepts the new camelCase `ObsvrConfig` (recommended) or the legacy
   * snake_case `LLMAuditInitConfig`. init() never patches provider SDKs.
   * Global, zero-code coverage comes from the module interceptor
   * (`node --import @obsvr/sdk/register`), which swaps provider exports for
   * construct-trap Proxies without touching prototypes. Without it, wrap
   * each client explicitly with `obsvr.wrap()`.
   *
   * @param config - Configuration options
   *
   * @example
   * ```typescript
   * // New style (recommended)
   * import config from './obsvr.config';
   * obsvr.init(config);
   *
   * // Legacy style still works
   * obsvr.init({ api_key: 'your-api-key', environment: 'production' });
   * ```
   */
  init: initWithAutoInstrumentation,

  /**
   * Wrap an LLM client for automatic audit tracking
   *
   * The returned client has the same interface as the original,
   * but all auditable methods (like chat.completions.create) are
   * intercepted to extract and send audit events.
   *
   * @param client - The LLM client instance (e.g., new OpenAI())
   * @param options - Optional configuration for this wrapped client
   * @returns The wrapped client with the same interface
   *
   * @example
   * ```typescript
   * const openai = obsvr.wrap(
   *   new OpenAI({ apiKey: process.env.OPENAI_API_KEY }),
   *   { customer_id: 'customer_123', region: 'us-east-1' }
   * );
   * ```
   */
  wrap: <T extends object>(client: T, options?: WrapOptions): T => {
    // A copy that yielded to another SDK instance in this process passes the
    // client through: one governing instance, never two interceptions of the
    // same call. The stand-down was already reported once at init().
    if (!isGoverningCopy()) return client;
    return wrap(client, options);
  },

  /** Govern an application-owned action or workflow function. */
  governFn: _governFn,

  /**
   * Run a function inside a named span scope. Governed calls made within it
   * (directly or in awaited descendants) link to this span as their parent,
   * building the execution-graph DAG. Deterministic and developer-declared.
   *
   * @example
   * ```typescript
   * await obsvr.withSpan("retrieval", "retrieval", async () => {
   *   await openai.embeddings.create(...); // parent_span_id = this span
   * });
   * ```
   */
  withSpan: _withSpan,

  /**
   * Run a function as a recorded execution span (tool / retrieval / memory /
   * planner). Signed evidence, linked into the chain, surfaced through traces
   * rather than the main governance feed.
   */
  span: _span,

  /**
   * Run a top-level agent invocation as ONE agent run. Emits signed
   * run-start/finish events and groups every governed action inside it (LLM
   * calls, `obsvrGovernTool` tool calls, spans) under one `agent_run_id`, so it
   * appears as a single row in the dashboard's Runs tab. Use for frameworks
   * governed at the tool level (LlamaIndex, Vercel AI); LangChain and
   * OpenAI-Agents form runs on their own.
   *
   * @example
   * ```typescript
   * await obsvr.agentRun("support-agent", () => agent.run(msg), {
   *   source: "llamaindex_ts",
   * });
   * ```
   */
  agentRun: _agentRun,

  /**
   * Check if the SDK has been initialized
   */
  isInitialized,

  /**
   * Flush all pending audit events
   *
   * Useful for graceful shutdown in serverless environments.
   *
   * @param timeoutMs - Maximum time to wait (default: 5000ms)
   */
  flush: async (timeoutMs?: number): Promise<void> => {
    if (!isInitialized()) {
      return;
    }
    const config = getConfig();
    await flushQueue(config, timeoutMs);
  },

  /**
   * Get the number of events currently in the send queue.
   */
  getQueueSize,

  /**
   * Get the number of events dropped due to queue overflow.
   */
  getDroppedCount,

  /**
   * Evaluate an action against the governance policy engine.
   * Returns PERMITTED/BLOCKED with optional JWT execution token.
   */
  evaluate: _evaluate,

  /**
   * Convenience: evaluate using singleton config.
   */
  evaluateAction: _evaluateAction,

  /**
   * Verify the integrity of an audit event chain.
   */
  verifyAuditChain: _verifyAuditChain,

  /**
   * Reset the SDK state (for testing only)
   * @internal
   */
  _reset,
};
