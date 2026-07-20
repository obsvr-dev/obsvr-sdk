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
 * 2. **Manual Tracking**: Explicit tracking calls for full control
 *    ```typescript
 *    import { ObsvrClient } from '@obsvr/sdk';
 *
 *    const client = new ObsvrClient({ apiKey: 'your-api-key' });
 *    await client.trackCompletion({
 *      prompt: 'Hello!',
 *      response: 'Hi!',
 *      model: 'gpt-4',
 *      region: 'us-east-1'
 *    });
 *    ```
 *
 * @packageDocumentation
 */

// Re-export manual tracking client (LLMAuditClient kept as deprecated alias)
export {
  ObsvrClient,
  LLMAuditClient,
  trackCompletion,
  trackBatch,
  generateUUID,
  default,
} from "./client.js";

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

// Re-export manual tracking types (LLMAuditClientConfig kept as deprecated alias)
export type {
  ObsvrClientConfig,
  LLMAuditClientConfig,
  TrackCompletionParams,
  TrackBatchParams,
  TrackResult,
  TrackBatchResult,
  TrackResponse,
  TrackBatchResponse,
  TrackErrorResponse,
} from "./client.js";

// Import proxy functions
import { init as _init, wrap, getConfig, isInitialized, flushQueue, getQueueSize, getDroppedCount, _reset } from "./proxy/index.js";
import { evaluate as _evaluate, evaluateAction as _evaluateAction } from "./governance/evaluate.js";
import { verifyAuditChain as _verifyAuditChain } from "./governance/verify-chain.js";
import { startPolicyPolling } from "./proxy/config.js";
import type { LLMAuditInitConfig, ObsvrConfig, WrapOptions } from "./proxy/types.js";
import { autoInstrument } from "./auto/index.js";

// Re-export proxy types
export type { LLMAuditInitConfig, ObsvrConfig, WrapOptions, AuditEvent, AuditFields, AgentPolicy } from "./proxy/types.js";
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
export { checkQuota, incrementQuota, resetQuota, getQuotaStatus } from "./governance/quota.js";
export { createGovernanceServer } from "./governance/server.js";

// Re-export MCP client governance (also available as `@obsvr/sdk/mcp`)
export { patchMCP, obsvrGovernMCP } from "./integrations/mcp.js";

// Framework-agnostic tool governance: wrap any framework's tool (Vercel AI,
// LlamaIndex, LangChain, ...) so its execution is allow/deny-gated, PII-scanned,
// and audited. Works where per-framework tool hooks don't exist or aren't stable.
export { obsvrGovernTool, obsvrGovernTools } from "./integrations/tools.js";
export type { GovernToolOptions } from "./integrations/tools.js";

// Canary-leak detection: mint a honeytoken, plant it where only the model
// should see it; if it later surfaces in output/tool-args/tool-results it is
// a CRITICAL leak. Only the token HASH is ever stored or audited.
export { mintCanary, scanForCanary, canaryCandidates } from "./policy/canary.js";
export type { MintedCanary, CanaryHit, CanaryScanResult, CanaryCandidate } from "./policy/canary.js";

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
function initWithAutoInstrumentation(config: LLMAuditInitConfig | ObsvrConfig): void {
  _init(config);
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
  wrap: <T extends object>(client: T, options?: WrapOptions): T => wrap(client, options),

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
