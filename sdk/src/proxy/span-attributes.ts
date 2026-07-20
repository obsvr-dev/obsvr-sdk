/**
 * Span attribute vocabulary (DASHBOARD_TELEMETRY.md M5, agent cluster).
 *
 * These are the semantic-convention KEYS for the open `attributes` bag on a
 * span (see span.ts). They mirror the OpenTelemetry GenAI / OpenLIT conventions
 * catalogued in DASHBOARD_TELEMETRY.md. Using shared keys is what lets the
 * dashboard render known attributes without the SDK growing feature-specific
 * fields: the primitive stays generic, the vocabulary grows.
 *
 * Convention: pass hashes, counts, and small scalars, never raw content
 * (tool arguments, retrieval text, memory contents) which must be hashed.
 *
 * @example
 *   import { obsvr, SPAN_ATTR } from "@obsvr/sdk";
 *   await obsvr.span("vector_search", "retrieval", () => retriever.search(q), {
 *     attributes: { [SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT]: 5,
 *                   [SPAN_ATTR.RETRIEVAL_SOURCE]: "kb_prod" },
 *   });
 *
 * @packageDocumentation
 */

export const SPAN_ATTR = {
  // Tool
  TOOL_NAME: "gen_ai.tool.name",
  TOOL_TYPE: "gen_ai.tool.type",
  TOOL_CALL_ID: "gen_ai.tool.call.id",
  TOOL_ARGS_HASH: "gen_ai.tool.call.arguments_hash",
  TOOL_RESULT_HASH: "gen_ai.tool.call.result_hash",
  TOOL_ERROR: "gen_ai.tool.error",
  TOOL_ALLOWED: "obsvr.tool.allowed",

  // Retrieval / RAG
  RETRIEVAL_QUERY_HASH: "gen_ai.retrieval.query_hash",
  RETRIEVAL_DOCUMENT_COUNT: "gen_ai.retrieval.document_count",
  RETRIEVAL_SOURCE: "gen_ai.retrieval.source",
  RETRIEVAL_SIMILARITY_THRESHOLD: "gen_ai.rag.similarity_threshold",
  RETRIEVAL_TOP_K: "db.vector.query.top_k",

  // Memory
  MEMORY_OPERATION: "gen_ai.memory.operation",
  MEMORY_TYPE: "gen_ai.memory.type",
  MEMORY_COUNT: "gen_ai.memory.count",
  MEMORY_RESULT_COUNT: "gen_ai.memory.operation.result_count",

  // Agent / planner
  AGENT_NAME: "gen_ai.agent.name",
  AGENT_STEP_COUNT: "gen_ai.agent.step_count",
  AGENT_MAX_STEPS: "gen_ai.agent.max_steps",
  WORKFLOW_NAME: "gen_ai.workflow.name",

  // Promoted to first-class storage (people filter / aggregate / alert on these
  // daily). Everything else in this file stays in the span_attributes bag.
  AGENT_ID: "gen_ai.agent.id",
  WORKFLOW_ID: "gen_ai.workflow.id",
  LOOP_COUNT: "gen_ai.agent.loop_count",
  PLANNER_ITERATIONS: "gen_ai.agent.planner_iterations",
  DELEGATION_DEPTH: "gen_ai.agent.delegation_depth",

  // Evaluation (M12) and guardrail (M13)
  EVALUATION_NAME: "gen_ai.evaluation.name",
  EVALUATION_SCORE: "gen_ai.evaluation.score.value",
  EVALUATION_LABEL: "gen_ai.evaluation.score.label",
  GUARDRAIL_TRIGGERED: "guard.denied",
  GUARDRAIL_VERDICT: "guard.verdict",

  // Common (set automatically by span())
  DURATION_MS: "duration_ms",
} as const;

/** A span attribute key (the values of SPAN_ATTR). */
export type SpanAttrKey = (typeof SPAN_ATTR)[keyof typeof SPAN_ATTR];
