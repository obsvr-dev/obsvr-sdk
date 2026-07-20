"""Span attribute vocabulary (DASHBOARD_TELEMETRY.md M5, agent cluster).

Semantic-convention KEYS for the open ``attributes`` bag on a span. Mirror of
sdk/src/proxy/span-attributes.ts, aligned with the OpenTelemetry GenAI /
OpenLIT conventions catalogued in DASHBOARD_TELEMETRY.md. Shared keys let the
dashboard render known attributes without the SDK growing feature-specific
fields: the primitive stays generic, the vocabulary grows.

Convention: pass hashes, counts, and small scalars, never raw content.

Example:
    import obsvr
    from obsvr import SPAN_ATTR
    with obsvr.span("vector_search", "retrieval",
                    {SPAN_ATTR["RETRIEVAL_DOCUMENT_COUNT"]: 5,
                     SPAN_ATTR["RETRIEVAL_SOURCE"]: "kb_prod"}):
        docs = retriever.search(q)
"""

SPAN_ATTR = {
    # Tool
    "TOOL_NAME": "gen_ai.tool.name",
    "TOOL_TYPE": "gen_ai.tool.type",
    "TOOL_CALL_ID": "gen_ai.tool.call.id",
    "TOOL_ARGS_HASH": "gen_ai.tool.call.arguments_hash",
    "TOOL_RESULT_HASH": "gen_ai.tool.call.result_hash",
    "TOOL_ERROR": "gen_ai.tool.error",
    "TOOL_ALLOWED": "obsvr.tool.allowed",
    # Retrieval / RAG
    "RETRIEVAL_QUERY_HASH": "gen_ai.retrieval.query_hash",
    "RETRIEVAL_DOCUMENT_COUNT": "gen_ai.retrieval.document_count",
    "RETRIEVAL_SOURCE": "gen_ai.retrieval.source",
    "RETRIEVAL_SIMILARITY_THRESHOLD": "gen_ai.rag.similarity_threshold",
    "RETRIEVAL_TOP_K": "db.vector.query.top_k",
    # Memory
    "MEMORY_OPERATION": "gen_ai.memory.operation",
    "MEMORY_TYPE": "gen_ai.memory.type",
    "MEMORY_COUNT": "gen_ai.memory.count",
    "MEMORY_RESULT_COUNT": "gen_ai.memory.operation.result_count",
    # Agent / planner
    "AGENT_NAME": "gen_ai.agent.name",
    "AGENT_STEP_COUNT": "gen_ai.agent.step_count",
    "AGENT_MAX_STEPS": "gen_ai.agent.max_steps",
    "WORKFLOW_NAME": "gen_ai.workflow.name",
    # Promoted to first-class storage (filtered / aggregated / alerted on daily).
    "AGENT_ID": "gen_ai.agent.id",
    "WORKFLOW_ID": "gen_ai.workflow.id",
    "LOOP_COUNT": "gen_ai.agent.loop_count",
    "PLANNER_ITERATIONS": "gen_ai.agent.planner_iterations",
    "DELEGATION_DEPTH": "gen_ai.agent.delegation_depth",
    # Evaluation (M12) and guardrail (M13)
    "EVALUATION_NAME": "gen_ai.evaluation.name",
    "EVALUATION_SCORE": "gen_ai.evaluation.score.value",
    "EVALUATION_LABEL": "gen_ai.evaluation.score.label",
    "GUARDRAIL_TRIGGERED": "guard.denied",
    "GUARDRAIL_VERDICT": "guard.verdict",
    # Common (set automatically by span())
    "DURATION_MS": "duration_ms",
}
