"""obsvr - LLM governance SDK for Python.

Usage:
    import obsvr
    from openai import OpenAI

    obsvr.init(api_key="...", ingest_url="https://audit.example.com")
    client = obsvr.wrap(OpenAI())
    # every call is now policy-checked and audited

Framework integrations (LangChain, CrewAI, AutoGen, LlamaIndex) live under
obsvr.integrations; MCP governance under obsvr.integrations.mcp.
"""

from .config import (  # noqa: F401
    ResolvedConfig,
    _reset,
    get_config,
    init,
    is_initialized,
    try_get_config,
)
from .policy import explain  # noqa: F401
from .canary import mint_canary, scan_for_canary  # noqa: F401
from .reason_codes import (  # noqa: F401
    REASON_CODES,
    RULE_TYPE_TO_REASON_CODE,
    ReasonCode,
    rule_type_to_reason_code,
)
from .agent_run import (  # noqa: F401
    agent_run,
    current_agent_run,
    current_agent_run_id,
    generate_run_id,
)
# Agent-run controls. Loop detection is driven for you by the LangChain and
# OpenAI-Agents integrations when agent_policy declares it; the delegation
# tracker is yours to drive from your own handoff path, as in TypeScript.
from .agent_policy import (  # noqa: F401
    DelegationTracker,
    LoopDetector,
    create_delegation_tracker,
    create_loop_detector,
    has_circular_delegation,
)
from .sender import flush  # noqa: F401
from .span import current_span_id, span, with_span  # noqa: F401
from .audit_gap import parse_audit_gap_prompt  # noqa: F401
from .verify_chain import ChainVerificationResult, verify_chain  # noqa: F401
# Layered call cost: a caller estimate, an operator-declared override, and a
# metered figure from real usage at operator-declared rates - all three kept,
# because the gap between estimate and correction is the auditable part.
from .cost import price_tokens, resolve_call_cost  # noqa: F401
# CloudEvents v1.0 export: an additive projection for CNCF-ecosystem sinks, so
# fanning audit events out does not need a bespoke adapter per consumer.
from .cloudevents import (  # noqa: F401
    safe_serialize_cloud_event,
    serialize_cloud_event,
    to_cloud_event,
)
# Typed policy-block error: catch this to tell "refused by policy" apart
# from a provider or transport failure without matching on the message.
from .errors import ObsvrPolicyError, ObsvrUnknownPolicyError  # noqa: F401
from .span_attributes import SPAN_ATTR  # noqa: F401
from .wrap import wrap  # noqa: F401

from ._version import __version__  # noqa: F401  # single source: obsvr/_version.py

__all__ = [
    "init",
    "wrap",
    "explain",
    "mint_canary",
    "scan_for_canary",
    "get_config",
    "is_initialized",
    "try_get_config",
    "flush",
    "span",
    "with_span",
    "current_span_id",
    "agent_run",
    "current_agent_run",
    "current_agent_run_id",
    "generate_run_id",
    "LoopDetector",
    "create_loop_detector",
    "DelegationTracker",
    "create_delegation_tracker",
    "has_circular_delegation",
    "verify_chain",
    # Gap markers: a verified chain can still declare events the bounded sender
    # queue dropped. verify_chain totals them; this identifies which events
    # carry the claim, for callers processing their own exports.
    "parse_audit_gap_prompt",
    "to_cloud_event",
    "serialize_cloud_event",
    "safe_serialize_cloud_event",
    "resolve_call_cost",
    "price_tokens",
    "ObsvrPolicyError",
    "ObsvrUnknownPolicyError",
    "ChainVerificationResult",
    "SPAN_ATTR",
    "ResolvedConfig",
    "ReasonCode",
    "REASON_CODES",
    "RULE_TYPE_TO_REASON_CODE",
    "rule_type_to_reason_code",
    "__version__",
]
