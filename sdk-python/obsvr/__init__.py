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
from .sender import flush  # noqa: F401
from .span import current_span_id, span, with_span  # noqa: F401
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
    "SPAN_ATTR",
    "ResolvedConfig",
    "ReasonCode",
    "REASON_CODES",
    "RULE_TYPE_TO_REASON_CODE",
    "rule_type_to_reason_code",
    "__version__",
]
