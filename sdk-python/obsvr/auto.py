"""Auto-instrumentation: wire the frameworks that expose a clean GLOBAL
registration point, so `obsvr.init(auto=True)` governs them without the user
passing handler objects by hand — the zero-wiring auto-instrumentation UX, but done
WITHOUT monkey-patching framework internals (a WHY_OBSVR non-goal).

Cleanly auto-wired (global, non-mutating registration):
  * Providers (openai / anthropic) — construct interception via obsvr.register.
  * OpenAI Agents SDK — agents.add_trace_processor(ObsvrTracingProcessor()).
  * LlamaIndex — Settings.callback_manager.add_handler(ObsvrLlamaIndexHandler()).

Detected but NOT auto-wired (require per-call / per-agent handlers by design —
obsvr integrates via each framework's official extension point, not by patching
its internals): LangChain (pass ObsvrCallbackHandler() in callbacks=[...]),
CrewAI (make_*_callback factories), AutoGen (register_obsvr(agent)). These are
reported so the developer knows the one line to add.

Every step is best-effort and isolated: a failure to wire one framework never
raises and never affects the audit path.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

logger = logging.getLogger("obsvr.auto")

# Idempotency guard: init() may run more than once in tests / long-lived procs.
_wired: List[str] = []


def _module_available(name: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _wire_providers() -> List[str]:
    try:
        from .register import install

        return install()  # governs openai/anthropic client construction
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("obsvr.auto: provider interception skipped: %s", exc)
        return []


def _wire_openai_agents() -> bool:
    if not _module_available("agents"):
        return False
    try:
        from agents import add_trace_processor  # type: ignore
        from .integrations.openai_agents import ObsvrTracingProcessor

        add_trace_processor(ObsvrTracingProcessor())
        return True
    except Exception as exc:
        logger.debug("obsvr.auto: openai-agents wiring skipped: %s", exc)
        return False


def _wire_llamaindex() -> bool:
    if not _module_available("llama_index"):
        return False
    try:
        from llama_index.core import Settings  # type: ignore
        from llama_index.core.callbacks import CallbackManager  # type: ignore
        from .integrations.llamaindex import ObsvrLlamaIndexHandler

        handler = ObsvrLlamaIndexHandler()
        cm = getattr(Settings, "callback_manager", None) or CallbackManager([])
        cm.add_handler(handler)
        Settings.callback_manager = cm
        return True
    except Exception as exc:
        logger.debug("obsvr.auto: llamaindex wiring skipped: %s", exc)
        return False


# Frameworks obsvr integrates via per-call/per-agent handlers (no global hook).
_MANUAL_HINTS = {
    "langchain_core": "LangChain: pass obsvr.integrations.langchain.ObsvrCallbackHandler() in callbacks=[...]",
    "crewai": "CrewAI: wire obsvr.integrations.crewai.make_crew_callbacks(...) on your Crew",
    "autogen": "AutoGen: call obsvr.integrations.autogen.register_obsvr(agent)",
}


def enable_auto_instrumentation() -> Dict[str, Any]:
    """Wire every framework that supports clean global registration. Returns a
    report: {"wired": [...], "manual": [...]}. Idempotent and non-throwing."""
    report: Dict[str, Any] = {"wired": [], "manual": []}

    if "providers" not in _wired:
        installed = _wire_providers()
        if installed:
            _wired.append("providers")
            report["wired"].append(f"providers:{'+'.join(installed)}")

    if "openai_agents" not in _wired and _wire_openai_agents():
        _wired.append("openai_agents")
        report["wired"].append("openai-agents")

    if "llamaindex" not in _wired and _wire_llamaindex():
        _wired.append("llamaindex")
        report["wired"].append("llamaindex")

    for mod, hint in _MANUAL_HINTS.items():
        if _module_available(mod):
            report["manual"].append(hint)

    if report["wired"]:
        logger.info("obsvr auto-instrumentation wired: %s", ", ".join(report["wired"]))
    for hint in report["manual"]:
        logger.info("obsvr: %s", hint)
    return report


def _reset_auto() -> None:
    """Test hook: clear the idempotency guard."""
    _wired.clear()
