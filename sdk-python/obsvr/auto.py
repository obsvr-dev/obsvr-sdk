"""Auto-instrumentation: wire the frameworks that expose a clean GLOBAL
registration point, so `obsvr.init(auto=True)` governs them without the user
passing handler objects by hand — the zero-wiring auto-instrumentation UX, but done
without scanning the heap or patching framework internals. Provider module
constructor exports are rebound at registration time; objects or constructor
references saved earlier are outside that boundary.

Cleanly auto-wired (global registration or an explicitly supported class gate):
  * Providers (openai / anthropic) — construct interception via obsvr.register.
  * OpenAI Agents SDK — trace processor plus future Agent construction with
    pre-tool input guardrails on function tools present at construction time.
  * LlamaIndex — Settings.callback_manager.add_handler(ObsvrLlamaIndexHandler()).
  * CrewAI — official process-global before_tool_call hook.
  * AutoGen/ag2 0.x — supported ConversableAgent tool-execution boundary.

Detected but NOT auto-wired (require per-call / per-agent handlers by design —
obsvr integrates via each framework's official extension point, not by patching
its internals): LangChain (pass ObsvrCallbackHandler() in callbacks=[...]).
CrewAI run/step audit callbacks and AutoGen message policy remain explicit;
their pre-tool execution gates are installed automatically. These residual
bindings are reported so the developer knows the one line to add.

Every step is best-effort and isolated: a failure to wire one framework never
raises and never affects the audit path.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, Callable, Dict, Generic, List, TypeVar

logger = logging.getLogger("obsvr.auto")

_TContext = TypeVar("_TContext")

# Idempotency guard: init() may run more than once in tests / long-lived procs.
_wired: List[str] = []
_uninstallers: List[Callable[[], None]] = []


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


def _wire_openai_agents_tool_gate() -> bool:
    """Replace future ``agents.Agent`` construction with a gated subclass."""
    if not _module_available("agents"):
        return False
    try:
        import agents  # type: ignore
        from .binding_report import record_binding
        from .integrations.openai_agents import (
            attach_tool_gate,
            make_tool_gate_guardrail,
        )

        original = getattr(agents, "Agent", None)
        if not isinstance(original, type):
            raise ImportError("agents exports no Agent class")
        if getattr(original, "_obsvr_auto_tool_gate_class", False):
            return True
        # Validate both the public guardrail type and the executor consult site
        # before replacing Agent. An accepted-but-never-consulted gate would be
        # worse than leaving construction untouched and reporting the bind gap.
        make_tool_gate_guardrail()

        if getattr(original, "__parameters__", ()):
            class GovernedAgent(  # type: ignore[misc,valid-type,no-redef]
                original[_TContext], Generic[_TContext]
            ):
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    super().__init__(*args, **kwargs)
                    _uninstallers.append(attach_tool_gate(self))
        else:
            class GovernedAgent(original):  # type: ignore[misc,valid-type,no-redef]
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    super().__init__(*args, **kwargs)
                    _uninstallers.append(attach_tool_gate(self))

        GovernedAgent.__name__ = original.__name__
        GovernedAgent.__qualname__ = original.__qualname__
        GovernedAgent.__module__ = original.__module__
        GovernedAgent._obsvr_auto_tool_gate_class = True

        rebound: List[tuple[Any, str]] = []
        for module in (agents, sys.modules.get("agents.agent")):
            if module is None:
                continue
            for name, value in list(vars(module).items()):
                if value is not original:
                    continue
                setattr(module, name, GovernedAgent)
                if getattr(module, name, None) is GovernedAgent:
                    rebound.append((module, name))
        if getattr(agents, "Agent", None) is not GovernedAgent:
            raise RuntimeError("agents.Agent refused constructor substitution")

        removed = False

        def _uninstall() -> None:
            nonlocal removed
            if removed:
                return
            removed = True
            for module, name in rebound:
                try:
                    if getattr(module, name, None) is GovernedAgent:
                        setattr(module, name, original)
                except Exception:
                    pass

        _uninstallers.append(_uninstall)
        record_binding("openai_agents", "agents.Agent")
        return True
    except Exception as exc:
        try:
            from .binding_report import record_binding

            record_binding("openai_agents", "agents.Agent", exc)
        except Exception:
            pass
        logger.debug("obsvr.auto: openai-agents tool gate skipped: %s", exc)
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


def _wire_crewai_tool_gate() -> bool:
    """Install CrewAI's process-global pre-tool hook when it is dispatchable."""
    if not _module_available("crewai"):
        return False
    try:
        from .integrations.crewai import install_tool_gate_hook

        _uninstallers.append(install_tool_gate_hook())
        return True
    except Exception as exc:
        logger.debug("obsvr.auto: CrewAI tool gate skipped: %s", exc)
        return False


def _wire_autogen_tool_gate() -> bool:
    """Install the supported AutoGen/ag2 class-level execution gate."""
    if not _module_available("autogen"):
        return False
    try:
        from .integrations.autogen import install_tool_gate

        _uninstallers.append(install_tool_gate())
        return True
    except Exception as exc:
        logger.debug("obsvr.auto: AutoGen tool gate skipped: %s", exc)
        return False


# Frameworks obsvr integrates via per-call/per-agent handlers (no global hook).
_MANUAL_HINTS = {
    "langchain_core": "LangChain: pass obsvr.integrations.langchain.ObsvrCallbackHandler() in callbacks=[...]",
    "crewai": "CrewAI run/step audit: wire obsvr.integrations.crewai.make_crew_callbacks(...) on your Crew; the pre-tool gate is automatic where supported",
    "autogen": "AutoGen message policy: call obsvr.integrations.autogen.register_obsvr(agent); the tool-execution gate is automatic on supported ag2 0.x",
    "agents": "OpenAI Agents model policy still requires govern_model()/govern_model_provider(); hosted and dynamically converted MCP tools must be governed at their execution boundary",
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

    if (
        "openai_agents_tool_gate" not in _wired
        and _wire_openai_agents_tool_gate()
    ):
        _wired.append("openai_agents_tool_gate")
        report["wired"].append("openai-agents:tool-gate")

    if "llamaindex" not in _wired and _wire_llamaindex():
        _wired.append("llamaindex")
        report["wired"].append("llamaindex")

    if "crewai_tool_gate" not in _wired and _wire_crewai_tool_gate():
        _wired.append("crewai_tool_gate")
        report["wired"].append("crewai:tool-gate")

    if "autogen_tool_gate" not in _wired and _wire_autogen_tool_gate():
        _wired.append("autogen_tool_gate")
        report["wired"].append("autogen:tool-gate")

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
    while _uninstallers:
        uninstall = _uninstallers.pop()
        try:
            uninstall()
        except Exception:
            pass
    _wired.clear()
