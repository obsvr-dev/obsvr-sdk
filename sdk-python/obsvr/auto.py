"""Auto-instrumentation: wire the frameworks that expose a clean GLOBAL
registration point, so `obsvr.init(auto=True)` governs them without the user
passing handler objects by hand — the zero-wiring auto-instrumentation UX, but done
without scanning the heap or patching framework internals. Provider module
constructor exports are rebound at registration time; objects or constructor
references saved earlier are outside that boundary.

Cleanly auto-wired (global registration or an explicitly supported class gate):
  * Providers (openai / anthropic) — construct interception via obsvr.register.
  * OpenAI Agents SDK — trace processor plus future Agent construction with
    pre-call model governance and pre-tool input guardrails. Later concrete
    model assignments and mutable tool/handoff list changes are covered too.
  * MCP — future ClientSession construction is returned behind govern_mcp.
  * LlamaIndex — Settings.callback_manager.add_handler(ObsvrLlamaIndexHandler()).
  * CrewAI — official process-global before_tool_call hook.
  * AutoGen/ag2 0.x — supported ConversableAgent tool-execution boundary.

Detected but NOT auto-wired (require per-call / per-agent handlers by design —
obsvr integrates via each framework's official extension point, not by patching
its internals): LangChain (pass ObsvrCallbackHandler() in callbacks=[...]).
CrewAI run/step audit callbacks and AutoGen message policy remain explicit;
their pre-tool execution gates are installed automatically. These residual
bindings are reported so the developer knows the one line to add.

Every step is best-effort and isolated. Deployments that require an automatic
surface must declare its exact key through ``OBSVR_REQUIRED_BINDINGS`` so a
failed or missing attachment stops startup instead of silently degrading.
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
_auto_enabled = False

_AUTO_SURFACES = {
    "openai.client": "openai",
    "anthropic.client": "anthropic",
    "mcp.client": "mcp",
    "openai_agents.tools": "agents",
    "openai_agents.model": "agents",
    "llamaindex.models": "llama_index",
    "crewai.tools": "crewai",
    "autogen.tools": "autogen",
}

_EXPLICIT_SURFACES = {
    "langchain.models": (
        "LangChain exposes callbacks per model or invocation, not a "
        "process-global pre-call registration point"
    ),
    "langchain.tools": (
        "LangChain tool callbacks remain an explicit pre-call handler binding"
    ),
    "llamaindex.tools": (
        "LlamaIndex agent tools require an explicit pre-invocation wrapper"
    ),
}


def _warn_late_production_startup() -> None:
    """Say when automatic interception begins after supported packages loaded."""
    try:
        from .config import get_config

        if get_config().environment != "production":
            return
    except Exception:
        return
    loaded = sorted(
        package
        for package in {
            "openai",
            "anthropic",
            "mcp",
            "agents",
            "llama_index",
            "crewai",
            "autogen",
        }
        if package in sys.modules
    )
    if loaded:
        logger.warning(
            "obsvr automatic governance started after supported packages were "
            "already imported in production: %s. Public aliases are rebound where "
            "supported, but constructor or object references copied before init may "
            "bypass. Start through obsvr-run or initialize before those imports.",
            ", ".join(loaded),
        )


def _module_available(name: str) -> bool:
    import importlib.util

    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _wire_providers() -> List[str]:
    try:
        from .register import install

        installed = install()  # governs openai/anthropic client construction
        from .binding_report import record_binding

        for provider in ("openai", "anthropic"):
            if any(label.startswith(provider + ".") for label in installed):
                record_binding(
                    f"{provider}.client",
                    f"{provider}.public_client_constructors",
                )
        return installed
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
    """Replace future ``agents.Agent`` construction with a governed subclass.

    Concrete models are wrapped at assignment, and mutable tool/handoff lists
    re-run the real pre-execution attachment transaction after every mutation.
    String model aliases remain strings and are governed by the intercepted
    provider client they resolve through.
    """
    if not _module_available("agents"):
        return False
    try:
        import agents  # type: ignore
        from .binding_report import record_binding
        from .integrations.openai_agents import (
            attach_tool_gate,
            govern_model,
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

        def _govern_model_value(value: Any) -> Any:
            if value is None or isinstance(value, str):
                return value
            try:
                from agents.models.interface import Model  # type: ignore
            except Exception:
                return value
            if not isinstance(value, Model):
                return value
            return govern_model(value)

        class _GovernedAgentList(list):
            """A transactional list that refreshes the owner's tool gate."""

            def __init__(self, owner: Any, values: Any) -> None:
                super().__init__(values or [])
                self._obsvr_owner = owner

            def _mutate(self, operation: Callable[[], Any]) -> Any:
                snapshot = list(self)
                try:
                    result = operation()
                    self._obsvr_owner._obsvr_refresh_tool_gate()
                    return result
                except Exception:
                    list.clear(self)
                    list.extend(self, snapshot)
                    raise

            def append(self, value: Any) -> None:
                self._mutate(lambda: list.append(self, value))

            def extend(self, values: Any) -> None:
                self._mutate(lambda: list.extend(self, values))

            def insert(self, index: int, value: Any) -> None:
                self._mutate(lambda: list.insert(self, index, value))

            def pop(self, index: int = -1) -> Any:
                return self._mutate(lambda: list.pop(self, index))

            def remove(self, value: Any) -> None:
                self._mutate(lambda: list.remove(self, value))

            def clear(self) -> None:
                self._mutate(lambda: list.clear(self))

            def reverse(self) -> None:
                self._mutate(lambda: list.reverse(self))

            def sort(self, *args: Any, **kwargs: Any) -> None:
                self._mutate(lambda: list.sort(self, *args, **kwargs))

            def __setitem__(self, key: Any, value: Any) -> None:
                self._mutate(lambda: list.__setitem__(self, key, value))

            def __delitem__(self, key: Any) -> None:
                self._mutate(lambda: list.__delitem__(self, key))

            def __iadd__(self, values: Any) -> Any:
                self.extend(values)
                return self

            def __imul__(self, count: int) -> Any:
                self._mutate(lambda: list.__imul__(self, count))
                return self

        class _AutoGovernedAgentMixin:
            def _obsvr_refresh_tool_gate(self) -> None:
                if not getattr(self, "_obsvr_auto_ready", False):
                    return
                _uninstallers.append(attach_tool_gate(self))

            def __setattr__(self, name: str, value: Any) -> None:
                if name == "model":
                    value = _govern_model_value(value)
                elif name in {"tools", "handoffs"} and isinstance(value, list):
                    if not isinstance(value, _GovernedAgentList):
                        value = _GovernedAgentList(self, value)
                super().__setattr__(name, value)
                if name in {"tools", "handoffs"}:
                    self._obsvr_refresh_tool_gate()

            def _obsvr_finish_init(self) -> None:
                object.__setattr__(self, "_obsvr_auto_ready", True)
                self._obsvr_refresh_tool_gate()

        if getattr(original, "__parameters__", ()):
            class GovernedAgent(  # type: ignore[misc,valid-type,no-redef]
                _AutoGovernedAgentMixin,
                original[_TContext],
                Generic[_TContext],
            ):
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    object.__setattr__(self, "_obsvr_auto_ready", False)
                    super().__init__(*args, **kwargs)
                    self._obsvr_finish_init()
        else:
            class GovernedAgent(  # type: ignore[misc,valid-type,no-redef]
                _AutoGovernedAgentMixin,
                original,
            ):
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    object.__setattr__(self, "_obsvr_auto_ready", False)
                    super().__init__(*args, **kwargs)
                    self._obsvr_finish_init()

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
        import time

        initialized_at_ms = int(time.time() * 1000)
        record_binding(
            "openai_agents.tools",
            "agents.Agent.tools",
            metadata={
                "enforcement_depth": "enforce",
                "initialized_at_ms": initialized_at_ms,
                "exclusions": [
                    "hosted tools",
                    "tools executed outside the governed Agent boundary",
                ],
            },
        )
        record_binding(
            "openai_agents.model",
            "agents.Agent.model",
            metadata={
                "enforcement_depth": "enforce",
                "initialized_at_ms": initialized_at_ms,
                "exclusions": [
                    "string model aliases resolved through an ungoverned provider client"
                ],
            },
        )
        return True
    except Exception as exc:
        try:
            from .binding_report import record_binding

            record_binding("openai_agents.tools", "agents.Agent.tools", exc)
            record_binding("openai_agents.model", "agents.Agent.model", exc)
        except Exception:
            pass
        logger.debug("obsvr.auto: openai-agents tool gate skipped: %s", exc)
        return False


def _wire_llamaindex() -> bool:
    if not _module_available("llama_index"):
        return False


def _wire_mcp_client_gate() -> bool:
    """Intercept future construction of the official MCP ClientSession."""
    if not _module_available("mcp"):
        return False
    try:
        import mcp  # type: ignore
        import mcp.client.session as session_module  # type: ignore
        from .binding_report import record_binding
        from .integrations.mcp import govern_mcp

        original = getattr(mcp, "ClientSession", None)
        if not isinstance(original, type):
            raise ImportError("mcp exports no ClientSession class")
        if getattr(original, "_obsvr_auto_mcp_session_class", False):
            return True

        class GovernedClientSession(original):  # type: ignore[misc,valid-type]
            def __new__(_cls, *args: Any, **kwargs: Any) -> Any:  # noqa: N804
                return govern_mcp(original(*args, **kwargs))

        GovernedClientSession.__name__ = original.__name__
        GovernedClientSession.__qualname__ = original.__qualname__
        GovernedClientSession.__module__ = original.__module__
        GovernedClientSession._obsvr_auto_mcp_session_class = True

        rebound: List[tuple[Any, str]] = []
        for module in (mcp, session_module):
            for name, value in list(vars(module).items()):
                if value is not original:
                    continue
                setattr(module, name, GovernedClientSession)
                if getattr(module, name, None) is GovernedClientSession:
                    rebound.append((module, name))
        if getattr(mcp, "ClientSession", None) is not GovernedClientSession:
            raise RuntimeError("mcp.ClientSession refused constructor substitution")

        removed = False

        def _uninstall() -> None:
            nonlocal removed
            if removed:
                return
            removed = True
            for module, name in rebound:
                try:
                    if getattr(module, name, None) is GovernedClientSession:
                        setattr(module, name, original)
                except Exception:
                    pass

        _uninstallers.append(_uninstall)
        import time

        record_binding(
            "mcp.client",
            "mcp.ClientSession",
            metadata={
                "enforcement_depth": "enforce",
                "initialized_at_ms": int(time.time() * 1000),
                "exclusions": [
                    "hosted or provider-side tools outside the client session"
                ],
            },
        )
        return True
    except Exception as exc:
        try:
            from .binding_report import record_binding

            record_binding("mcp.client", "mcp.ClientSession", exc)
        except Exception:
            pass
        logger.debug("obsvr.auto: MCP ClientSession gate skipped: %s", exc)
        return False
    try:
        from llama_index.core import Settings  # type: ignore
        from llama_index.core.callbacks import CallbackManager  # type: ignore
        from .integrations.llamaindex import ObsvrLlamaIndexHandler

        handler = ObsvrLlamaIndexHandler()
        cm = getattr(Settings, "callback_manager", None) or CallbackManager([])
        cm.add_handler(handler)
        Settings.callback_manager = cm
        from .binding_report import record_binding

        import time

        record_binding(
            "llamaindex.models",
            "llama_index.core.Settings.callback_manager",
            metadata={
                "enforcement_depth": "enforce",
                "initialized_at_ms": int(time.time() * 1000),
                "exclusions": ["LlamaIndex agent tools"],
            },
        )
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
        from .binding_report import record_binding

        import time

        record_binding(
            "crewai.tools",
            "crewai.before_tool_call",
            metadata={
                "enforcement_depth": "enforce",
                "initialized_at_ms": int(time.time() * 1000),
                "exclusions": ["run and step telemetry callbacks"],
            },
        )
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
        from .binding_report import record_binding

        import time

        record_binding(
            "autogen.tools",
            "autogen.ConversableAgent.execute_function",
            metadata={
                "enforcement_depth": "enforce",
                "initialized_at_ms": int(time.time() * 1000),
                "exclusions": ["message policy outside the tool execution boundary"],
            },
        )
        return True
    except Exception as exc:
        logger.debug("obsvr.auto: AutoGen tool gate skipped: %s", exc)
        return False


# Frameworks obsvr integrates via per-call/per-agent handlers (no global hook).
_MANUAL_HINTS = {
    "langchain_core": "LangChain: pass obsvr.integrations.langchain.ObsvrCallbackHandler() in callbacks=[...]",
    "crewai": "CrewAI run/step audit: wire obsvr.integrations.crewai.make_crew_callbacks(...) on your Crew; the pre-tool gate is automatic where supported",
    "autogen": "AutoGen message policy: call obsvr.integrations.autogen.register_obsvr(agent); the tool-execution gate is automatic on supported ag2 0.x",
    "agents": "OpenAI Agents tracing remains observe-only; future intercepted Agents govern concrete models and local function tools, while hosted and dynamically converted MCP tools must be governed at their execution boundary",
}


def enable_auto_instrumentation() -> Dict[str, Any]:
    """Wire every framework that supports clean global registration. Returns a
    report: {"wired": [...], "manual": [...]}. Idempotent and non-throwing."""
    global _auto_enabled
    _auto_enabled = True
    report: Dict[str, Any] = {"wired": [], "manual": []}
    _warn_late_production_startup()

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

    if "mcp_client" not in _wired and _wire_mcp_client_gate():
        _wired.append("mcp_client")
        report["wired"].append("mcp:client")

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


def auto_governance_status() -> Dict[str, Any]:
    """Report every automatic surface as armed, bound, or not-applicable."""
    from .binding_report import integration_bindings

    recorded = integration_bindings()
    bindings: Dict[str, Dict[str, str]] = {}
    for surface, package in _AUTO_SURFACES.items():
        entries = recorded.get(surface)
        if entries and all(entry.get("bound") for entry in entries.values()):
            bindings[surface] = {"state": "bound"}
            continue
        if entries:
            detail = next(
                (
                    str(entry.get("error"))
                    for entry in entries.values()
                    if not entry.get("bound") and entry.get("error")
                ),
                "automatic attachment did not bind",
            )
            bindings[surface] = {"state": "not-applicable", "detail": detail}
            continue
        if not _module_available(package):
            bindings[surface] = {
                "state": "not-applicable",
                "detail": f"optional package {package} is not installed",
            }
            continue
        if _auto_enabled:
            bindings[surface] = {
                "state": "not-applicable",
                "detail": "automatic attachment ran but this surface did not bind",
            }
        else:
            bindings[surface] = {"state": "armed"}
    for surface, detail in _EXPLICIT_SURFACES.items():
        bindings[surface] = {"state": "not-applicable", "detail": detail}
    return {"enabled": _auto_enabled, "bindings": bindings}


def _reset_auto() -> None:
    """Test hook: clear the idempotency guard."""
    global _auto_enabled
    while _uninstallers:
        uninstall = _uninstallers.pop()
        try:
            uninstall()
        except Exception:
            pass
    _wired.clear()
    _auto_enabled = False
