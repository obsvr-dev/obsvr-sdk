"""Agent-run controls: loop detection and delegation tracking.

Twins of sdk-typescript/src/policy/industry/devops.ts (``LoopDetector``) and
sdk-typescript/src/policy/industry/agentic.ts (``DelegationTracker``), plus the emitting
halves that live in sdk-typescript/src/integrations/core.ts (``applyLoopDetection`` /
``applyDelegationPolicy``). These are the owning controls for the
``LOOP_DETECTED`` and ``DELEGATION_BLOCKED`` reason codes.

Both are per-agent-run state, built from ``agent_policy`` and held by the
framework integration for the life of one run. Neither is on the LLM hot path:
they are driven once per agent step and once per delegation.

Decision semantics are pinned cross-language by
conformance/fixtures/agent_controls.json, message strings included - an
operator reading ``policy_reason`` on an audit event should not be able to tell
which SDK wrote it.

Config shape follows the rest of ``agent_policy`` (``denied_tools``,
``max_steps``): snake_case here, camelCase in TypeScript. The
``resolve_*`` helpers below are the Python-only half - TypeScript gets the
"is this block usable" answer from its type checker, and a control silently
built from a block with no threshold in it would enforce nothing.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Set

from .config import ResolvedConfig
from .events import emit_event
from .reason_codes import ReasonCode


def _default_compliance() -> Dict[str, Any]:
    """The TS twin's DEFAULT_COMPLIANCE, fresh per call so a caller mutating
    one event's compliance cannot bleed into the next."""
    return {
        "event_type": "llm_call",
        "policy_version": "v1",
        "action_taken": "allowed",
        "action_reason": "none",
        "action_source": "unknown",
        "redacted_types": [],
        "blocked_types": [],
    }


def _positive_int(value: Any) -> Optional[int]:
    """An int > 0, or None for anything that cannot be a threshold."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != int(value) or int(value) <= 0:
        return None
    return int(value)


# ── Loop detection ───────────────────────────────────────────────────────────


class LoopDetector:
    """Sliding-window loop detector.

    Tracks iteration timestamps in a rolling window. When the number of
    iterations within ``window_ms`` exceeds ``max_iterations``, the detector
    fires. Twin: ``LoopDetector`` in sdk-typescript/src/policy/industry/devops.ts.
    """

    __slots__ = ("_max_iterations", "_window_ms", "_action", "_timestamps")

    def __init__(self, max_iterations: int, window_ms: int, action: str) -> None:
        self._max_iterations = max_iterations
        self._window_ms = window_ms
        # Stored verbatim, like the TS twin: the caller declared the action and
        # the emitter compares against it, so normalizing here would make a
        # malformed value behave differently in the two SDKs.
        self._action = action
        self._timestamps: List[float] = []

    def record_iteration(self) -> Optional[Dict[str, Any]]:
        """Record a new iteration. Returns ``{"action", "iteration_count"}``
        when the threshold is exceeded, or None while within limits."""
        now = time.time() * 1000.0
        self._timestamps.append(now)
        cutoff = now - self._window_ms
        self._timestamps = [t for t in self._timestamps if t >= cutoff]
        if len(self._timestamps) > self._max_iterations:
            return {"action": self._action, "iteration_count": len(self._timestamps)}
        return None

    def get_iteration_count(self) -> int:
        """Iteration count currently inside the window."""
        cutoff = time.time() * 1000.0 - self._window_ms
        self._timestamps = [t for t in self._timestamps if t >= cutoff]
        return len(self._timestamps)

    def reset(self) -> None:
        self._timestamps = []


def create_loop_detector(config: Dict[str, Any]) -> LoopDetector:
    """Build a LoopDetector from a ``loop_detection`` block:
    ``max_iterations``, ``window_ms``, ``action`` ('block' | 'escalate').
    Total and verbatim, like the TS ``createLoopDetector``; use
    ``resolve_loop_detection`` first if the block came from operator config."""
    return LoopDetector(
        max_iterations=config.get("max_iterations"),
        window_ms=config.get("window_ms"),
        action=config.get("action"),
    )


def resolve_loop_detection(agent_policy: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The ``loop_detection`` block, or None when it is absent or carries no
    usable threshold. A detector built from ``{}`` would never fire, and a
    control that silently enforces nothing is the failure this returns None to
    avoid."""
    block = (agent_policy or {}).get("loop_detection")
    if not isinstance(block, dict):
        return None
    if _positive_int(block.get("max_iterations")) is None:
        return None
    if _positive_int(block.get("window_ms")) is None:
        return None
    return block


def apply_loop_detection(
    detector: LoopDetector,
    config: ResolvedConfig,
    agent_run_id: str,
    source: str,
    operation: str,
) -> Optional[Dict[str, Any]]:
    """Record an iteration and emit an audit event when the loop fires.

    Returns ``{"action", "iteration_count"}`` for the caller to enforce, or
    None while within limits. The event records the FINDING either way: the
    classification is LOOP_DETECTED whether the threshold escalates or blocks,
    and the caller is what actually stops the run.
    """
    result = detector.record_iteration()
    if result is None:
        return None

    compliance = _default_compliance()
    compliance["event_type"] = "loop_detected"
    compliance["reason_code"] = ReasonCode.LOOP_DETECTED.value
    if result["action"] == "block":
        compliance["action_taken"] = "blocked"
        compliance["action_reason"] = "policy_violation"
        compliance["action_source"] = "policy_rules"

    emit_event(
        config,
        provider="unknown",
        model="unknown",
        operation=f"{operation}.loop_detected",
        source=source,
        prompt="",
        response="",
        success=result["action"] == "escalate",
        metadata={
            "agent_run_id": agent_run_id,
            "loop_iteration_count": result["iteration_count"],
            "loop_action": result["action"],
        },
        compliance=compliance,
    )
    return result


# ── Delegation tracking ──────────────────────────────────────────────────────


class DelegationTracker:
    """Tracks agent-to-agent delegation chains over an in-memory directed
    graph. Twin: ``DelegationTracker`` in sdk-typescript/src/policy/industry/agentic.ts.
    """

    __slots__ = (
        "_max_depth", "_allowed_delegates", "_block_circular", "_graph", "_active_chain",
    )

    def __init__(
        self,
        max_depth: int,
        allowed_delegates: Optional[List[str]] = None,
        block_circular: bool = False,
    ) -> None:
        self._max_depth = max_depth
        self._allowed_delegates = allowed_delegates
        self._block_circular = block_circular
        self._graph: Dict[str, Set[str]] = {}
        self._active_chain: List[str] = []

    def record_delegation(self, from_agent: str, to_agent: str) -> Optional[Dict[str, Any]]:
        """Record a delegation. Returns a violation dict when the allowlist,
        circularity, or depth rule is broken; otherwise records it and returns
        None. The check ORDER is part of the contract and fixture-pinned: a
        delegation that breaks two rules must report the same one in both SDKs.
        """
        if self._allowed_delegates is not None and to_agent not in self._allowed_delegates:
            return {
                "type": "not_allowed",
                "message": f'Agent "{to_agent}" is not in the allowed delegates list',
                "chain": [*self._active_chain, to_agent],
                "depth": len(self._active_chain) + 1,
            }

        if self._block_circular and to_agent in self._active_chain:
            return {
                "type": "circular",
                "message": "Circular delegation detected: "
                + " → ".join([*self._active_chain, to_agent]),
                "chain": [*self._active_chain, to_agent],
                "depth": len(self._active_chain) + 1,
            }

        if len(self._active_chain) >= self._max_depth:
            return {
                "type": "depth_exceeded",
                "message": f"Delegation depth {len(self._active_chain) + 1} "
                f"exceeds max {self._max_depth}",
                "chain": [*self._active_chain, to_agent],
                "depth": len(self._active_chain) + 1,
            }

        self._graph.setdefault(from_agent, set()).add(to_agent)
        self._active_chain.append(to_agent)
        return None

    def return_from_delegation(self) -> None:
        """Pop the last delegate from the active chain (delegation returned)."""
        if self._active_chain:
            self._active_chain.pop()

    def get_chain(self) -> List[str]:
        return list(self._active_chain)

    def get_depth(self) -> int:
        return len(self._active_chain)

    def would_create_circular(self, to_agent: str) -> bool:
        return to_agent in self._active_chain

    def reset(self) -> None:
        self._graph.clear()
        self._active_chain = []


def create_delegation_tracker(config: Dict[str, Any]) -> DelegationTracker:
    """Build a DelegationTracker from a ``delegation_policy`` block:
    ``max_depth``, ``allowed_delegates`` (absent = every delegate allowed, an
    EMPTY list = none), ``block_circular``. Total and verbatim, like the TS
    ``createDelegationTracker``."""
    allowed = config.get("allowed_delegates")
    return DelegationTracker(
        max_depth=config.get("max_depth"),
        allowed_delegates=list(allowed) if allowed is not None else None,
        block_circular=bool(config.get("block_circular", False)),
    )


def resolve_delegation_policy(agent_policy: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The ``delegation_policy`` block, or None when it is absent or declares
    no rule at all. A block with no depth limit still counts when it carries an
    allowlist or blocks circular chains - those enforce on their own."""
    block = (agent_policy or {}).get("delegation_policy")
    if not isinstance(block, dict):
        return None
    if _positive_int(block.get("max_depth")) is not None:
        return block
    if isinstance(block.get("allowed_delegates"), list):
        return block
    if block.get("block_circular"):
        return block
    return None


def has_circular_delegation(chain: List[str]) -> bool:
    """Whether a delegation chain repeats an agent."""
    seen: Set[str] = set()
    for agent in chain:
        if agent in seen:
            return True
        seen.add(agent)
    return False


def apply_delegation_policy(
    tracker: DelegationTracker,
    from_agent: str,
    to_agent: str,
    config: ResolvedConfig,
    agent_run_id: str,
    source: str,
    operation: str,
) -> Optional[Dict[str, Any]]:
    """Record a delegation and emit its audit event. Returns the violation for
    the caller to enforce, or None when the delegation is allowed - which still
    emits, so the chain is on the record either way."""
    violation = tracker.record_delegation(from_agent, to_agent)
    if violation is None:
        compliance = _default_compliance()
        compliance["event_type"] = "delegation"
        emit_event(
            config,
            provider="unknown",
            model="unknown",
            operation=f"{operation}.delegation",
            source=source,
            prompt="",
            response="",
            metadata={
                "agent_run_id": agent_run_id,
                "from_agent": from_agent,
                "to_agent": to_agent,
                "delegation_chain": tracker.get_chain(),
                "delegation_depth": tracker.get_depth(),
            },
            compliance=compliance,
        )
        return None

    compliance = _default_compliance()
    compliance["event_type"] = "delegation"
    compliance["action_taken"] = "blocked"
    compliance["action_reason"] = "policy_violation"
    compliance["reason_code"] = ReasonCode.DELEGATION_BLOCKED.value
    compliance["action_source"] = "policy_rules"
    compliance["policy_reason"] = violation["message"]
    emit_event(
        config,
        provider="unknown",
        model="unknown",
        operation=f"{operation}.delegation_blocked",
        source=source,
        prompt="",
        response="",
        success=False,
        metadata={
            "agent_run_id": agent_run_id,
            "from_agent": from_agent,
            "to_agent": to_agent,
            "violation_type": violation["type"],
            "delegation_chain": violation["chain"],
            "delegation_depth": violation["depth"],
        },
        compliance=compliance,
    )
    return violation
