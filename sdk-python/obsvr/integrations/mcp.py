"""MCP (Model Context Protocol) governance for Python.

Parity with sdk/src/integrations/mcp.ts:

- patch_mcp(ClientSessionClass) patches call_tool once on the class; every
  tool call on every connected MCP server is then policy-checked
  (allow/deny lists), PII-scanned, run through the pre-call hook (HITL),
  and audited with the same event shape as the TS SDK.
- list_tools is patched for tool-poisoning defense: tool descriptions are
  scanned at discovery for deterministic injection patterns. Flagged tools
  emit a policy_flag event; with mcp_tool_policy["block_poisoned_tools"]
  they are stripped from the list before the model sees them.

Usage:
    from mcp import ClientSession
    import obsvr
    from obsvr.integrations.mcp import patch_mcp

    obsvr.init(api_key="...", ingest_url="...",
               mcp_tool_policy={"denied_tools": ["delete_file"]})
    patch_mcp(ClientSession)
"""

import inspect
import weakref
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

from ..config import ResolvedConfig, get_config, try_get_config
from ..events import build_audit_event
from ..normalize import normalize_for_matching
from ..policy import apply_pre_call_policy
from ..remote import is_enforcement_degraded
from ..response_scan import sanitize_mcp_result, scan_mcp_tool_result
from ..tool_pinning import (
    ToolPinStore,
    evaluate_tool_pin,
    resolve_tool_pinning,
    tool_descriptor_hash,
)
from ..rules import derive_policy_version
from ..sender import send_audit_async, should_sample

SOURCE = "mcp_python"
_PATCHED_ATTR = "_obsvr_mcp_patched"

# ── Tool-poisoning patterns (exact port of the TS list) ─────────────────────

TOOL_POISONING_PATTERNS: List[Dict[str, Any]] = [
    {
        "reason": "embedded_instruction_override",
        "re": re.compile(
            r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|other|above)\s+(instructions?|tools?|rules?)",
            re.I,
        ),
    },
    {
        "reason": "embedded_directive_to_model",
        "re": re.compile(
            r"\b(IMPORTANT|SYSTEM|NOTE)\s*(NOTE|MESSAGE)?\s*:\s*(before|first|always|you must|do not tell)",
            re.I,
        ),
    },
    {
        "reason": "cross_tool_invocation",
        "re": re.compile(
            r"\b(first|before)\s+(calling|using)\s+(any\s+other|any|other|this)\s+tools?,?\s+(call|use|invoke)\b",
            re.I,
        ),
    },
    {
        "reason": "exfiltration_directive",
        "re": re.compile(
            r"\b(send|post|forward|upload|transmit)\s+(all\s+)?((conversation|context|chat|user)\s+)?(history|messages?|data|contents?|context)\s+(to|at)\b",
            re.I,
        ),
    },
    {
        "reason": "concealment_directive",
        "re": re.compile(
            r"\b(do\s+not|don'?t|never)\s+(tell|show|reveal|mention|inform)\s+(the\s+)?(user|human)\b",
            re.I,
        ),
    },
]


def scan_tool_description(tool: Any) -> List[str]:
    """Scan one tool definition (name + description) for poisoning patterns."""
    name = getattr(tool, "name", None) or (tool.get("name") if isinstance(tool, dict) else "") or ""
    description = (
        getattr(tool, "description", None)
        or (tool.get("description") if isinstance(tool, dict) else "")
        or ""
    )
    # Normalize before matching (NFKC + confusable-fold + zero-width/bidi strip),
    # like the PII/rules scanners — otherwise a malicious server hides a poisoning
    # directive behind homoglyphs / zero-width chars and evades every pattern.
    text = normalize_for_matching(f"{name} {description}")
    return [p["reason"] for p in TOOL_POISONING_PATTERNS if p["re"].search(text)]


# ── Policy helpers ───────────────────────────────────────────────────────────

def _check_tool_policy(tool_name: str, policy: Dict[str, Any]) -> Dict[str, Any]:
    denied = policy.get("denied_tools") or policy.get("deniedTools") or []
    allowed = policy.get("allowed_tools") or policy.get("allowedTools")
    if tool_name in denied:
        return {"allowed": False, "reason": "tool_denied"}
    if allowed is not None and tool_name not in allowed:
        return {"allowed": False, "reason": "tool_not_in_allowlist"}
    return {"allowed": True, "reason": ""}


def _extract_mcp_prompt(tool_name: str, arguments: Optional[Dict[str, Any]]) -> str:
    try:
        return f"{tool_name}({json.dumps(arguments or {}, default=str)})"
    except Exception:
        return f"{tool_name}(...)"


def _render_result_text(result_obj: Any) -> str:
    """Render an MCP CallToolResult (or bare value) to text for scanning/audit."""
    try:
        content = getattr(result_obj, "content", None)
        if content is None and isinstance(result_obj, dict):
            content = result_obj.get("content")
        if isinstance(content, list):
            parts = []
            for c in content:
                text = getattr(c, "text", None)
                if text is None and isinstance(c, dict):
                    text = c.get("text")
                parts.append(str(text or ""))
            return "\n".join(parts)
        if isinstance(result_obj, str):
            return result_obj
    except Exception:
        pass
    return ""


def _mcp_tool_policy(config: ResolvedConfig) -> Optional[Dict[str, Any]]:
    return getattr(config, "mcp_tool_policy", None) or getattr(config, "mcpToolPolicy", None)


def _emit(config: ResolvedConfig, **kwargs: Any) -> None:
    event = build_audit_event(config, **kwargs)
    # EV-2: a governed MCP event (blocked tool, redaction, tool-poisoning flag)
    # is ALWAYS recorded — only clean allowed tool calls are subject to sampling.
    # The TS MCP path routes through emitIntegrationEvent, which never samples;
    # gating every emission on should_sample dropped forensic evidence for
    # denied tools under sample_rate < 1.
    governed = event.get("action_taken", "allowed") != "allowed" or event.get("success") is False
    if governed or should_sample(config.sample_rate):
        send_audit_async(config, event)


class McpToolBlockedError(RuntimeError):
    """Raised when a tool call is blocked by policy (denylist, allowlist, PII, hook)."""


# ── The patch ────────────────────────────────────────────────────────────────

def _build_governed_mcp_callables(
    base_config: Optional[ResolvedConfig],
    base_options: Optional[Dict[str, Any]],
    original_call_tool: Any,
    original_list_tools: Any,
):
    """Build the governed ``call_tool`` / ``list_tools`` callables wrapping the
    given originals — the single home of the MCP enforcement logic, shared by
    the deprecated class-patch (:func:`patch_mcp`) and the non-mutating instance
    wrapper (:func:`govern_mcp`).

    Each returned callable takes the real MCP session as its first argument and
    invokes ``original_*(session, ...)``, so it behaves identically whether that
    session came from a patched class or from a wrapper delegating to a live
    instance. Returns ``(governed_call_tool, governed_list_tools_or_None)``.

    ``base_options`` mirrors the TS ``obsvrGovernMCP(Client, config, opts)``
    per-client options (``user_id`` / ``service_name`` / ``metadata``): the
    identity is threaded into the pre-call rules context so USER-SCOPED (and
    service/tenant-scoped) quota rules meter the RIGHT bucket, and attached to
    the audit as the caller principal (ADR-6).
    """
    base_options = base_options or {}

    # Cap on per-tool hashes carried in inventory-event metadata (TS parity).
    MAX_TOOL_HASHES_ON_EVENT = 50

    def _current_config() -> ResolvedConfig:
        return try_get_config() or base_config or get_config()

    # Per-session pin stores (descriptor content-hash pinning, rug-pull
    # defense): tool names are only unique per server, so TOFU pins must not
    # be shared across sessions. Keyed weakly on the REAL session object,
    # which both the patch path and the govern path pass as ``self`` — so the
    # scoping is per-instance on both paths (TS parity: per-client stores).
    _pin_stores: "weakref.WeakKeyDictionary[Any, ToolPinStore]" = weakref.WeakKeyDictionary()
    _pin_store_by_id: Dict[int, ToolPinStore] = {}

    def _pin_store_for(session: Any) -> ToolPinStore:
        try:
            store = _pin_stores.get(session)
            if store is None:
                store = ToolPinStore()
                _pin_stores[session] = store
            return store
        except TypeError:
            # Non-weakref-able session (e.g. __slots__ without __weakref__):
            # key by id() so each session keeps its OWN store (a shared store
            # would cross-contaminate two servers' TOFU pins). id() reuse after
            # GC is a theoretical, low-probability aliasing risk accepted for
            # this uncommon session shape; a real MCP ClientSession is
            # weakref-able and never reaches here.
            store = _pin_store_by_id.get(id(session))
            if store is None:
                store = ToolPinStore()
                _pin_store_by_id[id(session)] = store
            return store

    def _tool_name_of(tool: Any) -> str:
        name = getattr(tool, "name", None)
        if name is None and isinstance(tool, dict):
            name = tool.get("name")
        # Match TS `name ?? "unknown"`: a present empty string "" is kept
        # (only a truly absent name becomes "unknown").
        return name if name is not None else "unknown"

    def _principal_and_meta():
        """Caller principal + rules-eval identity metadata from the bound options."""
        principal = {
            "user_id": base_options.get("user_id"),
            "service_name": base_options.get("service_name"),
            "tenant_id": (base_options.get("metadata") or {}).get("tenant_id"),
        }
        meta = dict(base_options.get("metadata") or {})
        if principal["user_id"] is not None:
            meta["user_id"] = principal["user_id"]
        if principal["service_name"] is not None:
            meta["service_name"] = principal["service_name"]
        if principal["tenant_id"] is not None:
            meta["tenant_id"] = principal["tenant_id"]
        return principal, meta

    async def governed_call_tool(self: Any, name: str, arguments: Optional[Dict[str, Any]] = None, **kw: Any) -> Any:
        cfg = _current_config()
        tool_name = name or "unknown"
        prompt_text = _extract_mcp_prompt(tool_name, arguments)
        start = time.monotonic()
        principal, identity_meta = _principal_and_meta()
        event_options = base_options or None

        # 0. Enforcement-integrity gate: kill switch / stale policy with
        #    fail_mode="closed" (parity with TS mcp.ts). Without this, an MCP
        #    deployment with neither pii_policy nor on_pre_call configured
        #    would keep calling tools after the project was paused or the key
        #    revoked — the gate must not depend on optional policy config.
        degraded = is_enforcement_degraded(cfg)
        if degraded["degraded"]:
            gate_reason = (
                "Project paused or API key revoked (SDK kill switch)"
                if degraded["reason"] == "project_paused_or_key_revoked"
                else f"Policy sync unavailable with fail_mode=closed ({degraded['reason']})"
            )
            _emit(
                cfg,
                provider="mcp", model="mcp", operation="mcp.tool.call",
                source=SOURCE, prompt=prompt_text, response="", success=False,
                metadata={"tool_name": tool_name}, options=event_options,
                compliance={
                    "event_type": "blocked_call",
                    "policy_version": derive_policy_version(cfg.policy_rules or []),
                    "action_taken": "blocked",
                    "action_reason": "policy_violation",
                    "action_source": "policy_rules",
                    "redacted_types": [],
                    "blocked_types": [],
                    "rule_id": f"sdk:{degraded['reason']}",
                    "policy_reason": gate_reason,
                },
            )
            raise McpToolBlockedError(f"[obsvr] MCP tool call blocked: {gate_reason}")

        # 0.5 Descriptor content-hash pin gate (rug-pull defense). The
        #     descriptor is not on the wire at call time, so this consults the
        #     verdict cached at the most recent list_tools. Runs after the
        #     integrity gate (a paused project blocks first — EV-3 precedence)
        #     and before allow/deny and any argument scanning: a swapped tool
        #     is refused on IDENTITY. TS parity: runGovernedCallTool step 0.5.
        pinning = resolve_tool_pinning(_mcp_tool_policy(cfg))
        pin_verdict = None
        pin_store = _pin_store_for(self) if pinning else None
        if pinning and pin_store is not None:
            pin_verdict = pin_store.get_verdict(tool_name)
            flag_for = "block" if pinning["mode"] == "block" else "flag"
            if pin_verdict is None and pinning["require_pin"]:
                # Called without ever being listed: nothing was verified.
                # Strict mode treats that as a violation; lenient mode passes
                # it as unverified.
                pin_verdict = {
                    "status": "unpinned",
                    "enforcement": flag_for,
                    "reason": "tool_not_discovered",
                }
            elif pin_verdict is None and pin_store.saturated():
                # The verdict store hit its cap during discovery (an
                # attacker-flooded listing), so this tool was never verified.
                # Fail CLOSED: a missing verdict under saturation is a
                # violation, not a pass — otherwise a block-mode config-pin
                # mismatch becomes callable. TS parity.
                pin_verdict = {
                    "status": "unpinned",
                    "enforcement": flag_for,
                    "reason": "pin_unverified_store_saturated",
                }
            elif pin_verdict is not None and pin_verdict["enforcement"] != "none":
                # A cached VIOLATION (mismatch, or strict-mode pin_required):
                # its status is mode-independent, but its enforcement level
                # tracks the mode. Re-derive against the CURRENT mode so a
                # runtime warn<->block flip takes effect immediately. A lenient
                # pass (enforcement "none") is untouched.
                pin_verdict = {**pin_verdict, "enforcement": flag_for}
            if pin_verdict is not None and pin_verdict["enforcement"] == "block":
                reason_text = (
                    "tool_descriptor_pin_violation: %s (%s)"
                    % (tool_name, pin_verdict.get("reason") or pin_verdict["status"])
                )
                # Caller metadata first, then sealed pin stamps (TS precedence).
                pin_block_meta = dict((event_options or {}).get("metadata") or {})
                pin_block_meta["tool_name"] = tool_name
                pin_block_meta["tool_pin_status"] = pin_verdict["status"]
                if pin_verdict.get("expected") is not None:
                    pin_block_meta["tool_pin_expected"] = pin_verdict["expected"]
                if pin_verdict.get("observed") is not None:
                    pin_block_meta["tool_descriptor_hash"] = pin_verdict["observed"]
                _emit(
                    cfg,
                    provider="mcp", model="mcp", operation="mcp.tool.call",
                    source=SOURCE, prompt=prompt_text, response="",
                    success=False, status_code=403,
                    metadata=pin_block_meta, options=event_options,
                    compliance={
                        "event_type": "blocked_call",
                        "policy_version": derive_policy_version(cfg.policy_rules or []),
                        "action_taken": "blocked",
                        "action_reason": "policy_violation",
                        "action_source": "builtin",
                        "redacted_types": [],
                        "blocked_types": [],
                        "rule_id": "sdk:mcp_tool_pin",
                        "policy_reason": reason_text,
                    },
                )
                raise McpToolBlockedError(f"[obsvr] MCP tool call blocked: {reason_text}")

        # 1. Tool allow/deny policy
        policy = _mcp_tool_policy(cfg)
        if policy:
            verdict = _check_tool_policy(tool_name, policy)
            if not verdict["allowed"]:
                _emit(
                    cfg,
                    provider="mcp", model="mcp", operation="mcp.tool.call",
                    source=SOURCE, prompt=prompt_text, response="", success=False,
                    metadata={"tool_name": tool_name}, options=event_options,
                    compliance={
                        "event_type": "blocked_call",
                        "policy_version": derive_policy_version(cfg.policy_rules or []),
                        "action_taken": "blocked",
                        "action_reason": "policy_violation",
                        "action_source": "builtin",
                        "redacted_types": [],
                        "blocked_types": [],
                        "policy_reason": verdict["reason"],
                    },
                )
                raise McpToolBlockedError(
                    f"[obsvr] MCP tool blocked by policy: {tool_name} ({verdict['reason']})"
                )

        # 2. PII + rules + pre-call hook (HITL); fail_mode honored inside.
        #    Identity metadata is threaded so scoped quota rules bucket correctly.
        compliance = None
        final_prompt = prompt_text
        # Also run when a canary is minted: a canary in tool ARGUMENTS is a
        # CRITICAL exfil surface, and the canary scan lives inside
        # apply_pre_call_policy (TS parity: mcp.ts).
        from ..canary import canary_registry_size
        from ..session_taint import session_taint_size
        if (
            cfg.pii_policy is not None
            or cfg.on_pre_call is not None
            or canary_registry_size() > 0
            or session_taint_size() > 0
        ):
            try:
                result = apply_pre_call_policy(
                    prompt_text, cfg, provider="mcp", operation="mcp.tool.call",
                    metadata=identity_meta or None,
                )
                compliance = result["compliance"]
                final_prompt = result["redacted_prompt"]
                if result["decision"] == "block":
                    block_meta = {"tool_name": tool_name}
                    if result.get("security_normalized") is not None:
                        # Server-side normalizer mirror: which view defeated the obfuscation.
                        block_meta["security_normalized"] = result["security_normalized"]
                    if result.get("canary_telemetry") is not None:
                        # CRITICAL canary leak evidence on the telemetry channel.
                        block_meta["obsvr_telemetry"] = result["canary_telemetry"]
                    _emit(
                        cfg,
                        provider="mcp", model="mcp", operation="mcp.tool.call",
                        source=SOURCE, prompt=final_prompt, response="", success=False,
                        metadata=block_meta, options=event_options,
                        compliance=compliance,
                    )
                    raise McpToolBlockedError(
                        "[obsvr] MCP tool call blocked by policy (canary leak)"
                        if result.get("canary_telemetry") is not None
                        else "[obsvr] MCP tool call blocked by policy (PII detected)"
                    )
            except McpToolBlockedError:
                raise
            except Exception as e:
                # Parity with TS mcp.ts: a policy engine that cannot render a
                # verdict must not be treated as approval under fail_mode=
                # "closed" — block. fail_mode="open" (default): the evaluation
                # error does not block the tool call.
                if cfg.fail_mode == "closed":
                    raise McpToolBlockedError(
                        "[obsvr] MCP tool call blocked: policy evaluation failed "
                        f"and fail_mode=closed ({e})"
                    ) from e

        # 3. Execute the original call
        try:
            result_obj = await original_call_tool(self, name, arguments, **kw)
        except McpToolBlockedError:
            raise
        except BaseException as e:
            latency_ms = (time.monotonic() - start) * 1000
            event_compliance = compliance or {
                "event_type": "tool_call",
                "policy_version": derive_policy_version(cfg.policy_rules or []),
                "action_taken": "allowed",
                "action_reason": "none",
                "action_source": "unknown",
                "redacted_types": [],
                "blocked_types": [],
            }
            if event_compliance.get("event_type") == "llm_call":
                event_compliance["event_type"] = "tool_call"
            _emit(
                cfg,
                provider="mcp", model="mcp", operation="mcp.tool.call",
                source=SOURCE, prompt=final_prompt, response=str(e)[:500],
                latency_ms=latency_ms, success=False, error=e,
                metadata={"tool_name": tool_name}, options=event_options,
                compliance=event_compliance,
            )
            raise

        # 4. Response-side scan (ADR-6): the tool RESULT is the exfil/poisoning
        #    channel. Scan it for PII/secrets/injection and BLOCK / SANITIZE /
        #    LOG before it reaches the caller — mirrors the request-side scanner.
        response_text = _render_result_text(result_obj)
        resp_scan = scan_mcp_tool_result(response_text, cfg, principal)
        latency_ms = (time.monotonic() - start) * 1000

        if resp_scan["action"] == "block":
            _emit(
                cfg,
                provider="mcp", model="mcp", operation="mcp.tool.call",
                source=SOURCE, prompt=final_prompt, response="",
                latency_ms=latency_ms, success=False, status_code=403,
                metadata={
                    "tool_name": tool_name,
                    "response_blocked": True,
                    # Server-side normalizer mirror: which view defeated the obfuscation.
                    **(
                        {"security_normalized": resp_scan["via"]}
                        if resp_scan.get("via") is not None
                        else {}
                    ),
                    # CRITICAL canary leak evidence (tool result) on telemetry.
                    **(
                        {"obsvr_telemetry": resp_scan["canary_telemetry"]}
                        if resp_scan.get("canary_telemetry") is not None
                        else {}
                    ),
                },
                options=event_options,
                compliance={
                    "event_type": "blocked_call",
                    "policy_version": resp_scan["policy_version"],
                    "action_taken": "blocked",
                    "action_reason": (
                        "policy_violation"
                        if resp_scan["action_reason"] == "none"
                        else resp_scan["action_reason"]
                    ),
                    "action_source": (
                        "policy_rules"
                        if resp_scan["action_source"] == "unknown"
                        else resp_scan["action_source"]
                    ),
                    "redacted_types": resp_scan["redacted_types"],
                    "blocked_types": resp_scan["blocked_types"],
                    "policy_reason": resp_scan["policy_reason"] or "tool result blocked by policy",
                },
            )
            raise McpToolBlockedError(
                f"[obsvr] MCP tool result blocked by policy: {tool_name} "
                f"({resp_scan['policy_reason'] or 'policy violation'})"
            )

        # SANITIZE: redact the offending spans from the result before returning.
        final_result = result_obj
        if resp_scan["action"] == "sanitize":
            final_result = sanitize_mcp_result(result_obj)
            response_text = _render_result_text(final_result)

        event_compliance = compliance or {
            "event_type": "tool_call",
            "policy_version": derive_policy_version(cfg.policy_rules or []),
            "action_taken": "allowed",
            "action_reason": "none",
            "action_source": "unknown",
            "redacted_types": [],
            "blocked_types": [],
        }
        if event_compliance.get("event_type") == "llm_call":
            event_compliance["event_type"] = "tool_call"
        if resp_scan["action"] == "sanitize" and event_compliance.get("action_taken") != "blocked":
            event_compliance["action_taken"] = "redacted"
            if event_compliance.get("action_reason") in (None, "none"):
                event_compliance["action_reason"] = resp_scan["action_reason"]
            if event_compliance.get("action_source") in (None, "unknown"):
                event_compliance["action_source"] = resp_scan["action_source"]
            merged = list(event_compliance.get("redacted_types") or [])
            for t in resp_scan["redacted_types"]:
                if t not in merged:
                    merged.append(t)
            event_compliance["redacted_types"] = merged
            if not event_compliance.get("rule_id"):
                event_compliance["rule_id"] = resp_scan["rule_id"]
            if not event_compliance.get("policy_reason"):
                event_compliance["policy_reason"] = resp_scan["policy_reason"]

        event_metadata = {"tool_name": tool_name}
        if resp_scan["detected_types"]:
            event_metadata["response_detected_types"] = resp_scan["detected_types"]
        if resp_scan.get("via") is not None:
            # Server-side normalizer mirror: a detect-only view hit is still sealed evidence.
            event_metadata["security_normalized"] = resp_scan["via"]
        if pinning and pin_store is not None:
            # Pin surface: the descriptor hash that governed this call rides
            # the signed event (sealing), plus the pin status.
            event_metadata["tool_pin_status"] = (pin_verdict or {}).get("status") or "unverified"
            if (pin_verdict or {}).get("observed") is not None:
                event_metadata["tool_descriptor_hash"] = pin_verdict["observed"]
            if pin_verdict is not None and pin_verdict.get("enforcement") == "flag":
                event_metadata["pin_violation"] = pin_verdict.get("reason") or pin_verdict["status"]
        _emit(
            cfg,
            provider="mcp", model="mcp", operation="mcp.tool.call",
            source=SOURCE, prompt=final_prompt, response=response_text,
            latency_ms=latency_ms, success=True,
            metadata=event_metadata, options=event_options,
            compliance=event_compliance,
        )
        return final_result

    # ── Tool-poisoning defense on discovery ─────────────────────────────────
    governed_list_tools = None
    if original_list_tools is not None and inspect.iscoroutinefunction(original_list_tools):

        async def governed_list_tools(self: Any, *args: Any, **kw: Any) -> Any:
            cfg = _current_config()
            result = await original_list_tools(self, *args, **kw)
            tools = getattr(result, "tools", None) or []

            flagged = []
            for tool in tools:
                reasons = scan_tool_description(tool)
                if reasons:
                    # Use the dual-access name (matches the strip filter and
                    # pin loop) so flag/strip/pin all resolve dict-shaped tools
                    # to the SAME name — otherwise block_poisoned_tools fails to
                    # strip a poisoned DICT descriptor (regression parity).
                    flagged.append({"name": _tool_name_of(tool), "reasons": reasons})

            # ── Descriptor content-hash pinning (rug-pull defense) ──────────
            # Hash every listed descriptor, compare against config pins
            # (authoritative) then the per-session TOFU store, record first
            # sightings, and cache the verdict for the call-time gate. All
            # metadata below is added ONLY when pinning is enabled, so
            # existing events stay byte-identical. TS parity:
            # processListToolsResult.
            pinning = resolve_tool_pinning(_mcp_tool_policy(cfg))
            pin_store = _pin_store_for(self) if pinning else None
            pin_violations = []
            tool_hashes = {}
            tool_hashes_truncated = False
            missing_pinned = None
            pin_blocked_names = set()
            if pinning and pin_store is not None:
                for tool in tools:
                    name = _tool_name_of(tool)
                    try:
                        observed = tool_descriptor_hash(tool)
                    except Exception:
                        observed = None  # evaluate_tool_pin fails closed
                    if observed is not None:
                        if len(tool_hashes) < MAX_TOOL_HASHES_ON_EVENT:
                            tool_hashes[name] = observed
                        else:
                            tool_hashes_truncated = True
                    config_pin = (pinning.get("pins") or {}).get(name)
                    # Strict mode disables TOFU entirely (see evaluate_tool_pin);
                    # do not even read the TOFU pin so it cannot influence.
                    tofu_pin = None if pinning["require_pin"] else pin_store.get_tofu_pin(name)
                    verdict = evaluate_tool_pin(
                        config_pin=config_pin,
                        tofu_pin=tofu_pin,
                        observed_hash=observed,
                        mode=pinning["mode"],
                        require_pin=pinning["require_pin"],
                    )
                    # Record TOFU only for a genuinely unpinned tool that PASSED
                    # — never under require_pin (a pin_required violation must
                    # not ratify its own hash for the next listing).
                    if (
                        not pinning["require_pin"]
                        and config_pin is None
                        and tofu_pin is None
                        and observed is not None
                    ):
                        pin_store.record_tofu_pin(name, observed)  # first sighting
                    pin_store.set_verdict(name, verdict)
                    if verdict["enforcement"] != "none":
                        v = {"name": name, "reason": verdict.get("reason") or verdict["status"]}
                        if verdict.get("expected") is not None:
                            v["expected"] = verdict["expected"]
                        if verdict.get("observed") is not None:
                            v["observed"] = verdict["observed"]
                        pin_violations.append(v)
                        if verdict["enforcement"] == "block":
                            pin_blocked_names.add(name)
                # Removal detection: a tool THIS SESSION recorded a TOFU pin
                # for, now gone from a full (unpaginated) listing — a dropped
                # validator/guard signal. Scoped to TOFU-seen names (not the
                # global config-pin set, which would spuriously flag pins meant
                # for other servers on every listing). A non-None pagination
                # cursor means a page, so absence is not removal; None cursor =
                # full listing (parity with TS null/undefined handling).
                cursor_arg = args[0] if args else kw.get("cursor")
                paged = getattr(result, "nextCursor", None) is not None or cursor_arg is not None
                if not paged:
                    listed = {_tool_name_of(t) for t in tools}
                    missing = sorted(n for n in pin_store.pinned_names() if n not in listed)
                    if missing:
                        missing_pinned = missing

            reason_parts = []
            if flagged:
                reason_parts.append(
                    "tool_poisoning_detected: "
                    + "; ".join(f"{f['name']} ({','.join(f['reasons'])})" for f in flagged)
                )
            if pin_violations:
                reason_parts.append(
                    "tool_pin_violation: "
                    + "; ".join(f"{v['name']} ({v['reason']})" for v in pin_violations)
                )

            # Parity with TS processListToolsResult: the mcp.tools.list
            # INVENTORY event is emitted on EVERY discovery, clean or flagged —
            # a clean discovery is audit-relevant evidence of which tool
            # definitions the model was shown.
            if reason_parts:
                compliance = {
                    "event_type": "policy_flag",
                    "policy_version": derive_policy_version(cfg.policy_rules or []),
                    "action_taken": "allowed",
                    "action_reason": "policy_violation",
                    "action_source": "builtin",
                    "redacted_types": [],
                    "blocked_types": [],
                    "policy_reason": "; ".join(reason_parts),
                }
            else:
                compliance = {
                    "event_type": "tool_call",
                    "policy_version": derive_policy_version(cfg.policy_rules or []),
                    "action_taken": "allowed",
                    "action_reason": "none",
                    "action_source": "builtin",
                    "redacted_types": [],
                    "blocked_types": [],
                }
            # Caller metadata first, then flagged_tools + sealed pin stamps
            # (so obsvr-controlled evidence wins over a caller key collision —
            # TS inventory-event precedence parity).
            inventory_meta = dict(base_options.get("metadata") or {})
            inventory_meta["flagged_tools"] = [f["name"] for f in flagged]
            if pinning and pin_store is not None:
                # Pin surface: per-tool descriptor hashes ride the signed
                # inventory event — the operator copies an observed hash into
                # config pins, and the record proves which definitions were live.
                inventory_meta["tool_hashes"] = tool_hashes
                if tool_hashes_truncated:
                    inventory_meta["tool_hashes_truncated"] = True
                if pin_violations:
                    inventory_meta["pin_violations"] = pin_violations
                if missing_pinned:
                    inventory_meta["missing_pinned_tools"] = missing_pinned
                if pin_store.saturated():
                    inventory_meta["pin_store_saturated"] = True
            _emit(
                cfg,
                provider="mcp", model="mcp", operation="mcp.tools.list",
                source=SOURCE,
                prompt=json.dumps(
                    [
                        {
                            "name": getattr(t, "name", None),
                            "description": getattr(t, "description", None),
                        }
                        for t in tools
                    ],
                    default=str,
                )[:4000],
                response="", success=True,
                metadata=inventory_meta,
                compliance=compliance,
            )
            strip_names = set()
            if flagged:
                policy = _mcp_tool_policy(cfg) or {}
                if policy.get("block_poisoned_tools") or policy.get("blockPoisonedTools"):
                    strip_names |= {f["name"] for f in flagged}
            strip_names |= pin_blocked_names  # pinning mode "block"
            if strip_names:
                kept = [t for t in tools if _tool_name_of(t) not in strip_names]
                try:
                    result.tools = kept
                except Exception:
                    pass

            return result

    return governed_call_tool, governed_list_tools


_PATCH_MCP_DEPRECATION_WARNED = False


def patch_mcp(
    session_class: Any,
    config: Optional[ResolvedConfig] = None,
    options: Optional[Dict[str, Any]] = None,
) -> None:
    """DEPRECATED — class-level monkey-patch of an MCP ClientSession.

    Mutates ``session_class.call_tool`` / ``list_tools`` in place, so it affects
    EVERY ClientSession in the process and can collide with other instrumentation.
    Prefer :func:`govern_mcp`, which wraps a session INSTANCE non-mutatingly (the
    Python analog of TS ``obsvrGovernMCP``). Kept for back-compat; will be removed
    in the next major release.

    Pass the class (e.g. ``mcp.ClientSession``), not an instance. Idempotent.
    """
    global _PATCH_MCP_DEPRECATION_WARNED
    if session_class is None or not hasattr(session_class, "call_tool"):
        return
    if getattr(session_class, _PATCHED_ATTR, False):
        return
    if not _PATCH_MCP_DEPRECATION_WARNED:
        _PATCH_MCP_DEPRECATION_WARNED = True
        logging.getLogger("obsvr").warning(
            "patch_mcp() is deprecated and will be removed in the next major "
            "release. Use govern_mcp(session) instead — it is non-mutating (no "
            "ClientSession class patching)."
        )
    original_call_tool = session_class.call_tool
    original_list_tools = getattr(session_class, "list_tools", None)
    governed_call_tool, governed_list_tools = _build_governed_mcp_callables(
        config, options, original_call_tool, original_list_tools
    )
    session_class.call_tool = governed_call_tool
    if governed_list_tools is not None:
        session_class.list_tools = governed_list_tools
    setattr(session_class, _PATCHED_ATTR, True)


class _GovernedMCPSession:
    """Non-mutating governed wrapper around an MCP ClientSession INSTANCE.

    Delegates every attribute to the real session via ``__getattr__``; only
    ``call_tool`` and ``list_tools`` are intercepted for governance. No
    ClientSession class, prototype, or module is mutated — the Python analog of
    the TS ``obsvrGovernMCP`` get-trap Proxy, so other instrumentation on the
    same session keeps working. (As with any wrapper, ``isinstance(wrapped,
    ClientSession)`` is False — call methods on the returned object.)
    """

    __slots__ = ("_obsvr_session", "_obsvr_call_tool", "_obsvr_list_tools")

    def __init__(self, session: Any, governed_call_tool: Any, governed_list_tools: Any) -> None:
        object.__setattr__(self, "_obsvr_session", session)
        object.__setattr__(self, "_obsvr_call_tool", governed_call_tool)
        object.__setattr__(self, "_obsvr_list_tools", governed_list_tools)

    def __getattr__(self, name: str) -> Any:
        # Reached only for attributes not defined on this wrapper → real session.
        return getattr(object.__getattribute__(self, "_obsvr_session"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_obsvr_session"), name, value)

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None, **kw: Any) -> Any:
        return await self._obsvr_call_tool(self._obsvr_session, name, arguments, **kw)

    async def list_tools(self, *args: Any, **kw: Any) -> Any:
        if self._obsvr_list_tools is None:
            return await self._obsvr_session.list_tools(*args, **kw)
        return await self._obsvr_list_tools(self._obsvr_session, *args, **kw)


def govern_mcp(
    session: Any,
    config: Optional[ResolvedConfig] = None,
    options: Optional[Dict[str, Any]] = None,
) -> Any:
    """Return a governed wrapper around an MCP ClientSession INSTANCE — non-mutating.

    Every tool call on the returned object is policy-checked (allow/deny),
    PII-scanned, run through the pre-call hook (HITL), and audited, and
    ``list_tools`` gets the tool-poisoning scan — while the real ClientSession
    class is never patched (mirrors TS ``obsvrGovernMCP``). Use it as::

        async with ClientSession(read, write) as session:
            session = govern_mcp(session)
            await session.call_tool("read_file", {"path": "/tmp/x"})

    ``options`` mirrors :func:`patch_mcp` / TS per-client options (``user_id`` /
    ``service_name`` / ``metadata``). Returns the input unchanged if it is not an
    MCP session.
    """
    if session is None or not hasattr(session, "call_tool"):
        return session
    original_call_tool = type(session).call_tool
    original_list_tools = getattr(type(session), "list_tools", None)
    governed_call_tool, governed_list_tools = _build_governed_mcp_callables(
        config, options, original_call_tool, original_list_tools
    )
    return _GovernedMCPSession(session, governed_call_tool, governed_list_tools)
