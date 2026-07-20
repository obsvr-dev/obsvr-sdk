"""Singleton configuration manager.

Mirrors sdk/src/proxy/config.ts: validation, defaults, sample-rate
clamping, trailing-slash stripping and legacy pii_policy conversion.
"""

import dataclasses
import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

DEFAULT_INGEST_URL = "http://localhost:3000"
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_MAX_PAYLOAD_CHARS = 100000

# Loopback hosts exempt from the HTTPS requirement (local development).
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def _validate_ingest_url_scheme(url: str) -> None:
    """HTTPS enforced for non-localhost: a plaintext ingest URL would leak
    prompts, responses, and the API key in transit. Rejected AT INIT with a
    typed error (same posture as the E14 validation below). Explicit opt-out
    for TLS-terminating proxies / private networks: OBSVR_ALLOW_HTTP=1."""
    from urllib.parse import urlsplit
    try:
        parts = urlsplit(url)
    except ValueError:
        return  # unparseable URLs fail loudly at first request instead
    if parts.scheme != "http":
        return
    if (parts.hostname or "").lower() in _LOCAL_HOSTNAMES:
        return
    if os.environ.get("OBSVR_ALLOW_HTTP", "").strip().lower() in ("1", "true"):
        return
    raise ValueError(
        "obsvr.init(): ingest_url must use https for non-localhost hosts, "
        f"got {url!r}. Set OBSVR_ALLOW_HTTP=1 to allow plaintext http."
    )


@dataclass
class ResolvedConfig:
    api_key: str
    environment: str = "development"
    ingest_url: str = DEFAULT_INGEST_URL
    # Emission rate for ALLOWED-call audit events (0-1). Gates audit EMISSION
    # only, never enforcement: PII/policy/hook/kill-switch checks run on every
    # call regardless, and blocked/redacted/error events are always emitted.
    # Lower = less ingest volume, NOT less per-call enforcement cost.
    sample_rate: float = 1.0
    max_payload_chars: int = DEFAULT_MAX_PAYLOAD_CHARS
    disabled: bool = False
    debug: bool = False
    timeout: float = DEFAULT_TIMEOUT_S
    # PII policy: {"default": "block"|"redact"|"detect_only", "rules": {type: action}}
    # NOTE: an *empty dict* enables the built-in severity defaults
    # (parity with the TS SDK where `pii_policy: {}` is truthy).
    pii_policy: Optional[Dict[str, Any]] = None
    on_pre_call: Optional[Callable[[Dict[str, Any]], str]] = None
    on_post_call: Optional[Callable] = None
    hook_timeout_ms: int = 2000
    post_call_timeout_ms: int = 2000
    # Enforcement fail mode when the pre-call hook times out or throws.
    # "open" (default): allow the call. "closed": block it. Parity with TS.
    fail_mode: str = "open"
    policy_rules: Optional[List[Any]] = None
    # Anti-tamper policy floor: rules that cannot be silently disabled/
    # downgraded (see TS ObsvrConfig.policyFloor). Its own field so a remote
    # sync replacing policy_rules can never delete it.
    policy_floor: Optional[List[Any]] = None
    default_source: Optional[str] = None
    default_region: Optional[str] = None
    default_service_name: Optional[str] = None
    agent_policy: Optional[Dict[str, Any]] = None
    # MCP tool policy: {"allowed_tools": [...], "denied_tools": [...],
    #                   "block_poisoned_tools": bool,
    #                   "pinning": {"enabled": bool, "mode": "warn"|"block",
    #                               "pins": {tool_name: sha256_hex},
    #                               "require_pin": bool}}
    # pinning = descriptor content-hash pinning (rug-pull defense): descriptors
    # seen at list_tools are hashed (canonical projection, full SHA-256);
    # config pins are authoritative and survive restarts, otherwise first-seen
    # hashes are TOFU-recorded per governed session and NEVER silently
    # re-pinned. On a mismatch: mode "warn" (default) flags on signed events;
    # "block" strips the tool at discovery and refuses calls. Off by default.
    mcp_tool_policy: Optional[Dict[str, Any]] = None
    # Remote policy polling: interval in seconds (0 disables). Parity with
    # the TS SDK's policyRefreshIntervalMs. Also powers the kill switch and
    # fail-closed staleness enforcement.
    policy_refresh_interval_s: float = 30.0
    # With fail_mode="closed": max age (s) of the last successful policy
    # sync before governed calls block. Default max(3x interval, 90).
    policy_staleness_budget_s: Optional[float] = None
    # Presidio NLP PII services (optional; regex scan always runs)
    presidio_analyzer_url: Optional[str] = None
    presidio_anonymizer_url: Optional[str] = None
    # Multi-turn injection scoring:
    # {"enabled": bool, "threshold": float, "half_life_s": float, "action": "block"|"flag"}
    multi_turn_injection: Optional[Dict[str, Any]] = None
    # Session taint latch: {"enabled": bool, "action": "block"|"flag"}. Once a
    # prompt-injection or canary leak is detected in a session, the session's
    # subsequent egress is escalated. Keyed on metadata.user_id ?? session_id
    # ?? tenant_id. action defaults to "flag". Off by default.
    session_taint: Optional[Dict[str, Any]] = None
    # De-obfuscation scan views (server-side normalizer mirror): {"enabled": bool}.
    # When enabled, the builtin scanners also see base64/hex/percent-decoded
    # and invisible-stripped/confusable-folded/HTML-comment-stripped views of
    # the text. Detection-only (views never feed span redaction); a hit found
    # ONLY in a view escalates redact->block pre-delivery and stores whole-text
    # placeholders (no locatable span). Off by default: enabling can turn
    # previously-allowed calls into blocks under a block-/redact-mode policy.
    deobfuscation: Optional[Dict[str, Any]] = None
    # Mirror audit events as OpenTelemetry spans (optional opentelemetry-api)
    otel: Optional[Dict[str, Any]] = None
    # Inbound external policy backend (ADR-4): OPA/Cedar, merged DENY-WINS with
    # local rules. Dict shape: {"type": "opa"|"cedar", "url": str, "shadow"?: bool,
    # "timeout_ms"?: int, "headers"?: dict, "name"?: str, "policy"?: str,
    # "allow_private_network"?: bool}. None (default) = no backend.
    external_policy_backend: Optional[Dict[str, Any]] = None


_state: Dict[str, Any] = {"initialized": False, "config": None}
_tenant_registry: Dict[str, Dict[str, Any]] = {}


def init(
    api_key: Optional[str] = None,
    *,
    ingest_url: Optional[str] = None,
    environment: Optional[str] = None,
    sample_rate: Optional[float] = None,
    max_payload_chars: Optional[int] = None,
    disabled: Optional[bool] = None,
    debug: Optional[bool] = None,
    timeout: Optional[float] = None,
    pii_policy: Optional[Dict[str, Any]] = None,
    on_pre_call: Optional[Callable[[Dict[str, Any]], str]] = None,
    on_post_call: Optional[Callable] = None,
    hook_timeout_ms: Optional[int] = None,
    post_call_timeout_ms: Optional[int] = None,
    fail_mode: Optional[str] = None,
    policy_rules: Optional[List[Any]] = None,
    policy_floor: Optional[List[Any]] = None,
    default_source: Optional[str] = None,
    default_region: Optional[str] = None,
    default_service_name: Optional[str] = None,
    agent_policy: Optional[Dict[str, Any]] = None,
    mcp_tool_policy: Optional[Dict[str, Any]] = None,
    policy_refresh_interval_s: Optional[float] = None,
    policy_staleness_budget_s: Optional[float] = None,
    presidio_analyzer_url: Optional[str] = None,
    presidio_anonymizer_url: Optional[str] = None,
    multi_turn_injection: Optional[Dict[str, Any]] = None,
    session_taint: Optional[Dict[str, Any]] = None,
    deobfuscation: Optional[Dict[str, Any]] = None,
    otel: Optional[Dict[str, Any]] = None,
    external_policy_backend: Optional[Dict[str, Any]] = None,
    auto: Optional[bool] = None,
) -> None:
    """Initialize the obsvr SDK. Must be called before integrations emit."""
    if not isinstance(api_key, str) or api_key.strip() == "":
        raise ValueError("obsvr.init(): api_key must be a non-empty string")

    # Strict init validation (E14, parity with the TS SDK): reject
    # clearly-invalid values with a typed error AT INIT, never at first
    # use. Silent misconfiguration of a governance SDK is itself a
    # governance failure.
    if fail_mode is not None and fail_mode not in ("open", "closed"):
        raise ValueError(
            f'obsvr.init(): fail_mode must be "open" or "closed", got {fail_mode!r}'
        )
    if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
        raise ValueError(
            f"obsvr.init(): timeout must be a positive number of seconds, got {timeout!r}"
        )
    if policy_refresh_interval_s is not None and (
        not isinstance(policy_refresh_interval_s, (int, float))
        or policy_refresh_interval_s < 0
    ):
        raise ValueError(
            "obsvr.init(): policy_refresh_interval_s must be >= 0, got "
            f"{policy_refresh_interval_s!r}"
        )
    if policy_staleness_budget_s is not None and (
        not isinstance(policy_staleness_budget_s, (int, float))
        or policy_staleness_budget_s <= 0
    ):
        raise ValueError(
            "obsvr.init(): policy_staleness_budget_s must be a positive number "
            f"of seconds, got {policy_staleness_budget_s!r}"
        )
    if sample_rate is not None and not isinstance(sample_rate, (int, float)):
        raise ValueError(
            f"obsvr.init(): sample_rate must be a number in [0, 1], got {sample_rate!r}"
        )

    # External policy backend (ADR-4): validate the shape and run the STATIC
    # SSRF guard (scheme + literal-IP range) so a clearly-unsafe backend URL
    # fails at init. Hostname resolution is checked per-call.
    if external_policy_backend is not None:
        if not isinstance(external_policy_backend, dict):
            raise ValueError("obsvr.init(): external_policy_backend must be a dict")
        btype = external_policy_backend.get("type")
        if btype not in ("opa", "cedar"):
            raise ValueError(
                'obsvr.init(): external_policy_backend["type"] must be "opa" or "cedar", '
                f"got {btype!r}"
            )
        burl = external_policy_backend.get("url")
        if not isinstance(burl, str) or burl.strip() == "":
            raise ValueError(
                'obsvr.init(): external_policy_backend["url"] must be a non-empty string'
            )
        btmo = external_policy_backend.get("timeout_ms")
        if btmo is not None and (not isinstance(btmo, (int, float)) or btmo <= 0):
            raise ValueError(
                'obsvr.init(): external_policy_backend["timeout_ms"] must be a positive '
                f"number of ms, got {btmo!r}"
            )
        # Raises SsrfError on a non-http(s) scheme or a literal metadata/private
        # IP (unless allow_private_network permits the private case).
        from .ssrf import assert_backend_url_static
        assert_backend_url_static(
            burl, bool(external_policy_backend.get("allow_private_network"))
        )

    # Presidio analyzer/anonymizer endpoints receive the PROMPT/PII content to
    # scan, so a misconfigured or hijacked URL is both an SSRF primitive and a
    # data-exfiltration surface — the endpoint that sees the MOST sensitive
    # data. Run the STATIC SSRF guard at init on each configured endpoint
    # (parity with the external policy backend above and TS config.ts). A
    # presidio deployment is normally a LOCAL sidecar (localhost / private
    # host), so private/loopback are permitted here — but the cloud-metadata /
    # link-local endpoint (169.254.169.254 and the IPv6 forms) is ALWAYS
    # refused, no opt-out, closing the crown-jewel SSRF vector.
    from .ssrf import SsrfError as _SsrfError
    from .ssrf import assert_backend_url_static as _assert_presidio_url

    for _pname, _purl in (
        ("presidio_analyzer_url", presidio_analyzer_url),
        ("presidio_anonymizer_url", presidio_anonymizer_url),
    ):
        if _purl is not None:
            if not isinstance(_purl, str) or _purl.strip() == "":
                raise ValueError(f"obsvr.init(): {_pname} must be a non-empty string")
            try:
                _assert_presidio_url(_purl, True)  # allow_private_network (sidecar)
            except _SsrfError as e:
                raise ValueError(
                    f"obsvr.init(): {_pname} failed the SSRF guard: {e}"
                )

    rate = 1.0 if sample_rate is None else float(sample_rate)
    if rate < 0:
        rate = 0.0
    if rate > 1:
        rate = 1.0

    url = (ingest_url or DEFAULT_INGEST_URL).rstrip("/")
    _validate_ingest_url_scheme(url)

    # Legacy {"action": "block"} shape -> {"default": "block"}
    policy = pii_policy
    if (
        isinstance(policy, dict)
        and "action" in policy
        and "default" not in policy
        and "rules" not in policy
    ):
        policy = {"default": policy["action"]}

    _state["config"] = ResolvedConfig(
        api_key=api_key.strip(),
        environment=environment or "development",
        ingest_url=url,
        sample_rate=rate,
        max_payload_chars=(
            max_payload_chars
            if max_payload_chars is not None
            else DEFAULT_MAX_PAYLOAD_CHARS
        ),
        disabled=bool(disabled) if disabled is not None else False,
        debug=bool(debug) if debug is not None else False,
        timeout=timeout if timeout is not None else DEFAULT_TIMEOUT_S,
        pii_policy=policy,
        on_pre_call=on_pre_call,
        on_post_call=on_post_call,
        hook_timeout_ms=hook_timeout_ms if hook_timeout_ms is not None else 2000,
        post_call_timeout_ms=post_call_timeout_ms if post_call_timeout_ms is not None else 2000,
        fail_mode=fail_mode if fail_mode in ("open", "closed") else "open",
        policy_rules=policy_rules,
        policy_floor=policy_floor,
        default_source=default_source,
        default_region=default_region,
        default_service_name=default_service_name,
        agent_policy=agent_policy,
        mcp_tool_policy=mcp_tool_policy,
        policy_refresh_interval_s=(
            policy_refresh_interval_s if policy_refresh_interval_s is not None else 30.0
        ),
        policy_staleness_budget_s=policy_staleness_budget_s,
        presidio_analyzer_url=presidio_analyzer_url,
        presidio_anonymizer_url=presidio_anonymizer_url,
        multi_turn_injection=multi_turn_injection,
        session_taint=session_taint,
        deobfuscation=deobfuscation,
        otel=otel,
        external_policy_backend=external_policy_backend,
    )
    _state["initialized"] = True

    # disabling governance in production is a bypass — put it on the
    # tamper-evident record (parity with the TS SDK, SECURITY.md): a prominent
    # warning plus a single signed governance_disabled event.
    _resolved: ResolvedConfig = _state["config"]
    if _resolved.disabled and _resolved.environment == "production":
        logging.getLogger("obsvr").warning(
            "governance is DISABLED (disabled=True) in a production environment - "
            "all subsequent calls are UNAUDITED and UNENFORCED; recording a "
            "governance_disabled event."
        )
        _emit_governance_disabled_event(_resolved)

    # fail_mode="closed" but polling disabled is effectively fail-OPEN —
    # the kill switch and staleness enforcement both require the /policies poll.
    # Warn loudly rather than silently contradict the operator's intent.
    if (
        _resolved.fail_mode == "closed"
        and getattr(_resolved, "policy_refresh_interval_s", 30.0) <= 0
        and not _resolved.disabled
    ):
        logging.getLogger("obsvr").warning(
            "fail_mode is 'closed' but policy polling is disabled "
            "(policy_refresh_interval_s <= 0). The kill switch and staleness "
            "enforcement require polling - with it off they cannot trip, so calls "
            "will NOT fail closed on a paused project / revoked key / stale sync. "
            "Enable polling for a working fail-closed posture."
        )

    # Remote policy sync: fetch server rules + approval grants, detect the
    # dashboard kill switch, and (with fail_mode="closed") enforce staleness.
    cfg: ResolvedConfig = _state["config"]
    if cfg.policy_refresh_interval_s > 0 and not cfg.disabled:
        from .remote import start_policy_polling
        start_policy_polling(cfg, cfg.policy_refresh_interval_s)

    # Auto-instrumentation: wire frameworks with clean global registration
    # (providers, openai-agents, llamaindex). On by default; opt out with
    # init(auto=False). Best-effort and non-throwing — never blocks init.
    if auto is not False and not cfg.disabled:
        try:
            from .auto import enable_auto_instrumentation
            enable_auto_instrumentation()
        except Exception:  # pragma: no cover - defensive; auto must never break init
            pass


def get_config() -> ResolvedConfig:
    if not _state["initialized"] or _state["config"] is None:
        raise RuntimeError("obsvr: call init() before using integrations")
    return _state["config"]


def is_initialized() -> bool:
    return bool(_state["initialized"])


def try_get_config() -> Optional[ResolvedConfig]:
    """Config or None when uninitialized/disabled (observe-only safety)."""
    if not _state["initialized"] or _state["config"] is None:
        return None
    config: ResolvedConfig = _state["config"]
    if config.disabled:
        return None
    return config


def _emit_governance_disabled_event(cfg: ResolvedConfig) -> None:
    """Emit one governance_disabled audit event (parity with the TS SDK). Uses a
    non-disabled config copy because ``send_audit_async`` suppresses events for a
    disabled config — but recording the bypass is the whole point here."""
    try:
        from . import sender
        from .rules import derive_policy_version

        event = {
            "request_id": f"governance-disabled-{int(time.time() * 1000)}",
            "environment": cfg.environment,
            "region": cfg.default_region or "unknown",
            "provider": "unknown",
            "model": "none",
            "operation": "governance.disabled",
            "source": "obsvr_sdk",
            "prompt": "",
            "response": "",
            "success": True,
            "latency_ms": 0,
            "event_type": "policy_flag",
            "policy_version": derive_policy_version(cfg.policy_rules or []),
            "action_taken": "allowed",
            "action_reason": "customer_override",
            "action_source": "customer_hook",
            "redacted_types": [],
            "blocked_types": [],
            "metadata": {
                "governance_event": "governance_disabled",
                "note": "SDK initialized with disabled=True in production - all subsequent calls unaudited",
            },
        }
        sender.send_audit_async(dataclasses.replace(cfg, disabled=False), event)
    except Exception:
        pass


def set_tenant_policy(tenant_id: str, rules: list, changed_by: Optional[str] = None) -> None:
    """Set policy rules for a specific tenant."""
    from .policy_log import snapshot_policy, emit_policy_changed_event, send_policy_event
    existing = _tenant_registry.get(tenant_id, {})
    prev_rules = existing.get("policy_rules", []) or []
    _tenant_registry[tenant_id] = {"policy_rules": rules}
    snapshot_policy(rules, tenant_id)
    event = emit_policy_changed_event(prev_rules, rules, tenant_id, changed_by)
    # actually record the change in the audit trail (was built + dropped).
    cfg = _state.get("config")
    if cfg is not None and getattr(cfg, "ingest_url", None):
        send_policy_event(event, cfg.ingest_url, cfg.api_key)


def get_tenant_config(tenant_id: str) -> "ResolvedConfig":
    """Get config merged with tenant-specific overrides."""
    base = get_config()
    override = _tenant_registry.get(tenant_id)
    if not override:
        return base
    return dataclasses.replace(base, policy_rules=override.get("policy_rules", base.policy_rules))


def _reset() -> None:
    """Reset state (tests only)."""
    from .remote import _reset_remote
    from .canary import _reset_canaries
    from .session_taint import _reset_session_taint
    _reset_remote()
    _reset_canaries()
    _reset_session_taint()
    _state["initialized"] = False
    _state["config"] = None
    _tenant_registry.clear()
