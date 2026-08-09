"""Singleton configuration manager.

Mirrors sdk-typescript/src/proxy/config.ts: validation, defaults, sample-rate
clamping, trailing-slash stripping and legacy pii_policy conversion.
"""

import dataclasses
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

# No default destination. A defaulted ingest URL means a misconfigured process
# streams governed events - including redacted prompt text on blocked calls - to
# whatever happens to be listening on that port. Unset is unset: the SDK warns
# loudly and delivers nothing. (Twin: DEFAULT_INGEST_URL in sdk-typescript/src/constants.ts.)
DEFAULT_INGEST_URL = ""
DEFAULT_TIMEOUT_S = 5.0
DEFAULT_MAX_PAYLOAD_CHARS = 100000

#: The environments the ingest service accepts. It enforces this set as an enum
#: and answers 400 to every event carrying anything else, so a value outside it
#: is not a cosmetic mistake — it is the whole audit trail, silently.
VALID_ENVIRONMENTS = ("development", "staging", "production")

#: Options whose enforcement lives on SOME surfaces and not others, and the
#: surfaces that actually read each one.
#:
#: An option accepted at init and consumed by nothing is dead config that reads
#: as a control. ``agent_policy["max_steps"]`` is the measured case: a step
#: budget set alongside ``denied_tools`` looks like one policy, but only the
#: framework callback integrations count steps — the generic tool governor and
#: the MCP boundary implement the allow/deny gate and no budget, so a deployment
#: whose only wiring is ``govern_tool`` has a limit nothing will ever consult.
#:
#: This drives a WARNING, never a refusal: the option is legitimate, and whether
#: a consuming surface gets wired is not knowable at init — a caller may import
#: an integration later in the process. What is knowable is that none is
#: importable at all, and saying so is the difference between a control and a
#: comment. Same principle as the strict validation above, one step weaker
#: because the evidence is one step weaker.
#: The probe is on the FRAMEWORK package, not on obsvr's own integration module.
#: Every integration module here ships in this package and always imports, so
#: asking whether obsvr can import its own code answers nothing; what decides
#: the question is whether the framework that would drive it is installed at
#: all. Absent, the option is inert with certainty. Present, it MIGHT be
#: consumed — the caller still has to wire the handler — and a warning that
#: cannot tell the two apart is one an operator learns to ignore, so the
#: uncertain case stays silent.
_SURFACE_SCOPED_OPTIONS = {
    "agent_policy.max_steps": (
        ("langchain_core", "LangChain callback handler"),
        ("crewai", "CrewAI step callbacks"),
        ("autogen", "AutoGen register_obsvr"),
        ("agents", "OpenAI Agents tracing processor"),
    ),
    "agent_policy.loop_detection": (
        ("langchain_core", "LangChain callback handler"),
        ("crewai", "CrewAI step callbacks"),
        ("autogen", "AutoGen register_obsvr"),
        ("agents", "OpenAI Agents tracing processor"),
    ),
    "agent_policy.allow_pii_access": (
        ("crewai", "CrewAI step callbacks"),
        ("autogen", "AutoGen register_obsvr"),
    ),
}


def _warn_unconsumed_options(agent_policy: Optional[Dict[str, Any]]) -> List[str]:
    """Name every configured option no importable surface will read.

    Returns the warnings emitted, so a caller (and a test) can assert on them
    rather than on log capture. Never raises: a misconfiguration report that can
    break init is worse than the misconfiguration.
    """
    import importlib.util

    warnings: List[str] = []
    policy = agent_policy or {}
    for key, consumers in _SURFACE_SCOPED_OPTIONS.items():
        option = key.split(".", 1)[1]
        if policy.get(option) is None:
            continue
        available = []
        for module, label in consumers:
            try:
                if importlib.util.find_spec(module) is not None:
                    available.append(label)
            except (ImportError, ValueError):  # noqa: PERF203 - probe, not a gate
                continue
        if available:
            continue
        message = (
            f"obsvr.init(): agent_policy[{option!r}] is set, but nothing that "
            "consumes it is wired. It is enforced by the framework callback "
            f"integrations ({', '.join(label for _, label in consumers)}) and "
            "NOT by govern_tool or the MCP boundary, which implement the "
            "allow/deny gate only. As configured this value governs nothing."
        )
        logging.getLogger("obsvr").warning(message)
        warnings.append(message)
    return warnings

#: Identifies THIS copy of the package inside the process (see instance_guard).
_MODULE_INSTANCE_ID = f"obsvr-{uuid.uuid4().hex[:12]}"


def _sdk_version() -> str:
    """Read the version lazily: importing it at module scope would widen this
    module's import graph for no reason."""
    from ._version import __version__

    return __version__

# Loopback hosts exempt from the HTTPS requirement (local development).
_LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


def _validate_ingest_url(url: str) -> None:
    """Validate ``ingest_url`` at init.

    This endpoint receives every prompt, every response and the ``X-API-Key``
    header, so it is the largest egress surface the SDK has -- larger than the
    external policy backend or the Presidio endpoints, both of which already run
    the SSRF guard while this one ran none of it.

    Two checks, in order:

      1. The STATIC SSRF guard, at the same posture as the Presidio endpoints.
         The scheme must be http(s), so ``file:``, ``gopher:``, ``ftp:`` and
         everything else are refused rather than accepted -- this function
         previously returned early for ANY non-``http`` scheme, so
         ``file:///etc/passwd`` was waved through. A literal-IP host must not be
         a cloud-metadata / link-local address (ALWAYS refused, no opt-out, in
         all four IPv6 spellings) and must not be a private/reserved range
         unless the host is loopback.
      2. TLS posture: a plaintext ``http`` ingest URL leaks prompts, responses
         and the API key in transit, so it is refused off-loopback. Explicit
         opt-out for TLS-terminating proxies / private networks:
         ``OBSVR_ALLOW_HTTP=1``.

    Loopback keeps working so local development and a local collector are
    unaffected; the metadata address is refused there too, because it is refused
    everywhere.

    One limit, stated rather than implied: this is the STATIC guard, so a
    HOSTNAME that resolves to a private or metadata address is not refused.
    ``init()`` is synchronous and the resolving guard needs DNS, which is the
    same limit the Presidio endpoints carry.

    Twin: ``validateIngestUrl`` in sdk-typescript/src/proxy/config.ts, which has
    no ``OBSVR_ALLOW_HTTP`` opt-out because that SDK reads no environment
    variable at all. ``SECURITY.md`` scopes the opt-out to Python for that
    reason.
    """
    from urllib.parse import urlsplit

    from .ssrf import SsrfError, assert_backend_url_static

    if not url:
        return  # unconfigured: resolve_config() has already warned, nothing is delivered

    # Parse for the host first so the loopback exemption and the guard agree on
    # what the host is. An unparseable URL leaves it empty and the guard reports
    # it, rather than this raising a second, worse-worded error for the same URL.
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        host = ""
    is_local = host in _LOCAL_HOSTNAMES

    try:
        parts = assert_backend_url_static(url, is_local)
    except SsrfError as e:
        raise ValueError(f"obsvr.init(): ingest_url failed the SSRF guard: {e}") from e

    if parts.scheme != "http" or is_local:
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
    # Blocking human approval. When > 0, a require_approval block HOLDS the
    # governed call in the calling thread for up to this many milliseconds,
    # polling the grant channel, and proceeds only if a covering grant lands
    # AND is still live at the end of the pipeline (revalidate_approval).
    # 0 (default) keeps the fire-and-forget behavior exactly: the call is
    # refused, an approval request is filed, and a retry passes once granted.
    # Strictly opt-in — a library that starts blocking for minutes on upgrade
    # is a production incident, so the default must stay 0.
    approval_wait_ms: int = 0
    # Grant-channel poll cadence while an approval wait is in progress. Each
    # poll re-drives the same /policies refresh the daemon uses (signature
    # verification and grant-shape validation included), so keep it coarse:
    # this is a human-timescale wait, not a busy loop.
    approval_poll_ms: int = 5000
    # Enforcement fail mode when the pre-call hook times out or throws.
    # "open" (default): allow the call. "closed": block it. Parity with TS.
    fail_mode: str = "open"
    # Global enforcement mode. "enforce" (default) applies blocks. "monitor"
    # evaluates every layer, emits every event, and converts a final block
    # into an allow whose shadow_outcome carries the would-be verdict — one
    # flip for a staged rollout or rollback that keeps the evidence stream
    # intact. Two classes are NEVER converted: the enforcement-integrity gate
    # (kill switch / fail-closed staleness — monitor mode must not become a
    # way to defeat a revoked key) and canary-leak blocks (an exfiltration in
    # flight is stopped in any mode).
    enforcement_mode: str = "enforce"
    # Refuse an unattributed call (opt-in). When True, a governed call whose
    # enforcing metadata carries no user_id at all is blocked with
    # PRINCIPAL_REQUIRED before any scanning layer runs. An empty string is a
    # supplied principal; only an absent one refuses — the decision digest's
    # presence byte draws the same absent-vs-empty line. Default False: a
    # single-tenant deployment that legitimately passes no user_id must not
    # start refusing on upgrade.
    require_principal: bool = False
    # Refuse a wrap() that governs nothing (opt-in). When True, wrapping a
    # client on which no auditable method path resolves raises instead of
    # returning a proxy that will never emit an event. Default False, and the
    # default still WARNS (see wrap.py). A deployment that treats coverage as a
    # deploy-time invariant sets this so the process refuses to start rather
    # than running ungoverned. Twin: requireGovernedSurface.
    require_governed_surface: bool = False
    # Declared conflict-resolution mode for the policy rules ("first_match"
    # or "deny_wins"). None (the default) is undeclared: the original
    # first-match contract AND the original policy_version bytes are kept.
    # Declaring a mode is what opts a deployment into order-insensitive
    # deny-wins evaluation and the order-committed policy_version that makes
    # it auditable. Validated at init; an unknown value is refused loudly.
    rule_resolution: Optional[str] = None
    # Optional client-held device signing identity (Ed25519). Path to an
    # operator-generated private key (PKCS8 PEM, or a raw 32-byte seed as
    # hex/base64). When set, every signed event ALSO carries device_sig /
    # device_key_id over the same payload the HMAC signs — non-repudiation
    # against everyone who does not hold this key, with the HMAC chain
    # untouched. The SDK NEVER generates this key; a configured key that
    # cannot sign refuses at init. See obsvr/device_identity.py.
    device_signing_key_file: Optional[str] = None
    policy_rules: Optional[List[Any]] = None
    # Anti-tamper policy floor: rules that cannot be silently disabled/
    # downgraded (see TS ObsvrConfig.policyFloor). Its own field so a remote
    # sync can never delete it — the strongest of the three tiers, and since
    # apply_policy_rules the middle tier (locally declared policy_rules) also
    # survives a poll; only the server's own set is the poll's to replace.
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
    # Pinned base64 raw 32-byte Ed25519 public key. When set, every /policies
    # response MUST carry a valid signature block or the fetched policy is
    # refused and the last-good policy stays in force (parity with the TS
    # SDK's policyPublicKey). Verification needs an optional crypto backend:
    # pip install "obsvr-sdk[crypto]". Without one the policy is still refused
    # and events carry policy_verification_unavailable.
    policy_public_key: Optional[str] = None
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
    # Layered call cost (see ObsvrConfig.costPolicy in the TS types): a caller
    # estimate, an operator-declared override, and a metered figure from real
    # usage at operator-declared rates - all three retained, because the gap
    # between estimate and correction is the auditable part. No provider price
    # list ships here; a stale rate would produce a SEALED wrong number.
    cost_policy: Optional[Dict[str, Any]] = None
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
    # Meter framework-integration events for cost and token quota. Default
    # False. Framework-integration events (LangChain, LlamaIndex, Vercel AI, the
    # agent frameworks) are UNMETERED UNLESS THIS IS SET: they carry no cost
    # fragment and never increment a token-unit quota. Only the wrap()
    # client-proxy path is metered by default, and it is metered either way —
    # this flag does not affect it.
    #
    # The default is off because turning it on is not a neutral correction. A
    # quota_unit "tokens" budget that has never bound on framework traffic
    # begins binding, and calls that previously succeeded start being blocked
    # once the budget is reached. For someone already running a token quota that
    # is an outage, not a fix, so it has to be a deliberate choice.
    #
    # One flag covers BOTH cost and quota rather than two, because the two only
    # make sense together: metering what a call cost without counting it against
    # the budget it belongs to produces an audit record that disagrees with
    # itself, and a governance record that contradicts itself is worse than one
    # that is silent. Twin: ObsvrConfig.meterIntegrationEvents (TypeScript).
    meter_integration_events: bool = False
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
    approval_wait_ms: Optional[int] = None,
    approval_poll_ms: Optional[int] = None,
    fail_mode: Optional[str] = None,
    enforcement_mode: Optional[str] = None,
    require_principal: Optional[bool] = None,
    require_governed_surface: Optional[bool] = None,
    rule_resolution: Optional[str] = None,
    device_signing_key_file: Optional[str] = None,
    policy_rules: Optional[List[Any]] = None,
    policy_floor: Optional[List[Any]] = None,
    default_source: Optional[str] = None,
    default_region: Optional[str] = None,
    default_service_name: Optional[str] = None,
    agent_policy: Optional[Dict[str, Any]] = None,
    mcp_tool_policy: Optional[Dict[str, Any]] = None,
    policy_refresh_interval_s: Optional[float] = None,
    policy_staleness_budget_s: Optional[float] = None,
    policy_public_key: Optional[str] = None,
    presidio_analyzer_url: Optional[str] = None,
    presidio_anonymizer_url: Optional[str] = None,
    multi_turn_injection: Optional[Dict[str, Any]] = None,
    session_taint: Optional[Dict[str, Any]] = None,
    cost_policy: Optional[Dict[str, Any]] = None,
    deobfuscation: Optional[Dict[str, Any]] = None,
    otel: Optional[Dict[str, Any]] = None,
    meter_integration_events: bool = False,
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
    # A typo'd mode must never silently monitor a deployment the operator
    # meant to enforce — the same reasoning the rule validator states for a
    # rule-level mode (remote.py).
    if enforcement_mode is not None and enforcement_mode not in ("enforce", "monitor"):
        raise ValueError(
            'obsvr.init(): enforcement_mode must be "enforce" or "monitor", got '
            f"{enforcement_mode!r}"
        )
    # The environment is an ENUM at ingest, and the SDK used to accept any
    # string for it. A value outside the set is rejected there with a 400 on
    # EVERY event, so a single typo costs the entire audit trail of the run
    # while the application sees nothing — the same class of silent failure a
    # typo'd fail_mode is refused for, with a larger blast radius. Refused at
    # init, where the operator can still read the message.
    if environment is not None and environment not in VALID_ENVIRONMENTS:
        raise ValueError(
            "obsvr.init(): environment must be one of "
            f"{', '.join(VALID_ENVIRONMENTS)}, got {environment!r}. The ingest "
            "service enforces this set and rejects every event carrying "
            "anything else, so the audit trail would not be recorded at all."
        )
    # A governance flag must be a real boolean: a truthy string like "false"
    # silently enabling (or a falsy 0 silently disabling) an attribution
    # requirement is exactly the misconfiguration strict init exists to catch.
    if require_governed_surface is not None and not isinstance(
        require_governed_surface, bool
    ):
        raise ValueError(
            "obsvr.init(): require_governed_surface must be a boolean, got "
            f"{require_governed_surface!r}"
        )
    if require_principal is not None and not isinstance(require_principal, bool):
        raise ValueError(
            f"obsvr.init(): require_principal must be a boolean, got {require_principal!r}"
        )
    if rule_resolution is not None:
        # The rules engine's own validator: an unknown declaration must
        # refuse loudly at init, never silently evaluate under semantics the
        # author did not choose.
        from .rules import ensure_rule_resolution

        try:
            ensure_rule_resolution(rule_resolution)
        except ValueError as exc:
            raise ValueError(f"obsvr.init(): {exc}") from None
    _device_signer = None
    if device_signing_key_file is not None:
        # Loud at init: the operator asked for non-repudiation, so a key that
        # cannot be read or cannot sign must refuse now — shipping unsigned
        # events under a config that promised signing is the silent no-op
        # this control exists to rule out. The loaded signer is installed on
        # the sender further down, so the key is read exactly once.
        from .device_identity import DeviceIdentityError, load_device_signer

        try:
            _device_signer = load_device_signer(device_signing_key_file)
        except DeviceIdentityError as exc:
            raise ValueError(
                f"obsvr.init(): device_signing_key_file: {exc}"
            ) from None
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
    if approval_wait_ms is not None and (
        isinstance(approval_wait_ms, bool)
        or not isinstance(approval_wait_ms, (int, float))
        or approval_wait_ms < 0
    ):
        raise ValueError(
            "obsvr.init(): approval_wait_ms must be a number of ms >= 0, got "
            f"{approval_wait_ms!r}"
        )
    if approval_poll_ms is not None and (
        isinstance(approval_poll_ms, bool)
        or not isinstance(approval_poll_ms, (int, float))
        or approval_poll_ms <= 0
    ):
        raise ValueError(
            "obsvr.init(): approval_poll_ms must be a positive number of ms, got "
            f"{approval_poll_ms!r}"
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

    # Declared rule lists are coerced HERE, at the boundary that accepts them.
    #
    # The engine reads a rule by attribute, so a mapping reached it as an
    # AttributeError raised inside the caller's detector guard — where
    # fail_mode resolves it open. A `policy_rules` block written as a dict
    # therefore did not block: the call went to the provider with only a
    # stderr notice behind it. Mappings are the natural spelling here (the TS
    # twin takes object literals, both parameters are typed List[Any], and
    # `policy_floor` has always accepted them), so the fix is to accept them
    # rather than to require the dataclass.
    #
    # A ValueError at init(), not a warning: a rule that cannot be built is
    # the operator's configuration being unreadable, and there is no later
    # moment at which it becomes readable. Raising here is the only point at
    # which they can still be told before a governed call depends on it.
    from .rules import coerce_policy_rules as _coerce_policy_rules
    from .rules import invalid_rule_reason as _invalid_rule_reason

    _coerced: Dict[str, List[Any]] = {}
    for _rname, _rlist in (("policy_rules", policy_rules), ("policy_floor", policy_floor)):
        for _i, _raw in enumerate(_rlist or []):
            _why = _invalid_rule_reason(_raw)
            if _why is not None:
                raise ValueError(f"obsvr.init(): {_rname}[{_i}] is not a usable rule: {_why}")
        _coerced[_rname] = _coerce_policy_rules(_rlist)
    # None and [] stay distinguishable: "no rules declared" and "an empty rule
    # set was declared" read the same to the engine but not to every caller.
    policy_rules = None if policy_rules is None else _coerced["policy_rules"]
    policy_floor = None if policy_floor is None else _coerced["policy_floor"]

    rate = 1.0 if sample_rate is None else float(sample_rate)
    if rate < 0:
        rate = 0.0
    if rate > 1:
        rate = 1.0

    url = (ingest_url or DEFAULT_INGEST_URL).rstrip("/")
    if not url:
        # Same condition, severity, and content as the TypeScript SDK's warning
        # (sdk-typescript/src/proxy/config.ts). Governance still runs; only delivery stops.
        logging.getLogger("obsvr").warning(
            "WARNING: ingest_url is not configured. Audit events will not be "
            "delivered until ingest_url is set in obsvr.init()."
        )
    _validate_ingest_url(url)

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
        approval_wait_ms=int(approval_wait_ms) if approval_wait_ms is not None else 0,
        approval_poll_ms=int(approval_poll_ms) if approval_poll_ms is not None else 5000,
        fail_mode=fail_mode if fail_mode in ("open", "closed") else "open",
        enforcement_mode=(
            enforcement_mode if enforcement_mode in ("enforce", "monitor") else "enforce"
        ),
        require_principal=require_principal if require_principal is True else False,
        require_governed_surface=require_governed_surface is True,
        rule_resolution=rule_resolution,
        device_signing_key_file=device_signing_key_file,
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
        policy_public_key=policy_public_key,
        presidio_analyzer_url=presidio_analyzer_url,
        presidio_anonymizer_url=presidio_anonymizer_url,
        multi_turn_injection=multi_turn_injection,
        session_taint=session_taint,
        cost_policy=cost_policy,
        deobfuscation=deobfuscation,
        otel=otel,
        meter_integration_events=bool(meter_integration_events),
        external_policy_backend=external_policy_backend,
    )
    _state["initialized"] = True
    # What the caller declared in code, kept apart from what a poll delivers.
    # See apply_policy_rules in remote.py. Replaced only by another init().
    _state["local_policy_rules"] = list(policy_rules or [])
    _state["server_policy_rules"] = None

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

    # Two copies of the SDK in one process would each poll, each wrap, and each
    # emit - duplicate evidence for one call. The first copy to init governs;
    # this one says so once and stands down.
    from .instance_guard import claim_governing_instance, duplicate_instance_message

    claim = claim_governing_instance(_sdk_version(), _MODULE_INSTANCE_ID)
    if not claim["governing"]:
        logging.getLogger("obsvr").warning(duplicate_instance_message(claim))
        return

    # Device signing identity (optional): validated and loaded once above,
    # installed on the sender so every signed event also carries the device
    # seal. Cleared when the config carries no key, so a re-init without one
    # stops sealing rather than inheriting the previous identity.
    from .sender import configure_device_signer

    configure_device_signer(_device_signer)

    # Remote policy sync: fetch server rules + approval grants, detect the
    # dashboard kill switch, and (with fail_mode="closed") enforce staleness.
    cfg: ResolvedConfig = _state["config"]
    if cfg.policy_refresh_interval_s > 0 and not cfg.disabled:
        from .remote import start_policy_polling
        start_policy_polling(cfg, cfg.policy_refresh_interval_s)

    # A fresh governed session has recorded nothing yet. Without this, an
    # event id the previous session already claimed would be read as
    # already-recorded and the call dropped.
    from .dedupe import _reset_dedupe as _clear_emission_memory
    _clear_emission_memory()

    # Dead config reads as a control. Say so now, while the operator is looking
    # at the init call, rather than leaving them to infer it from a limit that
    # never fires.
    if not cfg.disabled:
        _warn_unconsumed_options(cfg.agent_policy)

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
            "policy_version": derive_policy_version(
                cfg.policy_rules or [], getattr(cfg, "rule_resolution", None)
            ),
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
    from .policy_log import snapshot_policy, emit_policy_changed_event
    existing = _tenant_registry.get(tenant_id, {})
    prev_rules = existing.get("policy_rules", []) or []
    _tenant_registry[tenant_id] = {"policy_rules": rules}
    cfg = _state.get("config")
    resolution = getattr(cfg, "rule_resolution", None) if cfg is not None else None
    snapshot_policy(rules, tenant_id, resolution=resolution)
    event = emit_policy_changed_event(
        prev_rules, rules, tenant_id, changed_by, resolution=resolution
    )
    # Put policy changes through the SAME signed sender as every other audit
    # event. The old standalone POST ignored HTTP status, retried nothing,
    # updated no counters, and swallowed every failure — a rejected governance
    # event was indistinguishable from a recorded one.
    if cfg is not None and getattr(cfg, "ingest_url", None):
        from . import sender
        sender.send_audit_async(cfg, dataclasses.asdict(event))


def get_tenant_config(tenant_id: str) -> "ResolvedConfig":
    """Get config merged with tenant-specific overrides."""
    base = get_config()
    override = _tenant_registry.get(tenant_id)
    if not override:
        return base
    return dataclasses.replace(base, policy_rules=override.get("policy_rules", base.policy_rules))


def apply_policy_rules(config: "ResolvedConfig", rules: List[Any]) -> None:
    """Install the rules a poll delivered, keeping locally declared ones.

    LOCALLY-DECLARED RULES SURVIVE A POLL. The two sources have separate
    lifetimes: a poll owns the server set and may legitimately empty it, but it
    never deletes a rule the caller passed to ``init(policy_rules=...)``.

    Why, given that wholesale replacement looks like the simpler contract: a
    200 carrying ``{"rules":[]}`` used to erase locally declared rules AND
    stamp the sync as successful, so ``fail_mode="closed"`` never tripped — a
    deployment was silently disarmed by a response nobody ever sees, with
    nothing on the record saying its rules had gone. ``policy_floor`` already
    survived a poll (its own field exists for exactly that reason), so local
    rules were the one tier a network response could delete. This makes the
    three consistent: the floor always survives, local survives a poll, the
    server set is the poll's to manage.

    A server rule carrying the id of a local one does NOT replace it — that is
    the same disarming edit wearing a matching id, and letting it through would
    reopen the hole for any deployment that has not pinned a policy key.

    Mirror of updatePolicyRules in config.ts.
    """
    local = _state.get("local_policy_rules") or []
    _state["server_policy_rules"] = list(rules)
    local_ids = {getattr(r, "id", None) for r in local}
    shadowed = [r for r in rules if getattr(r, "id", None) in local_ids]
    if shadowed:
        logging.getLogger("obsvr").warning(
            "[obsvr] Policy poll returned %d rule(s) whose id is declared locally "
            "(%s); the local declaration stands."
            % (len(shadowed), ", ".join(str(getattr(r, "id", "?")) for r in shadowed))
        )
    config.policy_rules = list(local) + [
        r for r in rules if getattr(r, "id", None) not in local_ids
    ]


def _reset() -> None:
    """Reset state (tests only)."""
    from .remote import _reset_remote
    from .canary import _reset_canaries
    from .session_taint import _reset_session_taint
    from .policy import _reset_detector_errors
    from .policy_verify import _reset_policy_verify
    _reset_remote()
    _reset_canaries()
    _reset_session_taint()
    _reset_policy_verify()
    _reset_detector_errors()
    # Framework handlers remember which calls they have already recorded, so
    # that registering obsvr twice (auto-instrumentation plus a manual call)
    # still yields one evidence record per call. That memory outlives config,
    # so a test that resets config has to clear it or a replayed id is read as
    # already-recorded.
    from .dedupe import _reset_dedupe
    _reset_dedupe()
    # The AutoGen send hook keeps its per-conversation step budget in a
    # thread-local, which outlives config the same way the dedupe memory does.
    # A test that reset config and then spent a budget was starting from the
    # previous test's count.
    from .integrations.autogen import _reset_run_state
    _reset_run_state()
    _state["initialized"] = False
    _state["config"] = None
    _state["local_policy_rules"] = None
    _state["server_policy_rules"] = None
    _tenant_registry.clear()
