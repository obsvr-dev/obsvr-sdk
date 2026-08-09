"""Audit event builder + emitter.

Field mapping is identical to the TS SDK's buildAuditEvent /
buildIntegrationEvent (sdk-typescript/src/integrations/core.ts) and matches the
ingest RawEventSchema (snake_case, compliance fields, truncation marker).
"""

import json
import uuid
from typing import TYPE_CHECKING, Any, Dict, Optional

from . import sender
from .agent_run import with_run_metadata
from .config import ResolvedConfig
from .policy import DEFAULT_COMPLIANCE
from .reason_codes import ReasonCode


#: The closed set of ``action_taken`` verdicts, sorted.
#:
#: PYTHON HAD NO ENUMERATION OF THIS AT ALL. Comments in this file already called
#: it "the closed action_taken enum", and the closure existed only in TypeScript,
#: as a string-literal union. So the field a post-incident reader consults to
#: learn what governance did was closed by convention on one side and by nothing
#: at all on the other.
#:
#: What made that urgent rather than untidy: ``not_evaluated`` was live in BOTH
#: SDKs, emitted from several surfaces, and pinned by no fixture. The two
#: languages agreed only because they had been widened in the same commit. Every
#: other instance of that pattern in this codebase was found by a live probe
#: rather than by a check.
#:
#: Pinned cross-language by ``conformance/fixtures/action_taken.json``; the twin
#: is ``ACTION_TAKEN`` in sdk-typescript/src/governance/action-taken.ts, where a
#: compile-time check binds it to both interfaces that declare the union. Each
#: language asserts against the fixture, which makes the two agree transitively
#: without comparing them directly.
#:
#: Adding a member is BREAKING for consumers with exhaustive branches; renaming
#: one is a wire-format change to evidence already stored.
ACTION_TAKEN = (
    "allowed",
    "blocked",
    "hook_error",
    "hook_timeout",
    "not_evaluated",
    "redacted",
)


def _resolved_reason_code(comp):
    """The event's registry reason code: the deciding layer's explicit code
    when it supplied one, PERMITTED for a clean or overridden allow, else the
    same derivation ``create_policy_error`` uses — one resolution rule for the
    record and the exception alike. Always the wire string, never an enum
    member, so the serialized event is stable."""
    explicit = comp.get("reason_code")
    if explicit:
        return explicit.value if isinstance(explicit, ReasonCode) else str(explicit)
    if comp.get("action_reason") in ("none", "customer_override"):
        return ReasonCode.PERMITTED.value
    from .errors import _resolve_reason_code

    return _resolve_reason_code(comp.get("action_reason"), comp.get("action_source"), None)

if TYPE_CHECKING:  # import cycle: errors -> reason_codes is fine, events -> errors at runtime is not
    from .errors import ObsvrPolicyError

# keep metadata under the ingest 10 KB canonical cap (with headroom), or
# the canonicalizer replaces it wholesale with {"_truncated": true}, destroying
# trace_id / agent_run_id / the span envelope and orphaning the event.
_METADATA_BUDGET_CHARS = 9000

#: Reserved-metadata key ``content_provenance`` rides on until ingest has a
#: column for it, following the ``obsvr_tool_content_hash`` carriage plan
#: verbatim:
#:
#: 1. (now) the SDK stamps both the top-level field and this key; consumers
#:    read it from metadata;
#: 2. ingest declares a ``content_provenance`` column and backfills from here;
#: 3. the SDK keeps mirroring for one minor release, then stops.
#:
#: Nothing downstream depends on the top-level name until step 2, so steps 1
#: and 3 are additive and need no coordinated release. Twin:
#: CONTENT_PROVENANCE_METADATA_KEY in sdk-typescript/src/proxy/sender/fire-and-forget.ts.
CONTENT_PROVENANCE_METADATA_KEY = "obsvr_content_provenance"

_RESERVED_META_KEYS = (
    "trace_id",
    "agent_run_id",
    "agent_run_name",
    "obsvr_span",
    "obsvr_telemetry",
    "obsvr_external_backend",
    "obsvr_integrity_flags",
    "obsvr_tool_content_hash",
    CONTENT_PROVENANCE_METADATA_KEY,
)


def _within_metadata_budget(md: Dict[str, Any]) -> bool:
    """Is the metadata bag inside the budget? An UNMEASURABLE bag counts as over.

    ``metadata`` is caller-supplied. ``default=str`` already covers a value
    ``json`` cannot serialize, but two shapes still raise straight through it: a
    CIRCULAR reference (``ValueError: Circular reference detected``) and a value
    whose own ``__str__`` raises. This runs on the caller's synchronous emit
    path, so an unguarded raise leaves the sender and lands in the application's
    own call — the one exception to "an exception inside any detector layer never
    reaches your application".

    Answering "over budget" rather than inventing a posture is the point. A bag
    this cannot measure is a bag ingest's canonicalizer cannot measure either,
    and ingest REPLACES metadata wholesale with ``{"_truncated":true}`` past
    10 KB — destroying ``trace_id`` / ``agent_run_id`` and orphaning the event
    from its run. Taking the existing trim keeps the grouping keys, which is
    exactly what that branch exists to do.

    Twin: ``withinBudget`` in sdk-typescript/src/proxy/sender/fire-and-forget.ts.
    """
    try:
        return len(json.dumps(md, default=str)) <= _METADATA_BUDGET_CHARS
    except Exception:  # noqa: BLE001 - a bag that cannot be measured is over
        return False


def _trim_metadata_to_budget(md: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not md:
        return md
    if _within_metadata_budget(md):
        return md
    # 1. The span attribute bag is the usual culprit — collapse it first.
    span = md.get("obsvr_span")
    if isinstance(span, dict) and "attributes" in span:
        md = {**md, "obsvr_span": {**span, "attributes": {"_trimmed": True}}}
        if _within_metadata_budget(md):
            md["_obsvr_metadata_trimmed"] = True
            return md
    # 2. Still over: keep only the reserved grouping/provenance keys.
    trimmed: Dict[str, Any] = {"_obsvr_metadata_trimmed": True}
    for k in _RESERVED_META_KEYS:
        if k in md:
            trimmed[k] = md[k]
    return trimmed

def _principal_string(value: Any) -> Optional[str]:
    """Canonical string form of the signed principal, or None for absent.

    ``user_id`` is inside the format-3 decision digest, and the offline
    verifiers in both languages must reach the same verdict over one export.
    The two runtimes do not stringify scalars alike — ``str(1.0)`` is
    ``"1.0"`` where JS ``String(1.0)`` is ``"1"``, ``str(True)`` is ``"True"``
    where JS prints ``"true"`` — and a JSON export erases the distinction JS
    would need to reproduce Python's rendering (``1.0`` parses to the number
    ``1``). So the event stores ONE canonical string, minted at this boundary
    under the SDK's shared canonical-scalar rules (the same ECMAScript
    rendering ``policy_version`` hashing already uses), and everything
    downstream — the signer, both verifiers, the export — handles only that
    string. The TypeScript boundary (proxy/filters/filter.ts) mints the same
    strings via ``String()``.

    The vocabulary is deliberately restricted to scalars: str unchanged,
    bool as the JSON literals, int exact, finite float in shortest ECMAScript
    form. Anything else — containers, objects, non-finite floats — is treated
    as ABSENT rather than sealed as a repr no other consumer can recompute.
    None stays None: the decision digest's presence byte keeps an absent
    principal distinct from an empty one, and that distinction is
    load-bearing.
    """
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        import math

        if not math.isfinite(value):
            return None
        from .rules import _js_number

        return _js_number(value)
    return None


TRUNCATION_MARKER = " [TRUNCATED]"


def truncate(text: Optional[str], max_chars: int) -> str:
    if text is None:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + TRUNCATION_MARKER


def classify_error(error: Any) -> str:
    """Same taxonomy as the TS proxy wrapper."""
    if not isinstance(error, BaseException):
        return "api_error"
    message = str(error).lower()
    name = type(error).__name__.lower()
    if "rate limit" in message or "429" in message or "ratelimit" in name:
        return "rate_limit"
    if "timeout" in message or "timeout" in name or "timed out" in message:
        return "timeout"
    if (
        "auth" in message
        or "401" in message
        or "403" in message
        or "unauthorized" in message
    ):
        return "auth_error"
    return "api_error"


def infer_provider_from_model(model: str) -> str:
    """Provider for a MODEL name, where :func:`infer_provider_from_string`
    answers for a PROVIDER id.

    The two are different questions, and conflating them is why LlamaIndex
    events came out unattributed: the provider-id form matches vendor tokens
    ("openai", "anthropic", "google"), which an id like "openai.responses"
    contains and a model name like "gpt-4o-mini" does not. Anthropic and Google
    model names happen to carry their vendor ("claude-", "gemini-") so they
    resolved by accident; OpenAI's never do.

    Only families that map to exactly ONE supported provider are recognised.
    Llama, Mistral and Qwen models are deliberately absent: the same weights are
    served by Bedrock, Together and others, so a guess would be a fabricated
    attribution rather than a missing one. Those stay "unknown", which is the
    honest answer.
    """
    import re

    by_vendor_token = infer_provider_from_string(model)
    if by_vendor_token != "unknown":
        return by_vendor_token
    s = (model or "").lower().strip()
    if re.match(r"^(gpt-|chatgpt-|o[1345](-|$)|davinci|babbage|text-davinci)", s):
        return "openai"
    if re.match(r"^(palm|bison|text-bison|chat-bison)", s):
        return "google"
    return "unknown"


def infer_provider_from_string(identifier: str) -> str:
    """Infer a provider label from an arbitrary identifier string."""
    s = identifier.lower()
    if "azure" in s:
        return "azure_openai"
    if "bedrock" in s:
        return "bedrock"
    if "vertex" in s:
        return "vertex_ai"
    if "together" in s:
        return "together"
    if "cloudflare" in s or "workersai" in s:
        return "cloudflare"
    if "openai" in s:
        return "openai"
    if "anthropic" in s or "claude" in s:
        return "anthropic"
    if "google" in s or "gemini" in s or "genai" in s:
        return "google"
    return "unknown"


def _with_provider_detail(
    md: Optional[Dict[str, Any]], provider: str
) -> Optional[Dict[str, Any]]:
    """preserve MCP identity in metadata.provider_detail (ingest coerces
    the "mcp" provider enum to "unknown")."""
    if provider != "mcp":
        return md
    out = dict(md or {})
    out.setdefault("provider_detail", "mcp")
    return out


def _with_destination_attribution(
    md: Optional[Dict[str, Any]], attribution: Optional[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Stamp where the call went, over anything the caller put there.

    Twin of `withProviderAttribution` in sdk-typescript/src/proxy/wrapper.ts.
    """
    if not attribution:
        return md
    out = dict(md or {})
    out.update(attribution)
    return out


def build_audit_event(
    config: ResolvedConfig,
    *,
    provider: str,
    model: str,
    operation: str,
    source: str,
    # Keyword-only, so a defaulted parameter may precede the required `prompt`.
    # See AuditEvent.content_provenance (sdk-typescript/src/proxy/types.ts) for the
    # vocabulary and for why it is never inferred.
    content_provenance: Optional[str] = None,
    prompt: str,
    response: str = "",
    user_input: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
    latency_ms: Optional[float] = None,
    time_to_first_token_ms: Optional[float] = None,
    success: bool = True,
    status_code: Optional[int] = None,
    error: Any = None,
    request_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    options: Optional[Dict[str, Any]] = None,
    compliance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    opts = options or {}
    comp = compliance or DEFAULT_COMPLIANCE
    # Ambient use_subject() scope, resolved once for the identity fields
    # below. Explicit per-call/wrap-time options always win over it.
    from .subject import get_current_subject

    _ambient_subject = get_current_subject() or {}

    # WHERE the call went, versus what the client looked like.
    #
    # `provider` as passed in is the client's API SHAPE: it selects the
    # prompt/response extractors upstream, and it is a question about the
    # object, not about the network. The RECORD must name the destination, and
    # those are different questions. One variable answered both, and the second
    # answer was wrong for every client pointed somewhere other than its shape
    # implied - an OpenAI-shaped client against a local server recorded
    # `provider: "openai"`.
    #
    # `wrap()` resolves the destination once and leaves it on the options dict,
    # which already reaches every emit site. Absent (integration paths that do
    # not resolve an endpoint), the shape-derived label stands exactly as before.
    from .provider_attribution import (
        ATTRIBUTION_OPTION_KEY,
        RECORDED_PROVIDER_OPTION_KEY,
    )

    _recorded = opts.get(RECORDED_PROVIDER_OPTION_KEY)
    _attribution = opts.get(ATTRIBUTION_OPTION_KEY)
    if _recorded:
        provider = _recorded

    # Final canary safety net (parity with TS buildIntegrationEvent): NO event
    # may carry a raw canary token in its content on ANY path — a model
    # echoing a planted token into its OUTPUT is the primary leak surface, and
    # some integrations have no post-call scan. Scrub prompt/response/
    # user_input; stamp evidence (ids/hash-prefixes, never the token). Zero
    # cost until a canary is minted.
    _canary_tel: Optional[Dict[str, Any]] = None
    _canary_scan_failed = False
    from .canary import canary_registry_size

    if canary_registry_size() > 0:
        from .canary import (
            CANARY_REDACTION_PLACEHOLDER,
            canary_leak_telemetry,
            scan_for_canary,
        )

        _hits: list = []
        _leak_surface: Optional[str] = None

        def _scrub(v: Optional[str], surface: str) -> Optional[str]:
            nonlocal _leak_surface
            if not v:
                return v
            leak = scan_for_canary(v)
            if leak["leaked"]:
                _hits.extend(leak["hits"])
                if _leak_surface is None:
                    _leak_surface = surface
                return CANARY_REDACTION_PLACEHOLDER
            return v

        # This net runs on EVERY emitted event on EVERY path, so an exception
        # here would reach the host from places that never touch the policy
        # engine. It is building a stored record, not deciding a call, so the
        # resolution is the response-phase one: never raise, and withhold the
        # stored copy rather than persist text no canary scan ever vetted.
        try:
            prompt = _scrub(prompt, "prompt")
            response = _scrub(response, "response")
            if user_input is not None:
                user_input = _scrub(user_input, "user_input")
        except Exception as _canary_exc:  # noqa: BLE001 - deliberate catch-all
            from .policy import UNSCANNED_PLACEHOLDER, record_detector_failure

            record_detector_failure("canary", _canary_exc, config)
            _canary_scan_failed = True
            prompt = UNSCANNED_PLACEHOLDER
            response = UNSCANNED_PLACEHOLDER if response else response
            if user_input is not None:
                user_input = UNSCANNED_PLACEHOLDER
        if _hits:
            _canary_tel = canary_leak_telemetry(_hits, _leak_surface or "response")

    error_message: Optional[str] = None
    if error is not None:
        m = str(error)
        error_message = m[:500] if len(m) > 500 else m

    _event = {
        # Core fields
        "request_id": request_id or str(uuid.uuid4()),
        # Environment fields
        "environment": config.environment,
        "service_name": opts.get("service_name")
        or _ambient_subject.get("service_name")
        or config.default_service_name,
        "region": opts.get("region") or config.default_region or "unknown",
        # Identity fields — read from the SAME view policy enforced against,
        # so the signed principal is the principal the decision was made for.
        # `metadata` is the enforcing channel: wrap() options folded with the
        # per-call obsvr_metadata kwarg (wrap._collect_metadata, later wins)
        # and then ambient-filled at the head of apply_pre_call_policy. Reading
        # `options` alone left the per-call channel out, so a call that
        # overrode the principal was METERED under the override and SIGNED
        # under the wrap-time name. Options and the ambient scope remain the
        # fallbacks for surfaces that pass no folded metadata. Coerced to the
        # one canonical string both offline verifiers recompute identically.
        "user_id": _principal_string(
            (metadata or {}).get("user_id")
            or opts.get("user_id")
            or _ambient_subject.get("user_id")
        ),
        # Network fields. This SDK has no capture path for either, so they are
        # always None rather than sometimes None — there is no per-call kwarg
        # and no config default that reaches them. A DIVERGENCE from the
        # TypeScript SDK, whose `AuditFields` type accepts both on the call and
        # strips them before the request goes out; here the per-call channel is
        # the namespaced `obsvr_metadata` kwarg (see wrap._collect_metadata),
        # which carries identity keys and not these two. Stated because a reader
        # of a hardcoded None is entitled to know whether it is a default or a
        # dead end.
        "client_ip": None,
        "user_agent": None,
        # LLM call fields
        "provider": provider,
        "model": model or "unknown",
        "operation": operation,
        "source": opts.get("source")
        or source
        or config.default_source
        or "integration",
        # Where inside the payload the content below came from. Absent unless
        # the caller passed one (None is stripped at the end of this builder) —
        # never derived here, since this function cannot see anything its caller
        # did not already know.
        "content_provenance": content_provenance,
        # Content fields
        "prompt": truncate(prompt, config.max_payload_chars),
        "response": truncate(response or "", config.max_payload_chars),
        "user_input": (
            truncate(user_input, config.max_payload_chars)
            if user_input is not None
            else None
        ),
        # Usage fields
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        # Performance fields
        "latency_ms": round(latency_ms) if latency_ms is not None else None,
        "time_to_first_token_ms": time_to_first_token_ms,
        # Success/status fields
        "success": success,
        # ABSENT when a failure carried no HTTP status, matching the TS SDK.
        # A client-side failure has no status code, and defaulting to 500
        # asserted a server error the provider never sent; `success` and
        # `error_type` already carry the failure.
        "status_code": status_code
        if status_code is not None
        else (200 if success else None),
        "error_type": classify_error(error) if error is not None else None,
        "error_message": error_message,
        # Metadata. with_run_metadata stamps agent_run_id when this event is
        # built inside an agent_run(...) scope, so proxy calls, integration
        # events, and spans all group into one run. No-op (byte-identical)
        # outside a run scope; a caller-set agent_run_id always wins.
        # ingest coerces provider "mcp" → "unknown"; stamp provider_detail
        # so provider-level analytics can recover the MCP identity.
        # Destination attribution is merged LAST and deliberately wins: it
        # describes where the call went, which is not a caller-supplied opinion.
        # Letting per-request metadata shadow it would drop the destination
        # evidence exactly when a caller attaches metadata of their own.
        "metadata": _with_destination_attribution(
            with_run_metadata(
                _with_provider_detail(
                    metadata if metadata is not None else opts.get("metadata"), provider
                )
            ),
            _attribution,
        ),
        # Compliance fields
        "event_type": comp["event_type"],
        "policy_version": comp["policy_version"],
        "action_taken": comp["action_taken"],
        "action_reason": comp["action_reason"],
        # Registry reason code for the classification the decision rests on.
        # Callers that resolved a fine-grained code pass it through; the rest
        # derive here exactly the way the raised error derives, so the record
        # and the exception cannot disagree.
        "reason_code": _resolved_reason_code(comp),
        "action_source": comp["action_source"],
        "redacted_types": comp["redacted_types"],
        "blocked_types": comp["blocked_types"],
        # What the scan FOUND, as distinct from what policy DID about it.
        # ``reason_code: PII_DETECTED`` is derived from the detection while the
        # two lists above are filled only by the block and redact branches, so a
        # type that resolves to detect_only produced that code with both lists
        # empty and nothing on the record naming what matched. Present only when
        # something was detected, so an event with no finding is unchanged.
        "detected_types": comp.get("detected_types"),
        # Optional compliance detail (parity with TS: rule_id/policy_reason
        # identify WHICH rule fired, not just that one did)
        "rule_id": comp.get("rule_id"),
        "policy_reason": comp.get("policy_reason"),
        # What shadow-mode rules would have done (EV-21); informational only
        "shadow_outcome": comp.get("shadow_outcome"),
        # Canonical decision record (ADR-2, additive — never part of the
        # HMAC chain preimage; sealed by the ledger's v7 Merkle leaf)
        "decision_input_hash": comp.get("decision_input_hash"),
        "engine_version": comp.get("engine_version"),
        # External policy backend provenance (ADR-4, additive)
        "external_backend": comp.get("external_backend"),
    }
    # external_backend has NO top-level ingest schema field and is stripped;
    # mirror it onto the preserved metadata channel so the ADR-4 provenance
    # survives (parity with the TS sender's normalizeWireShape).
    _external = comp.get("external_backend")
    if _external is not None:
        _md = dict(_event.get("metadata") or {})
        _md.setdefault("obsvr_external_backend", _external)
        _event["metadata"] = _md
    # Same route, same reason: ingest has no ``content_provenance`` column and
    # strips unknown top-level fields, so the top-level name alone would lose
    # the value silently. Mirror onto the reserved key the sender's trimmer
    # preserves (parity with TS normalizeWireShape); drop the mirror once
    # ingest declares the column.
    if content_provenance is not None:
        _md = dict(_event.get("metadata") or {})
        _md.setdefault(CONTENT_PROVENANCE_METADATA_KEY, content_provenance)
        _event["metadata"] = _md
    # A detector layer that raised has no top-level ingest field either (and
    # must not widen the closed action_taken enum), so the record of WHICH
    # layer was lost and how it resolved rides the reserved telemetry channel.
    if _canary_scan_failed:
        _md = dict(_event.get("metadata") or {})
        _tel = dict(_md.get("obsvr_telemetry") or {})
        _tel.setdefault("detector_failure", {
            "layer": "canary", "resolution": "open", "floor_class": True,
            "phase": "event_build", "stored_unscanned": True,
        })
        _md["obsvr_telemetry"] = _tel
        _event["metadata"] = _md
    _detector_failure = comp.get("detector_failure")
    if _detector_failure is not None:
        _md = dict(_event.get("metadata") or {})
        _tel = dict(_md.get("obsvr_telemetry") or {})
        _tel["detector_failure"] = _detector_failure
        _md["obsvr_telemetry"] = _tel
        _event["metadata"] = _md
    # Same route, same reason: a quota rule the bounded meter had no slot for
    # did not run on this call, and an allowed call that says nothing about it
    # reads as a rule that was in force and never exceeded.
    _quota_unmetered = comp.get("quota_unmetered")
    if _quota_unmetered is not None:
        _md = dict(_event.get("metadata") or {})
        _tel = dict(_md.get("obsvr_telemetry") or {})
        _tel["quota_unmetered"] = _quota_unmetered
        _md["obsvr_telemetry"] = _tel
        _event["metadata"] = _md
    # Same route again, and the sharpest of the three: an event whose subject no
    # gate evaluated still carries action_taken "allowed", which asserts a
    # decision rather than reporting the absence of one. (TS parity:
    # integrations/core.ts — the field had a route there and none here, so the
    # reason a gate was skipped was dropped on this side.)
    _policy_not_evaluated = comp.get("policy_not_evaluated")
    if _policy_not_evaluated is not None:
        _md = dict(_event.get("metadata") or {})
        _tel = dict(_md.get("obsvr_telemetry") or {})
        _tel["policy_not_evaluated"] = _policy_not_evaluated
        _md["obsvr_telemetry"] = _tel
        _event["metadata"] = _md
    if bool(getattr(config, "policy_floor", None)):
        # Anti-tamper floor evidence: floor_version is a pure function of
        # config.policy_floor, so it is stamped HERE for EVERY event under an
        # active floor (matching the proxy wrap path and the TS
        # buildIntegrationEvent) — so a change to the floor is auditable from
        # the allowed-event stream on every integration path, not just blocks.
        # Any call-specific floor_override_ignored already merged into metadata
        # by the caller (block path) is preserved: it is a separate key and
        # setdefault never clobbers an existing floor_version.
        from .rules import derive_floor_version

        _md = dict(_event.get("metadata") or {})
        _tel = dict(_md.get("obsvr_telemetry") or {})
        _tel.setdefault("floor_version", derive_floor_version(config.policy_floor))
        _md["obsvr_telemetry"] = _tel
        _event["metadata"] = _md
    if _canary_tel is not None:
        # Stamp the canary evidence the scrub caught; surface a clean event as
        # a policy_flag so a leak never reads as "allowed" (TS parity).
        _md = dict(_event.get("metadata") or {})
        _md["obsvr_telemetry"] = {**(_md.get("obsvr_telemetry") or {}), **_canary_tel}
        _event["metadata"] = _md
        # "not_evaluated" is included for the same reason "allowed" is: a
        # leaked canary must surface as a policy_flag rather than sit on an
        # event whose verdict field reads as untroubled. Deliberately NOT
        # widened to != "blocked" — that would newly escalate redacted and
        # hook_* events, a behaviour change this one does not need. (TS parity:
        # integrations/core.ts.)
        if _event["action_taken"] in ("allowed", "not_evaluated"):
            _event["event_type"] = "policy_flag"
            if not _event.get("rule_id"):
                _event["rule_id"] = "sdk:canary_leak"
            if not _event.get("policy_reason"):
                _event["policy_reason"] = "Canary token leaked in emitted content"
    # Cost and token-quota metering, OPT-IN on this path.
    #
    # The wrap() client-proxy path has always metered; this one never has, so
    # every framework integration has been invisible to cost reporting and to
    # token budgets since it shipped. Switching it on unconditionally would make
    # budgets that never bound start binding — an outage for anyone already
    # running a token quota — so it is gated and defaults to off. Absent the
    # flag this call site is the only difference from the previous behaviour and
    # it does nothing. Run BEFORE the metadata trim below so the cost fragment
    # is subject to the same budget as every other reserved key.
    if getattr(config, "meter_integration_events", False):
        from .metering import meter_event

        meter_event(config, _event)

    # cap metadata so ingest doesn't replace it wholesale (losing grouping keys).
    _event["metadata"] = _trim_metadata_to_budget(_event.get("metadata"))
    # Drop keys whose value is None so the strict ingest schema (which wants
    # optional fields absent, not null) accepts the event. Signature fields
    # are added later by the sender and are never None.
    return {k: v for k, v in _event.items() if v is not None}


def tool_denied_compliance() -> Dict[str, Any]:
    """Blocked-tool verdict shared by the agent integrations.

    TOOL_DENIED covers both refusal shapes - an explicit deny-list hit and
    absence from a configured allowlist are the same classification: this
    tool may not run. Returned fresh per call so a caller mutating one
    event's compliance cannot bleed into the next (twin of the TS
    integrations' BLOCKED_COMPLIANCE + TOOL_DENIED spread).
    """
    return {
        "event_type": "blocked_call",
        "policy_version": "none",
        "action_taken": "blocked",
        "action_reason": "policy_violation",
        "reason_code": ReasonCode.TOOL_DENIED.value,
        "action_source": "policy_rules",
        "redacted_types": [],
        "blocked_types": [],
    }


def step_limit_compliance() -> Dict[str, Any]:
    """Refusal verdict for an exhausted per-run step budget.

    A step-limit refusal used to carry no compliance at all, so it inherited
    the default and landed as ``event_type: "llm_call"`` with
    ``reason_code: PERMITTED`` — a refusal recorded as a permitted call, which
    every ``blocked_call`` filter steps straight over. An operator reviewing
    refusals never saw it.

    No ``reason_code`` is set deliberately. The registry is closed and pinned
    cross-language, and it has no step-limit member; leaving the code to be
    derived yields POLICY_VIOLATION by exactly the rule ``create_policy_error``
    uses, so the record and the raised error cannot classify this differently.
    Minting a dedicated code would touch both enums, the shared fixture, the
    corpus hash and the TypeScript emission path — and TypeScript's own step
    limits are still unmeasured, so that is not a change to make blind.
    """
    return {
        "event_type": "blocked_call",
        "policy_version": "none",
        "action_taken": "blocked",
        "action_reason": "policy_violation",
        "action_source": "policy_rules",
        "redacted_types": [],
        "blocked_types": [],
    }


def tool_gate_not_evaluated_compliance(
    surface: str, gate: str, reason: str
) -> Dict[str, Any]:
    """Verdict for a tool event NO GATE could decide.

    The honest value when a control did not run. Its opposite is not "allowed" —
    that asserts a gate looked and permitted — and it is emphatically not
    "blocked", which asserts a refusal. A surface whose gate cannot reach the
    invocation boundary has no verdict to report, so it reports the absence and
    says why.

    Omitting the field would not have helped: the ingest schema defaults an
    absent action_taken, so the server would mint "allowed" one layer down.
    Twin of the TS tool-runner path in proxy/wrapper.ts, routed through
    metadata.obsvr_telemetry the same way.
    """
    return {
        "event_type": "tool_call",
        "policy_version": "none",
        "action_taken": "not_evaluated",
        "action_reason": "none",
        "action_source": "unknown",
        "redacted_types": [],
        "blocked_types": [],
        "policy_not_evaluated": {
            "surface": surface,
            "gate": gate,
            "reason": reason,
        },
    }


def emit_event(config: ResolvedConfig, **params: Any) -> Optional[Dict[str, Any]]:
    """Build and fire-and-forget send an audit event. Never raises."""
    if config.disabled:
        return None
    try:
        event = build_audit_event(config, **params)
        sender.send_audit_async(config, event)
        return event
    except Exception:
        return None


def blocked_call_error(compliance: Dict[str, Any]) -> "ObsvrPolicyError":
    """Standard blocked-call error. Delegates to the one construction choke
    point so every surface raises the same typed error with the same
    classification; the message is unchanged (same as the TS SDK)."""
    from .errors import create_policy_error

    return create_policy_error(compliance)
