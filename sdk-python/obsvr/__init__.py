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
# Ambient per-request subject: bind an end-user identity for a scope instead
# of threading user_id through every call. Twin of the TypeScript
# `useSubject()` (`import { useSubject } from "@obsvr/sdk"`).
from .subject import get_current_subject, parse_subject, use_subject  # noqa: F401
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
# Framework-agnostic tool governance at the package root, matching the
# TypeScript twin (`import { obsvrGovernTool } from "@obsvr/sdk"`): the two
# SDKs must not diverge on the entry point for the same primitive.
from .integrations.tools import govern_tool, govern_tools  # noqa: F401
from .govern_fn import govern, govern_fn  # noqa: F401
from .span_attributes import SPAN_ATTR  # noqa: F401
from .otel_mirror import (  # noqa: F401
    correlate_strict_runtime_checkpoint_v2_1_to_otel,
    with_strict_otel_correlation_v2_1,
)
from .wrap import wrap  # noqa: F401
from .strict_action_boundary_v2_1 import (  # noqa: F401
    ObsvrStrictActionBoundaryV21Error,
    StrictActionBoundaryV21Capability,
    create_strict_action_boundary_v2_1,
    execute_strict_action_v2_1,
)
from .strict_provider_boundary_v2_1 import (  # noqa: F401
    ObsvrStrictProviderBoundaryV21Error,
    StrictProviderBoundaryV21Capability,
    create_strict_provider_boundary_v2_1,
)
from .strict_receipt_runtime_v2_1 import (  # noqa: F401
    StrictReceiptRuntimeV21,
    bind_strict_v2_1_json_arguments,
)
from .strict_runtime_recovery_v2_1 import (  # noqa: F401
    StrictRuntimeRecoveryV21Error,
    finalize_interrupted_strict_runtime_execution_v2_1,
    reconcile_strict_runtime_execution_v2_1,
)
from .strict_policy_continuity_v2_1 import (  # noqa: F401
    STRICT_POLICY_CONTINUITY_V2_1_SCHEMA,
    StrictPolicyContinuityV21Error,
    reconstruct_strict_policy_continuity_v2_1,
)
from .strict_evidence_bundle_v2_1 import (  # noqa: F401
    STRICT_EVIDENCE_BUNDLE_V2_1_ENVELOPE_SCHEMA,
    STRICT_EVIDENCE_BUNDLE_V2_1_SCHEMA,
    StrictEvidenceBundleV21Error,
    build_strict_evidence_bundle_v2_1_body,
    create_strict_evidence_bundle_v2_1,
    strict_evidence_bundle_v2_1_hash,
    strict_evidence_bundle_v2_1_signature_preimage,
    verify_strict_evidence_bundle_v2_1,
)
from .strict_execution_outcome_v2_1 import (  # noqa: F401
    StrictExecutionOutcomeV21ValidationError,
    build_strict_execution_outcome_v2_1_body,
    canonicalize_strict_execution_outcome_v2_1_body,
    sign_strict_execution_outcome_v2_1,
    strict_execution_outcome_v2_1_hash,
    strict_execution_outcome_v2_1_signature_preimage,
    strict_execution_result_v2_1_hash,
    strict_execution_start_v2_1_hash,
    verify_strict_execution_outcome_v2_1,
)
from .strict_execution_outcome_transport_v2_1 import (  # noqa: F401
    STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA,
    STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT,
    STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA,
    STRICT_EXECUTION_OUTCOME_V2_1_MAX_REQUEST_BYTES,
    StrictExecutionOutcomeV21TransportError,
    submit_strict_execution_outcome_v2_1,
    submit_strict_runtime_terminal_journal_v2_1,
)
from .strict_receipt_coordinator_v2_1 import (  # noqa: F401
    StrictReceiptCoordinatorV21,
    create_trusted_intent_decision_provider_v2_1,
)
from .strict_evaluation_evidence_v2_1 import (  # noqa: F401
    create_trusted_evaluation_evidence_provider_v2_1,
)
from .strict_identity_evidence_v2_1 import (  # noqa: F401
    create_strict_identity_evidence_v2_1_authority,
)
from .device_identity import load_device_signer  # noqa: F401
# Why an optional integration failed to bind, not merely that it did: an
# absent package, a renamed upstream symbol and a broken transitive dependency
# are three different problems that used to produce one identical silent flag.
from .binding_report import (  # noqa: F401
    RequiredBindingsError,
    assert_required_bindings,
    integration_bindings,
    required_binding_failures,
    unbound_symbols,
)
from .coverage_attestation import (  # noqa: F401
    COVERAGE_ATTESTATION_ENVELOPE_SCHEMA,
    COVERAGE_ATTESTATION_SCHEMA,
    CoverageAttestationValidationError,
    build_coverage_attestation_body,
    canonicalize_coverage_attestation_body,
    coverage_attestation_body_hash,
    sign_coverage_attestation,
    verify_coverage_attestation,
)

from ._version import __version__  # noqa: F401  # single source: obsvr/_version.py
from .auto import auto_governance_status  # noqa: F401

__all__ = [
    "init",
    "wrap",
    "create_strict_action_boundary_v2_1",
    "execute_strict_action_v2_1",
    "ObsvrStrictActionBoundaryV21Error",
    "StrictActionBoundaryV21Capability",
    "create_strict_provider_boundary_v2_1",
    "ObsvrStrictProviderBoundaryV21Error",
    "StrictProviderBoundaryV21Capability",
    "StrictReceiptRuntimeV21",
    "StrictRuntimeRecoveryV21Error",
    "finalize_interrupted_strict_runtime_execution_v2_1",
    "reconcile_strict_runtime_execution_v2_1",
    "STRICT_POLICY_CONTINUITY_V2_1_SCHEMA",
    "StrictPolicyContinuityV21Error",
    "reconstruct_strict_policy_continuity_v2_1",
    "STRICT_EVIDENCE_BUNDLE_V2_1_SCHEMA",
    "STRICT_EVIDENCE_BUNDLE_V2_1_ENVELOPE_SCHEMA",
    "StrictEvidenceBundleV21Error",
    "build_strict_evidence_bundle_v2_1_body",
    "create_strict_evidence_bundle_v2_1",
    "strict_evidence_bundle_v2_1_hash",
    "strict_evidence_bundle_v2_1_signature_preimage",
    "verify_strict_evidence_bundle_v2_1",
    "StrictExecutionOutcomeV21ValidationError",
    "build_strict_execution_outcome_v2_1_body",
    "canonicalize_strict_execution_outcome_v2_1_body",
    "sign_strict_execution_outcome_v2_1",
    "strict_execution_outcome_v2_1_hash",
    "strict_execution_outcome_v2_1_signature_preimage",
    "strict_execution_result_v2_1_hash",
    "strict_execution_start_v2_1_hash",
    "verify_strict_execution_outcome_v2_1",
    "STRICT_EXECUTION_OUTCOME_V2_1_INGEST_SCHEMA",
    "STRICT_EXECUTION_OUTCOME_V2_1_ADMISSION_SCHEMA",
    "STRICT_EXECUTION_OUTCOME_V2_1_ENDPOINT",
    "STRICT_EXECUTION_OUTCOME_V2_1_MAX_REQUEST_BYTES",
    "StrictExecutionOutcomeV21TransportError",
    "submit_strict_execution_outcome_v2_1",
    "submit_strict_runtime_terminal_journal_v2_1",
    "StrictReceiptCoordinatorV21",
    "create_trusted_intent_decision_provider_v2_1",
    "create_trusted_evaluation_evidence_provider_v2_1",
    "create_strict_identity_evidence_v2_1_authority",
    "bind_strict_v2_1_json_arguments",
    "load_device_signer",
    "govern_tool",
    "govern_tools",
    "govern",
    "govern_fn",
    "integration_bindings",
    "required_binding_failures",
    "assert_required_bindings",
    "RequiredBindingsError",
    "auto_governance_status",
    "COVERAGE_ATTESTATION_ENVELOPE_SCHEMA",
    "COVERAGE_ATTESTATION_SCHEMA",
    "CoverageAttestationValidationError",
    "build_coverage_attestation_body",
    "canonicalize_coverage_attestation_body",
    "coverage_attestation_body_hash",
    "sign_coverage_attestation",
    "verify_coverage_attestation",
    "unbound_symbols",
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
    "use_subject",
    "get_current_subject",
    "parse_subject",
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
    "correlate_strict_runtime_checkpoint_v2_1_to_otel",
    "with_strict_otel_correlation_v2_1",
    "ResolvedConfig",
    "ReasonCode",
    "REASON_CODES",
    "RULE_TYPE_TO_REASON_CODE",
    "rule_type_to_reason_code",
    "__version__",
]
