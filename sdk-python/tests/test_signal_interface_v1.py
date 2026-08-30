from obsvr.signal_interface_v1 import resolve_signal_v1, signal_resolution_to_cedar_context_v1, signal_resolution_to_opa_input_v1, signal_resolution_to_otel_attributes_v1

DECLARATION = {"signal_id": "customer-risk", "version": "2", "determinism": "probabilistic", "locality": "remote", "timeout_ms": 500, "cache_ttl_ms": 1000, "failure_disposition": "defer"}
OBSERVATION = {"signal_id": "customer-risk", "version": "2", "input_hash": "a" * 64, "status": "matched", "labels": ["high-risk"], "score_bps": 8700, "provenance_hash": "b" * 64, "evaluated_at_ms": 100, "latency_ms": 30, "cache_state": "miss"}


def test_records_remote_probabilistic_facts_without_granting_authority():
    result = resolve_signal_v1(DECLARATION, OBSERVATION)
    assert result["fact"] == {"matched": True, "labels": ["high-risk"], "score_bps": 8700}
    assert result["required_outcome"] is None
    assert result["authoritative_allow"] is result["declaration"]["authoritative_allow"] is False
    assert result["resolution_hash"] == "7fb165138893b6749a98511f198a759b59bc2ef017dcdd5155eb9037469fc610"


def test_turns_declared_failures_into_deterministic_kernel_constraint():
    result = resolve_signal_v1(DECLARATION, {**OBSERVATION, "status": "timeout", "labels": []})
    assert result["required_outcome"] == "DEFER"
    assert result["authoritative_allow"] is False


def test_exports_correlation_and_policy_inputs_without_replacing_evidence():
    result = resolve_signal_v1(DECLARATION, OBSERVATION)
    assert signal_resolution_to_otel_attributes_v1(result)["obsvr.signal.resolution_hash"] == result["resolution_hash"]
    assert signal_resolution_to_opa_input_v1(result)["obsvr_signal"]["authoritative_allow"] is False
    assert signal_resolution_to_cedar_context_v1(result)["obsvrSignalAuthoritativeAllow"] is False
