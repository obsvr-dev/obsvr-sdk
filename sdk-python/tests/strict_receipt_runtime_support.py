"""Deterministic helpers shared by strict runtime tests."""

from obsvr.device_identity import load_device_signer
from obsvr.strict_receipt_coordinator import StrictReceiptCoordinator
from obsvr.strict_receipt_runtime import STRICT_BOUND_ARGUMENTS

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_D = "d" * 64
POLICY = {
    "schema": "obsvr-intent-policy-v1",
    "profile_version": "1.0",
    "intent_scopes": [
        {
            "intent_id": "deploy",
            "allowed_actions": [{"kind": "tool", "name": "send"}],
            "allowed_targets": ["prod"],
            "allowed_requested_scopes": ["write"],
            "allowed_data_classifications": ["confidential"],
        }
    ],
}


def make_signer(tmp_path):
    path = tmp_path / "runtime-seed.key"
    path.write_text("00" * 32, encoding="ascii")
    return load_device_signer(str(path))


def context(arguments_hash=HASH_A):
    return {
        "agent_id": "agent-1",
        "active_intents": ["deploy"],
        "privilege_scope": ["write"],
        "current_action": {
            "kind": "tool",
            "name": "send",
            "arguments_hash": arguments_hash,
            "target": "prod",
            "requested_scopes": ["write"],
            "data_classifications": ["confidential"],
        },
        "run_id": "run-1",
        "thread_id": "thread-1",
    }


def coordinator(tmp_path, clock):
    def verify(evidence, expected):
        if not isinstance(evidence, dict) or evidence.get("token") != "trusted":
            raise ValueError("untrusted approval evidence")
        return {
            "request_id": expected["request_id"],
            "action_hash": expected["action_hash"],
            "principal_id": "reviewer-1",
            "decision": expected["decision"],
            "source_hash": HASH_D,
            "expires_at_ms": evidence["expires_at_ms"],
        }

    return StrictReceiptCoordinator(
        signer=make_signer(tmp_path),
        policy=POLICY,
        sdk_language="python",
        sdk_version="0.test",
        session_id="session-1",
        clock=clock,
        defer_ttl_ms=500,
        approval_verifier=verify,
    )


def decision(action_id, base_result):
    return {
        "context": context(),
        "base_result": base_result,
        "policy_version": "policy-1",
        "rule_ids": ["rule-a"],
        "action_id": action_id,
    }


def accepted(receipt_hash, status="accepted"):
    return {
        "disposition": "accepted",
        "receipt_hash": receipt_hash,
        "status": status,
        "attempts": 1,
    }


def action(action_id, invoke, original=None):
    return {
        "runtime_action_id": action_id,
        "original_arguments": {
            "capability": STRICT_BOUND_ARGUMENTS,
            "arguments_hash": HASH_A,
            "value": {"value": "original"} if original is None else original,
        },
        "invoke": invoke,
    }
