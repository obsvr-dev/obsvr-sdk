"""Post-admission execution and terminal finalization for strict profile 2.1."""

from __future__ import annotations

from typing import Any, Dict

from .strict_receipt_runtime_v2_1_outcomes import (
    classify_strict_runtime_error_v2_1,
    create_strict_runtime_error_outcome_v2_1,
    create_strict_runtime_execution_start_v2_1,
    create_strict_runtime_success_outcome_v2_1,
    default_strict_runtime_result_projection_v2_1,
)
from .strict_receipt_runtime_v2_1_support import (
    StrictReceiptRuntimeV21Error,
    finish_runtime_result,
    persist_runtime_checkpoint,
    runtime_state,
)


def _finish(
    runtime: Any,
    result_key: str,
    fingerprint: str,
    base: Dict[str, Any],
    admission: Dict[str, Any],
    **result: Any,
) -> Dict[str, Any]:
    return finish_runtime_result(
        runtime,
        result_key,
        fingerprint,
        {**base, "admission": admission, **result},
    )


def _finalization_failed(
    runtime: Any,
    result_key: str,
    fingerprint: str,
    base: Dict[str, Any],
    admission: Dict[str, Any],
    error: Exception,
) -> Dict[str, Any]:
    runtime_state(runtime).frozen_reason = "terminal_outcome_failed"
    return _finish(
        runtime,
        result_key,
        fingerprint,
        base,
        admission,
        status="invocation_uncertain",
        error=error,
    )


def execute_committed_strict_action_v2_1(
    runtime: Any,
    *,
    prepared: Dict[str, Any],
    receipt: Dict[str, Any],
    action: Dict[str, Any],
    arguments: Any,
    action_id: str,
    result_key: str,
    fingerprint: str,
    admission: Dict[str, Any],
    base: Dict[str, Any],
) -> Dict[str, Any]:
    state = runtime_state(runtime)
    try:
        execution_start = create_strict_runtime_execution_start_v2_1(
            receipt, fingerprint, state.coordinator.observe_execution_time()
        )
    except Exception as error:
        state.frozen_reason = "execution_start_unavailable"
        return _finish(
            runtime,
            result_key,
            fingerprint,
            base,
            admission,
            status="nonexecuted",
            reason="execution_state_unavailable",
            error=error,
        )
    try:
        persist_runtime_checkpoint(
            runtime,
            "invocation_started",
            prepared,
            receipt,
            action_id,
            fingerprint,
            execution_start=execution_start,
        )
    except Exception as error:
        state.frozen_reason = "invocation_started_journal_failed"
        return _finish(
            runtime,
            result_key,
            fingerprint,
            base,
            admission,
            status="nonexecuted",
            reason="checkpoint_persist_failed",
            error=error,
        )
    state.results[result_key] = {
        "fingerprint": fingerprint,
        "result": {
            **base,
            "status": "invocation_uncertain",
            "admission": admission,
            "error": StrictReceiptRuntimeV21Error(
                "action invocation is already in progress"
            ),
        },
    }
    try:
        value = action["invoke"](arguments)
    except Exception as error:
        classification = classify_strict_runtime_error_v2_1(
            error, action.get("classify_error")
        )
        try:
            execution_outcome = state.coordinator.sign_execution_outcome(
                create_strict_runtime_error_outcome_v2_1(
                    receipt,
                    execution_start,
                    state.coordinator.observe_execution_time(),
                    classification,
                ),
                receipt,
            )
            terminal_status = (
                "invocation_failed"
                if classification["status"] == "failed"
                else "invocation_uncertain"
            )
            persist_runtime_checkpoint(
                runtime,
                "terminal",
                prepared,
                receipt,
                action_id,
                fingerprint,
                terminal_status=terminal_status,
                execution_start=execution_start,
                execution_outcome=execution_outcome,
            )
        except Exception as finalization_error:
            return _finalization_failed(
                runtime,
                result_key,
                fingerprint,
                base,
                admission,
                finalization_error,
            )
        return _finish(
            runtime,
            result_key,
            fingerprint,
            base,
            admission,
            execution_outcome=execution_outcome,
            status=terminal_status,
            error=error,
        )
    try:
        projector = action.get("result_projection")
        result_projection = (
            projector(value)
            if callable(projector)
            else default_strict_runtime_result_projection_v2_1()
        )
    except Exception as error:
        try:
            classification = {
                "status": "uncertain",
                "error_code": "result_projection_failed",
            }
            execution_outcome = state.coordinator.sign_execution_outcome(
                create_strict_runtime_error_outcome_v2_1(
                    receipt,
                    execution_start,
                    state.coordinator.observe_execution_time(),
                    classification,
                ),
                receipt,
            )
            persist_runtime_checkpoint(
                runtime,
                "terminal",
                prepared,
                receipt,
                action_id,
                fingerprint,
                terminal_status="invocation_uncertain",
                execution_start=execution_start,
                execution_outcome=execution_outcome,
            )
        except Exception as finalization_error:
            return _finalization_failed(
                runtime,
                result_key,
                fingerprint,
                base,
                admission,
                finalization_error,
            )
        return _finish(
            runtime,
            result_key,
            fingerprint,
            base,
            admission,
            execution_outcome=execution_outcome,
            status="invocation_uncertain",
            error=error,
        )
    try:
        execution_outcome = state.coordinator.sign_execution_outcome(
            create_strict_runtime_success_outcome_v2_1(
                receipt,
                execution_start,
                state.coordinator.observe_execution_time(),
                result_projection,
            ),
            receipt,
        )
        persist_runtime_checkpoint(
            runtime,
            "terminal",
            prepared,
            receipt,
            action_id,
            fingerprint,
            terminal_status="executed",
            execution_start=execution_start,
            execution_outcome=execution_outcome,
        )
    except Exception as error:
        return _finalization_failed(
            runtime,
            result_key,
            fingerprint,
            base,
            admission,
            error,
        )
    return _finish(
        runtime,
        result_key,
        fingerprint,
        base,
        admission,
        execution_outcome=execution_outcome,
        status="executed",
        value=value,
    )
