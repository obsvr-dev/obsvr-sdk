import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  STRICT_EXECUTION_OUTCOME_V21_SCHEMA,
  strictExecutionResultV21Hash,
  strictExecutionStartV21Hash,
  type StrictExecutionOutcomeV21Body,
  type StrictExecutionStartV21,
} from './strict-execution-outcome-v2-1.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';

export interface StrictRuntimeFailureClassificationV21 {
  status: 'failed' | 'uncertain';
  error_code: string;
}

export function createStrictRuntimeExecutionStartV21(
  receipt: StrictReceiptV21Envelope,
  operationFingerprint: string,
  startedAtMs: number,
): StrictExecutionStartV21 & { execution_start_hash: string } {
  const start: StrictExecutionStartV21 = {
    tenant_id: receipt.body.tenant_id,
    session_id: receipt.body.session_id,
    action_id: receipt.body.action.action_id,
    decision_receipt_hash: receipt.receipt_hash,
    operation_fingerprint: operationFingerprint,
    attempt: 1,
    started_at_ms: startedAtMs,
  };
  return { ...start, execution_start_hash: strictExecutionStartV21Hash(start) };
}

function outcomeId(receiptHash: string, operationFingerprint: string): string {
  return createHash('sha256').update(canonicalJsonForHash({
    schema: 'obsvr-strict-runtime-outcome-id-v2-1',
    receipt_hash: receiptHash,
    operation_fingerprint: operationFingerprint,
    attempt: 1,
  })).digest('hex');
}

export function createStrictRuntimeSuccessOutcomeV21(
  receipt: StrictReceiptV21Envelope,
  start: StrictExecutionStartV21 & { execution_start_hash: string },
  completedAtMs: number,
  resultProjection: unknown,
): StrictExecutionOutcomeV21Body {
  return {
    schema: STRICT_EXECUTION_OUTCOME_V21_SCHEMA,
    profile_version: '2.1',
    record_type: 'execution_outcome',
    outcome_id: outcomeId(receipt.receipt_hash, start.operation_fingerprint),
    tenant_id: start.tenant_id,
    session_id: start.session_id,
    action_id: start.action_id,
    decision_receipt_hash: start.decision_receipt_hash,
    decision_sequence: receipt.body.sequence,
    operation_fingerprint: start.operation_fingerprint,
    attempt: 1,
    started_at_ms: start.started_at_ms,
    execution_start_hash: start.execution_start_hash,
    completed_at_ms: completedAtMs,
    status: 'succeeded',
    result_hash: strictExecutionResultV21Hash(resultProjection),
  };
}

export function createStrictRuntimeErrorOutcomeV21(
  receipt: StrictReceiptV21Envelope,
  start: StrictExecutionStartV21 & { execution_start_hash: string },
  completedAtMs: number,
  classification: StrictRuntimeFailureClassificationV21,
): StrictExecutionOutcomeV21Body {
  return {
    schema: STRICT_EXECUTION_OUTCOME_V21_SCHEMA,
    profile_version: '2.1',
    record_type: 'execution_outcome',
    outcome_id: outcomeId(receipt.receipt_hash, start.operation_fingerprint),
    tenant_id: start.tenant_id,
    session_id: start.session_id,
    action_id: start.action_id,
    decision_receipt_hash: start.decision_receipt_hash,
    decision_sequence: receipt.body.sequence,
    operation_fingerprint: start.operation_fingerprint,
    attempt: 1,
    started_at_ms: start.started_at_ms,
    execution_start_hash: start.execution_start_hash,
    completed_at_ms: completedAtMs,
    status: classification.status,
    error_code: classification.error_code,
  };
}

export function defaultStrictRuntimeResultProjectionV21(): unknown {
  return { schema: 'obsvr-strict-runtime-result-v2-1', status: 'succeeded' };
}

export function classifyStrictRuntimeErrorV21(
  error: unknown,
  classifier?: (error: unknown) => StrictRuntimeFailureClassificationV21,
): StrictRuntimeFailureClassificationV21 {
  if (!classifier) return { status: 'uncertain', error_code: 'action_error_unclassified' };
  try {
    const result = classifier(error);
    if (result && (result.status === 'failed' || result.status === 'uncertain')
      && typeof result.error_code === 'string') return result;
  } catch { /* classification failures are themselves uncertain */ }
  return { status: 'uncertain', error_code: 'error_classification_failed' };
}
