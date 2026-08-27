import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { ActionContextV2Document } from './action-context-v2.js';
import {
  trustedApprovalResult,
} from './strict-receipt-coordinator-support.js';
import {
  createTrustedIntentDecisionProviderV21,
  evaluateDecisionV21,
  v21Clone,
  v21Hash,
  v21Text,
} from './strict-receipt-coordinator-v2-1-support.js';
import type {
  StrictApprovalResolutionV21Input,
  StrictReceiptCoordinatorV21Options,
} from './strict-receipt-coordinator-v2-1-types.js';
import {
  STRICT_RECEIPT_V21_PROFILE_VERSION,
  STRICT_RECEIPT_V21_SCHEMA,
  signStrictReceiptV21,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
} from './strict-receipt-v2-1.js';

export interface PendingApprovalV21 {
  receipt: StrictReceiptV21Envelope;
  context: ActionContextV2Document;
}

function canonicalHash(value: unknown): string {
  return createHash('sha256').update(canonicalJsonForHash(value)).digest('hex');
}

export function normalizeApprovalResolutionV21(
  input: StrictApprovalResolutionV21Input,
): StrictApprovalResolutionV21Input {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('approval resolution must be an object');
  }
  const record = input as unknown as Record<string, unknown>;
  if (Object.keys(record).sort().join(',') !== 'approval_evidence,method,suspended_receipt_hash') {
    throw new Error('approval resolution has missing or unsupported fields');
  }
  if (record.method !== 'approval_granted' && record.method !== 'approval_denied') {
    throw new Error('approval resolution method is unsupported');
  }
  return {
    suspended_receipt_hash: v21Hash(record.suspended_receipt_hash, 'suspended_receipt_hash'),
    method: record.method,
    approval_evidence: v21Clone(record.approval_evidence),
  };
}

export function approvalResolutionFingerprintV21(
  input: StrictApprovalResolutionV21Input,
  tenantId: string,
  sessionId: string,
): string {
  return canonicalHash({
    schema: 'obsvr-strict-approval-resolution-request-v2-1',
    tenant_id: tenantId,
    session_id: sessionId,
    input,
  });
}

function assertAuthorityActive(pending: PendingApprovalV21, timestamp: number): void {
  for (const hop of pending.receipt.body.identity.delegation_chain) {
    if (hop.issued_at_ms > timestamp || timestamp >= hop.expires_at_ms) {
      throw new Error('delegated authority is not active at approval time');
    }
  }
}

export function signApprovalResolutionV21(params: {
  input: StrictApprovalResolutionV21Input;
  pending: PendingApprovalV21;
  options: StrictReceiptCoordinatorV21Options;
  policy: Parameters<typeof evaluateDecisionV21>[1];
  tenant_id: string;
  session_id: string;
  sequence: number;
  timestamp: number;
  previous_hash: string | null;
}): StrictReceiptV21Envelope {
  const prior = params.pending.receipt;
  const suspension = prior.body.suspension;
  if (!suspension || suspension.type !== 'approval') {
    throw new Error('suspended receipt is not awaiting approval');
  }
  const actionHash = suspension.approval_action_hash;
  if (!actionHash) throw new Error('suspended approval is missing its action binding');
  if (params.timestamp >= suspension.expires_at_ms && params.input.method === 'approval_granted') {
    throw new Error('approval cannot authorize after suspension expiry');
  }
  if (typeof params.options.approval_verifier !== 'function') {
    throw new Error('approval_verifier is required to resolve an approval');
  }
  assertAuthorityActive(params.pending, params.timestamp);
  const decision = params.input.method === 'approval_granted' ? 'granted' : 'denied';
  const expected = {
    request_id: suspension.suspension_id,
    action_hash: actionHash,
    decision,
    current_time_ms: params.timestamp,
  } as const;
  const trusted = trustedApprovalResult(
    params.options.approval_verifier(params.input.approval_evidence, expected),
    expected,
    suspension.expires_at_ms,
  );
  const evaluated = evaluateDecisionV21(
    params.pending.context,
    params.policy,
    createTrustedIntentDecisionProviderV21(() => ({
      action_taken: decision === 'granted' ? 'allowed' : 'blocked',
    })),
    params.options.evaluation_evidence_provider,
  );
  if (decision === 'granted' && !['ALLOW', 'MODIFY'].includes(evaluated.evidence.outcome)) {
    throw new Error('granted approval did not produce an authorized policy outcome');
  }
  if (decision === 'denied' && evaluated.evidence.outcome !== 'DENY') {
    throw new Error('denied approval did not produce a deny policy outcome');
  }
  const body: StrictReceiptV21Body = {
    schema: STRICT_RECEIPT_V21_SCHEMA,
    profile_version: STRICT_RECEIPT_V21_PROFILE_VERSION,
    record_type: 'resolution',
    receipt_id: `${params.session_id}:${params.sequence}`,
    tenant_id: params.tenant_id,
    session_id: params.session_id,
    sequence: params.sequence,
    timestamp_ms: params.timestamp,
    previous_receipt_hash: params.previous_hash,
    action: v21Clone(prior.body.action),
    context_hash: evaluated.intent.context_hash,
    identity: v21Clone(prior.body.identity),
    evaluation: evaluated.evidence,
    outcome: evaluated.evidence.outcome,
    reason_code: evaluated.evidence.reason_code,
    execution_authorized: decision === 'granted',
    resolution: {
      resolves_receipt_hash: prior.receipt_hash,
      suspension_id: suspension.suspension_id,
      method: params.input.method,
      resolver_ref_hash: canonicalHash({
        schema: 'obsvr-strict-resolver-ref-v2-1',
        principal_id: v21Text(trusted.principalId, 'trusted principal_id'),
      }),
      resolved_at_ms: params.timestamp,
      approval_evidence_hash: trusted.sourceHash,
    },
  };
  return signStrictReceiptV21(body, params.options.signer);
}
