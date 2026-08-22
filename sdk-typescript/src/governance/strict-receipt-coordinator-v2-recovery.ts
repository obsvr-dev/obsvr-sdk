import type { IntentV2BaseResult } from '../policy/intent-alignment-v2.js';
import type { ActionContextV2Document } from './action-context-v2.js';
import {
  StrictReceiptCoordinatorV2, type PendingV2,
} from './strict-receipt-coordinator-v2.js';
import {
  buildCoordinatorContextV2, v2Clone,
} from './strict-receipt-coordinator-v2-support.js';
import type {
  PreparedDecisionV2, PreparedResolutionV2, StrictCoordinatorV2StateInspection,
  StrictDecisionV2Input, StrictDecisionV2Result, StrictReceiptCoordinatorV2Options,
  StrictResolutionV2Input, StrictTimeoutV2Input,
} from './strict-receipt-coordinator-v2-types.js';
import type { DefinitiveNoStore } from './strict-receipt-prepared-state.js';
import type { StrictReceiptV2Envelope } from './strict-receipt-v2.js';
import {
  type RecoveryPendingV2, signStrictRecoveryV2, type StrictRecoveryV2Document,
  type StrictRecoveryV2Envelope, verifyStrictRecoveryV2,
} from './strict-receipt-recovery-v2.js';
import {
  assertAcceptedStrictReconciliationV2, type StrictReconciliationV2Result,
} from './strict-receipt-reconcile-v2.js';

export interface StrictCoordinatorV2Restore {
  checkpoint: StrictRecoveryV2Envelope;
  expected_origin_pid: number;
}

export class RecoverableStrictReceiptCoordinatorV2 extends StrictReceiptCoordinatorV2 {
  private recoveryPrepared: RecoveryPendingV2 | undefined;

  constructor(options: StrictReceiptCoordinatorV2Options, restore?: StrictCoordinatorV2Restore) {
    super(options);
    if (restore) this.restore(verifyStrictRecoveryV2(restore.checkpoint, options.signer), restore.expected_origin_pid);
  }

  override prepareDecision(input: StrictDecisionV2Input): PreparedDecisionV2 {
    this.assertRecoveryReady();
    const context = buildCoordinatorContextV2(input.context, this.sessionId, this.priorActions);
    const prepared = super.prepareDecision(input);
    const value = prepared.value;
    this.recoveryPrepared = { kind: 'decision', receipt: v2Clone(value.receipt),
      context: v2Clone(context), base_result: { ...input.base_result }, evaluation: v2Clone(value.evaluation) };
    return prepared;
  }
  override prepareResolution(input: StrictResolutionV2Input): PreparedResolutionV2 {
    this.assertRecoveryReady();
    const prepared = super.prepareResolution(input);
    this.recoveryPrepared = { kind: 'resolution', receipt: v2Clone(prepared.value),
      suspended_receipt_hash: input.suspended_receipt_hash };
    return prepared;
  }
  override prepareTimeout(input: StrictTimeoutV2Input): PreparedResolutionV2 {
    this.assertRecoveryReady();
    const prepared = super.prepareTimeout(input);
    this.recoveryPrepared = { kind: 'timeout', receipt: v2Clone(prepared.value),
      suspended_receipt_hash: input.suspended_receipt_hash };
    return prepared;
  }
  override commitPrepared(token: string, hash: string): StrictDecisionV2Result | StrictReceiptV2Envelope {
    const result = super.commitPrepared(token, hash);
    this.recoveryPrepared = undefined;
    return result;
  }
  override abortPrepared(token: string, hash: string, capability: DefinitiveNoStore): void {
    super.abortPrepared(token, hash, capability);
    this.recoveryPrepared = undefined;
  }
  override inspectState(): StrictCoordinatorV2StateInspection {
    const state = super.inspectState();
    return this.recoveryPrepared && !state.prepared
      ? { ...state, frozen: true, freeze_reason: 'restart_reconciliation_required' }
      : state;
  }

  exportRecoveryCheckpoint(): StrictRecoveryV2Envelope {
    this.ensureProcess();
    const suspended = [...this.suspended.entries()].map(([receipt_hash, value]) => ({
      receipt_hash, receipt: v2Clone(value.receipt), context: v2Clone(value.context),
      base_result: { ...value.baseResult },
    }));
    const document: StrictRecoveryV2Document = {
      schema: 'obsvr-strict-receipt-recovery-v2', profile_version: '2.0',
      tenant_id: this.tenantId, session_id: this.sessionId,
      sdk_language: 'typescript', sdk_version: this.sdkVersion, origin_pid: this.ownerPid,
      committed: { sequence: this.sequence, head_receipt_hash: this.lastReceiptHash,
        last_timestamp_ms: this.lastTimestamp, prior_actions: v2Clone(this.priorActions),
        suspended, resolved_receipt_hashes: [...this.resolved].sort(),
        action_ids: [...this.actionIds].sort(),
        approval_requests: [...this.approvalRequests.entries()]
          .map(([request_id, receipt_hash]) => ({ request_id, receipt_hash }))
          .sort((left, right) => left.request_id.localeCompare(right.request_id)) },
      ...(this.recoveryPrepared ? { prepared: v2Clone(this.recoveryPrepared) } : {}),
    };
    return signStrictRecoveryV2(document, this.signer);
  }

  reconcileRecoveredAccepted(proof: StrictReconciliationV2Result): StrictReceiptV2Envelope {
    this.ensureProcess();
    const pending = this.recoveryPrepared;
    if (!pending) throw new Error('no recovered receipt is pending');
    assertAcceptedStrictReconciliationV2(proof, pending.receipt);
    if (pending.kind === 'decision') {
      if (!pending.context || !pending.base_result || !pending.evaluation) throw new Error('recovered decision state is incomplete');
      this.commitDecision({ evaluation: pending.evaluation, receipt: pending.receipt },
        pending.context, pending.base_result);
    } else {
      const hash = pending.suspended_receipt_hash;
      if (!hash) throw new Error('recovered resolution state is incomplete');
      const index = this.priorActions.findIndex((item) => item.receipt_hash === hash);
      if (index < 0) throw new Error('recovered suspension summary is missing');
      this.commitResolution(pending.receipt, hash, index);
    }
    this.recoveryPrepared = undefined;
    return v2Clone(pending.receipt);
  }

  private restore(document: StrictRecoveryV2Document, expectedOriginPid: number): void {
    if (!Number.isSafeInteger(expectedOriginPid) || expectedOriginPid < 0
      || document.origin_pid !== expectedOriginPid) throw new Error('recovery origin PID mismatch');
    if (document.tenant_id !== this.tenantId || document.session_id !== this.sessionId
      || document.sdk_version !== this.sdkVersion) throw new Error('recovery tenant/session/sdk mismatch');
    const state = document.committed;
    this.sequence = state.sequence; this.lastReceiptHash = state.head_receipt_hash;
    this.lastTimestamp = state.last_timestamp_ms; this.priorActions = v2Clone(state.prior_actions);
    this.suspended.clear();
    for (const item of state.suspended) this.suspended.set(item.receipt_hash, {
      receipt: v2Clone(item.receipt), context: v2Clone(item.context), baseResult: { ...item.base_result },
    } as PendingV2);
    this.resolved.clear(); state.resolved_receipt_hashes.forEach((hash) => this.resolved.add(hash));
    this.actionIds.clear(); state.action_ids.forEach((id) => this.actionIds.add(id));
    this.approvalRequests.clear(); state.approval_requests.forEach((item) => this.approvalRequests.set(item.request_id, item.receipt_hash));
    this.recoveryPrepared = document.prepared ? v2Clone(document.prepared) : undefined;
  }
  private assertRecoveryReady(): void {
    if (this.recoveryPrepared) throw new Error('recovered receipt requires reconciliation before new work');
  }
}
