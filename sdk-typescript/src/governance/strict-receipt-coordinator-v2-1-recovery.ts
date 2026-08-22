import {
  StrictReceiptCoordinatorV21,
} from './strict-receipt-coordinator-v2-1.js';
import {
  normalizeDecisionActionV21, v21Clone,
} from './strict-receipt-coordinator-v2-1-support.js';
import type {
  PreparedDecisionV21, StrictCoordinatorV21StateInspection,
  StrictDecisionActionV21Input, StrictDecisionV21Result,
  StrictReceiptCoordinatorV21Options,
} from './strict-receipt-coordinator-v2-1-types.js';
import type { DefinitiveNoStore } from './strict-receipt-prepared-state.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import {
  signStrictRecoveryV21, type RecoveryPreparedV21,
  type StrictRecoveryV21Document, type StrictRecoveryV21Envelope,
  verifyStrictRecoveryV21,
} from './strict-receipt-recovery-v2-1.js';
import {
  assertAcceptedStrictReconciliationV21, type StrictReconciliationV21Result,
} from './strict-receipt-reconcile-v2-1.js';

export interface RecoverableStrictReceiptCoordinatorV21Options
  extends StrictReceiptCoordinatorV21Options { sdk_version: string }
export interface StrictCoordinatorV21Restore {
  checkpoint: StrictRecoveryV21Envelope;
  expected_origin_pid: number;
}

export class RecoverableStrictReceiptCoordinatorV21 extends StrictReceiptCoordinatorV21 {
  private readonly sdkVersion: string;
  private recoveryPrepared: RecoveryPreparedV21 | undefined;

  constructor(options: RecoverableStrictReceiptCoordinatorV21Options, restore?: StrictCoordinatorV21Restore) {
    super(options);
    if (typeof options.sdk_version !== 'string' || !options.sdk_version.trim()) throw new Error('sdk_version must be nonblank');
    this.sdkVersion = options.sdk_version;
    if (restore) this.restore(
      verifyStrictRecoveryV21(restore.checkpoint, options.signer), restore.expected_origin_pid,
    );
  }

  override prepareDecision(input: StrictDecisionActionV21Input): PreparedDecisionV21 {
    this.assertRecoveryReady();
    const normalized = normalizeDecisionActionV21(input);
    const prepared = super.prepareDecision(normalized);
    this.recoveryPrepared = { kind: 'decision', input: v21Clone(normalized), result: v21Clone(prepared.value) };
    return prepared;
  }

  override commitPrepared(token: string, hash: string): StrictDecisionV21Result {
    const result = super.commitPrepared(token, hash); this.recoveryPrepared = undefined; return result;
  }

  override abortPrepared(token: string, hash: string, capability: DefinitiveNoStore): void {
    super.abortPrepared(token, hash, capability); this.recoveryPrepared = undefined;
  }

  override inspectState(): StrictCoordinatorV21StateInspection {
    const state = super.inspectState();
    return this.recoveryPrepared && !state.prepared
      ? { ...state, frozen: true, freeze_reason: 'restart_reconciliation_required' }
      : state;
  }

  exportRecoveryCheckpoint(): StrictRecoveryV21Envelope {
    this.ensureProcess();
    const document: StrictRecoveryV21Document = {
      schema: 'obsvr-strict-receipt-recovery-v2-1', profile_version: '2.1',
      tenant_id: this.tenantId, session_id: this.sessionId,
      sdk_language: 'typescript', sdk_version: this.sdkVersion, origin_pid: this.ownerPid,
      committed: {
        sequence: this.sequence, head_receipt_hash: this.headReceiptHash,
        last_timestamp_ms: this.lastTimestamp, prior_actions: v21Clone(this.priorActions),
        action_ids: [...this.committedActionIds].sort(),
        pending_approval_ids: [...this.pendingApprovalIds].sort(),
      },
      ...(this.recoveryPrepared ? { prepared: v21Clone(this.recoveryPrepared) } : {}),
    };
    return signStrictRecoveryV21(document, this.options.signer);
  }

  reconcileRecoveredAccepted(proof: StrictReconciliationV21Result): StrictReceiptV21Envelope {
    this.ensureProcess(); const pending = this.recoveryPrepared;
    if (!pending) throw new Error('no recovered decision is pending');
    assertAcceptedStrictReconciliationV21(proof, pending.result.receipt);
    this.commitDecision(pending.result, pending.input);
    this.recoveryPrepared = undefined;
    return v21Clone(pending.result.receipt);
  }

  private restore(document: StrictRecoveryV21Document, expectedOriginPid: number): void {
    if (!Number.isSafeInteger(expectedOriginPid) || expectedOriginPid < 0
      || document.origin_pid !== expectedOriginPid) throw new Error('recovery origin PID mismatch');
    if (document.tenant_id !== this.tenantId || document.session_id !== this.sessionId
      || document.sdk_language !== 'typescript' || document.sdk_version !== this.sdkVersion
      || document.profile_version !== '2.1') throw new Error('recovery tenant/session/sdk/profile mismatch');
    const state = document.committed;
    this.sequence = state.sequence; this.headReceiptHash = state.head_receipt_hash;
    this.lastTimestamp = state.last_timestamp_ms; this.priorActions = v21Clone(state.prior_actions);
    this.committedActionIds.clear(); state.action_ids.forEach((id) => this.committedActionIds.add(id));
    this.pendingApprovalIds.clear(); state.pending_approval_ids.forEach((id) => this.pendingApprovalIds.add(id));
    this.recoveryPrepared = document.prepared ? v21Clone(document.prepared) : undefined;
  }

  private assertRecoveryReady(): void {
    if (this.recoveryPrepared) throw new Error('recovered decision requires accepted reconciliation before new work');
  }
}
