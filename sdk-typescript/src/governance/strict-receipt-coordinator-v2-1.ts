import { randomUUID } from 'node:crypto';
import type { IntentPolicyV2Document } from '../policy/intent-alignment-v2.js';
import type { PriorActionV2Input } from './action-context-v2.js';
import {
  assertTrustedIntentDecisionProviderV21,
  buildCoordinatorContextV21,
  buildIntentPolicyV2,
  captureIdentityV21,
  createTrustedIntentDecisionProviderV21,
  decisionV21Fingerprint,
  evaluateDecisionV21,
  normalizeDecisionActionV21,
  signDecisionV21,
  StrictReceiptCoordinatorV21Error,
  v21Clone,
  v21Integer,
  v21Text,
} from './strict-receipt-coordinator-v2-1-support.js';
import type {
  PreparedDecisionV21,
  StrictCoordinatorV21StateInspection,
  StrictDecisionActionV21Input,
  StrictDecisionV21Result,
  StrictReceiptCoordinatorV21Options,
} from './strict-receipt-coordinator-v2-1-types.js';
import {
  strictReceiptV21KeyId,
  type StrictReceiptV21Envelope,
} from './strict-receipt-v2-1.js';
import {
  signStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Body,
  type StrictExecutionOutcomeV21Envelope,
} from './strict-execution-outcome-v2-1.js';
import {
  PreparedReceiptState,
  type DefinitiveNoStore,
} from './strict-receipt-prepared-state.js';

export type {
  PreparedDecisionV21,
  StrictCoordinatorV21StateInspection,
  StrictDecisionActionV21Input,
  StrictDecisionV21Result,
  StrictReceiptCoordinatorV21Options,
  TrustedIntentDecisionProviderV21,
} from './strict-receipt-coordinator-v2-1-types.js';
export { createTrustedIntentDecisionProviderV21, StrictReceiptCoordinatorV21Error };

export class StrictReceiptCoordinatorV21 {
  protected readonly options: StrictReceiptCoordinatorV21Options;
  protected readonly policy: IntentPolicyV2Document;
  protected readonly tenantId: string;
  protected readonly sessionId: string;
  protected readonly ownerPid: number;
  protected readonly pidSource: () => number;
  protected readonly preparedState: PreparedReceiptState;
  protected sequence = 0;
  protected headReceiptHash: string | null = null;
  protected lastTimestamp: number | null = null;
  protected priorActions: PriorActionV2Input[] = [];
  protected readonly committedActionIds = new Set<string>();
  protected readonly pendingApprovalIds = new Set<string>();

  constructor(options: StrictReceiptCoordinatorV21Options) {
    if (options.sdk_language !== 'typescript') {
      throw new StrictReceiptCoordinatorV21Error('sdk_language must be typescript');
    }
    if (typeof options.clock !== 'function') {
      throw new StrictReceiptCoordinatorV21Error('clock must be callable');
    }
    if (typeof options.identity_snapshot !== 'function'
      || !options.identity_authority || typeof options.identity_authority.issue !== 'function') {
      throw new StrictReceiptCoordinatorV21Error('trusted identity authority and snapshot are required');
    }
    assertTrustedIntentDecisionProviderV21(options.intent_decision_provider);
    this.options = Object.freeze({ ...options });
    this.policy = buildIntentPolicyV2(options.policy);
    this.tenantId = v21Text(options.tenant_id, 'tenant_id');
    this.sessionId = v21Text(options.session_id, 'session_id');
    const ttl = v21Integer(options.defer_ttl_ms, 'defer_ttl_ms');
    if (ttl === 0) throw new StrictReceiptCoordinatorV21Error('defer_ttl_ms must be positive');
    this.pidSource = options.pid ?? (() => process.pid);
    this.ownerPid = v21Integer(this.pidSource(), 'pid');
    strictReceiptV21KeyId(options.signer.rawPublicKey);
    this.preparedState = new PreparedReceiptState(
      options.prepared_token_factory ?? (() => randomUUID()),
    );
  }

  prepareDecision(rawInput: StrictDecisionActionV21Input): PreparedDecisionV21 {
    this.ensureProcess();
    const input = normalizeDecisionActionV21(rawInput);
    if (this.committedActionIds.has(input.action_id)) {
      throw new StrictReceiptCoordinatorV21Error('action_id is already committed');
    }
    const fingerprint = decisionV21Fingerprint(input, this.tenantId, this.sessionId, this.policy);
    const retry = this.preparedState.retry<StrictDecisionV21Result>(fingerprint, 'decision');
    if (retry) return v21Clone(retry);
    const timestamp = this.allocateTimestamp();
    const identity = captureIdentityV21(this.options, timestamp);
    const context = buildCoordinatorContextV21(
      input, identity, this.sessionId, v21Clone(this.priorActions),
    );
    const evaluated = evaluateDecisionV21(
      context, this.policy, this.options.intent_decision_provider,
      this.options.evaluation_evidence_provider,
    );
    const receipt = signDecisionV21({
      input, identity, context, evaluation: evaluated.evidence,
      base_result: evaluated.base_result, tenant_id: this.tenantId,
      session_id: this.sessionId, sequence: this.sequence + 1,
      timestamp, previous_hash: this.headReceiptHash,
      defer_ttl_ms: this.options.defer_ttl_ms, signer: this.options.signer,
    });
    if (receipt.body.context_hash !== evaluated.intent.context_hash) {
      throw new StrictReceiptCoordinatorV21Error('signed context_hash does not match intent evaluation');
    }
    const approvalId = receipt.body.suspension?.type === 'approval'
      ? receipt.body.suspension.suspension_id : undefined;
    if (approvalId !== undefined && this.pendingApprovalIds.has(approvalId)) {
      throw new StrictReceiptCoordinatorV21Error('approval request is already pending');
    }
    const result: StrictDecisionV21Result = {
      action_context: context,
      intent_evaluation: {
        outcome: evaluated.intent.outcome,
        reason_code: evaluated.intent.reason_code,
        context_hash: evaluated.intent.context_hash,
        policy_hash: evaluated.intent.policy_hash,
      },
      evaluation_evidence: evaluated.evidence,
      receipt,
    };
    return v21Clone(this.preparedState.prepare({
      fingerprint,
      receipt_hash: receipt.receipt_hash,
      kind: 'decision',
      value: result,
      commit: () => this.commitDecision(result, input),
    }));
  }

  commitPrepared(token: string, receiptHash: string): StrictDecisionV21Result {
    this.ensureProcess();
    return v21Clone(this.preparedState.commit<StrictDecisionV21Result>(token, receiptHash));
  }

  abortPrepared(token: string, receiptHash: string, capability: DefinitiveNoStore): void {
    this.ensureProcess();
    this.preparedState.abort(token, receiptHash, capability);
  }

  freezePrepared(token: string, receiptHash: string, reason = 'transport_ambiguous'): void {
    this.ensureProcess();
    this.preparedState.freeze(token, receiptHash, reason);
  }

  inspectState(): StrictCoordinatorV21StateInspection {
    this.ensureProcess();
    return {
      tenant_id: this.tenantId,
      session_id: this.sessionId,
      sequence: this.sequence,
      head_receipt_hash: this.headReceiptHash,
      ...this.preparedState.inspect(),
    };
  }

  observeExecutionTime(): number {
    this.ensureProcess();
    const observed = v21Integer(this.options.clock(), 'clock');
    if (this.lastTimestamp !== null && observed < this.lastTimestamp) {
      throw new StrictReceiptCoordinatorV21Error('clock regressed');
    }
    return observed;
  }

  signExecutionOutcome(
    body: StrictExecutionOutcomeV21Body,
    decision: StrictReceiptV21Envelope,
  ): StrictExecutionOutcomeV21Envelope {
    this.ensureProcess();
    return signStrictExecutionOutcomeV21(body, this.options.signer, decision);
  }

  private allocateTimestamp(): number {
    const observed = v21Integer(this.options.clock(), 'clock');
    if (this.lastTimestamp !== null && observed < this.lastTimestamp) {
      throw new StrictReceiptCoordinatorV21Error('clock regressed');
    }
    return observed;
  }

  protected commitDecision(
    result: StrictDecisionV21Result,
    input: StrictDecisionActionV21Input,
  ): void {
    const receipt = result.receipt;
    this.sequence = receipt.body.sequence;
    this.headReceiptHash = receipt.receipt_hash;
    this.lastTimestamp = receipt.body.timestamp_ms;
    this.committedActionIds.add(receipt.body.action.action_id);
    this.priorActions.push({
      sequence: receipt.body.sequence,
      kind: receipt.body.action.kind,
      name: receipt.body.action.name,
      outcome: receipt.body.outcome,
      receipt_hash: receipt.receipt_hash,
      data_classifications: [...input.current_action.data_classifications],
    });
    if (receipt.body.suspension?.type === 'approval') {
      this.pendingApprovalIds.add(receipt.body.suspension.suspension_id);
    }
  }

  protected ensureProcess(): void {
    if (v21Integer(this.pidSource(), 'pid') !== this.ownerPid) {
      throw new StrictReceiptCoordinatorV21Error(
        'strict profile 2.1 coordinator cannot cross a process boundary',
      );
    }
  }
}
