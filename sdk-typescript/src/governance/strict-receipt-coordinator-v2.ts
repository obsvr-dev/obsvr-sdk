import { randomUUID } from 'node:crypto';
import type { DeviceSigner } from '../proxy/device-identity.js';
import {
  type IntentAlignmentV2Result, type IntentPolicyV2Document, type IntentV2BaseResult,
} from '../policy/intent-alignment-v2.js';
import type { ActionContextV2Document, PriorActionV2Input } from './action-context-v2.js';
import type { AarmOutcome } from './aarm-outcome.js';
import {
  buildCoordinatorContextV2, buildIntentPolicyV2, contextInputFromV2Document,
  decisionV2Fingerprint, evaluateV2, resolutionV2Fingerprint, signDecisionV2,
  signResolutionV2, timeoutV2Fingerprint, v2CanonicalHash, v2Clone, v2Hash,
  v2Integer, v2Text, validateDeferredChangesV2,
} from './strict-receipt-coordinator-v2-support.js';
import type {
  PreparedDecisionV2, PreparedResolutionV2, StrictCoordinatorV2StateInspection,
  StrictDecisionV2Input, StrictDecisionV2Result, StrictReceiptCoordinatorV2Options,
  StrictResolutionV2Input, StrictTimeoutV2Input,
} from './strict-receipt-coordinator-v2-types.js';
import { trustedApprovalResult, type StrictApprovalVerifier } from './strict-receipt-coordinator-support.js';
import { type StrictReceiptV2Envelope, strictReceiptV2KeyId } from './strict-receipt-v2.js';
import {
  PreparedReceiptState, type DefinitiveNoStore,
} from './strict-receipt-prepared-state.js';

export type {
  PreparedDecisionV2, PreparedResolutionV2, StrictCoordinatorV2ContextInput,
  StrictCoordinatorV2StateInspection, StrictDecisionV2Input, StrictDecisionV2Result,
  StrictReceiptCoordinatorV2Options, StrictResolutionV2Input, StrictTimeoutV2Input,
} from './strict-receipt-coordinator-v2-types.js';

const FINAL = new Set<AarmOutcome>(['ALLOW', 'DENY', 'MODIFY']);
export interface PendingV2 {
  receipt: StrictReceiptV2Envelope;
  context: ActionContextV2Document;
  baseResult: IntentV2BaseResult;
}

export class StrictReceiptCoordinatorV2Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictReceiptCoordinatorV2Error'; }
}

export class StrictReceiptCoordinatorV2 {
  protected readonly signer: DeviceSigner;
  private readonly policy: IntentPolicyV2Document;
  protected readonly sdkVersion: string;
  protected readonly tenantId: string;
  protected readonly sessionId: string;
  private readonly clock: () => number;
  private readonly deferTtlMs: number;
  private readonly approvalVerifier: StrictApprovalVerifier;
  private readonly includePublicKey: boolean;
  private readonly pidSource: () => number;
  protected readonly ownerPid: number;
  protected sequence = 0;
  protected lastReceiptHash: string | null = null;
  protected lastTimestamp: number | null = null;
  protected priorActions: PriorActionV2Input[] = [];
  protected readonly suspended = new Map<string, PendingV2>();
  protected readonly resolved = new Set<string>();
  protected readonly actionIds = new Set<string>();
  protected readonly approvalRequests = new Map<string, string>();
  private readonly preparedState: PreparedReceiptState;

  constructor(options: StrictReceiptCoordinatorV2Options) {
    if (options.sdk_language !== 'typescript') throw new StrictReceiptCoordinatorV2Error('sdk_language must be typescript');
    this.signer = options.signer;
    this.policy = buildIntentPolicyV2(options.policy);
    this.sdkVersion = v2Text(options.sdk_version, 'sdk_version');
    this.tenantId = v2Text(options.tenant_id, 'tenant_id');
    this.sessionId = v2Text(options.session_id, 'session_id');
    this.clock = options.clock;
    this.deferTtlMs = v2Integer(options.defer_ttl_ms, 'defer_ttl_ms');
    if (this.deferTtlMs === 0) throw new StrictReceiptCoordinatorV2Error('defer_ttl_ms must be positive');
    if (typeof options.approval_verifier !== 'function') throw new StrictReceiptCoordinatorV2Error('approval_verifier must be a function');
    this.approvalVerifier = options.approval_verifier;
    this.includePublicKey = options.include_public_key ?? true;
    this.pidSource = options.pid ?? (() => process.pid);
    this.ownerPid = v2Integer(this.pidSource(), 'pid');
    this.preparedState = new PreparedReceiptState(options.prepared_token_factory ?? (() => randomUUID()));
    strictReceiptV2KeyId(this.signer.rawPublicKey);
  }

  prepareDecision(input: StrictDecisionV2Input): PreparedDecisionV2 {
    this.ensureProcess();
    const actionId = v2Text(input.action_id, 'action_id');
    const fingerprint = decisionV2Fingerprint(input, this.tenantId, this.sessionId);
    if (this.actionIds.has(actionId)) throw new StrictReceiptCoordinatorV2Error('action_id is already committed');
    const retry = this.preparedState.retry<StrictDecisionV2Result>(fingerprint, 'decision');
    if (retry) return v2Clone(retry);
    const baseResult = { ...input.base_result };
    const context = buildCoordinatorContextV2(input.context, this.sessionId, this.priorActions);
    const evaluation = evaluateV2(context, baseResult, this.policy);
    const { timestamp, clamped } = this.allocateTimestamp();
    const receipt = signDecisionV2({
      action_id: actionId, tenant_id: this.tenantId, session_id: this.sessionId,
      sequence: this.sequence + 1, timestamp, clamped, previous_hash: this.lastReceiptHash,
      sdk_version: this.sdkVersion, signer: this.signer, include_public_key: this.includePublicKey,
      context, base_result: baseResult, evaluation, policy_version: input.policy_version,
      rule_ids: input.rule_ids, defer_ttl_ms: this.deferTtlMs,
    });
    const requestId = receipt.body.suspension?.approval_request_id;
    if (requestId !== undefined && this.approvalRequests.has(requestId)) {
      throw new StrictReceiptCoordinatorV2Error('approval_request_id is already pending');
    }
    const result = { evaluation, receipt };
    return v2Clone(this.preparedState.prepare({
      fingerprint, receipt_hash: receipt.receipt_hash, kind: 'decision', value: result,
      commit: () => this.commitDecision(result, context, baseResult),
    }));
  }

  prepareResolution(input: StrictResolutionV2Input): PreparedResolutionV2 {
    this.ensureProcess();
    if ((input.method as string) === 'expired') {
      throw new StrictReceiptCoordinatorV2Error('expired suspensions must use prepareTimeout');
    }
    const fingerprint = resolutionV2Fingerprint(input, this.tenantId, this.sessionId);
    const retry = this.preparedState.retry<StrictReceiptV2Envelope>(fingerprint, 'resolution');
    if (retry) return v2Clone(retry);
    const receiptHash = v2Hash(input.suspended_receipt_hash, 'suspended_receipt_hash');
    const pending = this.pending(receiptHash);
    const suspension = pending.receipt.body.suspension!;
    const context = buildCoordinatorContextV2(input.context, this.sessionId, this.priorActions);
    const baseResult = { ...input.base_result };
    const evaluation = evaluateV2(context, baseResult, this.policy);
    const { timestamp, clamped } = this.allocateTimestamp();
    const evidence = this.validateResolution(input, pending, context, baseResult, evaluation, timestamp);
    const index = this.priorActions.findIndex((item) => item.receipt_hash === receiptHash);
    if (index < 0) throw new StrictReceiptCoordinatorV2Error('suspended action summary is missing');
    const receipt = signResolutionV2({
      prior: pending.receipt, method: input.method, principal_id: evidence.principalId,
      source_hash: evidence.sourceHash, tenant_id: this.tenantId, session_id: this.sessionId,
      sequence: this.sequence + 1, timestamp, clamped, previous_hash: this.lastReceiptHash,
      sdk_version: this.sdkVersion, signer: this.signer, include_public_key: this.includePublicKey,
      context, base_result: baseResult, evaluation, policy_version: input.policy_version,
      rule_ids: input.rule_ids,
    });
    return v2Clone(this.preparedState.prepare({ fingerprint, receipt_hash: receipt.receipt_hash,
      kind: 'resolution', value: receipt, commit: () => this.commitResolution(receipt, receiptHash, index) }));
  }

  prepareTimeout(input: StrictTimeoutV2Input): PreparedResolutionV2 {
    this.ensureProcess();
    const fingerprint = timeoutV2Fingerprint(input, this.tenantId, this.sessionId);
    const retry = this.preparedState.retry<StrictReceiptV2Envelope>(fingerprint, 'timeout');
    if (retry) return v2Clone(retry);
    const receiptHash = v2Hash(input.suspended_receipt_hash, 'suspended_receipt_hash');
    const pending = this.pending(receiptHash);
    const suspension = pending.receipt.body.suspension!;
    const context = buildCoordinatorContextV2(contextInputFromV2Document(pending.context), this.sessionId, this.priorActions);
    const baseResult: IntentV2BaseResult = { action_taken: 'blocked' };
    const evaluation = evaluateV2(context, baseResult, this.policy);
    const { timestamp, clamped } = this.allocateTimestamp();
    if (timestamp < suspension.expires_at_ms) throw new StrictReceiptCoordinatorV2Error('suspension has not expired');
    const index = this.priorActions.findIndex((item) => item.receipt_hash === receiptHash);
    if (index < 0) throw new StrictReceiptCoordinatorV2Error('suspended action summary is missing');
    const sourceHash = v2CanonicalHash({ schema: 'obsvr-strict-timeout-evidence-v2',
      tenant_id: this.tenantId, session_id: this.sessionId, suspended_receipt_hash: receiptHash,
      expires_at_ms: suspension.expires_at_ms });
    const receipt = signResolutionV2({ prior: pending.receipt, method: 'expired',
      principal_id: 'obsvr:strict-receipt-coordinator', source_hash: sourceHash,
      tenant_id: this.tenantId, session_id: this.sessionId, sequence: this.sequence + 1,
      timestamp, clamped, previous_hash: this.lastReceiptHash, sdk_version: this.sdkVersion,
      signer: this.signer, include_public_key: this.includePublicKey, context, base_result: baseResult,
      evaluation, policy_version: input.policy_version, rule_ids: input.rule_ids });
    return v2Clone(this.preparedState.prepare({ fingerprint, receipt_hash: receipt.receipt_hash,
      kind: 'timeout', value: receipt, commit: () => this.commitResolution(receipt, receiptHash, index) }));
  }

  commitPrepared(token: string, receiptHash: string): StrictDecisionV2Result | StrictReceiptV2Envelope {
    this.ensureProcess();
    return v2Clone(this.preparedState.commit(token, receiptHash));
  }
  abortPrepared(token: string, receiptHash: string, capability: DefinitiveNoStore): void {
    this.ensureProcess(); this.preparedState.abort(token, receiptHash, capability);
  }
  freezePrepared(token: string, receiptHash: string, reason = 'transport_ambiguous'): void {
    this.ensureProcess(); this.preparedState.freeze(token, receiptHash, reason);
  }
  inspectState(): StrictCoordinatorV2StateInspection {
    this.ensureProcess();
    return { tenant_id: this.tenantId, session_id: this.sessionId, sequence: this.sequence,
      head_receipt_hash: this.lastReceiptHash, ...this.preparedState.inspect() };
  }

  private validateResolution(
    input: StrictResolutionV2Input, pending: PendingV2, context: ActionContextV2Document,
    base: IntentV2BaseResult, evaluation: IntentAlignmentV2Result, timestamp: number,
  ): { principalId: string; sourceHash: string } {
    if (!FINAL.has(evaluation.outcome)) throw new StrictReceiptCoordinatorV2Error('resolution evaluation must be final');
    const prior = pending.receipt; const suspension = prior.body.suspension!;
    if (context.agent.agent_id !== prior.body.initiator.agent_id || context.action.kind !== prior.body.action.kind
      || context.action.name !== prior.body.action.name || context.action.arguments_hash !== prior.body.action.arguments_hash
      || context.action.target_hash !== prior.body.action.target_hash) {
      throw new StrictReceiptCoordinatorV2Error('resolution action or initiator does not match suspension');
    }
    const approvalMethod = input.method === 'approval_granted' || input.method === 'approval_denied';
    if ((suspension.type === 'approval') !== approvalMethod && input.method !== 'cancelled') {
      throw new StrictReceiptCoordinatorV2Error('resolution method does not match suspension');
    }
    if (approvalMethod) {
      if (input.resolver_principal_id !== undefined || input.resolution_source_hash !== undefined) {
        throw new StrictReceiptCoordinatorV2Error('approval source must come from approval_evidence');
      }
      if (this.approvalRequests.get(suspension.approval_request_id!) !== prior.receipt_hash) {
        throw new StrictReceiptCoordinatorV2Error('approval request belongs to another suspension');
      }
      const expected = { request_id: suspension.approval_request_id!, action_hash: suspension.approval_action_hash!,
        decision: input.method === 'approval_granted' ? 'granted' as const : 'denied' as const, current_time_ms: timestamp };
      const trusted = trustedApprovalResult(this.approvalVerifier(input.approval_evidence, expected), expected, suspension.expires_at_ms);
      this.validateFinal(input.method, prior, base, evaluation, timestamp);
      return { principalId: trusted.principalId, sourceHash: trusted.sourceHash };
    }
    if (input.approval_evidence !== undefined) throw new StrictReceiptCoordinatorV2Error('approval_evidence requires an approval method');
    if (suspension.type === 'context') validateDeferredChangesV2({ original_context: pending.context,
      current_context: context, original_base: pending.baseResult, current_base: base,
      required_fields: suspension.required_fields });
    const principalId = v2Text(input.resolver_principal_id, 'resolver_principal_id');
    const sourceHash = v2Hash(input.resolution_source_hash, 'resolution_source_hash');
    this.validateFinal(input.method, prior, base, evaluation, timestamp);
    return { principalId, sourceHash };
  }

  private validateFinal(method: StrictResolutionV2Input['method'], prior: StrictReceiptV2Envelope,
    base: IntentV2BaseResult, evaluation: IntentAlignmentV2Result, timestamp: number): void {
    const suspension = prior.body.suspension!;
    if ((method === 'approval_granted' || method === 'context_supplied') && timestamp >= suspension.expires_at_ms) {
      throw new StrictReceiptCoordinatorV2Error('authorization cannot occur after suspension expiry');
    }
    if (['approval_denied', 'cancelled'].includes(method) && evaluation.outcome !== 'DENY') {
      throw new StrictReceiptCoordinatorV2Error('resolution method requires DENY');
    }
    if (method === 'approval_granted' && !['ALLOW', 'MODIFY'].includes(evaluation.outcome)) {
      throw new StrictReceiptCoordinatorV2Error('approval_granted requires ALLOW or MODIFY');
    }
    if (evaluation.outcome === 'MODIFY') {
      const effective = v2Hash(base.modified_arguments_hash, 'modified_arguments_hash');
      if (effective === prior.body.action.arguments_hash) throw new StrictReceiptCoordinatorV2Error('effective_arguments_hash must change arguments');
    }
  }

  private pending(hash: string): PendingV2 {
    const value = this.suspended.get(hash);
    if (!value) throw new StrictReceiptCoordinatorV2Error('suspended receipt is not known');
    if (this.resolved.has(hash)) throw new StrictReceiptCoordinatorV2Error('suspension is already resolved');
    return value;
  }
  private allocateTimestamp(): { timestamp: number; clamped: boolean } {
    const observed = v2Integer(this.clock(), 'clock'); const timestamp = Math.max(observed, this.lastTimestamp ?? 0);
    return { timestamp, clamped: observed < timestamp };
  }
  protected commitDecision(result: StrictDecisionV2Result, context: ActionContextV2Document, base: IntentV2BaseResult): void {
    const receipt = result.receipt; this.advance(receipt); this.actionIds.add(receipt.body.action.action_id);
    this.priorActions.push({ sequence: receipt.body.sequence, kind: receipt.body.action.kind,
      name: receipt.body.action.name, outcome: receipt.body.evaluation.outcome,
      receipt_hash: receipt.receipt_hash, data_classifications: [...context.action.data_classifications] });
    if (receipt.body.suspension) this.suspended.set(receipt.receipt_hash,
      { receipt: v2Clone(receipt), context: v2Clone(context), baseResult: { ...base } });
    const requestId = receipt.body.suspension?.approval_request_id;
    if (requestId !== undefined) this.approvalRequests.set(requestId, receipt.receipt_hash);
  }
  protected commitResolution(receipt: StrictReceiptV2Envelope, hash: string, index: number): void {
    const classifications = this.priorActions[index]!.data_classifications; this.advance(receipt);
    this.priorActions[index] = { sequence: receipt.body.sequence, kind: receipt.body.action.kind,
      name: receipt.body.action.name, outcome: receipt.body.evaluation.outcome,
      receipt_hash: receipt.receipt_hash, data_classifications: [...classifications] };
    this.priorActions.sort((left, right) => left.sequence - right.sequence); this.resolved.add(hash);
  }
  private advance(receipt: StrictReceiptV2Envelope): void {
    this.sequence = receipt.body.sequence; this.lastReceiptHash = receipt.receipt_hash;
    this.lastTimestamp = receipt.body.timestamp_ms;
  }
  protected ensureProcess(): void {
    if (v2Integer(this.pidSource(), 'pid') !== this.ownerPid) {
      throw new StrictReceiptCoordinatorV2Error('strict v2 coordinator cannot cross a process boundary');
    }
  }
}
