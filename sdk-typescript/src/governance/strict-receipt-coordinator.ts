import { randomUUID } from 'node:crypto';
import type { DeviceSigner } from '../proxy/device-identity.js';
import {
  buildIntentPolicy,
  evaluateIntentAlignment,
  type IntentAlignmentResult,
  type IntentBaseResult,
  type IntentPolicyDocument,
} from '../policy/intent-alignment.js';
import {
  type ActionContextDocument,
  type PriorActionInput,
} from './action-context.js';
import type { AarmOutcome } from './aarm-outcome.js';
import {
  strictReceiptKeyId,
  type StrictReceiptBody,
  type StrictReceiptEnvelope,
} from './strict-receipt.js';
import {
  buildCoordinatorContext,
  canonicalHash,
  cloneCoordinatorValue,
  contextInputFromDocument,
  coordinatorHash,
  coordinatorSafeInteger,
  coordinatorText,
  requestFingerprint,
  signCoordinatorDecision,
  signCoordinatorResolution,
  trustedApprovalResult,
  validateDeferredChanges,
  type StrictApprovalVerifier,
} from './strict-receipt-coordinator-support.js';
import {
  PreparedReceiptState,
  type DefinitiveNoStore,
  type PreparedReconciliation,
} from './strict-receipt-prepared-state.js';
import type {
  PreparedDecision, PreparedResolution, StrictCoordinatorStateInspection,
  StrictDecisionInput, StrictDecisionResult, StrictReceiptCoordinatorOptions,
  StrictResolutionInput, StrictTimeoutInput,
} from './strict-receipt-coordinator-types.js';
export type {
  PreparedDecision, PreparedResolution, StrictCoordinatorContextInput,
  StrictCoordinatorStateInspection, StrictDecisionInput, StrictDecisionResult,
  StrictReceiptCoordinatorOptions, StrictResolutionInput, StrictTimeoutInput,
} from './strict-receipt-coordinator-types.js';

const FINAL_OUTCOMES = new Set<AarmOutcome>(['ALLOW', 'DENY', 'MODIFY']);
interface PendingState {
  receipt: StrictReceiptEnvelope;
  context: ActionContextDocument;
  baseResult: IntentBaseResult;
}


export class StrictReceiptCoordinatorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictReceiptCoordinatorError';
  }
}

export class StrictReceiptCoordinator {
  private readonly signer: DeviceSigner;
  private readonly policy: IntentPolicyDocument;
  private readonly sdkVersion: string;
  private readonly clock: () => number;
  private readonly deferTtlMs: number;
  private readonly approvalVerifier: StrictApprovalVerifier;
  private readonly includePublicKey: boolean;
  private readonly pidSource: () => number;
  private readonly sessionFactory: () => string;
  private ownerPid: number;
  private sessionId: string;
  private sequence = 0;
  private lastReceiptHash: string | null = null;
  private lastTimestamp: number | null = null;
  private priorActions: PriorActionInput[] = [];
  private suspended = new Map<string, PendingState>();
  private resolved = new Set<string>();
  private decisions = new Map<string, { fingerprint: string; result: StrictDecisionResult }>();
  private approvalRequests = new Map<string, string>();
  private readonly preparedState: PreparedReceiptState;

  constructor(options: StrictReceiptCoordinatorOptions) {
    if (options.sdk_language !== 'typescript') {
      throw new StrictReceiptCoordinatorError('sdk_language must be typescript');
    }
    this.signer = options.signer;
    this.policy = buildIntentPolicy(options.policy);
    this.sdkVersion = coordinatorText(options.sdk_version, 'sdk_version');
    this.sessionId = coordinatorText(options.session_id, 'session_id');
    this.clock = options.clock;
    this.deferTtlMs = coordinatorSafeInteger(options.defer_ttl_ms, 'defer_ttl_ms');
    if (this.deferTtlMs === 0) {
      throw new StrictReceiptCoordinatorError('defer_ttl_ms must be positive');
    }
    if (typeof options.approval_verifier !== 'function') {
      throw new StrictReceiptCoordinatorError('approval_verifier must be a function');
    }
    this.approvalVerifier = options.approval_verifier;
    this.includePublicKey = options.include_public_key ?? true;
    this.pidSource = options.pid ?? (() => process.pid);
    this.sessionFactory = options.session_factory ?? (() => randomUUID());
    this.ownerPid = coordinatorSafeInteger(this.pidSource(), 'pid');
    this.preparedState = new PreparedReceiptState(
      options.prepared_token_factory ?? (() => randomUUID()),
    );
    strictReceiptKeyId(this.signer.rawPublicKey);
  }

  decide(input: StrictDecisionInput): StrictDecisionResult {
    this.ensureProcess();
    const fingerprint = requestFingerprint({ ...input, session_id: this.sessionId });
    const cached = this.decisions.get(input.action_id);
    if (cached) {
      if (cached.fingerprint !== fingerprint) {
        throw new StrictReceiptCoordinatorError('action_id was reused with different input');
      }
      return cloneCoordinatorValue(cached.result);
    }
    const prepared = this.prepareDecision(input);
    return this.commitPrepared(prepared.token, prepared.receipt_hash) as StrictDecisionResult;
  }

  prepareDecision(input: StrictDecisionInput): PreparedDecision {
    this.ensureProcess();
    const actionId = coordinatorText(input.action_id, 'action_id');
    const fingerprint = requestFingerprint({ ...input, session_id: this.sessionId });
    if (this.decisions.has(actionId)) {
      throw new StrictReceiptCoordinatorError('action_id is already committed');
    }
    const retry = this.preparedState.retry<StrictDecisionResult>(fingerprint, 'decision');
    if (retry) return cloneCoordinatorValue(retry);
    const baseResult = { ...input.base_result };
    const context = buildCoordinatorContext(input.context, this.sessionId, this.priorActions);
    const evaluation = evaluateIntentAlignment({
      context,
      base_result: baseResult,
      policy: this.policy,
    });
    const { timestamp, clamped } = this.allocateTimestamp();
    const sequence = this.sequence + 1;
    const receipt = signCoordinatorDecision({
      action_id: actionId, context, base_result: baseResult, evaluation,
      policy_version: input.policy_version, rule_ids: input.rule_ids,
      timestamp, clamped, sequence, session_id: this.sessionId,
      previous_hash: this.lastReceiptHash, sdk_version: this.sdkVersion,
      signer: this.signer, include_public_key: this.includePublicKey,
      defer_ttl_ms: this.deferTtlMs,
      approval_request_pending: (requestId) => this.approvalRequests.has(requestId),
    });
    const result = { evaluation, receipt };
    return cloneCoordinatorValue(this.preparedState.prepare({
      fingerprint, receipt_hash: receipt.receipt_hash, kind: 'decision', value: result,
      commit: () => this.commitDecision(result, context, baseResult, fingerprint),
    }));
  }

  resolve(input: StrictResolutionInput): StrictReceiptEnvelope {
    const prepared = this.prepareResolution(input);
    return this.commitPrepared(prepared.token, prepared.receipt_hash) as StrictReceiptEnvelope;
  }

  prepareResolution(input: StrictResolutionInput): PreparedResolution {
    this.ensureProcess();
    if (input.method === 'expired') {
      throw new StrictReceiptCoordinatorError('expired suspensions must use timeout');
    }
    const fingerprint = canonicalHash({
      schema: 'obsvr-strict-prepare-resolution-v1', session_id: this.sessionId, input,
    });
    const retry = this.preparedState.retry<StrictReceiptEnvelope>(fingerprint, 'resolution');
    if (retry) return cloneCoordinatorValue(retry);
    coordinatorHash(input.suspended_receipt_hash, 'suspended_receipt_hash');
    const pending = this.suspended.get(input.suspended_receipt_hash);
    if (!pending) throw new StrictReceiptCoordinatorError('suspended receipt is not known');
    const prior = pending.receipt;
    if (this.resolved.has(input.suspended_receipt_hash)) {
      throw new StrictReceiptCoordinatorError('suspension is already resolved');
    }
    const suspension = prior.body.suspension;
    if (!suspension) throw new StrictReceiptCoordinatorError('receipt is not suspended');
    const context = buildCoordinatorContext(input.context, this.sessionId, this.priorActions);
    const baseResult = { ...input.base_result };
    const evaluation = evaluateIntentAlignment({
      context,
      base_result: baseResult,
      policy: this.policy,
    });
    const { timestamp, clamped } = this.allocateTimestamp();
    const evidence = this.validateResolution(
      input, pending, context, baseResult, evaluation, timestamp,
    );
    const priorIndex = this.priorActions.findIndex(
      (item) => item.receipt_hash === input.suspended_receipt_hash,
    );
    if (priorIndex < 0) {
      throw new StrictReceiptCoordinatorError('suspended action summary is missing');
    }
    const receipt = signCoordinatorResolution({
      prior, evaluation, context, base_result: baseResult,
      policy_version: input.policy_version, rule_ids: input.rule_ids,
      method: input.method, principal_id: evidence.principalId,
      source_hash: evidence.sourceHash, timestamp, clamped,
      sequence: this.sequence + 1, session_id: this.sessionId,
      previous_hash: this.lastReceiptHash, sdk_version: this.sdkVersion,
      signer: this.signer, include_public_key: this.includePublicKey,
    });
    return cloneCoordinatorValue(this.preparedState.prepare({
      fingerprint, receipt_hash: receipt.receipt_hash, kind: 'resolution', value: receipt,
      commit: () => this.commitResolution(receipt, input.suspended_receipt_hash, priorIndex),
    }));
  }

  timeout(input: StrictTimeoutInput): StrictReceiptEnvelope {
    const prepared = this.prepareTimeout(input);
    return this.commitPrepared(prepared.token, prepared.receipt_hash) as StrictReceiptEnvelope;
  }

  prepareTimeout(input: StrictTimeoutInput): PreparedResolution {
    this.ensureProcess();
    const fingerprint = canonicalHash({
      schema: 'obsvr-strict-prepare-timeout-v1', session_id: this.sessionId, input,
    });
    const retry = this.preparedState.retry<StrictReceiptEnvelope>(fingerprint, 'timeout');
    if (retry) return cloneCoordinatorValue(retry);
    const receiptHash = coordinatorHash(input.suspended_receipt_hash, 'suspended_receipt_hash');
    const pending = this.suspended.get(receiptHash);
    if (!pending) throw new StrictReceiptCoordinatorError('suspended receipt is not known');
    if (this.resolved.has(receiptHash)) {
      throw new StrictReceiptCoordinatorError('suspension is already resolved');
    }
    const suspension = pending.receipt.body.suspension as NonNullable<StrictReceiptBody['suspension']>;
    const context = buildCoordinatorContext(
      contextInputFromDocument(pending.context), this.sessionId, this.priorActions,
    );
    const evaluation = evaluateIntentAlignment({
      context,
      base_result: { action_taken: 'blocked' },
      policy: this.policy,
    });
    const { timestamp, clamped } = this.allocateTimestamp();
    if (timestamp < suspension.expires_at_ms) {
      throw new StrictReceiptCoordinatorError('suspension has not expired');
    }
    const priorIndex = this.priorActions.findIndex((item) => item.receipt_hash === receiptHash);
    if (priorIndex < 0) {
      throw new StrictReceiptCoordinatorError('suspended action summary is missing');
    }
    const sourceHash = coordinatorHash(
      // Domain-separated deterministic timeout evidence, not caller material.
      canonicalHash({
        schema: 'obsvr-strict-timeout-evidence-v1',
        suspended_receipt_hash: receiptHash,
        expires_at_ms: suspension.expires_at_ms,
      }),
      'timeout source hash',
    );
    const receipt = signCoordinatorResolution({
      prior: pending.receipt, evaluation, context,
      base_result: { action_taken: 'blocked' },
      policy_version: input.policy_version, rule_ids: input.rule_ids,
      method: 'expired', principal_id: 'obsvr:strict-receipt-coordinator',
      source_hash: sourceHash, timestamp, clamped,
      sequence: this.sequence + 1, session_id: this.sessionId,
      previous_hash: this.lastReceiptHash, sdk_version: this.sdkVersion,
      signer: this.signer, include_public_key: this.includePublicKey,
    });
    return cloneCoordinatorValue(this.preparedState.prepare({
      fingerprint, receipt_hash: receipt.receipt_hash, kind: 'timeout', value: receipt,
      commit: () => this.commitResolution(receipt, receiptHash, priorIndex),
    }));
  }

  commitPrepared(token: string, receiptHash: string): StrictDecisionResult | StrictReceiptEnvelope {
    this.ensureProcess();
    return cloneCoordinatorValue(this.preparedState.commit(token, receiptHash));
  }

  abortPrepared(token: string, receiptHash: string, status: DefinitiveNoStore): void {
    this.ensureProcess();
    this.preparedState.abort(token, receiptHash, status);
  }

  freezePrepared(token: string, receiptHash: string, reason = 'transport_ambiguous'): void {
    this.ensureProcess();
    this.preparedState.freeze(token, receiptHash, reason);
  }

  reconcilePrepared(
    input: PreparedReconciliation,
  ): StrictDecisionResult | StrictReceiptEnvelope | undefined {
    this.ensureProcess();
    const result = this.preparedState.reconcile<StrictDecisionResult | StrictReceiptEnvelope>(input);
    return result === undefined ? undefined : cloneCoordinatorValue(result);
  }

  inspectState(): StrictCoordinatorStateInspection {
    this.ensureProcess();
    return {
      session_id: this.sessionId, sequence: this.sequence,
      head_receipt_hash: this.lastReceiptHash, ...this.preparedState.inspect(),
    };
  }

  private validateResolution(
    input: StrictResolutionInput,
    pending: PendingState,
    context: ActionContextDocument,
    baseResult: IntentBaseResult,
    evaluation: IntentAlignmentResult,
    resolvedAt: number,
  ): { principalId: string; sourceHash: string } {
    const prior = pending.receipt;
    if (!FINAL_OUTCOMES.has(evaluation.outcome)) {
      throw new StrictReceiptCoordinatorError('resolution evaluation must be final');
    }
    const suspension = prior.body.suspension as NonNullable<StrictReceiptBody['suspension']>;
    if (context.agent.agent_id !== prior.body.initiator.agent_id
      || context.action.kind !== prior.body.action.kind
      || context.action.name !== prior.body.action.name
      || context.action.arguments_hash !== prior.body.action.arguments_hash
      || context.action.target !== prior.body.action.target) {
      throw new StrictReceiptCoordinatorError('resolution action or initiator does not match suspension');
    }
    const approval = suspension.type === 'approval';
    const approvalMethod = input.method === 'approval_granted'
      || input.method === 'approval_denied';
    if (approval !== approvalMethod
      && !['expired', 'cancelled'].includes(input.method)) {
      throw new StrictReceiptCoordinatorError('resolution method does not match suspension');
    }
    if (approvalMethod) {
      const expected = {
        request_id: suspension.approval_request_id as string,
        action_hash: suspension.approval_action_hash as string,
        decision: input.method === 'approval_granted' ? 'granted' as const : 'denied' as const,
        current_time_ms: resolvedAt,
      };
      const evidence = trustedApprovalResult(
        this.approvalVerifier(input.approval_evidence, expected),
        expected,
        suspension.expires_at_ms,
      );
      if (evidence.requestId !== suspension.approval_request_id) {
        throw new StrictReceiptCoordinatorError('approval_request_id does not match suspension');
      }
      if (evidence.actionHash !== suspension.approval_action_hash) {
        throw new StrictReceiptCoordinatorError('approval_action_hash does not match suspension');
      }
      if (this.approvalRequests.get(evidence.requestId) !== prior.receipt_hash) {
        throw new StrictReceiptCoordinatorError('approval request belongs to another suspension');
      }
      if (input.resolver_principal_id !== undefined
        || input.resolution_source_hash !== undefined) {
        throw new StrictReceiptCoordinatorError('approval source must come from approval_evidence');
      }
      this.validateFinalResolution(input, prior, evaluation, resolvedAt);
      return { principalId: evidence.principalId, sourceHash: evidence.sourceHash };
    }
    if (input.approval_evidence !== undefined) {
      throw new StrictReceiptCoordinatorError('approval_evidence requires an approval method');
    }
    if (suspension.type === 'context') {
      validateDeferredChanges({
        original_context: pending.context,
        current_context: context,
        original_base: pending.baseResult,
        current_base: baseResult,
        required_fields: suspension.required_fields,
      });
    }
    const principalId = coordinatorText(input.resolver_principal_id, 'resolver_principal_id');
    const sourceHash = coordinatorHash(input.resolution_source_hash, 'resolution_source_hash');
    this.validateFinalResolution(input, prior, evaluation, resolvedAt);
    return { principalId, sourceHash };
  }

  private validateFinalResolution(
    input: StrictResolutionInput,
    prior: StrictReceiptEnvelope,
    evaluation: IntentAlignmentResult,
    resolvedAt: number,
  ): void {
    const suspension = prior.body.suspension as NonNullable<StrictReceiptBody['suspension']>;
    if ((input.method === 'approval_granted' || input.method === 'context_supplied')
      && resolvedAt >= suspension.expires_at_ms) {
      throw new StrictReceiptCoordinatorError('authorization cannot occur after suspension expiry');
    }
    if (['approval_denied', 'expired', 'cancelled'].includes(input.method)
      && evaluation.outcome !== 'DENY') {
      throw new StrictReceiptCoordinatorError('resolution method requires DENY');
    }
    if (input.method === 'approval_granted' && evaluation.outcome === 'DENY') {
      throw new StrictReceiptCoordinatorError('approval_granted requires ALLOW or MODIFY');
    }
    if (evaluation.outcome === 'MODIFY') {
      const effective = coordinatorHash(
        input.base_result.modified_arguments_hash, 'modified_arguments_hash',
      );
      if (effective === prior.body.action.arguments_hash) {
        throw new StrictReceiptCoordinatorError('effective_arguments_hash must change arguments');
      }
    }
  }

  private allocateTimestamp(floor = 0): { timestamp: number; clamped: boolean } {
    const observed = coordinatorSafeInteger(this.clock(), 'clock');
    const previous = this.lastTimestamp ?? 0;
    const timestamp = Math.max(observed, previous, floor);
    return { timestamp, clamped: observed < timestamp };
  }

  private commitDecision(
    result: StrictDecisionResult,
    context: ActionContextDocument,
    baseResult: IntentBaseResult,
    fingerprint: string,
  ): void {
    const { receipt } = result;
    this.sequence = receipt.body.sequence;
    this.lastReceiptHash = receipt.receipt_hash;
    this.lastTimestamp = receipt.body.timestamp_ms;
    this.priorActions.push({
      sequence: receipt.body.sequence,
      kind: receipt.body.action.kind,
      name: receipt.body.action.name,
      outcome: receipt.body.evaluation.outcome,
      receipt_hash: receipt.receipt_hash,
      data_classifications: [...context.action.data_classifications],
    });
    if (receipt.body.suspension) this.suspended.set(receipt.receipt_hash, {
      receipt, context: cloneCoordinatorValue(context), baseResult: { ...baseResult },
    });
    this.decisions.set(receipt.body.action.action_id, {
      fingerprint, result: cloneCoordinatorValue(result),
    });
    const requestId = receipt.body.suspension?.approval_request_id;
    if (requestId !== undefined) this.approvalRequests.set(requestId, receipt.receipt_hash);
  }

  private commitResolution(
    receipt: StrictReceiptEnvelope, suspendedHash: string, index: number,
  ): void {
    const classifications = this.priorActions[index]!.data_classifications;
    this.sequence = receipt.body.sequence;
    this.lastReceiptHash = receipt.receipt_hash;
    this.lastTimestamp = receipt.body.timestamp_ms;
    this.priorActions[index] = {
      sequence: receipt.body.sequence,
      kind: receipt.body.action.kind,
      name: receipt.body.action.name,
      outcome: receipt.body.evaluation.outcome,
      receipt_hash: receipt.receipt_hash,
      data_classifications: [...classifications],
    };
    this.priorActions.sort((left, right) => left.sequence - right.sequence);
    this.resolved.add(suspendedHash);
  }

  private ensureProcess(): void {
    const current = coordinatorSafeInteger(this.pidSource(), 'pid');
    if (current === this.ownerPid) return;
    const nextSession = coordinatorText(this.sessionFactory(), 'session_factory result');
    if (nextSession === this.sessionId) {
      throw new StrictReceiptCoordinatorError('fork session_factory must return a new session_id');
    }
    this.ownerPid = current;
    this.sessionId = nextSession;
    this.sequence = 0;
    this.lastReceiptHash = null;
    this.lastTimestamp = null;
    this.priorActions = [];
    this.suspended = new Map();
    this.resolved = new Set();
    this.decisions = new Map();
    this.approvalRequests = new Map();
    this.preparedState.reset();
  }

}
