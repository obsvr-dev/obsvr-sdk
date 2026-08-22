import { randomUUID } from 'node:crypto';
import type { DeviceSigner } from '../proxy/device-identity.js';
import {
  buildIntentPolicy,
  evaluateIntentAlignment,
  type IntentAlignmentResult,
  type IntentBaseResult,
  type IntentPolicyDocument,
  type IntentPolicyInput,
} from '../policy/intent-alignment.js';
import {
  type ActionContextDocument,
  type ActionContextInput,
  type PriorActionInput,
} from './action-context.js';
import type { AarmOutcome } from './aarm-outcome.js';
import {
  STRICT_RECEIPT_PROFILE_VERSION,
  STRICT_RECEIPT_SCHEMA,
  signStrictReceipt,
  strictReceiptKeyId,
  type StrictReceiptBody,
  type StrictReceiptEnvelope,
} from './strict-receipt.js';
import {
  addSafeIntegers,
  buildCoordinatorContext,
  canonicalHash,
  cloneCoordinatorValue,
  contextInputFromDocument,
  coordinatorHash,
  coordinatorSafeInteger,
  coordinatorText,
  requestFingerprint,
  signCoordinatorResolution,
  trustedApprovalResult,
  validateDeferredChanges,
  type StrictApprovalVerifier,
} from './strict-receipt-coordinator-support.js';

const FINAL_OUTCOMES = new Set<AarmOutcome>(['ALLOW', 'DENY', 'MODIFY']);
type ResolutionMethod = NonNullable<StrictReceiptBody['resolution']>['method'];

interface PendingState {
  receipt: StrictReceiptEnvelope;
  context: ActionContextDocument;
  baseResult: IntentBaseResult;
}

export type StrictCoordinatorContextInput = Omit<
  ActionContextInput,
  'prior_actions' | 'session_id'
>;
export interface StrictReceiptCoordinatorOptions {
  signer: DeviceSigner;
  policy: IntentPolicyInput;
  sdk_language: 'typescript';
  sdk_version: string;
  session_id: string;
  clock: () => number;
  defer_ttl_ms: number;
  approval_verifier: StrictApprovalVerifier;
  include_public_key?: boolean;
  pid?: () => number;
  session_factory?: () => string;
}
export interface StrictDecisionInput {
  context: StrictCoordinatorContextInput;
  base_result: IntentBaseResult;
  policy_version: string;
  rule_ids: string[];
  action_id: string;
}
export interface StrictDecisionResult {
  evaluation: IntentAlignmentResult;
  receipt: StrictReceiptEnvelope;
}
export interface StrictResolutionInput {
  suspended_receipt_hash: string;
  method: ResolutionMethod;
  resolver_principal_id?: string;
  resolution_source_hash?: string;
  context: StrictCoordinatorContextInput;
  base_result: IntentBaseResult;
  policy_version: string;
  rule_ids: string[];
  approval_evidence?: unknown;
}

export interface StrictTimeoutInput {
  suspended_receipt_hash: string;
  policy_version: string;
  rule_ids: string[];
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
    strictReceiptKeyId(this.signer.rawPublicKey);
  }

  decide(input: StrictDecisionInput): StrictDecisionResult {
    this.ensureProcess();
    const actionId = coordinatorText(input.action_id, 'action_id');
    const fingerprint = requestFingerprint({ ...input, session_id: this.sessionId });
    const cached = this.decisions.get(actionId);
    if (cached) {
      if (cached.fingerprint !== fingerprint) {
        throw new StrictReceiptCoordinatorError('action_id was reused with different input');
      }
      return cloneCoordinatorValue(cached.result);
    }
    const baseResult = { ...input.base_result };
    const context = buildCoordinatorContext(input.context, this.sessionId, this.priorActions);
    const evaluation = evaluateIntentAlignment({
      context,
      base_result: baseResult,
      policy: this.policy,
    });
    const { timestamp, clamped } = this.allocateTimestamp();
    const sequence = this.sequence + 1;
    const body: StrictReceiptBody = {
      schema: STRICT_RECEIPT_SCHEMA,
      profile_version: STRICT_RECEIPT_PROFILE_VERSION,
      record_type: 'decision',
      receipt_id: `${this.sessionId}:${sequence}`,
      session_id: this.sessionId,
      sequence,
      timestamp_ms: timestamp,
      clock_regression_clamped: clamped,
      previous_receipt_hash: this.lastReceiptHash,
      sdk: { language: 'typescript', version: this.sdkVersion },
      initiator: {
        agent_id: context.agent.agent_id,
        key_id: strictReceiptKeyId(this.signer.rawPublicKey),
      },
      action: {
        action_id: actionId,
        kind: context.action.kind,
        name: context.action.name,
        arguments_hash: context.action.arguments_hash,
      },
      context: {
        schema: 'obsvr-action-context-v1',
        context_hash: evaluation.context_hash,
        run_id: context.run_id,
      },
      evaluation: {
        input_hash: evaluation.input_hash,
        policy_hash: evaluation.policy_hash,
        evaluator_hash: evaluation.evaluator_hash,
        engine_version: evaluation.engine_version,
        policy_version: input.policy_version,
        outcome: evaluation.outcome,
        reason_code: evaluation.reason_code,
        rule_ids: input.rule_ids,
      },
      execution_authorized: evaluation.outcome === 'ALLOW' || evaluation.outcome === 'MODIFY',
    };
    if (context.action.target !== undefined) body.action.target = context.action.target;
    if (context.thread_id !== undefined) body.context.thread_id = context.thread_id;
    if (evaluation.outcome === 'MODIFY') {
      body.action.effective_arguments_hash = baseResult.modified_arguments_hash;
    }
    if (evaluation.outcome === 'STEP_UP') {
      const approvalRequestId = baseResult.approval_request_id as string;
      if (this.approvalRequests.has(approvalRequestId)) {
        throw new StrictReceiptCoordinatorError('approval_request_id is already pending');
      }
      body.suspension = {
        suspension_id: approvalRequestId,
        type: 'approval',
        status: 'pending',
        required_fields: [],
        expires_at_ms: baseResult.approval_expires_at_ms as number,
        approval_request_id: baseResult.approval_request_id,
        approval_action_hash: baseResult.approval_action_hash,
      };
      if (body.suspension.expires_at_ms <= timestamp) {
        throw new StrictReceiptCoordinatorError('approval expiry must follow decision timestamp');
      }
    } else if (evaluation.outcome === 'DEFER') {
      body.suspension = {
        suspension_id: `defer:${this.sessionId}:${sequence}`,
        type: 'context',
        status: 'pending',
        required_fields: evaluation.required_fields as string[],
        expires_at_ms: addSafeIntegers(timestamp, this.deferTtlMs),
      };
    }
    const receipt = signStrictReceipt(body, this.signer, this.includePublicKey);
    const result = { evaluation, receipt };
    this.commitDecision(result, context, baseResult, fingerprint);
    return cloneCoordinatorValue(result);
  }

  resolve(input: StrictResolutionInput): StrictReceiptEnvelope {
    this.ensureProcess();
    if (input.method === 'expired') {
      throw new StrictReceiptCoordinatorError('expired suspensions must use timeout');
    }
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
    const receipt = signCoordinatorResolution({
      prior, evaluation, context, base_result: baseResult,
      policy_version: input.policy_version, rule_ids: input.rule_ids,
      method: input.method, principal_id: evidence.principalId,
      source_hash: evidence.sourceHash, timestamp, clamped,
      sequence: this.sequence + 1, session_id: this.sessionId,
      previous_hash: this.lastReceiptHash, sdk_version: this.sdkVersion,
      signer: this.signer, include_public_key: this.includePublicKey,
    });
    this.commitResolution(receipt, input.suspended_receipt_hash);
    return cloneCoordinatorValue(receipt);
  }

  timeout(input: StrictTimeoutInput): StrictReceiptEnvelope {
    this.ensureProcess();
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
    this.commitResolution(receipt, receiptHash);
    return cloneCoordinatorValue(receipt);
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

  private commitResolution(receipt: StrictReceiptEnvelope, suspendedHash: string): void {
    const index = this.priorActions.findIndex((item) => item.receipt_hash === suspendedHash);
    if (index < 0) throw new StrictReceiptCoordinatorError('suspended action summary is missing');
    const classifications = this.priorActions[index].data_classifications;
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
  }

}
