import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  transportPreparedStrictReceiptV21,
  type PreparedStrictReceiptV21,
  type StrictAdmissionV21Coordinator,
  type StrictAdmissionV21Options,
  type StrictAdmissionV21Result,
} from './strict-admission-v2-1.js';
import type {
  PreparedApprovalResolutionV21, PreparedDecisionV21,
  StrictApprovalResolutionV21Input, StrictDecisionActionV21Input,
} from './strict-receipt-coordinator-v2-1-types.js';
import { DEFINITIVE_NO_STORE } from './strict-receipt-prepared-state.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import type {
  StrictExecutionOutcomeV21Envelope,
  StrictExecutionStartV21,
} from './strict-execution-outcome-v2-1.js';
import {
  executeCommittedStrictActionV21,
} from './strict-receipt-runtime-v2-1-execution.js';
import type {
  StrictRuntimeExecutionJournalV21,
  StrictRuntimeV21Result,
  StrictV21ApprovalRuntimeAction,
  StrictV21BoundArguments,
  StrictV21CheckpointStore,
  StrictV21RuntimeAction,
} from './strict-receipt-runtime-v2-1-types.js';
import {
  bindStrictV21JsonArguments,
  deepFreezeStrictV21,
  readStrictV21ExecutionArguments,
} from './strict-receipt-runtime-v2-1-bindings.js';
export { bindStrictV21JsonArguments } from './strict-receipt-runtime-v2-1-bindings.js';
export type {
  StrictRuntimeExecutionJournalV21,
  StrictRuntimeV21Result,
  StrictV21ApprovalRuntimeAction,
  StrictV21BoundArguments,
  StrictV21CheckpointStore,
  StrictV21RuntimeAction,
} from './strict-receipt-runtime-v2-1-types.js';

const trustedRuntimes = new WeakSet<object>();
export const STRICT_RUNTIME_EXECUTION_JOURNAL_V21_SCHEMA = 'obsvr-strict-runtime-execution-journal-v2-1' as const;

interface CoordinatorV21 extends StrictAdmissionV21Coordinator {
  prepareDecision(input: StrictDecisionActionV21Input): PreparedDecisionV21;
  prepareApprovalResolution(
    input: StrictApprovalResolutionV21Input,
  ): PreparedApprovalResolutionV21;
  observeExecutionTime(): number;
  signExecutionOutcome(
    body: import('./strict-execution-outcome-v2-1.js').StrictExecutionOutcomeV21Body,
    decision: StrictReceiptV21Envelope,
  ): StrictExecutionOutcomeV21Envelope;
}
type TrustedRuntimeRunner = <A, R>(input: {
  decision: StrictDecisionActionV21Input;
  action: StrictV21RuntimeAction<A, R>;
}) => Promise<StrictRuntimeV21Result<R>>;
type TrustedApprovalRuntimeRunner = <A, R>(input: {
  resolution: StrictApprovalResolutionV21Input;
  action: StrictV21ApprovalRuntimeAction<A, R>;
}) => Promise<StrictRuntimeV21Result<R>>;
const trustedRuntimeRunners = new WeakMap<object, TrustedRuntimeRunner>();
const trustedApprovalRuntimeRunners = new WeakMap<object, TrustedApprovalRuntimeRunner>();
type TrustedRuntimeMethod = <A, R>(this: StrictReceiptRuntimeV21, input: {
  decision: StrictDecisionActionV21Input;
  action: StrictV21RuntimeAction<A, R>;
}) => Promise<StrictRuntimeV21Result<R>>;
type TrustedRunExclusive = <A, R>(
  this: StrictReceiptRuntimeV21,
  operation: StrictRuntimeOperationV21,
  action: StrictV21RuntimeAction<A, R>,
  expectedActionId: string | undefined,
  resultKey: string,
  fingerprint: string,
) => Promise<StrictRuntimeV21Result<R>>;
type TrustedPersist = (
  this: StrictReceiptRuntimeV21,
  phase: StrictRuntimeExecutionJournalV21['phase'],
  prepared: PreparedStrictReceiptV21,
  receipt: StrictReceiptV21Envelope,
  actionId: string,
  fingerprint: string,
  terminalStatus?: StrictRuntimeExecutionJournalV21['terminal_status'],
  executionStart?: StrictExecutionStartV21 & { execution_start_hash: string },
  executionOutcome?: StrictExecutionOutcomeV21Envelope,
) => Promise<void>;
type TrustedFreezePrepared = (
  this: StrictReceiptRuntimeV21, prepared: PreparedStrictReceiptV21, reason: string,
) => void;
type TrustedFinish = <T>(
  this: StrictReceiptRuntimeV21, actionId: string, fingerprint: string,
  result: StrictRuntimeV21Result<T>,
) => StrictRuntimeV21Result<T>;
type TrustedFingerprint = <A, R>(
  this: StrictReceiptRuntimeV21, decision: StrictDecisionActionV21Input,
  action: StrictV21RuntimeAction<A, R>,
) => string;
type TrustedApprovalFingerprint = <A, R>(
  this: StrictReceiptRuntimeV21, resolution: StrictApprovalResolutionV21Input,
  action: StrictV21ApprovalRuntimeAction<A, R>,
) => string;
type TrustedText = (
  this: StrictReceiptRuntimeV21, value: unknown, field: string,
) => string;
let trustedRunDecisionImpl: TrustedRuntimeMethod;
let trustedRunApprovalImpl: <A, R>(this: StrictReceiptRuntimeV21, input: {
  resolution: StrictApprovalResolutionV21Input;
  action: StrictV21ApprovalRuntimeAction<A, R>;
}) => Promise<StrictRuntimeV21Result<R>>;
let trustedRunExclusiveImpl: TrustedRunExclusive;
let trustedPersistImpl: TrustedPersist;
let trustedFreezePreparedImpl: TrustedFreezePrepared;
let trustedFinishImpl: TrustedFinish;
let trustedFingerprintImpl: TrustedFingerprint;
let trustedApprovalFingerprintImpl: TrustedApprovalFingerprint;
let trustedTextImpl: TrustedText;

type StrictRuntimeOperationV21 =
  | { kind: 'decision'; input: StrictDecisionActionV21Input }
  | { kind: 'resolution'; input: StrictApprovalResolutionV21Input };

function callTrustedRunExclusive<A, R>(
  runtime: StrictReceiptRuntimeV21,
  operation: StrictRuntimeOperationV21,
  action: StrictV21RuntimeAction<A, R>,
  expectedActionId: string | undefined,
  resultKey: string,
  fingerprint: string,
): Promise<StrictRuntimeV21Result<R>> {
  const implementation = trustedRunExclusiveImpl as unknown as (
    this: StrictReceiptRuntimeV21,
    operation: StrictRuntimeOperationV21,
    action: StrictV21RuntimeAction<A, R>,
    expectedActionId: string | undefined,
    resultKey: string,
    fingerprint: string,
  ) => Promise<StrictRuntimeV21Result<R>>;
  return implementation.call(
    runtime, operation, action, expectedActionId, resultKey, fingerprint,
  );
}

function callTrustedFinish<T>(
  runtime: StrictReceiptRuntimeV21,
  actionId: string,
  fingerprint: string,
  result: StrictRuntimeV21Result<T>,
): StrictRuntimeV21Result<T> {
  const implementation = trustedFinishImpl as unknown as (
    this: StrictReceiptRuntimeV21,
    actionId: string,
    fingerprint: string,
    result: StrictRuntimeV21Result<T>,
  ) => StrictRuntimeV21Result<T>;
  return implementation.call(runtime, actionId, fingerprint, result);
}

function callTrustedFingerprint<A, R>(
  runtime: StrictReceiptRuntimeV21,
  decision: StrictDecisionActionV21Input,
  action: StrictV21RuntimeAction<A, R>,
): string {
  const implementation = trustedFingerprintImpl as unknown as (
    this: StrictReceiptRuntimeV21,
    decision: StrictDecisionActionV21Input,
    action: StrictV21RuntimeAction<A, R>,
  ) => string;
  return implementation.call(runtime, decision, action);
}

function callTrustedApprovalFingerprint<A, R>(
  runtime: StrictReceiptRuntimeV21,
  resolution: StrictApprovalResolutionV21Input,
  action: StrictV21ApprovalRuntimeAction<A, R>,
): string {
  const implementation = trustedApprovalFingerprintImpl as unknown as (
    this: StrictReceiptRuntimeV21,
    resolution: StrictApprovalResolutionV21Input,
    action: StrictV21ApprovalRuntimeAction<A, R>,
  ) => string;
  return implementation.call(runtime, resolution, action);
}

export class StrictReceiptRuntimeV21Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictReceiptRuntimeV21Error'; }
}

export class StrictReceiptRuntimeV21 {
  private readonly tenantId: string;
  private readonly sessionId: string;
  private busy = false;
  private frozenReason: string | undefined;
  private readonly results = new Map<string, {
    fingerprint: string; result: StrictRuntimeV21Result<unknown>;
  }>();

  constructor(
    private readonly coordinator: CoordinatorV21,
    private readonly admissionConfig: StrictAdmissionV21Options,
    private readonly checkpointStore: StrictV21CheckpointStore,
  ) {
    if (!checkpointStore || typeof checkpointStore.save !== 'function') {
      throw new StrictReceiptRuntimeV21Error('durable checkpoint store is required');
    }
    this.coordinator = Object.freeze({
      inspectState: coordinator.inspectState.bind(coordinator),
      prepareDecision: coordinator.prepareDecision.bind(coordinator),
      prepareApprovalResolution: coordinator.prepareApprovalResolution.bind(coordinator),
      commitPrepared: coordinator.commitPrepared.bind(coordinator),
      abortPrepared: coordinator.abortPrepared.bind(coordinator),
      freezePrepared: coordinator.freezePrepared.bind(coordinator),
      observeExecutionTime: coordinator.observeExecutionTime.bind(coordinator),
      signExecutionOutcome: coordinator.signExecutionOutcome.bind(coordinator),
    });
    this.admissionConfig = Object.freeze({ ...admissionConfig });
    this.checkpointStore = Object.freeze({ save: checkpointStore.save.bind(checkpointStore) });
    const state = this.coordinator.inspectState();
    this.tenantId = trustedTextImpl.call(this, state.tenant_id, 'tenant_id');
    this.sessionId = trustedTextImpl.call(this, state.session_id, 'session_id');
    const trustedRunner = trustedRunDecisionImpl.bind(this) as TrustedRuntimeRunner;
    const trustedApprovalRunner = trustedRunApprovalImpl.bind(this) as TrustedApprovalRuntimeRunner;
    Object.defineProperties(this, {
      coordinator: { value: this.coordinator, writable: false, configurable: false },
      admissionConfig: { value: this.admissionConfig, writable: false, configurable: false },
      checkpointStore: { value: this.checkpointStore, writable: false, configurable: false },
      runDecision: { value: trustedRunner, writable: false, configurable: false },
      runApproval: { value: trustedApprovalRunner, writable: false, configurable: false },
    });
    trustedRuntimes.add(this);
    trustedRuntimeRunners.set(this, trustedRunner);
    trustedApprovalRuntimeRunners.set(this, trustedApprovalRunner);
  }

  runDecision<A, R>(input: {
    decision: StrictDecisionActionV21Input;
    action: StrictV21RuntimeAction<A, R>;
  }): Promise<StrictRuntimeV21Result<R>> {
    if (this.frozenReason) {
      throw new StrictReceiptRuntimeV21Error(`strict 2.1 runtime is frozen: ${this.frozenReason}`);
    }
    const actionId = trustedTextImpl.call(this, input.action.runtime_action_id, 'runtime_action_id');
    const fingerprint = callTrustedFingerprint(this, input.decision, input.action);
    const prior = this.results.get(actionId);
    if (prior) {
      if (prior.fingerprint !== fingerprint) {
        throw new StrictReceiptRuntimeV21Error('runtime_action_id was reused with different input');
      }
      return Promise.resolve(prior.result as StrictRuntimeV21Result<R>);
    }
    return callTrustedRunExclusive(
      this, { kind: 'decision', input: input.decision }, input.action,
      actionId, actionId, fingerprint,
    );
  }

  runApproval<A, R>(input: {
    resolution: StrictApprovalResolutionV21Input;
    action: StrictV21ApprovalRuntimeAction<A, R>;
  }): Promise<StrictRuntimeV21Result<R>> {
    if (this.frozenReason) {
      throw new StrictReceiptRuntimeV21Error(`strict 2.1 runtime is frozen: ${this.frozenReason}`);
    }
    const suspendedHash = trustedTextImpl.call(
      this, input.resolution.suspended_receipt_hash, 'suspended_receipt_hash',
    );
    const resultKey = `approval:${suspendedHash}`;
    const fingerprint = callTrustedApprovalFingerprint(this, input.resolution, input.action);
    const prior = this.results.get(resultKey);
    if (prior) {
      if (prior.fingerprint !== fingerprint) {
        throw new StrictReceiptRuntimeV21Error(
          'suspended_receipt_hash was reused with different approval input',
        );
      }
      return Promise.resolve(prior.result as StrictRuntimeV21Result<R>);
    }
    return callTrustedRunExclusive(
      this, { kind: 'resolution', input: input.resolution },
      { ...input.action, runtime_action_id: '' }, undefined, resultKey, fingerprint,
    );
  }

  private async runExclusive<A, R>(
    operation: StrictRuntimeOperationV21, action: StrictV21RuntimeAction<A, R>,
    expectedActionId: string | undefined, resultKey: string, fingerprint: string,
  ): Promise<StrictRuntimeV21Result<R>> {
    if (this.busy) throw new StrictReceiptRuntimeV21Error('strict 2.1 runtime is busy');
    this.busy = true;
    try {
      const prepared: PreparedStrictReceiptV21 = operation.kind === 'decision'
        ? this.coordinator.prepareDecision(operation.input)
        : this.coordinator.prepareApprovalResolution(operation.input);
      const receipt = structuredClone(prepared.kind === 'decision'
        ? (prepared as PreparedDecisionV21).value.receipt
        : (prepared as PreparedApprovalResolutionV21).value);
      const base = { receipt, receipt_hash: prepared.receipt_hash };
      const actionId = receipt.body.action.action_id;
      if ((expectedActionId !== undefined && actionId !== expectedActionId)
        || !actionId.trim()) {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'binding_unavailable' });
      }
      const argumentsSnapshot = receipt.body.execution_authorized
        ? readStrictV21ExecutionArguments(action, receipt)
        : { ok: true as const, value: undefined as A };
      if (!argumentsSnapshot.ok) {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'binding_unavailable' });
      }
      try { await trustedPersistImpl.call(this, 'prepared', prepared, receipt, actionId, fingerprint); } catch (error) {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', error });
      }
      let admission: StrictAdmissionV21Result;
      try {
        admission = await transportPreparedStrictReceiptV21(
          this.coordinator, prepared, this.admissionConfig,
        );
      } catch (error) {
        trustedFreezePreparedImpl.call(this, prepared, 'admission_threw');
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', error });
      }
      if (admission.disposition === 'definitive_no_store') {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        try { await trustedPersistImpl.call(this, 'terminal', prepared, receipt, actionId, fingerprint, 'nonexecuted'); } catch (error) {
          this.frozenReason = 'journal_terminal_failed';
          return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'definitive_no_store', admission });
      }
      if (admission.disposition !== 'accepted') {
        this.coordinator.freezePrepared(prepared.token, prepared.receipt_hash, `admission_${admission.reason}`);
        this.frozenReason = `admission_${admission.reason}`;
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', admission });
      }
      try { await trustedPersistImpl.call(this, 'remote_accepted', prepared, receipt, actionId, fingerprint); } catch (error) {
        trustedFreezePreparedImpl.call(this, prepared, 'remote_accepted_journal_failed');
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error });
      }
      try { this.coordinator.commitPrepared(prepared.token, prepared.receipt_hash); } catch (error) {
        trustedFreezePreparedImpl.call(this, prepared, 'accepted_but_local_commit_failed');
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', admission, error });
      }
      try { await trustedPersistImpl.call(this, 'committed', prepared, receipt, actionId, fingerprint); } catch (error) {
        this.frozenReason = 'committed_journal_failed';
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
      if (!receipt.body.execution_authorized) {
        try { await trustedPersistImpl.call(this, 'terminal', prepared, receipt, actionId, fingerprint, 'nonexecuted'); } catch (error) {
          this.frozenReason = 'terminal_journal_failed';
          return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
        return callTrustedFinish(this, resultKey, fingerprint, { ...base, status: 'nonexecuted', reason: 'not_authorized', admission });
      }
      return executeCommittedStrictActionV21({
        prepared, receipt, action, actionId, fingerprint, admission,
        argumentsSnapshot: argumentsSnapshot.value,
        host: {
          observeExecutionTime: () => this.coordinator.observeExecutionTime(),
          signExecutionOutcome: (body, decisionReceipt) => (
            this.coordinator.signExecutionOutcome(body, decisionReceipt)
          ),
          persist: (...args) => trustedPersistImpl.call(this, ...args),
          cache: (result) => {
            this.results.set(resultKey, {
              fingerprint, result: result as StrictRuntimeV21Result<unknown>,
            });
          },
          finish: (result) => callTrustedFinish(this, resultKey, fingerprint, result),
          freeze: (reason) => { this.frozenReason = reason; },
        },
      });
    } finally { this.busy = false; }
  }

  private async persist(
    phase: StrictRuntimeExecutionJournalV21['phase'], prepared: PreparedStrictReceiptV21,
    receipt: StrictReceiptV21Envelope, actionId: string, fingerprint: string,
    terminalStatus?: StrictRuntimeExecutionJournalV21['terminal_status'],
    executionStart?: StrictExecutionStartV21 & { execution_start_hash: string },
    executionOutcome?: StrictExecutionOutcomeV21Envelope,
  ): Promise<void> {
    const coordinatorState = this.coordinator.inspectState();
    const checkpoint: StrictRuntimeExecutionJournalV21 = {
      schema: STRICT_RUNTIME_EXECUTION_JOURNAL_V21_SCHEMA, profile_version: '2.1', phase,
      tenant_id: this.tenantId, session_id: this.sessionId,
      runtime_action_id: actionId, operation_fingerprint: fingerprint,
      prepared_token: prepared.token, receipt_hash: receipt.receipt_hash,
      receipt: structuredClone(receipt),
      committed_sequence: Number((coordinatorState as { sequence?: number }).sequence ?? 0),
      committed_head_receipt_hash: (coordinatorState as { head_receipt_hash?: string | null }).head_receipt_hash ?? null,
      ...(terminalStatus ? { terminal_status: terminalStatus } : {}),
      ...(executionStart ? {
        execution_start: {
          tenant_id: executionStart.tenant_id,
          session_id: executionStart.session_id,
          action_id: executionStart.action_id,
          decision_receipt_hash: executionStart.decision_receipt_hash,
          operation_fingerprint: executionStart.operation_fingerprint,
          attempt: executionStart.attempt,
          started_at_ms: executionStart.started_at_ms,
        },
        execution_start_hash: executionStart.execution_start_hash,
      } : {}),
      ...(executionOutcome ? { execution_outcome: structuredClone(executionOutcome) } : {}),
    };
    await this.checkpointStore.save(deepFreezeStrictV21(checkpoint));
  }
  private freezePrepared(prepared: PreparedStrictReceiptV21, reason: string): void {
    this.frozenReason = reason;
    try { this.coordinator.freezePrepared(prepared.token, prepared.receipt_hash, reason); } catch { /* already reconciled */ }
  }
  private finish<T>(
    actionId: string, fingerprint: string, result: StrictRuntimeV21Result<T>,
  ): StrictRuntimeV21Result<T> {
    this.results.set(actionId, { fingerprint, result: result as StrictRuntimeV21Result<unknown> });
    return result;
  }
  private fingerprint<A, R>(
    decision: StrictDecisionActionV21Input, action: StrictV21RuntimeAction<A, R>,
  ): string {
    return createHash('sha256').update(canonicalJsonForHash({
      schema: 'obsvr-strict-runtime-operation-v2-1', tenant_id: this.tenantId,
      session_id: this.sessionId, decision, runtime_action_id: action.runtime_action_id,
      original_arguments_hash: action.original_arguments?.arguments_hash,
      effective_arguments_hash: action.effective_arguments?.arguments_hash ?? null,
    })).digest('hex');
  }
  private approvalFingerprint<A, R>(
    resolution: StrictApprovalResolutionV21Input,
    action: StrictV21ApprovalRuntimeAction<A, R>,
  ): string {
    return createHash('sha256').update(canonicalJsonForHash({
      schema: 'obsvr-strict-runtime-approval-operation-v2-1',
      tenant_id: this.tenantId, session_id: this.sessionId, resolution,
      original_arguments_hash: action.original_arguments?.arguments_hash,
      effective_arguments_hash: action.effective_arguments?.arguments_hash ?? null,
    })).digest('hex');
  }
  private text(value: unknown, field: string): string {
    if (typeof value !== 'string' || !value.trim()) {
      throw new StrictReceiptRuntimeV21Error(`${field} must be nonblank`);
    }
    return value;
  }

  static {
    trustedRunDecisionImpl = StrictReceiptRuntimeV21.prototype.runDecision;
    trustedRunApprovalImpl = StrictReceiptRuntimeV21.prototype.runApproval;
    trustedRunExclusiveImpl = StrictReceiptRuntimeV21.prototype.runExclusive;
    trustedPersistImpl = StrictReceiptRuntimeV21.prototype.persist;
    trustedFreezePreparedImpl = StrictReceiptRuntimeV21.prototype.freezePrepared;
    trustedFinishImpl = StrictReceiptRuntimeV21.prototype.finish;
    trustedFingerprintImpl = StrictReceiptRuntimeV21.prototype.fingerprint;
    trustedApprovalFingerprintImpl = StrictReceiptRuntimeV21.prototype.approvalFingerprint;
    trustedTextImpl = StrictReceiptRuntimeV21.prototype.text;
    Object.freeze(StrictReceiptRuntimeV21.prototype);
  }
}

export function runTrustedStrictApprovalRuntimeV21<A, R>(
  runtime: StrictReceiptRuntimeV21,
  input: {
    resolution: StrictApprovalResolutionV21Input;
    action: StrictV21ApprovalRuntimeAction<A, R>;
  },
): Promise<StrictRuntimeV21Result<R>> {
  assertStrictReceiptRuntimeV21(runtime);
  return (trustedApprovalRuntimeRunners.get(runtime) as TrustedApprovalRuntimeRunner)(input);
}

export function assertStrictReceiptRuntimeV21(
  value: unknown,
): asserts value is StrictReceiptRuntimeV21 {
  if (!value || typeof value !== 'object' || !trustedRuntimes.has(value)) {
    throw new StrictReceiptRuntimeV21Error('trusted strict 2.1 runtime is required');
  }
}

export function runTrustedStrictReceiptRuntimeV21<A, R>(
  runtime: StrictReceiptRuntimeV21,
  input: {
    decision: StrictDecisionActionV21Input;
    action: StrictV21RuntimeAction<A, R>;
  },
): Promise<StrictRuntimeV21Result<R>> {
  assertStrictReceiptRuntimeV21(runtime);
  return (trustedRuntimeRunners.get(runtime) as TrustedRuntimeRunner)(input);
}
