import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  transportPreparedStrictReceiptV21,
  type StrictAdmissionV21Coordinator,
  type StrictAdmissionV21Options,
  type StrictAdmissionV21Result,
} from './strict-admission-v2-1.js';
import type {
  PreparedDecisionV21, StrictDecisionActionV21Input,
} from './strict-receipt-coordinator-v2-1-types.js';
import { DEFINITIVE_NO_STORE } from './strict-receipt-prepared-state.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';

const boundArguments = new WeakSet<object>();
export const STRICT_RUNTIME_EXECUTION_JOURNAL_V21_SCHEMA = 'obsvr-strict-runtime-execution-journal-v2-1' as const;

export interface StrictV21BoundArguments<T> {
  readonly arguments_hash: string;
  readonly value: T;
}
export interface StrictV21RuntimeAction<A, R> {
  runtime_action_id: string;
  original_arguments: StrictV21BoundArguments<A>;
  effective_arguments?: StrictV21BoundArguments<A>;
  invoke: (value: A) => Promise<R> | R;
}
export interface StrictV21CheckpointStore {
  /** Implementations must durably and atomically replace the prior journal entry. */
  save(checkpoint: StrictRuntimeExecutionJournalV21): Promise<void> | void;
}
/** An execution journal entry, not an authenticated recovery checkpoint. */
export interface StrictRuntimeExecutionJournalV21 {
  schema: typeof STRICT_RUNTIME_EXECUTION_JOURNAL_V21_SCHEMA;
  profile_version: '2.1';
  phase: 'prepared' | 'remote_accepted' | 'committed' | 'invocation_started' | 'terminal';
  tenant_id: string;
  session_id: string;
  runtime_action_id: string;
  operation_fingerprint: string;
  prepared_token: string;
  receipt_hash: string;
  committed_sequence: number;
  committed_head_receipt_hash: string | null;
  terminal_status?: 'executed' | 'invocation_failed' | 'nonexecuted';
  receipt?: StrictReceiptV21Envelope;
}
interface CoordinatorV21 extends StrictAdmissionV21Coordinator {
  prepareDecision(input: StrictDecisionActionV21Input): PreparedDecisionV21;
}
interface ResultBase { receipt: StrictReceiptV21Envelope; receipt_hash: string }
export type StrictRuntimeV21Result<T> =
  | (ResultBase & { status: 'executed'; value: T; admission: StrictAdmissionV21Result })
  | (ResultBase & { status: 'invocation_failed'; error: unknown; admission: StrictAdmissionV21Result })
  | (ResultBase & { status: 'invocation_uncertain'; error: unknown; admission: StrictAdmissionV21Result })
  | (ResultBase & { status: 'nonexecuted'; reason: 'not_authorized' | 'binding_unavailable' | 'checkpoint_persist_failed' | 'definitive_no_store' | 'admission_uncertain'; admission?: StrictAdmissionV21Result; error?: unknown });

export class StrictReceiptRuntimeV21Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictReceiptRuntimeV21Error'; }
}

function clone<T>(value: T): T { return structuredClone(value); }
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    Object.values(value as Record<string, unknown>).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}
export function bindStrictV21JsonArguments<T>(value: T): StrictV21BoundArguments<T> {
  const snapshot = deepFreeze(clone(value));
  const hash = createHash('sha256').update(canonicalJsonForHash(snapshot)).digest('hex');
  const result = Object.freeze({ arguments_hash: hash, value: snapshot });
  boundArguments.add(result); return result;
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
    const state = coordinator.inspectState();
    this.tenantId = this.text(state.tenant_id, 'tenant_id');
    this.sessionId = this.text(state.session_id, 'session_id');
  }

  runDecision<A, R>(input: {
    decision: StrictDecisionActionV21Input;
    action: StrictV21RuntimeAction<A, R>;
  }): Promise<StrictRuntimeV21Result<R>> {
    if (this.frozenReason) {
      throw new StrictReceiptRuntimeV21Error(`strict 2.1 runtime is frozen: ${this.frozenReason}`);
    }
    const actionId = this.text(input.action.runtime_action_id, 'runtime_action_id');
    const fingerprint = this.fingerprint(input.decision, input.action);
    const prior = this.results.get(actionId);
    if (prior) {
      if (prior.fingerprint !== fingerprint) {
        throw new StrictReceiptRuntimeV21Error('runtime_action_id was reused with different input');
      }
      return Promise.resolve(prior.result as StrictRuntimeV21Result<R>);
    }
    return this.runExclusive(input.decision, input.action, actionId, fingerprint);
  }

  private async runExclusive<A, R>(
    decision: StrictDecisionActionV21Input, action: StrictV21RuntimeAction<A, R>,
    actionId: string, fingerprint: string,
  ): Promise<StrictRuntimeV21Result<R>> {
    if (this.busy) throw new StrictReceiptRuntimeV21Error('strict 2.1 runtime is busy');
    this.busy = true;
    try {
      const prepared = this.coordinator.prepareDecision(decision);
      const receipt = clone(prepared.value.receipt);
      const base = { receipt, receipt_hash: prepared.receipt_hash };
      if (receipt.body.action.action_id !== actionId) {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'binding_unavailable' });
      }
      const argumentsSnapshot = receipt.body.execution_authorized
        ? this.executionArguments(action, receipt) : { ok: true as const, value: undefined as A };
      if (!argumentsSnapshot.ok) {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'binding_unavailable' });
      }
      try { await this.persist('prepared', prepared, receipt, actionId, fingerprint, true); } catch (error) {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', error });
      }
      let admission: StrictAdmissionV21Result;
      try {
        admission = await transportPreparedStrictReceiptV21(
          this.coordinator, prepared, this.admissionConfig,
        );
      } catch (error) {
        this.freezePrepared(prepared, 'admission_threw');
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', error });
      }
      if (admission.disposition === 'definitive_no_store') {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        try { await this.persist('terminal', prepared, receipt, actionId, fingerprint, false, 'nonexecuted'); } catch (error) {
          this.frozenReason = 'journal_terminal_failed';
          return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'definitive_no_store', admission });
      }
      if (admission.disposition !== 'accepted') {
        this.coordinator.freezePrepared(prepared.token, prepared.receipt_hash, `admission_${admission.reason}`);
        this.frozenReason = `admission_${admission.reason}`;
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', admission });
      }
      try { await this.persist('remote_accepted', prepared, receipt, actionId, fingerprint, true); } catch (error) {
        this.freezePrepared(prepared, 'remote_accepted_journal_failed');
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error });
      }
      try { this.coordinator.commitPrepared(prepared.token, prepared.receipt_hash); } catch (error) {
        this.freezePrepared(prepared, 'accepted_but_local_commit_failed');
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', admission, error });
      }
      try { await this.persist('committed', prepared, receipt, actionId, fingerprint, false); } catch (error) {
        this.frozenReason = 'committed_journal_failed';
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
      if (!receipt.body.execution_authorized) {
        try { await this.persist('terminal', prepared, receipt, actionId, fingerprint, false, 'nonexecuted'); } catch (error) {
          this.frozenReason = 'terminal_journal_failed';
          return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'not_authorized', admission });
      }
      try { await this.persist('invocation_started', prepared, receipt, actionId, fingerprint, false); } catch (error) {
        this.frozenReason = 'invocation_started_journal_failed';
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'checkpoint_persist_failed', admission, error }); }
      this.results.set(actionId, { fingerprint, result: {
        ...base, status: 'invocation_uncertain', admission,
        error: new StrictReceiptRuntimeV21Error('action invocation is already in progress'),
      } });
      try {
        const value = await action.invoke(argumentsSnapshot.value);
        try { await this.persist('terminal', prepared, receipt, actionId, fingerprint, false, 'executed'); } catch (error) {
          this.frozenReason = 'terminal_journal_failed';
          return this.finish(actionId, fingerprint, { ...base, status: 'invocation_uncertain', admission, error }); }
        return this.finish(actionId, fingerprint, { ...base, status: 'executed', admission, value });
      } catch (error) {
        try { await this.persist('terminal', prepared, receipt, actionId, fingerprint, false, 'invocation_failed'); } catch (journalError) {
          this.frozenReason = 'terminal_journal_failed';
          return this.finish(actionId, fingerprint, { ...base, status: 'invocation_uncertain', admission, error: journalError }); }
        return this.finish(actionId, fingerprint, { ...base, status: 'invocation_failed', admission, error });
      }
    } finally { this.busy = false; }
  }

  private executionArguments<A>(action: StrictV21RuntimeAction<A, unknown>, receipt: StrictReceiptV21Envelope):
    { ok: true; value: A } | { ok: false } {
    const modified = receipt.body.outcome === 'MODIFY';
    const bound = modified ? action.effective_arguments : action.original_arguments;
    const expected = modified
      ? receipt.body.action.effective_arguments_hash : receipt.body.action.arguments_hash;
    if (!bound || !boundArguments.has(bound) || bound.arguments_hash !== expected) return { ok: false };
    return { ok: true, value: bound.value };
  }

  private async persist(
    phase: StrictRuntimeExecutionJournalV21['phase'], prepared: PreparedDecisionV21,
    receipt: StrictReceiptV21Envelope, actionId: string, fingerprint: string,
    includeReceipt: boolean, terminalStatus?: StrictRuntimeExecutionJournalV21['terminal_status'],
  ): Promise<void> {
    const coordinatorState = this.coordinator.inspectState();
    const checkpoint: StrictRuntimeExecutionJournalV21 = {
      schema: STRICT_RUNTIME_EXECUTION_JOURNAL_V21_SCHEMA, profile_version: '2.1', phase,
      tenant_id: this.tenantId, session_id: this.sessionId,
      runtime_action_id: actionId, operation_fingerprint: fingerprint,
      prepared_token: prepared.token, receipt_hash: receipt.receipt_hash,
      committed_sequence: Number((coordinatorState as { sequence?: number }).sequence ?? 0),
      committed_head_receipt_hash: (coordinatorState as { head_receipt_hash?: string | null }).head_receipt_hash ?? null,
      ...(terminalStatus ? { terminal_status: terminalStatus } : {}),
      ...(includeReceipt ? { receipt: clone(receipt) } : {}),
    };
    await this.checkpointStore.save(deepFreeze(checkpoint));
  }
  private freezePrepared(prepared: PreparedDecisionV21, reason: string): void {
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
  private text(value: unknown, field: string): string {
    if (typeof value !== 'string' || !value.trim()) {
      throw new StrictReceiptRuntimeV21Error(`${field} must be nonblank`);
    }
    return value;
  }
}
