import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { admitStrictReceiptV2, type StrictAdmissionV2Options, type StrictAdmissionV2Result } from './strict-admission-v2.js';
import type { PreparedDecisionV2, PreparedResolutionV2, StrictDecisionV2Input, StrictDecisionV2Result, StrictResolutionV2Input, StrictTimeoutV2Input } from './strict-receipt-coordinator-v2-types.js';
import { cloneCoordinatorValue } from './strict-receipt-coordinator-support.js';
import { DEFINITIVE_NO_STORE } from './strict-receipt-prepared-state.js';
import { STRICT_RECEIPT_V2_ENVELOPE_SCHEMA, STRICT_RECEIPT_V2_SCHEMA, type StrictReceiptV2Envelope } from './strict-receipt-v2.js';

const boundArguments = new WeakSet<object>();
const trustedAdmissions = new WeakSet<object>();

export interface StrictV2BoundArguments<T> { readonly arguments_hash: string; readonly value: T }
export interface StrictV2RuntimeAction<A, R> {
  runtime_action_id: string;
  original_arguments: StrictV2BoundArguments<A>;
  effective_arguments?: StrictV2BoundArguments<A>;
  invoke: (value: A) => Promise<R> | R;
}
export interface TrustedStrictV2Admission {
  admit: (receipt: StrictReceiptV2Envelope, config: StrictAdmissionV2Options) => Promise<StrictAdmissionV2Result>;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    Object.values(value as Record<string, unknown>).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}
export function bindStrictV2JsonArguments<T>(value: T): StrictV2BoundArguments<T> {
  const snapshot = deepFreeze(cloneCoordinatorValue(value));
  const hash = createHash('sha256').update(canonicalJsonForHash(snapshot)).digest('hex');
  const bound = Object.freeze({ arguments_hash: hash, value: snapshot });
  boundArguments.add(bound);
  return bound;
}
/** Explicitly trusted test seam. Production uses admitStrictReceiptV2. */
export function createTrustedStrictV2Admission(admit: TrustedStrictV2Admission['admit']): TrustedStrictV2Admission {
  if (typeof admit !== 'function') throw new StrictReceiptRuntimeV2Error('trusted admission must be callable');
  const result = Object.freeze({ admit });
  trustedAdmissions.add(result);
  return result;
}

interface CoordinatorV2 {
  prepareDecision(input: StrictDecisionV2Input): PreparedDecisionV2;
  prepareResolution(input: StrictResolutionV2Input): PreparedResolutionV2;
  prepareTimeout(input: StrictTimeoutV2Input): PreparedResolutionV2;
  commitPrepared(token: string, hash: string): StrictDecisionV2Result | StrictReceiptV2Envelope;
  abortPrepared(token: string, hash: string, capability: typeof DEFINITIVE_NO_STORE): void;
  freezePrepared(token: string, hash: string, reason?: string): void;
  inspectState(): { tenant_id: string; session_id: string };
}
type Prepared = PreparedDecisionV2 | PreparedResolutionV2;
interface ResultBase { receipt: StrictReceiptV2Envelope; receipt_hash: string }
export type StrictRuntimeV2Result<T> =
  | (ResultBase & { status: 'admitted'; reason: 'local_commit_failed'; admission: StrictAdmissionV2Result; error: unknown })
  | (ResultBase & { status: 'nonexecuted'; reason: 'not_authorized' | 'definitive_no_store' | 'admission_uncertain' | 'receipt_hash_mismatch' | 'admission_schema_mismatch' | 'tenant_mismatch' | 'session_mismatch' | 'receipt_schema_mismatch' | 'action_id_mismatch' | 'original_arguments_unavailable' | 'effective_arguments_unavailable'; admission?: StrictAdmissionV2Result; error?: unknown })
  | (ResultBase & { status: 'executed'; value: T })
  | (ResultBase & { status: 'invocation_failed'; error: unknown });

export class StrictReceiptRuntimeV2Error extends Error {
  constructor(message: string) { super(message); this.name = 'StrictReceiptRuntimeV2Error'; }
}

export class StrictReceiptRuntimeV2 {
  private readonly tenantId: string;
  private readonly sessionId: string;
  private busy = false;
  private readonly results = new Map<string, { fingerprint: string; result: StrictRuntimeV2Result<unknown> }>();

  constructor(private readonly coordinator: CoordinatorV2,
    private readonly admissionConfig: StrictAdmissionV2Options,
    private readonly trustedAdmission?: TrustedStrictV2Admission) {
    if (trustedAdmission !== undefined && !trustedAdmissions.has(trustedAdmission)) {
      throw new StrictReceiptRuntimeV2Error('trusted admission must be created explicitly');
    }
    const state = coordinator.inspectState();
    this.tenantId = this.text(state.tenant_id, 'tenant_id');
    this.sessionId = this.text(state.session_id, 'session_id');
  }

  runDecision<A, R>(input: { decision: StrictDecisionV2Input; action: StrictV2RuntimeAction<A, R> }): Promise<StrictRuntimeV2Result<R>> {
    return this.runAction('decision', input.decision, input.action, () => this.coordinator.prepareDecision(input.decision));
  }
  runResolution<A, R>(input: { resolution: StrictResolutionV2Input; action: StrictV2RuntimeAction<A, R> }): Promise<StrictRuntimeV2Result<R>> {
    return this.runAction('resolution', input.resolution, input.action, () => this.coordinator.prepareResolution(input.resolution));
  }
  runTimeout(input: StrictTimeoutV2Input): Promise<StrictRuntimeV2Result<never>> {
    return this.runExclusive(undefined, undefined, () => this.coordinator.prepareTimeout(input));
  }

  private runAction<A, R>(kind: 'decision' | 'resolution', input: unknown,
    action: StrictV2RuntimeAction<A, R>, prepare: () => Prepared): Promise<StrictRuntimeV2Result<R>> {
    const fingerprint = this.fingerprint(kind, input, action);
    const prior = this.results.get(action.runtime_action_id);
    if (prior) {
      if (prior.fingerprint !== fingerprint) throw new StrictReceiptRuntimeV2Error('runtime_action_id was reused with different input');
      return Promise.resolve(this.copy(prior.result) as StrictRuntimeV2Result<R>);
    }
    return this.runExclusive(action, fingerprint, prepare);
  }

  private async runExclusive<A, R>(action: StrictV2RuntimeAction<A, R> | undefined,
    fingerprint: string | undefined, prepare: () => Prepared): Promise<StrictRuntimeV2Result<R>> {
    if (this.busy) throw new StrictReceiptRuntimeV2Error('strict v2 runtime is busy');
    this.busy = true;
    let actionId: string | undefined;
    try {
      if (action) {
        actionId = this.text(action.runtime_action_id, 'runtime_action_id');
        const prior = this.results.get(actionId);
        if (prior) {
          if (prior.fingerprint !== fingerprint) throw new StrictReceiptRuntimeV2Error('runtime_action_id was reused with different input');
          return this.copy(prior.result) as StrictRuntimeV2Result<R>;
        }
      }
      const prepared = prepare();
      const receipt = this.preparedReceipt(prepared);
      const base = { receipt: this.copy(receipt), receipt_hash: prepared.receipt_hash };
      const localReason = this.localContractReason(prepared, receipt, actionId);
      if (localReason) return this.abortLocal(prepared, base, localReason, actionId, fingerprint);
      const snapshot = receipt.body.execution_authorized
        ? this.executionArguments(action, receipt) : { ok: true as const, value: undefined as A };
      if (!snapshot.ok) return this.abortLocal(prepared, base, snapshot.reason, actionId, fingerprint);
      let admission: StrictAdmissionV2Result;
      try {
        admission = this.trustedAdmission
          ? await this.trustedAdmission.admit(this.copy(receipt), this.admissionConfig)
          : await admitStrictReceiptV2(this.copy(receipt), this.admissionConfig);
      } catch (error) {
        this.coordinator.freezePrepared(prepared.token, prepared.receipt_hash, 'admission_threw');
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', error });
      }
      const responseReason = this.admissionReason(admission, prepared.receipt_hash);
      if (responseReason) {
        this.coordinator.freezePrepared(prepared.token, prepared.receipt_hash, `admission_${responseReason}`);
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: responseReason, admission });
      }
      if (admission.disposition === 'definitive_no_store') {
        this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'definitive_no_store', admission });
      }
      if (admission.disposition === 'uncertain') {
        this.coordinator.freezePrepared(prepared.token, prepared.receipt_hash, `admission_${admission.reason}`);
        return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason: 'admission_uncertain', admission });
      }
      let committed: StrictDecisionV2Result | StrictReceiptV2Envelope;
      try { committed = this.coordinator.commitPrepared(prepared.token, admission.receipt_hash); } catch (error) {
        return this.finish(actionId, fingerprint, { ...base, status: 'admitted', reason: 'local_commit_failed', admission, error });
      }
      const committedReceipt = this.committedReceipt(committed);
      const committedBase = { receipt: this.copy(committedReceipt), receipt_hash: committedReceipt.receipt_hash };
      if (!committedReceipt.body.execution_authorized || !action) {
        return this.finish(actionId, fingerprint, { ...committedBase, status: 'nonexecuted', reason: 'not_authorized' });
      }
      this.store(actionId!, fingerprint!, { ...committedBase, status: 'invocation_failed', error: new StrictReceiptRuntimeV2Error('action invocation is already in progress') });
      try {
        const value = await action.invoke(snapshot.value);
        return this.finish(actionId, fingerprint, { ...committedBase, status: 'executed', value });
      } catch (error) {
        return this.finish(actionId, fingerprint, { ...committedBase, status: 'invocation_failed', error });
      }
    } finally { this.busy = false; }
  }

  private localContractReason(prepared: Prepared, receipt: StrictReceiptV2Envelope, actionId?: string):
    'receipt_schema_mismatch' | 'tenant_mismatch' | 'session_mismatch' | 'receipt_hash_mismatch' | 'action_id_mismatch' | undefined {
    if (receipt.schema !== STRICT_RECEIPT_V2_ENVELOPE_SCHEMA || receipt.body.schema !== STRICT_RECEIPT_V2_SCHEMA) return 'receipt_schema_mismatch';
    if (receipt.body.tenant_id !== this.tenantId) return 'tenant_mismatch';
    if (receipt.body.session_id !== this.sessionId) return 'session_mismatch';
    if (receipt.receipt_hash !== prepared.receipt_hash) return 'receipt_hash_mismatch';
    if (actionId !== undefined && receipt.body.action.action_id !== actionId) return 'action_id_mismatch';
    return undefined;
  }
  private admissionReason(value: unknown, hash: string): 'admission_schema_mismatch' | 'tenant_mismatch' | 'session_mismatch' | 'receipt_hash_mismatch' | undefined {
    if (!value || typeof value !== 'object') return 'admission_schema_mismatch';
    const result = value as StrictAdmissionV2Result;
    if (result.schema !== 'obsvr-strict-receipt-admission-v2') return 'admission_schema_mismatch';
    if (result.tenant_id !== this.tenantId) return 'tenant_mismatch';
    if (result.session_id !== this.sessionId) return 'session_mismatch';
    if (result.receipt_hash !== hash) return 'receipt_hash_mismatch';
    if (!Number.isSafeInteger(result.attempts) || result.attempts < 1) return 'admission_schema_mismatch';
    if (result.disposition === 'accepted' && !['accepted', 'already_accepted'].includes(result.status)) return 'admission_schema_mismatch';
    if (result.disposition === 'definitive_no_store' && ![400, 401, 403, 413].includes(result.http_status)) return 'admission_schema_mismatch';
    if (result.disposition === 'uncertain' && (typeof result.reason !== 'string' || !result.reason)) return 'admission_schema_mismatch';
    if (!['accepted', 'definitive_no_store', 'uncertain'].includes(result.disposition)) return 'admission_schema_mismatch';
    return undefined;
  }
  private executionArguments<A>(action: StrictV2RuntimeAction<A, unknown> | undefined, receipt: StrictReceiptV2Envelope):
    { ok: true; value: A } | { ok: false; reason: 'original_arguments_unavailable' | 'effective_arguments_unavailable' } {
    if (!action) return { ok: false, reason: 'original_arguments_unavailable' };
    const modified = receipt.body.evaluation.outcome === 'MODIFY';
    const bound = modified ? action.effective_arguments : action.original_arguments;
    const expected = modified ? receipt.body.action.effective_arguments_hash : receipt.body.action.arguments_hash;
    const reason = modified ? 'effective_arguments_unavailable' as const : 'original_arguments_unavailable' as const;
    if (!bound || !boundArguments.has(bound) || bound.arguments_hash !== expected) return { ok: false, reason };
    return { ok: true, value: bound.value };
  }
  private preparedReceipt(prepared: Prepared): StrictReceiptV2Envelope {
    return prepared.kind === 'decision' ? (prepared.value as StrictDecisionV2Result).receipt : prepared.value as StrictReceiptV2Envelope;
  }
  private committedReceipt(value: StrictDecisionV2Result | StrictReceiptV2Envelope): StrictReceiptV2Envelope {
    return Object.prototype.hasOwnProperty.call(value, 'receipt') ? (value as StrictDecisionV2Result).receipt : value as StrictReceiptV2Envelope;
  }
  private abortLocal<T>(prepared: Prepared, base: ResultBase,
    reason: Extract<StrictRuntimeV2Result<T>, { status: 'nonexecuted' }>['reason'], actionId?: string, fingerprint?: string): StrictRuntimeV2Result<T> {
    this.coordinator.abortPrepared(prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE);
    return this.finish(actionId, fingerprint, { ...base, status: 'nonexecuted', reason });
  }
  private finish<T>(actionId: string | undefined, fingerprint: string | undefined, result: StrictRuntimeV2Result<T>): StrictRuntimeV2Result<T> {
    if (actionId && fingerprint) this.store(actionId, fingerprint, result);
    return this.copy(result);
  }
  private store(actionId: string, fingerprint: string, result: StrictRuntimeV2Result<unknown>): void {
    this.results.set(actionId, { fingerprint, result: this.copy(result) });
  }
  private fingerprint<A, R>(kind: string, input: unknown, action: StrictV2RuntimeAction<A, R>): string {
    return createHash('sha256').update(canonicalJsonForHash({ schema: 'obsvr-strict-runtime-operation-v2', kind,
      tenant_id: this.tenantId, session_id: this.sessionId, runtime_action_id: action.runtime_action_id, input,
      original_arguments_hash: action.original_arguments?.arguments_hash,
      effective_arguments_hash: action.effective_arguments?.arguments_hash })).digest('hex');
  }
  private copy<T>(value: T): T { return cloneCoordinatorValue(value); }
  private text(value: unknown, field: string): string {
    if (typeof value !== 'string' || value.trim().length === 0) throw new StrictReceiptRuntimeV2Error(`${field} must be nonblank`);
    return value;
  }
}
