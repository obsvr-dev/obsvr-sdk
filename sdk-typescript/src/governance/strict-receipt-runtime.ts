import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import type { StrictAdmissionResult } from './strict-admission.js';
import type { StrictReceiptEnvelope } from './strict-receipt.js';
import {
  StrictReceiptCoordinator,
  type PreparedDecision,
  type PreparedResolution,
  type StrictDecisionInput,
  type StrictResolutionInput,
  type StrictTimeoutInput,
} from './strict-receipt-coordinator.js';
import { cloneCoordinatorValue } from './strict-receipt-coordinator-support.js';
import { DEFINITIVE_NO_STORE } from './strict-receipt-prepared-state.js';

export const STRICT_BOUND_ARGUMENTS = Object.freeze({
  status: 'trusted_bound_arguments' as const,
});

export interface StrictBoundArguments<T> {
  capability: typeof STRICT_BOUND_ARGUMENTS;
  arguments_hash: string;
  value: T;
}

export type StrictRuntimeAdmission<C> = (
  receipt: StrictReceiptEnvelope,
  config: C,
) => Promise<StrictAdmissionResult>;

interface StrictRuntimeBase {
  receipt: StrictReceiptEnvelope;
  receipt_hash: string;
}

export type StrictRuntimeResult<T> =
  | (StrictRuntimeBase & {
      status: 'admitted';
      reason: 'local_commit_failed';
      admission: Extract<StrictAdmissionResult, { disposition: 'accepted' }>;
      error: unknown;
    })
  | (StrictRuntimeBase & {
      status: 'nonexecuted';
      reason: 'not_authorized' | 'definitive_no_store' | 'admission_uncertain'
        | 'receipt_hash_mismatch' | 'effective_arguments_unavailable'
        | 'original_arguments_unavailable' | 'action_id_mismatch';
      admission?: StrictAdmissionResult;
      error?: unknown;
    })
  | (StrictRuntimeBase & { status: 'executed'; value: T })
  | (StrictRuntimeBase & { status: 'invocation_failed'; error: unknown });

export interface StrictRuntimeAction<TArguments, TResult> {
  runtime_action_id: string;
  original_arguments: StrictBoundArguments<TArguments>;
  effective_arguments?: StrictBoundArguments<TArguments>;
  invoke: (argumentsValue: TArguments) => Promise<TResult> | TResult;
}

export class StrictReceiptRuntimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StrictReceiptRuntimeError';
  }
}

type Prepared = PreparedDecision | PreparedResolution;

export class StrictReceiptRuntime<C> {
  private busy = false;
  private readonly invocationResults = new Map<string, {
    fingerprint: string;
    result: StrictRuntimeResult<unknown>;
  }>();

  constructor(
    private readonly coordinator: StrictReceiptCoordinator,
    private readonly admit: StrictRuntimeAdmission<C>,
    private readonly admissionConfig: C,
  ) {
    if (typeof admit !== 'function') {
      throw new StrictReceiptRuntimeError('admission function must be callable');
    }
  }

  runDecision<TArguments, TResult>(input: {
    decision: StrictDecisionInput;
    action: StrictRuntimeAction<TArguments, TResult>;
  }): Promise<StrictRuntimeResult<TResult>> {
    const fingerprint = this.operationFingerprint('decision', input.decision, input.action);
    return this.runExclusive(
      input.action, fingerprint,
      () => this.coordinator.prepareDecision(input.decision),
    );
  }

  runResolution<TArguments, TResult>(input: {
    resolution: StrictResolutionInput;
    action: StrictRuntimeAction<TArguments, TResult>;
  }): Promise<StrictRuntimeResult<TResult>> {
    const fingerprint = this.operationFingerprint('resolution', input.resolution, input.action);
    return this.runExclusive(
      input.action, fingerprint,
      () => this.coordinator.prepareResolution(input.resolution),
    );
  }

  runTimeout(input: StrictTimeoutInput): Promise<StrictRuntimeResult<never>> {
    return this.runExclusive<never, never>(undefined, undefined, () => (
      this.coordinator.prepareTimeout(input)
    ));
  }

  private async runExclusive<TArguments, TResult>(
    action: StrictRuntimeAction<TArguments, TResult> | undefined,
    fingerprint: string | undefined,
    prepare: () => Prepared,
  ): Promise<StrictRuntimeResult<TResult>> {
    if (this.busy) throw new StrictReceiptRuntimeError('strict runtime is busy');
    if (action) {
      const prior = this.invocationResults.get(action.runtime_action_id);
      if (prior) {
        if (prior.fingerprint !== fingerprint) {
          throw new StrictReceiptRuntimeError(
            'runtime_action_id was reused with different input',
          );
        }
        return this.copyResult(prior.result) as StrictRuntimeResult<TResult>;
      }
    }
    this.busy = true;
    try {
      const prepared = prepare();
      const receipt = this.preparedReceipt(prepared);
      const base = { receipt, receipt_hash: prepared.receipt_hash };
      if (action && action.runtime_action_id !== receipt.body.action.action_id) {
        this.coordinator.abortPrepared(
          prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE,
        );
        return { ...base, status: 'nonexecuted', reason: 'action_id_mismatch' };
      }
      let argumentSnapshot: { ok: true; value: TArguments } | undefined;
      if (receipt.body.execution_authorized) {
        if (!action) {
          this.coordinator.abortPrepared(
            prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE,
          );
          return { ...base, status: 'nonexecuted', reason: 'not_authorized' };
        }
        const preflight = this.executionArguments(action, receipt);
        if (!preflight.ok) {
          this.coordinator.abortPrepared(
            prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE,
          );
          return { ...base, status: 'nonexecuted', reason: preflight.reason };
        }
        // Snapshot the selected reference; adapters remain responsible for nested value immutability.
        argumentSnapshot = preflight;
      }
      let admission: StrictAdmissionResult;
      try {
        admission = await this.admit(receipt, this.admissionConfig);
      } catch (error) {
        this.coordinator.freezePrepared(
          prepared.token, prepared.receipt_hash, 'admission_threw',
        );
        return {
          ...base, status: 'nonexecuted', reason: 'admission_uncertain', error,
        };
      }
      if (admission.receipt_hash !== prepared.receipt_hash) {
        this.coordinator.freezePrepared(
          prepared.token, prepared.receipt_hash, 'admission_receipt_hash_mismatch',
        );
        return {
          ...base, status: 'nonexecuted', reason: 'receipt_hash_mismatch', admission,
        };
      }
      if (admission.disposition === 'definitive_no_store') {
        this.coordinator.abortPrepared(
          prepared.token, prepared.receipt_hash, DEFINITIVE_NO_STORE,
        );
        return {
          ...base, status: 'nonexecuted', reason: 'definitive_no_store', admission,
        };
      }
      if (admission.disposition === 'uncertain') {
        this.coordinator.freezePrepared(
          prepared.token, prepared.receipt_hash, `admission_${admission.reason}`,
        );
        return {
          ...base, status: 'nonexecuted', reason: 'admission_uncertain', admission,
        };
      }
      let committed: unknown;
      try {
        committed = this.coordinator.commitPrepared(
          prepared.token, admission.receipt_hash,
        );
      } catch (error) {
        return {
          ...base, status: 'admitted', reason: 'local_commit_failed', admission, error,
        };
      }
      const committedReceipt = this.committedReceipt(committed);
      const committedBase = {
        receipt: committedReceipt, receipt_hash: committedReceipt.receipt_hash,
      };
      if (!committedReceipt.body.execution_authorized) {
        return { ...committedBase, status: 'nonexecuted', reason: 'not_authorized' };
      }
      if (!action) {
        return { ...committedBase, status: 'nonexecuted', reason: 'not_authorized' };
      }
      if (!argumentSnapshot) throw new StrictReceiptRuntimeError('argument preflight was lost');
      const prior = this.invocationResults.get(action.runtime_action_id);
      if (prior) {
        if (prior.fingerprint !== fingerprint) {
          throw new StrictReceiptRuntimeError(
            'runtime_action_id was reused with different input',
          );
        }
        return this.copyResult(prior.result) as StrictRuntimeResult<TResult>;
      }
      const inProgress: StrictRuntimeResult<unknown> = {
        ...committedBase, status: 'invocation_failed',
        error: new StrictReceiptRuntimeError('action invocation is already in progress'),
      };
      this.invocationResults.set(action.runtime_action_id, {
        fingerprint: fingerprint as string, result: this.storedResult(inProgress),
      });
      try {
        const value = await action.invoke(argumentSnapshot.value);
        const result: StrictRuntimeResult<TResult> = {
          ...committedBase, status: 'executed', value,
        };
        this.invocationResults.set(action.runtime_action_id, {
          fingerprint: fingerprint as string, result: this.storedResult(result),
        });
        return this.copyResult(result);
      } catch (error) {
        const result: StrictRuntimeResult<TResult> = {
          ...committedBase, status: 'invocation_failed', error,
        };
        this.invocationResults.set(action.runtime_action_id, {
          fingerprint: fingerprint as string, result: this.storedResult(result),
        });
        return this.copyResult(result);
      }
    } finally {
      this.busy = false;
    }
  }

  private executionArguments<TArguments, TResult>(
    action: StrictRuntimeAction<TArguments, TResult>,
    receipt: StrictReceiptEnvelope,
  ): { ok: true; value: TArguments } | { ok: false;
    reason: 'original_arguments_unavailable' | 'effective_arguments_unavailable' } {
    if (receipt.body.evaluation.outcome !== 'MODIFY') {
      if (action.original_arguments?.capability !== STRICT_BOUND_ARGUMENTS
        || action.original_arguments.arguments_hash !== receipt.body.action.arguments_hash) {
        return { ok: false, reason: 'original_arguments_unavailable' };
      }
      return { ok: true, value: action.original_arguments.value };
    }
    if (action.effective_arguments?.capability !== STRICT_BOUND_ARGUMENTS
      || action.effective_arguments.arguments_hash
        !== receipt.body.action.effective_arguments_hash) {
      return { ok: false, reason: 'effective_arguments_unavailable' };
    }
    return { ok: true, value: action.effective_arguments.value };
  }

  private preparedReceipt(prepared: Prepared): StrictReceiptEnvelope {
    return 'receipt' in prepared.value ? prepared.value.receipt : prepared.value;
  }

  private committedReceipt(value: unknown): StrictReceiptEnvelope {
    const raw = value as StrictReceiptEnvelope | { receipt: StrictReceiptEnvelope };
    return 'receipt' in raw ? raw.receipt : raw;
  }

  private operationFingerprint<TArguments, TResult>(
    kind: 'decision' | 'resolution',
    coordinatorInput: StrictDecisionInput | StrictResolutionInput,
    action: StrictRuntimeAction<TArguments, TResult>,
  ): string {
    if (typeof action.runtime_action_id !== 'string'
      || action.runtime_action_id.trim().length === 0) {
      throw new StrictReceiptRuntimeError('runtime_action_id must be nonblank');
    }
    if (typeof action.invoke !== 'function') {
      throw new StrictReceiptRuntimeError('action invoke must be callable');
    }
    const effectiveHash = action.effective_arguments?.arguments_hash;
    const suppliedOriginalHash = action.original_arguments?.arguments_hash;
    const document = {
      schema: 'obsvr-strict-runtime-operation-v1', kind,
      runtime_action_id: action.runtime_action_id,
      coordinator_input: coordinatorInput,
      argument_bindings: {
        original_arguments_hash: coordinatorInput.context.current_action.arguments_hash,
        ...(suppliedOriginalHash === undefined
          ? {} : { supplied_original_arguments_hash: suppliedOriginalHash }),
        ...(effectiveHash === undefined ? {} : { effective_arguments_hash: effectiveHash }),
      },
    };
    return createHash('sha256').update(canonicalJsonForHash(document), 'utf8').digest('hex');
  }

  private storedResult<T>(result: StrictRuntimeResult<T>): StrictRuntimeResult<T> {
    return this.copyResult(result);
  }

  private copyResult<T>(result: StrictRuntimeResult<T>): StrictRuntimeResult<T> {
    return {
      ...result,
      receipt: cloneCoordinatorValue(result.receipt),
      ...('admission' in result
        ? { admission: cloneCoordinatorValue(result.admission) }
        : {}),
    } as StrictRuntimeResult<T>;
  }
}
