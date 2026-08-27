import type { StrictAdmissionV21Result, PreparedStrictReceiptV21 } from './strict-admission-v2-1.js';
import type {
  StrictExecutionOutcomeV21Body,
  StrictExecutionOutcomeV21Envelope,
  StrictExecutionStartV21,
} from './strict-execution-outcome-v2-1.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import {
  classifyStrictRuntimeErrorV21,
  createStrictRuntimeErrorOutcomeV21,
  createStrictRuntimeExecutionStartV21,
  createStrictRuntimeSuccessOutcomeV21,
  defaultStrictRuntimeResultProjectionV21,
  type StrictRuntimeFailureClassificationV21,
} from './strict-receipt-runtime-v2-1-outcomes.js';
import type {
  StrictRuntimeExecutionJournalV21,
  StrictRuntimeV21Result,
  StrictV21RuntimeAction,
} from './strict-receipt-runtime-v2-1-types.js';

export interface StrictRuntimeExecutionV21Host {
  observeExecutionTime(): number;
  signExecutionOutcome(
    body: StrictExecutionOutcomeV21Body,
    receipt: StrictReceiptV21Envelope,
  ): StrictExecutionOutcomeV21Envelope;
  persist(
    phase: StrictRuntimeExecutionJournalV21['phase'],
    prepared: PreparedStrictReceiptV21,
    receipt: StrictReceiptV21Envelope,
    actionId: string,
    fingerprint: string,
    terminalStatus?: StrictRuntimeExecutionJournalV21['terminal_status'],
    executionStart?: StrictExecutionStartV21 & { execution_start_hash: string },
    executionOutcome?: StrictExecutionOutcomeV21Envelope,
  ): Promise<void>;
  cache<T>(result: StrictRuntimeV21Result<T>): void;
  finish<T>(result: StrictRuntimeV21Result<T>): StrictRuntimeV21Result<T>;
  freeze(reason: string): void;
}

export async function executeCommittedStrictActionV21<A, R>(params: {
  host: StrictRuntimeExecutionV21Host;
  prepared: PreparedStrictReceiptV21;
  receipt: StrictReceiptV21Envelope;
  action: StrictV21RuntimeAction<A, R>;
  argumentsSnapshot: A;
  actionId: string;
  fingerprint: string;
  admission: StrictAdmissionV21Result;
}): Promise<StrictRuntimeV21Result<R>> {
  const { host, prepared, receipt, action, argumentsSnapshot, actionId,
    fingerprint, admission } = params;
  const base = { receipt, receipt_hash: prepared.receipt_hash };
  let executionStart: StrictExecutionStartV21 & { execution_start_hash: string };
  try {
    executionStart = createStrictRuntimeExecutionStartV21(
      receipt, fingerprint, host.observeExecutionTime(),
    );
  } catch (error) {
    host.freeze('execution_start_unavailable');
    return host.finish({ ...base, status: 'nonexecuted',
      reason: 'execution_state_unavailable', admission, error });
  }
  try {
    await host.persist('invocation_started', prepared, receipt, actionId, fingerprint,
      undefined, executionStart);
  } catch (error) {
    host.freeze('invocation_started_journal_failed');
    return host.finish({ ...base, status: 'nonexecuted',
      reason: 'checkpoint_persist_failed', admission, error });
  }
  host.cache({ ...base, status: 'invocation_uncertain', admission,
    error: new Error('action invocation is already in progress') });
  let value: R;
  try {
    value = await action.invoke(argumentsSnapshot);
  } catch (error) {
    const classification = classifyStrictRuntimeErrorV21(error, action.classify_error);
    try {
      const executionOutcome = host.signExecutionOutcome(
        createStrictRuntimeErrorOutcomeV21(
          receipt, executionStart, host.observeExecutionTime(), classification,
        ), receipt,
      );
      const terminal = classification.status === 'failed'
        ? 'invocation_failed' as const : 'invocation_uncertain' as const;
      await host.persist('terminal', prepared, receipt, actionId, fingerprint,
        terminal, executionStart, executionOutcome);
      return host.finish({ ...base, execution_outcome: executionOutcome,
        status: terminal, admission, error } as StrictRuntimeV21Result<R>);
    } catch (finalizationError) {
      host.freeze('terminal_outcome_failed');
      return host.finish({ ...base, status: 'invocation_uncertain', admission,
        error: finalizationError });
    }
  }
  let resultProjection: unknown;
  try {
    resultProjection = action.result_projection
      ? action.result_projection(value) : defaultStrictRuntimeResultProjectionV21();
  } catch (error) {
    const classification: StrictRuntimeFailureClassificationV21 = {
      status: 'uncertain', error_code: 'result_projection_failed',
    };
    try {
      const executionOutcome = host.signExecutionOutcome(
        createStrictRuntimeErrorOutcomeV21(
          receipt, executionStart, host.observeExecutionTime(), classification,
        ), receipt,
      );
      await host.persist('terminal', prepared, receipt, actionId, fingerprint,
        'invocation_uncertain', executionStart, executionOutcome);
      return host.finish({ ...base, execution_outcome: executionOutcome,
        status: 'invocation_uncertain', admission, error });
    } catch (finalizationError) {
      host.freeze('terminal_outcome_failed');
      return host.finish({ ...base, status: 'invocation_uncertain', admission,
        error: finalizationError });
    }
  }
  try {
    const executionOutcome = host.signExecutionOutcome(
      createStrictRuntimeSuccessOutcomeV21(
        receipt, executionStart, host.observeExecutionTime(), resultProjection,
      ), receipt,
    );
    await host.persist('terminal', prepared, receipt, actionId, fingerprint,
      'executed', executionStart, executionOutcome);
    return host.finish({ ...base, execution_outcome: executionOutcome,
      status: 'executed', admission, value });
  } catch (error) {
    host.freeze('terminal_outcome_failed');
    return host.finish({ ...base, status: 'invocation_uncertain', admission, error });
  }
}
