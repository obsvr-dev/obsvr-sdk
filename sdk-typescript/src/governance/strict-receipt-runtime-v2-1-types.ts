import type {
  StrictExecutionOutcomeV21Envelope,
  StrictExecutionStartV21,
} from './strict-execution-outcome-v2-1.js';
import type { StrictAdmissionV21Result } from './strict-admission-v2-1.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import type {
  StrictRuntimeFailureClassificationV21,
} from './strict-receipt-runtime-v2-1-outcomes.js';

export interface StrictV21BoundArguments<T> {
  readonly arguments_hash: string;
  readonly value: T;
}

export interface StrictV21RuntimeAction<A, R> {
  runtime_action_id: string;
  original_arguments: StrictV21BoundArguments<A>;
  effective_arguments?: StrictV21BoundArguments<A>;
  invoke: (value: A) => Promise<R> | R;
  result_projection?: (value: R) => unknown;
  classify_error?: (error: unknown) => StrictRuntimeFailureClassificationV21;
}

export interface StrictV21CheckpointStore {
  /** Implementations must durably and atomically replace the prior journal entry. */
  save(checkpoint: StrictRuntimeExecutionJournalV21): Promise<void> | void;
}

/** An execution journal entry, not an authenticated recovery checkpoint. */
export interface StrictRuntimeExecutionJournalV21 {
  schema: 'obsvr-strict-runtime-execution-journal-v2-1';
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
  terminal_status?: 'executed' | 'invocation_failed' | 'invocation_uncertain' | 'nonexecuted';
  receipt?: StrictReceiptV21Envelope;
  execution_start?: StrictExecutionStartV21;
  execution_start_hash?: string;
  execution_outcome?: StrictExecutionOutcomeV21Envelope;
}

interface ResultBase {
  receipt: StrictReceiptV21Envelope;
  receipt_hash: string;
  execution_outcome?: StrictExecutionOutcomeV21Envelope;
}

export type StrictRuntimeV21Result<T> =
  | (ResultBase & { status: 'executed'; value: T; admission: StrictAdmissionV21Result })
  | (ResultBase & { status: 'invocation_failed'; error: unknown; admission: StrictAdmissionV21Result })
  | (ResultBase & { status: 'invocation_uncertain'; error: unknown; admission: StrictAdmissionV21Result })
  | (ResultBase & {
      status: 'nonexecuted';
      reason: 'not_authorized' | 'binding_unavailable' | 'execution_state_unavailable'
        | 'checkpoint_persist_failed' | 'definitive_no_store' | 'admission_uncertain';
      admission?: StrictAdmissionV21Result;
      error?: unknown;
    });
