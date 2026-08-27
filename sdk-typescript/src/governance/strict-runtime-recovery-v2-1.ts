import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import {
  signStrictExecutionOutcomeV21,
  strictExecutionStartV21Hash,
  verifyStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Envelope,
  type StrictExecutionStartV21,
} from './strict-execution-outcome-v2-1.js';
import type { DeviceSigner } from '../proxy/device-identity.js';
import type {
  StrictRuntimeExecutionJournalV21,
} from './strict-receipt-runtime-v2-1-types.js';
import type { StrictReceiptV21Envelope } from './strict-receipt-v2-1.js';
import {
  verifyStrictReceiptV21,
  type StrictReceiptV21TrustOptions,
} from './strict-receipt-v2-1-verify.js';

const HEX64 = /^[0-9a-f]{64}$/;
const BASE_KEYS = new Set([
  'schema', 'profile_version', 'phase', 'tenant_id', 'session_id',
  'runtime_action_id', 'operation_fingerprint', 'prepared_token', 'receipt_hash',
  'committed_sequence', 'committed_head_receipt_hash', 'receipt',
]);
const OPTIONAL_KEYS = new Set([
  'terminal_status', 'execution_start', 'execution_start_hash', 'execution_outcome',
]);
const PHASES = new Set([
  'prepared', 'remote_accepted', 'committed', 'invocation_started', 'terminal',
]);
const TERMINAL = new Set([
  'executed', 'invocation_failed', 'invocation_uncertain', 'nonexecuted',
]);

export class StrictRuntimeRecoveryV21Error extends Error {
  constructor(message: string) {
    super(message); this.name = 'StrictRuntimeRecoveryV21Error';
  }
}

type TerminalStatusV21 = 'executed' | 'invocation_failed' | 'invocation_uncertain' | 'nonexecuted';

export type StrictRuntimeRecoveryV21Result =
  | { status: 'pre_invocation'; retry_safe: false; decision_trusted: boolean;
    journal: StrictRuntimeExecutionJournalV21 }
  | { status: 'outcome_unresolved'; retry_safe: false; decision_trusted: boolean;
    journal: StrictRuntimeExecutionJournalV21 }
  | { status: 'resolved'; retry_safe: false;
    terminal_status: TerminalStatusV21;
    decision_trusted: boolean; outcome_integrity_valid?: true; outcome_trusted?: boolean;
    journal: StrictRuntimeExecutionJournalV21 };

export interface StrictInterruptedExecutionFinalizerV21Options {
  completed_at_ms?: number;
  outcome_id?: string;
}

export interface StrictInterruptedExecutionCheckpointStoreV21 {
  save(checkpoint: StrictRuntimeExecutionJournalV21): Promise<void> | void;
}

function fail(message: string): never { throw new StrictRuntimeRecoveryV21Error(message); }
function record(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${field} must be an object`);
  return value as Record<string, unknown>;
}
function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) fail(`${field} must be nonblank`);
  return value;
}
function integer(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    fail(`${field} must be a nonnegative safe integer`);
  }
  return value;
}
function hash(value: unknown, field: string): string {
  if (typeof value !== 'string' || !HEX64.test(value)) fail(`${field} must be a SHA-256 hash`);
  return value;
}
function same(left: unknown, right: unknown): boolean {
  try { return canonicalJsonForHash(left) === canonicalJsonForHash(right); } catch { return false; }
}
function expectedTerminal(status: string): TerminalStatusV21 {
  if (status === 'succeeded') return 'executed';
  if (status === 'failed') return 'invocation_failed';
  if (status === 'uncertain') return 'invocation_uncertain';
  return fail('execution outcome has an unsupported status');
}

function validateStart(
  journal: StrictRuntimeExecutionJournalV21,
  receipt: StrictReceiptV21Envelope,
): StrictExecutionStartV21 {
  const start = record(journal.execution_start, 'execution_start') as unknown as StrictExecutionStartV21;
  const required = ['tenant_id', 'session_id', 'action_id', 'decision_receipt_hash',
    'operation_fingerprint', 'attempt', 'started_at_ms'];
  if (Object.keys(start).sort().join(',') !== required.sort().join(',')) {
    fail('execution_start contains missing or unsupported fields');
  }
  const startHash = hash(journal.execution_start_hash, 'execution_start_hash');
  if (start.tenant_id !== journal.tenant_id || start.session_id !== journal.session_id
    || start.action_id !== journal.runtime_action_id
    || start.decision_receipt_hash !== journal.receipt_hash
    || start.operation_fingerprint !== journal.operation_fingerprint
    || start.attempt !== 1 || start.started_at_ms < receipt.body.timestamp_ms
    || strictExecutionStartV21Hash(start) !== startHash) {
    fail('execution_start does not bind the journal and decision receipt');
  }
  return start;
}

function validateJournal(
  value: unknown,
  trust: StrictReceiptV21TrustOptions,
): { journal: StrictRuntimeExecutionJournalV21; decisionTrusted: boolean } {
  const root = record(value, 'runtime journal');
  if (Object.keys(root).some((key) => !BASE_KEYS.has(key) && !OPTIONAL_KEYS.has(key))
    || [...BASE_KEYS].some((key) => !Object.hasOwn(root, key))) {
    fail('runtime journal contains missing or unsupported fields');
  }
  if (root.schema !== 'obsvr-strict-runtime-execution-journal-v2-1'
    || root.profile_version !== '2.1' || !PHASES.has(root.phase as string)) {
    fail('runtime journal schema, profile, or phase is invalid');
  }
  text(root.tenant_id, 'tenant_id'); text(root.session_id, 'session_id');
  text(root.runtime_action_id, 'runtime_action_id'); text(root.prepared_token, 'prepared_token');
  hash(root.operation_fingerprint, 'operation_fingerprint');
  hash(root.receipt_hash, 'receipt_hash');
  integer(root.committed_sequence, 'committed_sequence');
  if (root.committed_head_receipt_hash !== null) {
    hash(root.committed_head_receipt_hash, 'committed_head_receipt_hash');
  }
  const journal = structuredClone(root) as unknown as StrictRuntimeExecutionJournalV21;
  const receipt = journal.receipt;
  const verification = verifyStrictReceiptV21(receipt, trust);
  if (!verification.integrity_valid
    || (receipt.body.record_type !== 'decision' && receipt.body.record_type !== 'resolution')
    || receipt.body.profile_version !== '2.1' || receipt.receipt_hash !== journal.receipt_hash
    || receipt.body.tenant_id !== journal.tenant_id
    || receipt.body.session_id !== journal.session_id
    || receipt.body.action.action_id !== journal.runtime_action_id) {
    fail('runtime journal does not contain its intact bound execution receipt');
  }
  const current = journal.committed_sequence === receipt.body.sequence
    && journal.committed_head_receipt_hash === receipt.receipt_hash;
  const previous = journal.committed_sequence === receipt.body.sequence - 1
    && journal.committed_head_receipt_hash === receipt.body.previous_receipt_hash;
  if ((journal.phase === 'prepared' || journal.phase === 'remote_accepted') && !previous) {
    fail('pre-commit journal does not continue the prior receipt head');
  }
  if ((journal.phase === 'committed' || journal.phase === 'invocation_started') && !current) {
    fail('committed journal does not match the decision receipt head');
  }
  if (journal.phase !== 'terminal' && journal.terminal_status !== undefined) {
    fail('only terminal journals can contain terminal_status');
  }
  if (journal.phase === 'invocation_started') {
    if (journal.execution_outcome !== undefined) fail('started journal cannot contain an outcome');
    validateStart(journal, receipt);
  } else if (journal.phase !== 'terminal'
    && (journal.execution_start !== undefined || journal.execution_start_hash !== undefined
      || journal.execution_outcome !== undefined)) {
    fail('pre-invocation journal cannot contain execution evidence');
  }
  if (journal.phase === 'terminal') {
    if (!journal.terminal_status || !TERMINAL.has(journal.terminal_status)) {
      fail('terminal journal requires a supported terminal_status');
    }
    if (journal.terminal_status === 'nonexecuted') {
      if (!current && !previous) fail('nonexecuted journal does not match a receipt head');
      if (journal.execution_start !== undefined || journal.execution_start_hash !== undefined
        || journal.execution_outcome !== undefined) {
        fail('nonexecuted journal cannot contain execution evidence');
      }
    } else {
      if (!current || journal.execution_outcome === undefined) {
        fail('executed terminal journal requires committed execution evidence');
      }
      validateStart(journal, receipt);
    }
  }
  return { journal, decisionTrusted: verification.trusted };
}

export function reconcileStrictRuntimeExecutionV21(
  value: unknown,
  outcome?: StrictExecutionOutcomeV21Envelope,
  trust: StrictReceiptV21TrustOptions = {
    trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [],
  },
): StrictRuntimeRecoveryV21Result {
  const validated = validateJournal(value, trust);
  const { journal, decisionTrusted } = validated;
  if (journal.phase === 'prepared' || journal.phase === 'remote_accepted'
    || journal.phase === 'committed') {
    if (outcome !== undefined) fail('pre-invocation journal cannot accept an outcome');
    return { status: 'pre_invocation', retry_safe: false, decision_trusted: decisionTrusted,
      journal };
  }
  if (journal.phase === 'terminal' && journal.terminal_status === 'nonexecuted') {
    if (outcome !== undefined) fail('nonexecuted journal cannot accept an outcome');
    return { status: 'resolved', retry_safe: false, terminal_status: 'nonexecuted',
      decision_trusted: decisionTrusted, journal };
  }
  const candidate = outcome ?? journal.execution_outcome;
  if (candidate === undefined) {
    return { status: 'outcome_unresolved', retry_safe: false,
      decision_trusted: decisionTrusted, journal };
  }
  if (journal.execution_outcome !== undefined && !same(journal.execution_outcome, candidate)) {
    fail('supplied outcome conflicts with the terminal journal');
  }
  const verification = verifyStrictExecutionOutcomeV21(candidate, journal.receipt, trust);
  if (!verification.integrity_valid) fail('execution outcome is not intact or bound to the journal');
  const terminalStatus = expectedTerminal(candidate.body.status);
  if (journal.terminal_status !== undefined && journal.terminal_status !== terminalStatus) {
    fail('execution outcome conflicts with terminal_status');
  }
  const terminal = structuredClone({
    ...journal, phase: 'terminal' as const, terminal_status: terminalStatus,
    execution_outcome: candidate,
  });
  return { status: 'resolved', retry_safe: false, terminal_status: terminalStatus,
    decision_trusted: decisionTrusted, outcome_integrity_valid: true,
    outcome_trusted: verification.trusted, journal: terminal };
}

export async function finalizeInterruptedStrictRuntimeExecutionV21(
  value: unknown,
  signer: DeviceSigner,
  checkpointStore: StrictInterruptedExecutionCheckpointStoreV21,
  options: StrictInterruptedExecutionFinalizerV21Options = {},
  trust: StrictReceiptV21TrustOptions = {
    trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [],
  },
): Promise<Extract<StrictRuntimeRecoveryV21Result, { status: 'resolved' }>> {
  if (!checkpointStore || typeof checkpointStore.save !== 'function') {
    fail('durable checkpoint store is required');
  }
  const recovered = reconcileStrictRuntimeExecutionV21(value, undefined, trust);
  if (recovered.status !== 'outcome_unresolved'
    || recovered.journal.phase !== 'invocation_started'
    || !recovered.journal.execution_start
    || !recovered.journal.execution_start_hash) {
    fail('only an unresolved invocation_started journal can be finalized as interrupted');
  }
  const requestedCompletedAt = options.completed_at_ms ?? Date.now();
  if (!Number.isSafeInteger(requestedCompletedAt) || requestedCompletedAt < 0) {
    fail('completed_at_ms must be a nonnegative safe integer');
  }
  const completedAt = Math.max(
    requestedCompletedAt, recovered.journal.execution_start.started_at_ms,
  );
  const outcomeId = options.outcome_id
    ?? `${recovered.journal.session_id}:${recovered.journal.receipt.body.sequence}:process_interrupted`;
  const outcome = signStrictExecutionOutcomeV21({
    schema: 'obsvr-strict-execution-outcome-v2-1',
    profile_version: '2.1',
    record_type: 'execution_outcome',
    outcome_id: text(outcomeId, 'outcome_id'),
    ...recovered.journal.execution_start,
    decision_sequence: recovered.journal.receipt.body.sequence,
    execution_start_hash: recovered.journal.execution_start_hash,
    completed_at_ms: completedAt,
    status: 'uncertain',
    error_code: 'process_interrupted',
  }, signer, recovered.journal.receipt);
  const terminal = reconcileStrictRuntimeExecutionV21(
    recovered.journal, outcome, trust,
  );
  if (terminal.status !== 'resolved') fail('interrupted outcome did not resolve the journal');
  await checkpointStore.save(terminal.journal);
  return terminal;
}
