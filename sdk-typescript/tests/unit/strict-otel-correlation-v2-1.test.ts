import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';
import {
  _resetOtelMirror,
  _setOtelApi,
  correlateStrictRuntimeCheckpointV21ToOtel,
  withStrictOtelCorrelationV21,
} from '../../src/proxy/otel-mirror.js';
import { signStrictExecutionOutcomeV21 } from '../../src/governance/strict-execution-outcome-v2-1.js';
import { signStrictReceiptV21, type StrictReceiptV21Body } from '../../src/governance/strict-receipt-v2-1.js';
import type { StrictRuntimeExecutionJournalV21 } from '../../src/governance/strict-receipt-runtime-v2-1-types.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const DECISION = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8',
));
const OUTCOME = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_execution_outcomes_v2_1.json'), 'utf8',
));
const ATTRIBUTES = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_otel_attributes_v2_1.json'), 'utf8',
));
const clone = <T>(value: T): T => structuredClone(value);

function journal(phase: 'prepared' | 'committed' | 'terminal'): StrictRuntimeExecutionJournalV21 {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-otel-v21-'));
  const path = join(directory, 'public-test-seed.key');
  writeFileSync(path, DECISION.public_test_key.seed_hex, 'ascii');
  const signer = loadDeviceSigner(path);
  const body = clone(DECISION.vector.body) as StrictReceiptV21Body;
  const patch = OUTCOME.decision_patch;
  Object.assign(body.evaluation, clone(patch.evaluation));
  body.outcome = patch.outcome;
  body.execution_authorized = patch.execution_authorized;
  for (const field of patch.remove) delete (body as unknown as Record<string, unknown>)[field];
  const receipt = signStrictReceiptV21(body, signer);
  const executionOutcome = signStrictExecutionOutcomeV21(
    clone(OUTCOME.vector.body), signer, receipt,
  );
  return {
    schema: 'obsvr-strict-runtime-execution-journal-v2-1', profile_version: '2.1', phase,
    tenant_id: body.tenant_id, session_id: body.session_id,
    runtime_action_id: body.action.action_id, operation_fingerprint: 'f'.repeat(64),
    prepared_token: 'prepared-token', receipt_hash: receipt.receipt_hash, receipt,
    committed_sequence: phase === 'prepared' ? 0 : 1,
    committed_head_receipt_hash: phase === 'prepared' ? null : receipt.receipt_hash,
    ...(phase === 'terminal' ? {
      terminal_status: 'executed' as const, execution_outcome: executionOutcome,
    } : {}),
  };
}

function capture(recording = true, throws = false) {
  const captured: Record<string, unknown>[] = [];
  _setOtelApi({
    trace: {
      getActiveSpan: () => ({
        isRecording: () => recording,
        setAttributes: (attributes) => {
          if (throws) throw new Error('telemetry unavailable');
          captured.push(attributes);
        },
        setStatus: () => undefined, end: () => undefined,
      }),
      getTracer: () => ({
        startSpan: () => ({ setStatus: () => undefined, end: () => undefined }),
      }),
    },
    SpanStatusCode: { OK: 1, ERROR: 2 },
  });
  return captured;
}

afterEach(() => _resetOtelMirror());

it('pins committed and terminal attribute parity without action content', () => {
  const captured = capture();
  expect(correlateStrictRuntimeCheckpointV21ToOtel(journal('prepared'))).toBe(false);
  const committed = journal('committed');
  expect(correlateStrictRuntimeCheckpointV21ToOtel(committed)).toBe(true);
  expect(Object.keys(captured[0]).sort()).toEqual(ATTRIBUTES.committed_attribute_keys);
  expect(captured[0]['obsvr.strict.receipt_hash']).toBe(committed.receipt_hash);
  const terminal = journal('terminal');
  expect(correlateStrictRuntimeCheckpointV21ToOtel(terminal)).toBe(true);
  expect(Object.keys(captured[1]).sort()).toEqual(ATTRIBUTES.terminal_attribute_keys);
  expect(captured[1]['obsvr.strict.execution_outcome_hash'])
    .toBe(terminal.execution_outcome?.outcome_hash);
  expect(JSON.stringify(captured)).not.toMatch(/arguments|target|prompt|content/);
});

it('never correlates a terminal outcome bound to another receipt', () => {
  const captured = capture();
  const terminal = journal('terminal');
  terminal.execution_outcome!.body.decision_receipt_hash = '0'.repeat(64);
  expect(correlateStrictRuntimeCheckpointV21ToOtel(terminal)).toBe(true);
  expect(captured[0]).not.toHaveProperty('obsvr.strict.execution_outcome_hash');
  expect(captured[0]).not.toHaveProperty('obsvr.strict.execution_status');
});

it('saves durably first and never lets telemetry failure alter execution', async () => {
  const events: string[] = [];
  capture(true, true);
  const wrapped = withStrictOtelCorrelationV21({ save: () => { events.push('saved'); } });
  await wrapped.save(journal('terminal'));
  expect(events).toEqual(['saved']);
  const failed = withStrictOtelCorrelationV21({ save: () => { throw new Error('disk'); } });
  await expect(failed.save(journal('terminal'))).rejects.toThrow('disk');
});

it('does nothing when the active span is not recording', () => {
  const captured = capture(false);
  expect(correlateStrictRuntimeCheckpointV21ToOtel(journal('terminal'))).toBe(false);
  expect(captured).toEqual([]);
});
