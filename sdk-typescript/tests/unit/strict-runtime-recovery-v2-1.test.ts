import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  signStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Body,
} from '../../src/governance/strict-execution-outcome-v2-1.js';
import {
  finalizeInterruptedStrictRuntimeExecutionV21,
  reconcileStrictRuntimeExecutionV21,
  StrictRuntimeRecoveryV21Error,
} from '../../src/governance/strict-runtime-recovery-v2-1.js';
import {
  signStrictReceiptV21,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
} from '../../src/governance/strict-receipt-v2-1.js';
import type { StrictReceiptV21TrustOptions } from '../../src/governance/strict-receipt-v2-1-verify.js';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const DECISION = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8',
));
const OUTCOME = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_execution_outcomes_v2_1.json'), 'utf8',
));
const clone = <T>(value: T): T => structuredClone(value);

function signer(): DeviceSigner {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-runtime-recovery-v21-'));
  const path = join(directory, 'public-test-seed.key');
  writeFileSync(path, DECISION.public_test_key.seed_hex, 'ascii');
  return loadDeviceSigner(path);
}

function receipt(device: DeviceSigner): StrictReceiptV21Envelope {
  const body = clone(DECISION.vector.body) as StrictReceiptV21Body;
  const patch = OUTCOME.decision_patch;
  body.evaluation.requested_outcome = patch.evaluation.requested_outcome;
  body.evaluation.outcome = patch.evaluation.outcome;
  body.evaluation.decision_reason_codes = clone(patch.evaluation.decision_reason_codes);
  body.outcome = patch.outcome;
  body.execution_authorized = patch.execution_authorized;
  for (const field of patch.remove) delete (body as unknown as Record<string, unknown>)[field];
  return signStrictReceiptV21(body, device);
}

function trust(): StrictReceiptV21TrustOptions {
  return {
    trusted_agent_keys: [{
      tenant_id: 'tenant-21', agent_ref_hash: 'b'.repeat(64),
      key_id: DECISION.public_test_key.key_id,
      public_key_b64: DECISION.public_test_key.public_key_b64, status: 'active',
    }],
    allowed_evaluator_manifest_hashes: [DECISION.evaluator_manifest_hash],
  };
}

function journal(phase: 'committed' | 'invocation_started' = 'invocation_started') {
  const device = signer(); const decision = receipt(device);
  const body = clone(OUTCOME.vector.body) as StrictExecutionOutcomeV21Body;
  const start = {
    tenant_id: body.tenant_id, session_id: body.session_id, action_id: body.action_id,
    decision_receipt_hash: body.decision_receipt_hash,
    operation_fingerprint: body.operation_fingerprint,
    attempt: body.attempt, started_at_ms: body.started_at_ms,
  };
  return {
    device, decision, body,
    value: {
      schema: 'obsvr-strict-runtime-execution-journal-v2-1',
      profile_version: '2.1', phase,
      tenant_id: decision.body.tenant_id, session_id: decision.body.session_id,
      runtime_action_id: decision.body.action.action_id,
      operation_fingerprint: body.operation_fingerprint,
      prepared_token: 'prepared-public', receipt_hash: decision.receipt_hash,
      committed_sequence: decision.body.sequence,
      committed_head_receipt_hash: decision.receipt_hash,
      receipt: decision,
      ...(phase === 'invocation_started'
        ? { execution_start: start, execution_start_hash: body.execution_start_hash }
        : {}),
    },
  };
}

describe('strict runtime recovery v2.1', () => {
  test('never treats a started action without a terminal outcome as retry-safe', () => {
    const subject = journal();
    expect(reconcileStrictRuntimeExecutionV21(subject.value, undefined, trust()))
      .toMatchObject({ status: 'outcome_unresolved', retry_safe: false,
        decision_trusted: true, journal: { phase: 'invocation_started' } });
  });

  test('accepts only a signed outcome bound to the durable start and receipt', () => {
    const subject = journal();
    const outcome = signStrictExecutionOutcomeV21(subject.body, subject.device, subject.decision);
    const resolved = reconcileStrictRuntimeExecutionV21(subject.value, outcome, trust());
    expect(resolved).toMatchObject({
      status: 'resolved', retry_safe: false, terminal_status: 'executed',
      decision_trusted: true, outcome_integrity_valid: true, outcome_trusted: true,
      journal: { phase: 'terminal', terminal_status: 'executed',
        execution_outcome: outcome },
    });
    expect(reconcileStrictRuntimeExecutionV21(resolved.journal, undefined, trust()))
      .toMatchObject({ status: 'resolved', terminal_status: 'executed' });
  });

  test('keeps pre-invocation state non-retryable until receipt reconciliation', () => {
    const subject = journal('committed');
    expect(reconcileStrictRuntimeExecutionV21(subject.value, undefined, trust()))
      .toMatchObject({ status: 'pre_invocation', retry_safe: false,
        decision_trusted: true, journal: { receipt: subject.decision } });
  });

  test.each(['receipt', 'start', 'outcome'])(
    'rejects tampered %s evidence instead of resolving execution', (field) => {
      const subject = journal();
      const outcome = signStrictExecutionOutcomeV21(subject.body, subject.device, subject.decision);
      const changed: any = clone(subject.value);
      let supplied: any = outcome;
      if (field === 'receipt') changed.receipt.body.sequence += 1;
      if (field === 'start') changed.execution_start.started_at_ms += 1;
      if (field === 'outcome') {
        supplied = clone(outcome); supplied.body.result_hash = '7'.repeat(64);
      }
      expect(() => reconcileStrictRuntimeExecutionV21(changed, supplied, trust()))
        .toThrow(StrictRuntimeRecoveryV21Error);
    },
  );

  test('persists a signed uncertain outcome for an interrupted process', async () => {
    const subject = journal(); const saved: unknown[] = [];
    const resolved = await finalizeInterruptedStrictRuntimeExecutionV21(
      subject.value,
      subject.device,
      { save: (checkpoint) => { saved.push(structuredClone(checkpoint)); } },
      { completed_at_ms: subject.body.started_at_ms + 500 },
      trust(),
    );
    expect(resolved).toMatchObject({
      status: 'resolved', terminal_status: 'invocation_uncertain', retry_safe: false,
      journal: {
        phase: 'terminal', terminal_status: 'invocation_uncertain',
        execution_outcome: { body: {
          status: 'uncertain', error_code: 'process_interrupted',
          completed_at_ms: subject.body.started_at_ms + 500,
        } },
      },
    });
    expect(saved).toEqual([resolved.journal]);
  });

  test('does not report interruption finalization when durable persistence fails', async () => {
    const subject = journal();
    await expect(finalizeInterruptedStrictRuntimeExecutionV21(
      subject.value,
      subject.device,
      { save: () => { throw new Error('disk full'); } },
      { completed_at_ms: subject.body.started_at_ms + 500 },
      trust(),
    )).rejects.toThrow('disk full');
    const terminal = reconcileStrictRuntimeExecutionV21(subject.value, undefined, trust());
    expect(terminal).toMatchObject({ status: 'outcome_unresolved', retry_safe: false });
  });

  test('refuses to relabel committed or terminal work as process-interrupted', async () => {
    const committed = journal('committed');
    await expect(finalizeInterruptedStrictRuntimeExecutionV21(
      committed.value, committed.device, { save: () => undefined }, {}, trust(),
    )).rejects.toThrow('only an unresolved invocation_started journal');
    const started = journal();
    const outcome = signStrictExecutionOutcomeV21(started.body, started.device, started.decision);
    const terminal = reconcileStrictRuntimeExecutionV21(started.value, outcome, trust());
    await expect(finalizeInterruptedStrictRuntimeExecutionV21(
      terminal.journal, started.device, { save: () => undefined }, {}, trust(),
    )).rejects.toThrow('only an unresolved invocation_started journal');
  });
});
