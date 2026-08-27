import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  signStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Body,
} from '../../src/governance/strict-execution-outcome-v2-1.js';
import {
  STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA,
  STRICT_EXECUTION_OUTCOME_V21_ENDPOINT,
  STRICT_EXECUTION_OUTCOME_V21_INGEST_SCHEMA,
  StrictExecutionOutcomeV21TransportError,
  submitStrictExecutionOutcomeV21,
  submitStrictRuntimeTerminalJournalV21,
} from '../../src/governance/strict-execution-outcome-transport-v2-1.js';
import { signStrictReceiptV21, type StrictReceiptV21Body } from
  '../../src/governance/strict-receipt-v2-1.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const DECISION = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8',
));
const OUTCOME = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_execution_outcomes_v2_1.json'), 'utf8',
));
const bytes = (value: unknown): Uint8Array => Buffer.from(JSON.stringify(value));

function subject() {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-outcome-transport-v21-'));
  const path = join(directory, 'seed.key');
  writeFileSync(path, DECISION.public_test_key.seed_hex, 'ascii');
  const signer = loadDeviceSigner(path);
  const body = structuredClone(DECISION.vector.body) as StrictReceiptV21Body;
  body.evaluation = { ...body.evaluation, ...structuredClone(OUTCOME.decision_patch.evaluation) };
  body.outcome = 'ALLOW'; body.execution_authorized = true;
  for (const field of OUTCOME.decision_patch.remove) {
    delete (body as unknown as Record<string, unknown>)[field];
  }
  const decision = signStrictReceiptV21(body, signer);
  const outcome = signStrictExecutionOutcomeV21(
    structuredClone(OUTCOME.vector.body) as StrictExecutionOutcomeV21Body,
    signer,
    decision,
  );
  const trust = {
    trusted_agent_keys: [{
      tenant_id: 'tenant-21', agent_ref_hash: 'b'.repeat(64),
      key_id: DECISION.public_test_key.key_id,
      public_key_b64: DECISION.public_test_key.public_key_b64, status: 'active' as const,
    }],
    allowed_evaluator_manifest_hashes: [DECISION.evaluator_manifest_hash],
  };
  return { decision, outcome, trust };
}

function response(
  hash: string,
  status: 'accepted' | 'already_accepted' = 'accepted',
) {
  return bytes({ schema: STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA, ok: true,
    status, outcome_hash: hash, accepted_at_ms: 10 });
}

function options(transport: NonNullable<Parameters<
  typeof submitStrictExecutionOutcomeV21
>[2]['trusted_pinned_transport']>) {
  return { ingest_url: 'https://example.com/base/', api_key: 'key', max_attempts: 1,
    resolver: async () => ['8.8.8.8'], trusted_pinned_transport: transport };
}

describe('strict execution outcome transport v2.1', () => {
  test('submits the exact wrapper through a DNS-pinned target', async () => {
    const value = subject(); let captured: any;
    const result = await submitStrictExecutionOutcomeV21(
      value.outcome,
      value.decision,
      options(async (target, body, headers) => {
        captured = { target, body: JSON.parse(body), headers };
        return { status: 201, body: response(value.outcome.outcome_hash) };
      }),
      value.trust,
    );
    expect(captured.target.url.pathname).toBe(`/base${STRICT_EXECUTION_OUTCOME_V21_ENDPOINT}`);
    expect(captured.target.addresses).toEqual([{ address: '8.8.8.8', family: 4 }]);
    expect(captured.headers).toMatchObject({
      'Idempotency-Key': value.outcome.outcome_hash, 'X-API-Key': 'key',
    });
    expect(captured.body).toEqual({
      schema: STRICT_EXECUTION_OUTCOME_V21_INGEST_SCHEMA,
      tenant_id: value.outcome.body.tenant_id,
      session_id: value.outcome.body.session_id,
      outcome: value.outcome,
    });
    expect(result).toMatchObject({ disposition: 'accepted', status: 'accepted', attempts: 1 });
  });

  test('accepts an exact idempotent replay response', async () => {
    const value = subject();
    const result = await submitStrictExecutionOutcomeV21(
      value.outcome,
      value.decision,
      options(async () => ({ status: 200,
        body: response(value.outcome.outcome_hash, 'already_accepted') })),
      value.trust,
    );
    expect(result).toMatchObject({ disposition: 'accepted', status: 'already_accepted' });
  });

  test.each([400, 401, 403, 413] as const)(
    'recognizes exact %s definitive rejection without altering execution state', async (status) => {
      const value = subject();
      const result = await submitStrictExecutionOutcomeV21(
        value.outcome,
        value.decision,
        options(async () => ({ status, body: bytes({
          schema: STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA, ok: false,
          status: 'rejected', code: 'rejected', outcome_hash: value.outcome.outcome_hash,
        }) })),
        value.trust,
      );
      expect(result).toMatchObject({ disposition: 'definitive_no_store', http_status: status });
    },
  );

  test('keeps conflict, redirect, malformed success, and transport exhaustion uncertain', async () => {
    const value = subject();
    const conflict = await submitStrictExecutionOutcomeV21(
      value.outcome, value.decision, options(async () => ({ status: 409, body: bytes({
        schema: STRICT_EXECUTION_OUTCOME_V21_ADMISSION_SCHEMA, ok: false,
        status: 'conflict', code: 'decision_outcome_conflict',
        outcome_hash: value.outcome.outcome_hash,
      }) })), value.trust,
    );
    const redirect = await submitStrictExecutionOutcomeV21(
      value.outcome, value.decision,
      options(async () => ({ status: 302, body: new Uint8Array() })), value.trust,
    );
    const malformed = await submitStrictExecutionOutcomeV21(
      value.outcome, value.decision,
      options(async () => ({ status: 200, body: bytes({ ok: true }) })), value.trust,
    );
    const exhausted = await submitStrictExecutionOutcomeV21(
      value.outcome, value.decision,
      options(async () => { throw new Error('offline'); }), value.trust,
    );
    expect(conflict).toMatchObject({ disposition: 'uncertain', reason: 'conflict' });
    expect(redirect).toMatchObject({ disposition: 'uncertain', reason: 'redirect' });
    expect(malformed).toMatchObject({ disposition: 'uncertain', reason: 'invalid_response' });
    expect(exhausted).toMatchObject({ disposition: 'uncertain', reason: 'retry_exhausted' });
  });

  test('rejects tampered evidence and mixed-address DNS before connecting', async () => {
    const value = subject(); const tampered: any = structuredClone(value.outcome);
    tampered.body.completed_at_ms += 1;
    await expect(submitStrictExecutionOutcomeV21(
      tampered, value.decision, options(async () => ({ status: 201, body: response('x') })),
      value.trust,
    )).rejects.toThrow(StrictExecutionOutcomeV21TransportError);
    let calls = 0;
    const result = await submitStrictExecutionOutcomeV21(
      value.outcome, value.decision, {
        ...options(async () => { calls += 1; throw new Error('must not connect'); }),
        resolver: async () => ['8.8.8.8', '127.0.0.1'],
      }, value.trust,
    );
    expect(calls).toBe(0);
    expect(result).toMatchObject({ disposition: 'uncertain', reason: 'retry_exhausted' });
  });

  test('submits an exact terminal journal but refuses unresolved state', async () => {
    const value = subject();
    const start = {
      tenant_id: value.outcome.body.tenant_id, session_id: value.outcome.body.session_id,
      action_id: value.outcome.body.action_id,
      decision_receipt_hash: value.outcome.body.decision_receipt_hash,
      operation_fingerprint: value.outcome.body.operation_fingerprint,
      attempt: 1 as const, started_at_ms: value.outcome.body.started_at_ms,
    };
    const base = {
      schema: 'obsvr-strict-runtime-execution-journal-v2-1' as const,
      profile_version: '2.1' as const,
      tenant_id: value.decision.body.tenant_id, session_id: value.decision.body.session_id,
      runtime_action_id: value.decision.body.action.action_id,
      operation_fingerprint: value.outcome.body.operation_fingerprint,
      prepared_token: 'prepared', receipt_hash: value.decision.receipt_hash,
      committed_sequence: value.decision.body.sequence,
      committed_head_receipt_hash: value.decision.receipt_hash,
      receipt: value.decision, execution_start: start,
      execution_start_hash: value.outcome.body.execution_start_hash,
    };
    await expect(submitStrictRuntimeTerminalJournalV21(
      { ...base, phase: 'invocation_started' },
      options(async () => ({ status: 201, body: response(value.outcome.outcome_hash) })),
      value.trust,
    )).rejects.toThrow('does not contain a signed terminal execution outcome');
    const result = await submitStrictRuntimeTerminalJournalV21(
      { ...base, phase: 'terminal', terminal_status: 'executed',
        execution_outcome: value.outcome },
      options(async () => ({ status: 201, body: response(value.outcome.outcome_hash) })),
      value.trust,
    );
    expect(result).toMatchObject({ disposition: 'accepted' });
  });
});
