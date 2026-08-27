import { jest } from '@jest/globals';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GoogleGenAI } from '@google/genai';
import OpenAI from 'openai';
import { actionTargetHash } from '../../src/governance/action-context-v2.js';
import { STRICT_RECEIPT_V21_ADMISSION_SCHEMA } from '../../src/governance/strict-admission-v2-1.js';
import {
  createTrustedEvaluationEvidenceProviderV21,
} from '../../src/governance/strict-evaluation-evidence-v2-1.js';
import {
  createStrictIdentityEvidenceV21Authority,
} from '../../src/governance/strict-identity-evidence-v2-1.js';
import {
  StrictReceiptCoordinatorV21, createTrustedIntentDecisionProviderV21,
} from '../../src/governance/strict-receipt-coordinator-v2-1.js';
import {
  createStrictProviderBoundaryV21,
  ObsvrStrictProviderBoundaryV21Error,
  strictProviderTargetV21,
} from '../../src/governance/strict-provider-boundary-v2-1.js';
import {
  StrictReceiptRuntimeV21, type StrictRuntimeExecutionJournalV21,
} from '../../src/governance/strict-receipt-runtime-v2-1.js';
import { strictReceiptV21KeyId } from '../../src/governance/strict-receipt-v2-1.js';
import { intentPolicyV2Hash, type IntentV2BaseResult } from '../../src/policy/intent-alignment-v2.js';
import { _reset, init } from '../../src/proxy/config.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget.js';
import { wrap } from '../../src/proxy/wrapper.js';

const B = 'b'.repeat(64);

class FakeOpenAI {
  baseURL = 'https://api.openai.com/v1';
  readonly calls: unknown[][] = [];
  readonly chat: { completions: { create: (...args: any[]) => Promise<any> } };
  constructor() {
    this.chat = { completions: { create: async (...args: unknown[]) => {
        this.calls.push(structuredClone(args));
        return { choices: [{ message: { content: 'ok' } }] };
      } } };
  }
}

function signer() {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-boundary-v21-')), 'seed.key');
  writeFileSync(path, '00'.repeat(32), 'ascii');
  return loadDeviceSigner(path);
}

function accepted(hash: string): Uint8Array {
  return Buffer.from(JSON.stringify({ schema: STRICT_RECEIPT_V21_ADMISSION_SCHEMA,
    ok: true, status: 'accepted', receipt_hash: hash, accepted_at_ms: 10 }));
}

function capability(
  target = 'https://api.openai.com/v1',
  base: IntentV2BaseResult = { action_taken: 'allowed' },
  beforeAccepted?: () => void,
) {
  const device = signer(); let now = 1_000; let token = 0;
  const policy = { schema: 'obsvr-intent-policy-v2' as const, profile_version: '2.0' as const,
    intent_scopes: [{ intent_id: 'serve',
      allowed_actions: [{ kind: 'model_call' as const, name: 'chat.completions.create' }],
      allowed_targets: [target], allowed_requested_scopes: ['model:invoke'],
      allowed_data_classifications: [] }] };
  const contexts: any[] = [];
  const checkpoints: StrictRuntimeExecutionJournalV21[] = [];
  const coordinator = new StrictReceiptCoordinatorV21({
    signer: device, policy, tenant_id: 'tenant-1', session_id: 'session-1',
    sdk_language: 'typescript', clock: () => now++, defer_ttl_ms: 500,
    identity_authority: createStrictIdentityEvidenceV21Authority(),
    identity_snapshot: (timestamp) => ({ schema: 'obsvr-strict-identity-evidence-v2-1',
      profile_version: '2.1', relationship: 'direct', receipt_time_ms: timestamp,
      requester: { requester_ref_hash: B, principal_type: 'agent', role_ids: ['worker'],
        privilege_scopes: ['model:invoke'] }, initiator: { agent_ref_hash: B,
        key_id: strictReceiptV21KeyId(device.rawPublicKey), role_ids: ['worker'],
        privilege_scopes: ['model:invoke'] }, delegation_chain: [] }),
    intent_decision_provider: createTrustedIntentDecisionProviderV21((context) => {
      contexts.push(structuredClone(context));
      return structuredClone(base);
    }),
    evaluation_evidence_provider: createTrustedEvaluationEvidenceProviderV21(() => ({
      effective_policy: { version: 'policy-1', artifact_hash: intentPolicyV2Hash(policy),
        matched_rule_ids: ['serve'] }, detector_requirements: [], detector_results: [],
    })), pid: () => 7, prepared_token_factory: () => `prepared-${++token}`,
  });
  const runtime = new StrictReceiptRuntimeV21(coordinator, {
    ingest_url: 'https://example.com', api_key: 'test', max_attempts: 1,
    resolver: async () => ['8.8.8.8'],
    trusted_pinned_transport: async (_target, _body, headers) => {
      beforeAccepted?.();
      return { status: 200, body: accepted(headers['Idempotency-Key']) };
    },
  }, { save: (checkpoint) => { checkpoints.push(structuredClone(checkpoint)); } });
  return { runtime, contexts, checkpoints, value: createStrictProviderBoundaryV21({
    runtime,
    context: () => ({ active_intents: ['serve'], requested_scopes: ['model:invoke'],
      run_id: 'run-1', thread_id: 'thread-1' }),
  }) };
}

describe('strict provider boundary v2.1', () => {
  beforeEach(() => { _reset(); _resetSender(); init({ api_key: 'test', sample_rate: 0 }); });
  afterEach(() => { _resetSender(); _reset(); });

  test('admits the exact cleaned invocation before one provider call', async () => {
    const strict = capability(); const raw = new FakeOpenAI();
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    const response = await client.chat.completions.create({ model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'hello' }], request_id: 'audit-only' });
    expect(response).toEqual({ choices: [{ message: { content: 'ok' } }] });
    expect(raw.calls).toEqual([[{ model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'hello' }] }]]);
    const receipt = strict.checkpoints[0].receipt as any;
    expect(strict.contexts[0].action).toMatchObject({ kind: 'model_call',
      name: 'chat.completions.create',
      target_hash: actionTargetHash('https://api.openai.com/v1'),
      data_classifications: [], requested_scopes: ['model:invoke'] });
    expect(receipt.body.action.action_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(receipt.body.action.action_id).not.toBe('audit-only');
  });

  test('re-resolves endpoint at call time and gives identical calls distinct action ids', async () => {
    const raw = new FakeOpenAI(); raw.baseURL = 'https://api.groq.com/openai/v1';
    const strict = capability(raw.baseURL);
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await client.chat.completions.create({ model: 'm', messages: [] });
    await client.chat.completions.create({ model: 'm', messages: [] });
    const receipts = strict.checkpoints.filter((item) => item.phase === 'prepared')
      .map((item) => item.receipt as any);
    expect(receipts[0].body.action.target_hash)
      .toBe(actionTargetHash('https://api.groq.com/openai/v1'));
    expect(receipts[0].body.action.action_id).not.toBe(receipts[1].body.action.action_id);
  });

  test('denial, legacy block, and streaming never contact the provider', async () => {
    const denied = capability(undefined, { action_taken: 'blocked' }); const raw = new FakeOpenAI();
    const client = wrap(raw, { strict_receipt_v2_1: denied.value });
    await expect(client.chat.completions.create({ model: 'm', messages: [] }))
      .rejects.toMatchObject({ code: 'not_authorized', receipt_hash: expect.stringMatching(/^[0-9a-f]{64}$/) });
    await expect(client.chat.completions.create({ model: 'm', messages: [], stream: true }))
      .rejects.toMatchObject({ code: 'unsupported_surface' });
    expect(raw.calls).toHaveLength(0);

    _reset(); init({ api_key: 'test', sample_rate: 0,
      pii_policy: { rules: { ssn: 'block' } } });
    const blockedStrict = capability(); const blockedRaw = new FakeOpenAI();
    const blocked = wrap(blockedRaw, { strict_receipt_v2_1: blockedStrict.value });
    await expect(blocked.chat.completions.create({ model: 'm',
      messages: [{ role: 'user', content: '123-45-6789' }] })).rejects.toThrow();
    expect(blockedRaw.calls).toHaveLength(0); expect(blockedStrict.checkpoints).toHaveLength(0);
  });

  test('rejects forged capability and preserves the original provider exception', async () => {
    const raw = new FakeOpenAI();
    expect(() => wrap(raw, { strict_receipt_v2_1: { profile_version: '2.1' } as any }))
      .toThrow(ObsvrStrictProviderBoundaryV21Error);
    const strict = capability(); const failure = new Error('provider failed');
    raw.chat.completions.create = jest.fn(async () => { throw failure; });
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await expect(client.chat.completions.create({ model: 'm', messages: [] }))
      .rejects.toBe(failure);
  });

  test('marks ambiguous provider transport failures as uncertain', async () => {
    const raw = new FakeOpenAI();
    const failure = Object.assign(new Error('timed out after send'), { code: 'ETIMEDOUT' });
    raw.chat.completions.create = jest.fn(async () => { throw failure; });
    const strict = capability();
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await expect(client.chat.completions.create({ model: 'm', messages: [] }))
      .rejects.toMatchObject({ code: 'admission_not_confirmed' });
    expect(strict.checkpoints.at(-1)).toMatchObject({
      terminal_status: 'invocation_uncertain',
      execution_outcome: { body: {
        status: 'uncertain', error_code: 'provider_transport_ambiguous',
      } },
    });
  });

  test('rejects an unbranded runtime', () => {
    expect(() => createStrictProviderBoundaryV21({
      runtime: { runDecision: jest.fn() } as unknown as StrictReceiptRuntimeV21,
      context: () => ({ active_intents: ['serve'], requested_scopes: [], run_id: 'run' }),
    })).toThrow(expect.objectContaining({ code: 'runtime_unavailable' }));
  });

  test('fails closed when the endpoint changes after admission', async () => {
    const raw = new FakeOpenAI();
    const strict = capability(raw.baseURL, { action_taken: 'allowed' },
      () => { raw.baseURL = 'https://api.openai.com/v2'; });
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await expect(client.chat.completions.create({ model: 'm', messages: [] }))
      .rejects.toMatchObject({ code: 'context_unavailable' });
    expect(raw.calls).toHaveLength(0);
  });

  test.each([
    'http://api.openai.com/v1',
    'https://user:secret@api.openai.com/v1',
    'https://api.openai.com/v1?key=secret',
    'https://api.openai.com/v1#fragment',
    'https://169.254.169.254/latest/meta-data',
    'https://10.0.0.5/v1',
    'https://example.com/v1',
    'https://api.openai.com/v1/../evil',
    'https://api.openai.com/v1/%2e%2e/evil',
  ])('rejects an unsafe endpoint without contacting the provider: %s', async (baseURL) => {
    const raw = new FakeOpenAI(); raw.baseURL = baseURL;
    const strict = capability();
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await expect(client.chat.completions.create({ model: 'm', messages: [] }))
      .rejects.toMatchObject({ code: 'context_unavailable' });
    expect(strict.checkpoints).toHaveLength(0); expect(raw.calls).toHaveLength(0);
  });

  test('rejects unreadable endpoints and every unlisted callable surface', async () => {
    const strict = capability(); const raw: any = new FakeOpenAI();
    raw.embeddings = { create: jest.fn() };
    raw.unknown = { nested: { execute: jest.fn() } };
    raw.withOptions = jest.fn();
    Object.defineProperty(raw, 'baseURL', { get: () => { throw new Error('hidden'); } });
    const client: any = wrap(raw, { strict_receipt_v2_1: strict.value });
    await expect(client.chat.completions.create({ model: 'm', messages: [] }))
      .rejects.toMatchObject({ code: 'context_unavailable' });
    expect(() => client.embeddings.create({ input: 'x' })).toThrow(
      expect.objectContaining({ code: 'unsupported_surface' }),
    );
    expect(() => client.unknown.nested.execute()).toThrow(
      expect.objectContaining({ code: 'unsupported_surface' }),
    );
    expect(() => client.withOptions()).toThrow(
      expect.objectContaining({ code: 'unsupported_surface' }),
    );
    expect(raw.embeddings.create).not.toHaveBeenCalled();
    expect(raw.unknown.nested.execute).not.toHaveBeenCalled();
    expect(raw.withOptions).not.toHaveBeenCalled();
  });

  test('rejects non-JSON invocation data without leaking it or contacting the provider', async () => {
    const strict = capability(); const raw = new FakeOpenAI();
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await expect(client.chat.completions.create({
      model: 'm', messages: [], secret_callback: () => 'never serialize me',
    })).rejects.toMatchObject({
      code: 'context_unavailable',
      message: 'obsvr strict provider boundary: context_unavailable',
    });
    expect(strict.checkpoints).toHaveLength(0); expect(raw.calls).toHaveLength(0);
  });

  test('resolves current OpenAI and Gemini client endpoints without network access', () => {
    expect(strictProviderTargetV21(new OpenAI({ apiKey: 'test' })))
      .toBe('https://api.openai.com/v1');
    expect(strictProviderTargetV21({ baseURL: 'https://api.openai.com/v1/' }))
      .toBe('https://api.openai.com/v1');
    expect(strictProviderTargetV21({ baseURL: 'https://API.OPENAI.COM:443/v1///' }))
      .toBe('https://api.openai.com/v1');
    expect(strictProviderTargetV21({ baseURL: 'https://api.anthropic.com/' }))
      .toBe('https://api.anthropic.com/');
    expect(strictProviderTargetV21({ baseURL: 'https://api.groq.com/openai/v1' }))
      .toBe('https://api.groq.com/openai/v1');
    expect(strictProviderTargetV21(new GoogleGenAI({ apiKey: 'test' })))
      .toBe('https://generativelanguage.googleapis.com/');
  });

  test('does not allow callers to replace the trusted runtime runner', async () => {
    const strict = capability(); const raw = new FakeOpenAI();
    expect(() => { (strict.runtime as any).runDecision = jest.fn(); }).toThrow(TypeError);
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await client.chat.completions.create({ model: 'm', messages: [] });
    expect(raw.calls).toHaveLength(1);
    expect(strict.checkpoints.map((item) => item.phase)).toEqual([
      'prepared', 'remote_accepted', 'committed', 'invocation_started', 'terminal',
    ]);
  });

  test('freezes public and downstream runtime prototype methods', async () => {
    const replacement = jest.fn(async () => ({ status: 'executed', value: 'bypass' }));
    expect(() => { StrictReceiptRuntimeV21.prototype.runDecision = replacement as any; })
      .toThrow(TypeError);
    expect(() => {
      (StrictReceiptRuntimeV21.prototype as any).runExclusive = replacement;
    }).toThrow(TypeError);
    const strict = capability();
    const raw = new FakeOpenAI();
    const client = wrap(raw, { strict_receipt_v2_1: strict.value });
    await client.chat.completions.create({ model: 'm', messages: [] });
    expect(replacement).not.toHaveBeenCalled();
    expect(raw.calls).toHaveLength(1);
    expect(strict.checkpoints).toHaveLength(5);
  });

  test('disabled mode and unsupported beta methods fail closed', async () => {
    const strict = capability(); const raw: any = new FakeOpenAI();
    raw.beta = { chat: { completions: { create: jest.fn() } } };
    _reset(); init({ api_key: 'test', disabled: true });
    expect(() => wrap(raw, { strict_receipt_v2_1: strict.value }))
      .toThrow(ObsvrStrictProviderBoundaryV21Error);
    _reset(); init({ api_key: 'test', sample_rate: 0 });
    const client: any = wrap(raw, { strict_receipt_v2_1: strict.value });
    expect(() => client.beta.chat.completions.create({})).toThrow();
    expect(raw.beta.chat.completions.create).not.toHaveBeenCalled();
  });
});
