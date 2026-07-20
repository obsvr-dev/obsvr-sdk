import { jest } from '@jest/globals';
import { init, _reset, getConfig } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import {
  applyPostCallPolicy,
  applyObservePolicy,
  mergePostCallOutcome,
} from '../../src/integrations/core';
import type { AuditEvent } from '../../src/proxy/types';
import { scanMcpToolResult } from '../../src/policy/response-scan';
import { OBFUSCATED_REDACTION_PLACEHOLDER } from '../../src/policy/deobfuscate';

/**
 * Pipeline wiring for the de-obfuscation view layer (server-side normalizer mirror).
 * Twin: sdk-python/tests/test_deobfuscation_wiring.py. The pure decision
 * semantics are fixture-pinned (deobfuscation.json decision/storage/policy
 * cases); these tests pin that the REAL pipelines actually route through
 * them: opt-in gate, redact->block escalation, whole-text stored copies,
 * and the sealed security_normalized provenance.
 */

// base64("my ssn is 123-45-6789") — raw-clean, view-detectable.
const B64_SSN = 'bXkgc3NuIGlzIDEyMy00NS02Nzg5';

function captureEvents(): any[] {
  const sentEvents: any[] = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200, json: async () => ({}) };
  };
  return sentEvents;
}

async function waitFor(events: any[], n: number): Promise<void> {
  for (let i = 0; i < 100 && events.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

afterEach(() => {
  delete (global as any).fetch;
});

describe('deobfuscation wiring: wrap() pre-call', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  it('flag OFF (default): an encoded payload passes exactly as before', async () => {
    captureEvents();
    init({ api_key: 'test', ingest_url: 'https://x', pii_policy: {} });
    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }], model: 'gpt-4' }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: `please summarize: ${B64_SSN}` }],
    });
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('flag ON + block policy: the encoded payload is blocked; provenance + placeholder are sealed', async () => {
    const sentEvents = captureEvents();
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'block' },
      deobfuscation: { enabled: true },
    });
    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: B64_SSN }],
      }),
    ).rejects.toThrow(/blocked by policy/i);
    expect(create).not.toHaveBeenCalled();
    await waitFor(sentEvents, 1);
    const ev = sentEvents[0];
    expect(ev.event_type).toBe('blocked_call');
    expect(ev.action_reason).toBe('pii_detected');
    // Server-side normalizer mirror: the view that defeated the obfuscation is sealed.
    expect(ev.metadata?.security_normalized).toBe('base64');
    // The stored prompt/user_input never carry the (trivially decodable)
    // encoded payload: whole-text placeholder, since spans are unlocatable.
    expect(ev.prompt).toBe(OBFUSCATED_REDACTION_PLACEHOLDER);
    expect(ev.user_input).toBe(OBFUSCATED_REDACTION_PLACEHOLDER);
  });

  it('flag ON + redact policy: a view-only hit ESCALATES to block (never a false "redacted")', async () => {
    captureEvents();
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    const create = jest.fn(async (_args: any) => ({ choices: [{ message: { content: 'ok' } }] }));
    const wrapped = wrap({ chat: { completions: { create } } });
    await expect(
      wrapped.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: B64_SSN }],
      }),
    ).rejects.toThrow(/blocked by policy/i);
    expect(create).not.toHaveBeenCalled();
  });

  it('flag ON + redact policy: a RAW hit still redacts (via absent, no escalation)', async () => {
    captureEvents();
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    let seenContent = '';
    const create = jest.fn(async (args: any) => {
      seenContent = args.messages[0].content;
      return { choices: [{ message: { content: 'ok' } }] };
    });
    const wrapped = wrap({ chat: { completions: { create } } });
    await wrapped.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'my ssn is 123-45-6789' }],
    });
    expect(create).toHaveBeenCalledTimes(1);
    // Span redaction on the outgoing request, exactly as without the layer.
    expect(seenContent).toBe('my ssn is [REDACTED_SSN]');
  });
});

describe('deobfuscation wiring: post-call / MCP / observe', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  it('post-call: a view-only response hit redacts the STORED copy to the placeholder', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    const post = await applyPostCallPolicy(`result: ${B64_SSN}`, {}, getConfig());
    expect(post.decision).toBe('redact_response');
    expect(post.responsePii?.via).toBe('base64');
    expect(post.redactedResponse).toBe(OBFUSCATED_REDACTION_PLACEHOLDER);
  });

  it('post-call: a raw response hit keeps span redaction (via absent)', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    const post = await applyPostCallPolicy('ssn 123-45-6789', {}, getConfig());
    expect(post.decision).toBe('redact_response');
    expect(post.responsePii?.via).toBeUndefined();
    expect(post.redactedResponse).toBe('ssn [REDACTED_SSN]');
  });

  it('post-call merge: response_pii_via telemetry is stamped and the stored response replaced', async () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    const post = await applyPostCallPolicy(`x ${B64_SSN}`, {}, getConfig());
    const event = { metadata: {} } as unknown as AuditEvent;
    mergePostCallOutcome(event, post);
    const telemetry = (event.metadata as Record<string, any>).obsvr_telemetry;
    expect(telemetry.response_pii_via).toBe('base64');
    expect(event.response).toBe(OBFUSCATED_REDACTION_PLACEHOLDER);
  });

  it('MCP tool result: a view-only hit under redact ESCALATES sanitize to block', () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    const verdict = scanMcpToolResult(B64_SSN, getConfig());
    expect(verdict.action).toBe('block');
    expect(verdict.via).toBe('base64');
    expect(verdict.policy_reason).toMatch(/no locatable span/);
  });

  it('MCP tool result: flag OFF leaves the encoded payload undetected (prior behavior)', () => {
    init({ api_key: 'test', ingest_url: 'https://x', pii_policy: { default: 'redact' } });
    const verdict = scanMcpToolResult(B64_SSN, getConfig());
    expect(verdict.action).toBe('allow');
    expect(verdict.via).toBeUndefined();
  });

  it('observe: a view-only hit sets storedRedactionVia so stored copies use the placeholder', () => {
    init({
      api_key: 'test',
      ingest_url: 'https://x',
      pii_policy: { default: 'redact' },
      deobfuscation: { enabled: true },
    });
    const res = applyObservePolicy(B64_SSN, getConfig());
    expect(res.shouldRedactStored).toBe(true);
    expect(res.storedRedactionVia).toBe('base64');
  });
});
