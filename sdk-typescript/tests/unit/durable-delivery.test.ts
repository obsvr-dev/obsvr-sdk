import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { jest } from '@jest/globals';
import {
  _resetSender,
  configureDurableDelivery,
  enqueueAuditEvent,
  flushQueue,
  getDeliveryStatus,
} from '../../src/proxy/sender/fire-and-forget';
import type { AuditEvent, ResolvedConfig } from '../../src/proxy/types';

function event(id: string): AuditEvent {
  return {
    request_id: id,
    region: 'test',
    provider: 'openai',
    model: 'gpt-test',
    operation: 'chat.completions.create',
    source: 'test',
    prompt: 'hello',
    response: 'world',
    success: true,
    event_type: 'llm_call',
    policy_version: 'v1',
    action_taken: 'allowed',
    action_reason: 'none',
    action_source: 'builtin',
    redacted_types: [],
  } as AuditEvent;
}

function config(directory: string): ResolvedConfig {
  return {
    api_key: 'key',
    environment: 'production',
    ingest_url: 'https://ingest.example.com',
    sample_rate: 1,
    max_payload_chars: 10000,
    disabled: false,
    debug: false,
    timeout: 1000,
    streaming_mode: 'skip',
    durable_delivery: {
      directory,
      maxBytes: 1024 * 1024,
      fsync: true,
      failureMode: 'error',
    },
  } as ResolvedConfig;
}

describe('durable audit delivery', () => {
  const realFetch = globalThis.fetch;
  let directory: string;

  beforeEach(() => {
    _resetSender();
    directory = mkdtempSync(join(tmpdir(), 'obsvr-outbox-'));
  });

  afterEach(() => {
    _resetSender();
    globalThis.fetch = realFetch;
    rmSync(directory, { recursive: true, force: true });
  });

  it('persists before return, replays after sender reset, and acknowledges only on success', async () => {
    const cfg = config(directory);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    globalThis.fetch = jest.fn(async () => {
      await gate;
      return { status: 200, json: async () => ({}) } as Response;
    }) as typeof fetch;

    configureDurableDelivery(cfg);
    enqueueAuditEvent(cfg, event('durable-1'));

    expect(readdirSync(join(directory, 'pending')).filter((name) => name.endsWith('.json'))).toHaveLength(1);
    expect(getDeliveryStatus().outbox.pending).toBe(1);

    // Simulate process memory disappearing while the durable directory remains.
    _resetSender();
    globalThis.fetch = jest.fn(async () => ({
      status: 200,
      json: async () => ({}),
    } as Response)) as typeof fetch;
    configureDurableDelivery(cfg);
    await flushQueue(cfg, 2000);

    expect(readdirSync(join(directory, 'pending')).filter((name) => name.endsWith('.json'))).toHaveLength(0);
    expect(getDeliveryStatus().outbox.acknowledged).toBe(1);
    release();
  });

  it('moves permanently refused evidence to dead-letter storage', async () => {
    const cfg = config(directory);
    globalThis.fetch = jest.fn(async () => ({
      status: 400,
      json: async () => ({ error: 'invalid_event' }),
    } as Response)) as typeof fetch;

    configureDurableDelivery(cfg);
    enqueueAuditEvent(cfg, event('durable-dead'));
    await flushQueue(cfg, 2000);

    expect(readdirSync(join(directory, 'pending')).filter((name) => name.endsWith('.json'))).toHaveLength(0);
    // The refused event and the signed gap marker that records the resulting
    // chain break are both terminal evidence and therefore both retained.
    expect(readdirSync(join(directory, 'dead')).filter((name) => name.endsWith('.json'))).toHaveLength(2);
    expect(getDeliveryStatus().outbox.dead_letters).toBe(2);
  });

  it('refuses a relative outbox directory', () => {
    const cfg = config('relative/outbox');
    expect(() => configureDurableDelivery(cfg)).toThrow(/must be absolute/);
  });

  it('refuses a symlinked outbox child directory', () => {
    const redirected = mkdtempSync(join(tmpdir(), 'obsvr-outbox-redirect-'));
    symlinkSync(redirected, join(directory, 'pending'));
    try {
      expect(() => configureDurableDelivery(config(directory))).toThrow(/symbolic link/);
    } finally {
      rmSync(redirected, { recursive: true, force: true });
    }
  });

  it('restricts existing outbox directories to the current user', () => {
    mkdirSync(join(directory, 'pending'));
    mkdirSync(join(directory, 'dead'));
    for (const path of [directory, join(directory, 'pending'), join(directory, 'dead')]) {
      chmodSync(path, 0o777);
    }

    configureDurableDelivery(config(directory));

    for (const path of [directory, join(directory, 'pending'), join(directory, 'dead')]) {
      expect(statSync(path).mode & 0o777).toBe(0o700);
    }
  });
});
