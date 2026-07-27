/**
 * Dropped events must leave a trace in the signed chain.
 *
 * The behavior this file pins is the one that used to be invisible. Overflow
 * drops happen BEFORE a sequence number is assigned, so the events that
 * survived a saturated burst formed a contiguous, perfectly verifiable chain -
 * the record said nothing was missing while most of the burst was. The sender
 * now signs a gap marker at the drop point, and the assertions below are about
 * the two things that make that marker evidence rather than a log line: it is
 * IN the chain (chained, signed, verifiable), and its count is INSIDE the
 * signature preimage, so editing the count breaks verification.
 *
 * Twin: sdk-python/tests/test_audit_gap.py.
 */
import {
  enqueueAuditEvent,
  flushQueue,
  getSenderStats,
  getQueueSize,
  getPendingGapCount,
  _resetSender,
} from '../../src/proxy/sender/fire-and-forget';
import { verifyAuditChain } from '../../src/governance/verify-chain';
import { parseAuditGapPrompt, AUDIT_GAP_METADATA_KEY } from '../../src/proxy/audit-gap';
import { MAX_QUEUE_SIZE } from '../../src/constants';
import type { AuditEvent, ResolvedConfig } from '../../src/proxy/types';

const API_KEY = 'test-key';

function config(): ResolvedConfig {
  return {
    api_key: API_KEY,
    environment: 'production',
    ingest_url: 'https://ingest.example.com',
    sample_rate: 1,
    max_payload_chars: 10000,
    disabled: false,
    debug: false,
    timeout: 5000,
    streaming_mode: 'skip',
    default_region: 'us-east-1',
  } as ResolvedConfig;
}

function auditEvent(id: string): AuditEvent {
  return {
    request_id: id,
    region: 'us-east-1',
    provider: 'openai',
    model: 'gpt-4o',
    operation: 'chat.completion',
    source: 'test',
    prompt: `prompt-${id}`,
    response: 'response',
    success: true,
    event_type: 'llm_call',
    policy_version: 'v1',
    action_taken: 'allowed',
    action_reason: 'none',
    action_source: 'builtin',
    redacted_types: [],
  } as AuditEvent;
}

const realFetch = globalThis.fetch;

describe('audit gap markers', () => {
  /** Every event the sender actually delivered, in chain order. */
  let delivered: AuditEvent[];
  /** Held closed to stall delivery, so the bounded queue fills and overflows. */
  let releaseDelivery: () => void;

  beforeEach(() => {
    _resetSender();
    delivered = [];
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    releaseDelivery = open;
    // A backend slower than the caller - the real overflow condition, rather
    // than a hand-poked queue. Requests block until the gate opens, then every
    // request (including the one already in flight) completes normally.
    globalThis.fetch = (async (_url: string, init: { body: string }) => {
      await gate;
      const body = JSON.parse(init.body);
      for (const e of Array.isArray(body) ? body : [body]) delivered.push(e);
      return { status: 200, ok: true, json: async () => ({ count: 1 }) };
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  /** Saturate the bounded queue; returns how many events it dropped. */
  function saturate(cfg: ResolvedConfig, overBy: number): number {
    for (let i = 0; i < MAX_QUEUE_SIZE + overBy; i++) enqueueAuditEvent(cfg, auditEvent(`e${i}`));
    return getSenderStats().dropped_overflow;
  }

  /** Let delivery through and wait for the sender to drain on its own. */
  async function drain(): Promise<void> {
    releaseDelivery();
    const deadline = Date.now() + 5000;
    while (getQueueSize() > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 10));
    }
    await new Promise((r) => setTimeout(r, 20));
  }

  it('counts an overflow drop as an undeclared gap until a marker carries it', () => {
    const dropped = saturate(config(), 40);

    expect(dropped).toBeGreaterThan(0);
    expect(getQueueSize()).toBe(MAX_QUEUE_SIZE);
    // The drops are counted but NOT yet on the record: this is the window the
    // marker exists to close, and a process that dies here still loses them.
    expect(getPendingGapCount()).toBe(dropped);
    expect(getSenderStats().gap_markers).toBe(0);
  });

  it('signs one marker declaring the whole burst on the next enqueue', async () => {
    const cfg = config();
    const dropped = saturate(cfg, 40);
    await drain();

    enqueueAuditEvent(cfg, auditEvent('after-the-gap'));
    await flushQueue(cfg, 2000);

    expect(getPendingGapCount()).toBe(0);
    expect(getSenderStats().gap_markers).toBe(1);
    expect(getSenderStats().gap_events_declared).toBe(dropped);

    // One marker for the burst, not one per dropped event.
    const markers = delivered.filter((e) => parseAuditGapPrompt(e.prompt));
    expect(markers).toHaveLength(1);
    expect(parseAuditGapPrompt(markers[0].prompt)).toEqual({
      dropped,
      reason: 'queue_overflow',
    });
    expect(markers[0].operation).toBe('audit.gap');
  });

  it('places the marker between the last surviving event and the first one after the loss', async () => {
    const cfg = config();
    saturate(cfg, 5);
    await drain();

    enqueueAuditEvent(cfg, auditEvent('after-the-gap'));
    await flushQueue(cfg, 2000);

    const at = delivered.findIndex((e) => parseAuditGapPrompt(e.prompt));
    expect(at).toBeGreaterThan(0);
    expect(delivered[at + 1].request_id).toBe('after-the-gap');
    // Contiguous with both neighbours: the marker occupies the chain position
    // the loss happened at, it is not appended somewhere convenient.
    expect(delivered[at].seq_no).toBe((delivered[at - 1].seq_no ?? 0) + 1);
    expect(delivered[at + 1].seq_no).toBe((delivered[at].seq_no ?? 0) + 1);
    expect(delivered[at].prev_sig).toBe(delivered[at - 1].sdk_sig);
    expect(delivered[at + 1].prev_sig).toBe(delivered[at].sdk_sig);
  });

  it('produces a chain that verifies AND reports what it is missing', async () => {
    const cfg = config();
    const dropped = saturate(cfg, 123);
    await drain();

    enqueueAuditEvent(cfg, auditEvent('after-the-gap'));
    await flushQueue(cfg, 2000);

    const result = verifyAuditChain(delivered, API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(delivered.length);
    // The half that used to be missing: valid, and openly short by `dropped`.
    expect(result.gapMarkers).toBe(1);
    expect(result.eventsDeclaredLost).toBe(dropped);
  });

  it('breaks verification if the declared count is edited', async () => {
    const cfg = config();
    saturate(cfg, 9);
    await drain();
    enqueueAuditEvent(cfg, auditEvent('after-the-gap'));
    await flushQueue(cfg, 2000);

    const at = delivered.findIndex((e) => parseAuditGapPrompt(e.prompt));
    // Rewriting the loss down to 1 is exactly the tamper the signature exists
    // to catch, and it is only caught because the count is in the preimage.
    delivered[at].prompt = 'obsvr:audit-gap/1 dropped=1 reason=queue_overflow';

    const result = verifyAuditChain(delivered, API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(at);
    expect(result.reason).toBe(`Signature mismatch at event ${at}`);
  });

  it('flushes an outstanding gap at shutdown rather than losing it with the process', async () => {
    const cfg = config();
    const dropped = saturate(cfg, 7);
    expect(getPendingGapCount()).toBe(dropped);

    // No further enqueue: only the flush stands between the drops and oblivion.
    releaseDelivery();
    await flushQueue(cfg, 3000);

    expect(getPendingGapCount()).toBe(0);
    expect(getSenderStats().gap_markers).toBe(1);
    const marker = delivered.find((e) => parseAuditGapPrompt(e.prompt));
    expect(parseAuditGapPrompt(marker?.prompt)).toEqual({
      dropped,
      reason: 'queue_overflow',
    });
  });

  it('emits no marker when nothing was dropped', async () => {
    const cfg = config();
    releaseDelivery();
    for (let i = 0; i < 10; i++) enqueueAuditEvent(cfg, auditEvent(`e${i}`));
    await flushQueue(cfg, 2000);

    expect(getSenderStats().gap_markers).toBe(0);
    expect(delivered.filter((e) => parseAuditGapPrompt(e.prompt))).toHaveLength(0);
    const result = verifyAuditChain(delivered, API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsDeclaredLost).toBe(0);
  });

  it('carries a structured copy of the claim in reserved metadata', async () => {
    const cfg = config();
    const dropped = saturate(cfg, 3);
    releaseDelivery();
    await flushQueue(cfg, 3000);

    const marker = delivered.find((e) => parseAuditGapPrompt(e.prompt))!;
    expect(marker.metadata?.[AUDIT_GAP_METADATA_KEY]).toEqual({
      dropped,
      reason: 'queue_overflow',
    });
    expect(marker.metadata?.governance_event).toBe('audit_gap');
    expect(marker.event_type).toBe('policy_flag');
    expect(marker.policy_version).toBe('none');
  });
});

describe('gap marker parsing', () => {
  it('does not let an ordinary prompt mint a loss claim', () => {
    // Without this, any caller could fabricate a declared gap by sending a
    // prompt that quotes the format.
    expect(
      parseAuditGapPrompt('note: obsvr:audit-gap/1 dropped=99 reason=queue_overflow'),
    ).toBeNull();
    expect(
      parseAuditGapPrompt('obsvr:audit-gap/1 dropped=99 reason=queue_overflow extra'),
    ).toBeNull();
    expect(parseAuditGapPrompt('summarize this')).toBeNull();
    expect(parseAuditGapPrompt(undefined)).toBeNull();
  });
});
