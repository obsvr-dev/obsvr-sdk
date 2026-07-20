import { createHmac, createHash, randomUUID } from 'crypto';
import { verifyAuditChain } from '../../src/governance/verify-chain';

const TEST_API_KEY = 'test-chain-key-12345';
const SIGNING_SALT = 'obsvr-sdk-signing-v1';

function deriveKey(apiKey: string): Buffer {
  return createHmac('sha256', SIGNING_SALT).update(apiKey).digest();
}

function buildChain(count: number, apiKey: string = TEST_API_KEY) {
  const key = deriveKey(apiKey);
  const sessionId = randomUUID();
  const events: any[] = [];
  let prevSig: string | null = null;

  for (let i = 0; i < count; i++) {
    const seq = i + 1;
    const ts = Date.now() + i;
    const prompt = `prompt-${i}`;
    const response = `response-${i}`;
    const contentHash = createHash('sha256').update(prompt + response).digest('hex');
    const sigPayload = [sessionId, seq, ts, contentHash, prevSig ?? ''].join('|');
    const sig = createHmac('sha256', key).update(sigPayload).digest('hex');

    events.push({
      sdk_session_id: sessionId,
      seq_no: seq,
      timestamp_sdk: ts,
      prompt,
      response,
      sdk_sig: sig,
      prev_sig: prevSig ?? undefined,
    });
    prevSig = sig;
  }
  return events;
}

describe('verifyAuditChain', () => {
  it('verifies a valid chain', () => {
    const events = buildChain(5);
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(5);
  });

  it('returns valid for empty chain', () => {
    const result = verifyAuditChain([], TEST_API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(0);
  });

  it('detects tampered signature', () => {
    const events = buildChain(3);
    events[1].sdk_sig = 'tampered';
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toContain('Signature mismatch');
  });

  it('detects tampered content', () => {
    const events = buildChain(3);
    events[1].prompt = 'tampered-prompt';
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects broken chain link', () => {
    const events = buildChain(3);
    events[2].prev_sig = 'wrong-prev';
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.reason).toContain('Chain break');
  });

  it('detects seq_no gap', () => {
    const events = buildChain(3);
    events[1].seq_no = 5; // gap from 1 to 5
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toContain('seq_no gap');
  });

  it('detects session ID mismatch', () => {
    const events = buildChain(3);
    events[2].sdk_session_id = randomUUID();
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.reason).toContain('Session ID mismatch');
  });

  it('detects wrong API key', () => {
    const events = buildChain(3);
    const result = verifyAuditChain(events, 'wrong-api-key');
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('verifies single-event chain', () => {
    const events = buildChain(1);
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(1);
  });
});
