import { createHmac, randomUUID } from 'crypto';
import { verifyAuditChain } from '../../src/governance/verify-chain';
import {
  CHAIN_FORMAT_CURRENT,
  CHAIN_FORMAT_LEGACY,
  signaturePayload,
} from '../../src/proxy/chain-format';

const TEST_API_KEY = 'test-chain-key-12345';
const SIGNING_SALT = 'obsvr-sdk-signing-v1';

function deriveKey(apiKey: string): Buffer {
  return createHmac('sha256', SIGNING_SALT).update(apiKey).digest();
}

/**
 * Build a signed chain under either format. Legacy (format 1) chains carry
 * no chain_format field, exactly as chains signed before the field existed;
 * the whole tamper matrix below runs against BOTH formats because a legacy
 * export must keep producing the same verdicts forever.
 */
function buildChain(
  count: number,
  apiKey: string = TEST_API_KEY,
  format: number = CHAIN_FORMAT_CURRENT
) {
  const key = deriveKey(apiKey);
  const sessionId = randomUUID();
  const events: any[] = [];
  let prevSig: string | null = null;

  for (let i = 0; i < count; i++) {
    const seq = i + 1;
    const ts = Date.now() + i;
    const prompt = `prompt-${i}`;
    const response = `response-${i}`;
    const sigPayload = signaturePayload(format, sessionId, seq, ts, prompt, response, prevSig);
    const sig = createHmac('sha256', key).update(sigPayload).digest('hex');

    events.push({
      sdk_session_id: sessionId,
      seq_no: seq,
      timestamp_sdk: ts,
      ...(format === CHAIN_FORMAT_LEGACY ? {} : { chain_format: format }),
      prompt,
      response,
      sdk_sig: sig,
      prev_sig: prevSig ?? undefined,
    });
    prevSig = sig;
  }
  return events;
}

describe.each([
  ['format 2 (current)', CHAIN_FORMAT_CURRENT],
  ['format 1 (legacy)', CHAIN_FORMAT_LEGACY],
])('verifyAuditChain, %s', (_label, format) => {
  const build = (count: number, apiKey: string = TEST_API_KEY) =>
    buildChain(count, apiKey, format);

  it('verifies a valid chain and reports its format', () => {
    const events = build(5);
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(5);
    expect(result.chainFormat).toBe(format);
  });

  it('detects tampered signature', () => {
    const events = build(3);
    events[1].sdk_sig = 'tampered';
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toContain('Signature mismatch');
  });

  it('detects tampered content', () => {
    const events = build(3);
    events[1].prompt = 'tampered-prompt';
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('detects broken chain link', () => {
    const events = build(3);
    events[2].prev_sig = 'wrong-prev';
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.reason).toContain('Chain break');
  });

  it('detects seq_no gap', () => {
    const events = build(3);
    events[1].seq_no = 5; // gap from 1 to 5
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
    expect(result.reason).toContain('seq_no gap');
  });

  it('detects session ID mismatch', () => {
    const events = build(3);
    events[2].sdk_session_id = randomUUID();
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.reason).toContain('Session ID mismatch');
  });

  it('detects wrong API key', () => {
    const events = build(3);
    const result = verifyAuditChain(events, 'wrong-api-key');
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('verifies single-event chain', () => {
    const events = build(1);
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(1);
  });
});

describe('verifyAuditChain, format boundaries', () => {
  it('returns valid for empty chain, with no format to report', () => {
    const result = verifyAuditChain([], TEST_API_KEY);
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(0);
    expect(result.chainFormat).toBeUndefined();
  });

  it('format 2 rejects a boundary re-split that format 1 accepts', () => {
    // The attack the format change closed: move the boundary between prompt
    // and response while preserving their concatenation. Under format 1 the
    // content hash cannot see the boundary, so the chain still verifies —
    // which is exactly why the verifier reports which format it checked.
    for (const [format, expected] of [
      [CHAIN_FORMAT_CURRENT, false],
      [CHAIN_FORMAT_LEGACY, true],
    ] as Array<[number, boolean]>) {
      const events = buildChain(2, TEST_API_KEY, format);
      const joined = `${events[0].prompt}${events[0].response}`;
      events[0].prompt = joined.slice(0, 3);
      events[0].response = joined.slice(3);
      const result = verifyAuditChain(events, TEST_API_KEY);
      expect(result.valid).toBe(expected);
    }
  });

  it('rejects a mid-chain format change', () => {
    const events = buildChain(3);
    delete events[2].chain_format;
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(2);
    expect(result.reason).toContain('Chain format mismatch');
  });

  it('fails closed on a format it does not know', () => {
    const events = buildChain(2);
    events[0].chain_format = 99;
    const result = verifyAuditChain(events, TEST_API_KEY);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
    expect(result.reason).toContain('Unsupported chain_format');
    expect(result.chainFormat).toBeUndefined();
  });
});
