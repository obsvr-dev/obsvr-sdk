/**
 * Enforcement claims, checked from OUTSIDE the SDK.
 *
 * Twin of sdk-python/tests/test_enforcement_observed_from_outside.py, and it
 * carries the same admission rule: every assertion here reads an instrument
 * this SDK does not author — the arguments an inner callee received, the bytes
 * a real HTTP server was handed, whether `init()` threw. Nothing asks an obsvr
 * event whether the obsvr event is right.
 *
 * That distinction is the whole reason the file exists. A suite that verifies
 * REPORTING passes just as happily when the report is wrong, and that is how
 * every defect in this release got as far as it did. Where the thing being
 * protected IS the record — the stored-copy scan below — the instrument is the
 * bytes that reach a real ingest server, not the object the SDK built.
 *
 * The rule for adding to this file: if the only way you can tell the
 * protection happened is by reading an obsvr event, it does not belong here —
 * find the instrument outside the SDK, or say plainly that the claim is
 * unproven.
 */
import { init, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';

const RAW_SSN = '412-55-9087';
const BLOCKED_KEYWORD = 'zarquon';

const KEYWORD_BLOCK_RULE = {
  id: 'no-zarquon',
  name: 'Block zarquon',
  enabled: true,
  action: 'block' as const,
  type: 'keyword' as const,
  conditions: { keywords: [BLOCKED_KEYWORD] },
};

// ── The provider client is the instrument ──────────────────────────────────
//
// What a governed client hands its provider is the only thing that decides
// whether a block blocked. This records it and is asked afterwards; the
// control proves the recorder can see a leak when one happens.

function recordingClient(received: string[]) {
  return {
    messages: {
      create: async (params: Record<string, unknown>) => {
        received.push(JSON.stringify(params.messages ?? ''));
        return {
          content: [{ type: 'text', text: 'ok' }],
          usage: { input_tokens: 1, output_tokens: 1 },
        };
      },
    },
  };
}

async function driveGovernedCall(config: Record<string, unknown>): Promise<string[]> {
  const received: string[] = [];
  init({ api_key: 'test', ingest_url: 'http://127.0.0.1:1', ...config });
  const client = wrap(recordingClient(received)) as {
    messages: { create: (p: Record<string, unknown>) => Promise<unknown> };
  };
  try {
    await client.messages.create({
      model: 'm',
      max_tokens: 8,
      messages: [{ role: 'user', content: `The password is ${BLOCKED_KEYWORD}.` }],
    });
  } catch {
    /* a refusal is one of the outcomes under test */
  }
  return received;
}

describe('a declared block rule reaches the wire decision', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });
  afterEach(() => _reset());

  it('the control reaches the provider with the keyword', async () => {
    // Without this every assertion below is satisfied by a broken recorder.
    const received = await driveGovernedCall({});
    expect(received).toHaveLength(1);
    expect(received[0]).toContain(BLOCKED_KEYWORD);
  });

  it('a block rule stops the call', async () => {
    const received = await driveGovernedCall({ policy_rules: [KEYWORD_BLOCK_RULE] });
    expect(received).toEqual([]);
  });
});

describe('a rule the engine cannot use is refused at init', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });
  afterEach(() => _reset());

  // Each of these was accepted and then enforced nothing: the engine reads
  // `enabled` as a truth value and matches on `type`, so a rule missing the one
  // or misspelling the other is skipped in silence. The instrument is `init()`
  // itself — it either refuses or it does not.
  const cases: Array<[string, unknown]> = [
    ['not a rule object', 'not-a-rule'],
    ['no enabled flag', { ...KEYWORD_BLOCK_RULE, enabled: undefined }],
    ["typo'd type", { ...KEYWORD_BLOCK_RULE, type: 'keywrod' }],
    ['reserved id prefix', { ...KEYWORD_BLOCK_RULE, id: 'sdk:forged' }],
    ['a ReDoS pattern', {
      ...KEYWORD_BLOCK_RULE,
      type: 'regex',
      conditions: { pattern: '(a|aa)+$' },
    }],
  ];

  it.each(cases)('refuses policyRules with %s', (_label, bad) => {
    expect(() =>
      init({ api_key: 'test', ingest_url: 'http://127.0.0.1:1', policy_rules: [bad] as never }),
    ).toThrow(/is not a usable rule/);
  });

  it('refuses the same shape in policyFloor', () => {
    expect(() =>
      init({
        api_key: 'test',
        ingest_url: 'http://127.0.0.1:1',
        policyFloor: [{ ...KEYWORD_BLOCK_RULE, type: 'keywrod' }] as never,
      }),
    ).toThrow(/policyFloor\[0\] is not a usable rule/);
  });

  it('accepts a well-formed rule, so the refusals above are about the defect', () => {
    expect(() =>
      init({
        api_key: 'test',
        ingest_url: 'http://127.0.0.1:1',
        policy_rules: [KEYWORD_BLOCK_RULE],
      }),
    ).not.toThrow();
  });
});
