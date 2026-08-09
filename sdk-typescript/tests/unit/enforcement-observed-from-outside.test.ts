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
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';

import { init, getConfig, _reset } from '../../src/proxy/config';
import { wrap } from '../../src/proxy/wrapper';
import { ObsvrTraceProcessor } from '../../src/integrations/openai-agents';
import { _resetSender, flushQueue } from '../../src/proxy/sender/fire-and-forget';

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

// ── A real ingest server is the instrument ─────────────────────────────────
//
// The stored-copy scan protects the RECORD, so the record cannot be its own
// witness. What can be is the bytes that actually leave the process: a real
// HTTP server, holding what it was POSTed.

describe('raw PII does not reach the ingest service from the tracing processor', () => {
  let server: Server;
  let bodies: string[];
  let url: string;

  beforeAll(async () => {
    bodies = [];
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        bodies.push(Buffer.concat(chunks).toString('utf8'));
        const payload = JSON.stringify({ count: 1 });
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': String(payload.length),
        });
        res.end(payload);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    _reset();
    _resetSender();
    bodies.length = 0;
  });
  afterEach(() => _reset());

  /** A completed response span in the shape processSpan parses. */
  function responseSpan(text: string) {
    return {
      trace_id: 'trace_1',
      span_data: {
        type: 'response',
        ended_at: '2026-08-07T00:00:00Z',
        _response: {
          id: 'resp_1',
          model: 'gpt-4o-2024-08-06',
          output: [{ content: [{ text }] }],
          usage: { input_tokens: 1, output_tokens: 1 },
        },
        _input: [{ role: 'user', content: text }],
      },
    };
  }

  it('the control delivers the span content, so the server can see a leak', async () => {
    init({ api_key: 'test', ingest_url: url, sample_rate: 1 });
    new ObsvrTraceProcessor().processSpan(responseSpan('the weather in Lisbon') as never);
    await flushQueue(getConfig());
    expect(bodies.join('')).toContain('Lisbon');
  });

  it('an SSN in the span never reaches the ingest service', async () => {
    // This processor ran no policy pipeline of any kind, so at any sample rate
    // it wrote whatever the agent said straight into the signed event.
    init({
      api_key: 'test',
      ingest_url: url,
      sample_rate: 1,
      pii_policy: { rules: { ssn: 'redact' } },
    });
    new ObsvrTraceProcessor().processSpan(
      responseSpan(`the customer SSN is ${RAW_SSN}`) as never,
    );
    await flushQueue(getConfig());
    const delivered = bodies.join('');
    expect(delivered).not.toContain(RAW_SSN);
    expect(delivered.length).toBeGreaterThan(0);
    const events = bodies.flatMap((body) => {
      const parsed = JSON.parse(body) as unknown;
      return Array.isArray(parsed) ? parsed : [parsed];
    }) as Array<Record<string, any>>;
    const event = events.find((item) => item.operation === 'llm');
    expect(event?.action_taken).toBe('not_evaluated');
    expect(event?.metadata?.obsvr_telemetry).toMatchObject({
      stored_redaction_scope: 'observe_only',
      stored_redaction_types: ['ssn'],
      stored_redaction_outbound_unmodified: true,
      stored_redaction_requested_action: 'redact',
    });
  });
});

// ── init() itself is the instrument ────────────────────────────────────────

describe('every customer-configured outbound URL is refused if it is a metadata address', () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });
  afterEach(() => _reset());

  // `hardDeletion.endpoint` was the fourth such URL and the one outside the
  // guard, while the security notes say every one of them is validated. It
  // carries a DELETE with the X-API-Key header.
  const METADATA = 'http://169.254.169.254/latest/meta-data/';

  const endpoints: Array<[string, Record<string, unknown>]> = [
    ['ingest_url', { ingest_url: METADATA }],
    ['presidioAnalyzerUrl', { presidio_analyzer_url: METADATA }],
    ['presidioAnonymizerUrl', { presidio_anonymizer_url: METADATA }],
    // The internal spelling: this object is snake_case throughout, and
    // mixing the two makes init() treat it as already-internal and skip
    // camelCase normalization entirely.
    [
      'externalPolicyBackend.url',
      { external_policy_backend: { type: 'opa', url: METADATA } },
    ],
    ['hardDeletion.endpoint', { hardDeletion: { enabled: true, endpoint: METADATA } }],
  ];

  it.each(endpoints)('refuses %s pointed at the metadata address', (_name, cfg) => {
    expect(() => init({ api_key: 'test', ...cfg } as never)).toThrow();
  });

  it('accepts an ordinary https endpoint, so the refusals are about the address', () => {
    expect(() =>
      init({
        api_key: 'test',
        ingest_url: 'https://ingest.example.com',
        hardDeletion: { enabled: true, endpoint: 'https://erasure.example.com' },
      } as never),
    ).not.toThrow();
  });
});
