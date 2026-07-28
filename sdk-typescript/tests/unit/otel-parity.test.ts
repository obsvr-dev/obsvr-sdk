import * as fs from 'fs';
import * as path from 'path';
import { mirrorToOtel, _setOtelApi, _resetOtelMirror } from '../../src/proxy/otel-mirror';
import type { AuditEvent, ResolvedConfig } from '../../src/proxy/types';

/**
 * OTel attribute parity (E29), twin of
 * sdk-python/tests/test_otel_parity.py: the mirrored span's attribute
 * KEY SET must match conformance/fixtures/otel_attributes.json exactly
 * in both SDKs, so downstream dashboards see identical fields
 * regardless of language.
 */

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/otel_attributes.json'), 'utf-8'),
) as { attribute_keys: string[] };

afterEach(() => _resetOtelMirror());

it('mirrors spans with exactly the fixture attribute keys', () => {
  const captured: Record<string, unknown>[] = [];
  _setOtelApi({
    trace: {
      getTracer: () => ({
        startSpan: (_name: string, options?: { attributes?: Record<string, unknown> }) => {
          captured.push(options?.attributes ?? {});
          return { setStatus: () => undefined, end: () => undefined };
        },
      }),
    },
    SpanStatusCode: { OK: 1, ERROR: 2 },
  });

  const config = {
    otel: { enabled: true },
    debug: false,
  } as unknown as ResolvedConfig;
  const event = {
    operation: 'chat.completions.create',
    provider: 'openai',
    model: 'gpt-4o',
    input_tokens: 10,
    output_tokens: 5,
    event_type: 'llm_call',
    action_taken: 'allowed',
    action_reason: 'none',
    rule_id: 'r1',
    seq_no: 3,
    sdk_session_id: 'sess-1',
    environment: 'production',
    timestamp_sdk: Date.now(),
    latency_ms: 12,
    success: true,
  } as unknown as AuditEvent;

  mirrorToOtel(config, event);

  expect(captured).toHaveLength(1);
  expect(Object.keys(captured[0]).sort()).toEqual(fixture.attribute_keys);
});
