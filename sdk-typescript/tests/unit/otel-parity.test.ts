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
) as { attribute_keys: string[]; conditional_keys: Record<string, string> };

const CONDITIONAL = Object.keys(fixture.conditional_keys).sort();
const UNCONDITIONAL = fixture.attribute_keys.filter((k) => !CONDITIONAL.includes(k)).sort();

function captureAttributes(event: Partial<AuditEvent>): Record<string, unknown> {
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
  const config = { otel: { enabled: true }, debug: false } as unknown as ResolvedConfig;
  mirrorToOtel(config, event as AuditEvent);
  expect(captured).toHaveLength(1);
  return captured[0];
}

const BASE = {
  operation: 'chat.completions.create',
  provider: 'openai',
  model: 'gpt-4o',
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
} as unknown as Partial<AuditEvent>;

afterEach(() => _resetOtelMirror());

it('mirrors spans with exactly the fixture attribute keys when tokens are known', () => {
  const attrs = captureAttributes({ ...BASE, input_tokens: 10, output_tokens: 5 });
  expect(Object.keys(attrs).sort()).toEqual(fixture.attribute_keys);
  expect(attrs['gen_ai.usage.input_tokens']).toBe(10);
  expect(attrs['gen_ai.usage.output_tokens']).toBe(5);
});

it('OMITS the token attributes when the counts were never read', () => {
  // A span reporting 0 for a measurement that never happened is the same
  // fabrication the extractors were fixed to stop making. An absent attribute
  // is how the semantic conventions say "not recorded".
  const attrs = captureAttributes(BASE);
  expect(Object.keys(attrs).sort()).toEqual(UNCONDITIONAL);
  for (const key of CONDITIONAL) expect(attrs).not.toHaveProperty(key);
});

it('keeps a GENUINE zero, which is a different fact from an unread count', () => {
  const attrs = captureAttributes({ ...BASE, input_tokens: 0, output_tokens: 0 });
  expect(Object.keys(attrs).sort()).toEqual(fixture.attribute_keys);
  expect(attrs['gen_ai.usage.input_tokens']).toBe(0);
  expect(attrs['gen_ai.usage.output_tokens']).toBe(0);
});

it('reports a half-known usage as half-known', () => {
  const attrs = captureAttributes({ ...BASE, output_tokens: 5 });
  expect(attrs).not.toHaveProperty('gen_ai.usage.input_tokens');
  expect(attrs['gen_ai.usage.output_tokens']).toBe(5);
});
