import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AuditEvent } from '../../src/proxy/types';
import {
  toCloudEvent,
  serializeCloudEvent,
  safeSerializeCloudEvent,
  rfc3339FromEpochMs,
} from '../../src/proxy/cloudevents';

/**
 * Cross-SDK CloudEvents v1.0 export conformance (TS side). Twin:
 * sdk-python/tests/test_cloudevents_conformance.py.
 *
 * The canonical STRING is the contract — an interchange envelope that two
 * SDKs render differently is not an interchange envelope — so each case
 * asserts the exact bytes as well as the parsed shape.
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

interface EnvelopeCase {
  id: string;
  desc?: string;
  event: Record<string, unknown>;
  expect: { envelope: Record<string, unknown>; serialized: string };
}
interface TimeCase {
  id: string;
  epoch_ms: unknown;
  expect: string | null;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/cloudevents.json'), 'utf-8'),
) as { envelope_cases: EnvelopeCase[]; time_cases: TimeCase[] };

describe('conformance: CloudEvents envelope projection', () => {
  for (const c of fixture.envelope_cases) {
    it(c.id, () => {
      const event = c.event as unknown as AuditEvent;
      expect(JSON.parse(JSON.stringify(toCloudEvent(event)))).toEqual(c.expect.envelope);
      expect(serializeCloudEvent(event)).toBe(c.expect.serialized);
    });
  }
});

describe('conformance: RFC 3339 rendering of the capture time', () => {
  for (const c of fixture.time_cases) {
    it(c.id, () => {
      expect(rfc3339FromEpochMs(c.epoch_ms) ?? null).toBe(c.expect);
    });
  }
});

describe('CloudEvents export: spec-level invariants', () => {
  const anyCase = fixture.envelope_cases[0].event as unknown as AuditEvent;

  it('every REQUIRED context attribute is a non-empty string on every case', () => {
    for (const c of fixture.envelope_cases) {
      const ce = toCloudEvent(c.event as unknown as AuditEvent);
      for (const key of ['id', 'source', 'specversion', 'type'] as const) {
        expect(typeof ce[key]).toBe('string');
        expect((ce[key] as string).length).toBeGreaterThan(0);
      }
    }
  });

  it('every OPTIONAL attribute present is non-empty (the spec forbids empty)', () => {
    for (const c of fixture.envelope_cases) {
      const ce = toCloudEvent(c.event as unknown as AuditEvent) as unknown as Record<string, unknown>;
      for (const key of ['subject', 'time', 'datacontenttype', 'dataschema']) {
        if (ce[key] !== undefined) expect(String(ce[key]).length).toBeGreaterThan(0);
      }
    }
  });

  it('extension attribute names are lower-case alphanumerics under 20 chars', () => {
    const RESERVED = new Set([
      'id', 'source', 'specversion', 'type', 'datacontenttype',
      'dataschema', 'subject', 'time', 'data',
    ]);
    for (const c of fixture.envelope_cases) {
      const ce = toCloudEvent(c.event as unknown as AuditEvent) as unknown as Record<string, unknown>;
      for (const key of Object.keys(ce)) {
        if (RESERVED.has(key)) continue;
        expect(key).toMatch(/^[a-z][a-z0-9]{0,19}$/);
      }
    }
  });

  it('carries the audit event unmodified, by reference', () => {
    const before = JSON.stringify(anyCase);
    const ce = toCloudEvent(anyCase);
    expect(ce.data).toBe(anyCase);
    expect(JSON.stringify(anyCase)).toBe(before);
  });

  it('refuses rather than silently disagreeing on an unrenderable number', () => {
    // An integer past 2^53 is a value the two runtimes cannot render
    // identically, so claiming byte-identical output for it would be a lie.
    const event = { ...anyCase, metadata: { huge: 12345678901234567890 } } as AuditEvent;
    expect(() => serializeCloudEvent(event)).toThrow();
    expect(safeSerializeCloudEvent(event)).toBeUndefined();
  });

  it('safeSerializeCloudEvent returns the string for a renderable event', () => {
    expect(safeSerializeCloudEvent(anyCase)).toBe(serializeCloudEvent(anyCase));
  });
});
