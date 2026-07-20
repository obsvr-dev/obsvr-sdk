import * as fs from 'fs';
import * as path from 'path';
import { runBuiltinPiiScan, redactBuiltinPii } from '../../src/policy/hook';

/**
 * Built-in PII/secret/injection scanner — TS side of the cross-SDK conformance
 * harness. Twin: sdk-python/tests/test_pii_scan_conformance.py. Every case in
 * conformance/fixtures/pii_scan.json must produce the pinned detected_types
 * (unique labels in span order after overlap suppression, Luhn validation
 * applied) and redacted output byte-for-byte. A divergence is a release blocker.
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

interface PiiScanCase {
  id: string;
  note?: string;
  input: string;
  detected_types: string[];
  redacted: string;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/pii_scan.json'), 'utf-8'),
) as { cases: PiiScanCase[] };

describe('conformance: pii_scan fixtures', () => {
  for (const c of fixture.cases) {
    it(`${c.id} detects the pinned types`, () => {
      const scan = runBuiltinPiiScan(c.input);
      expect(scan.detected_types).toEqual(c.detected_types);
      expect(scan.pii_detected).toBe(c.detected_types.length > 0);
    });

    it(`${c.id} redacts to the pinned string`, () => {
      expect(redactBuiltinPii(c.input)).toBe(c.redacted);
    });
  }
});
