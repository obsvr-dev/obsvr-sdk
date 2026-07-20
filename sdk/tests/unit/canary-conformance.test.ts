import * as fs from 'fs';
import * as path from 'path';
import {
  canaryCandidates,
  mintCanary,
  scanForCanary,
  _resetCanaries,
  canaryRegistrySize,
  CANARY_PREFIX,
} from '../../src/policy/canary';
import { sha256Hex } from '../../src/policy/decision-record';

/**
 * Cross-SDK canary-leak conformance harness (TS side). Twin:
 * sdk-python/tests/test_canary_conformance.py. Pins the deterministic,
 * registry-independent detection (hash of the canonical token; candidate
 * extraction over raw + de-obfuscation views). Minting randomness is not
 * fixture-pinned; the stateful mint/scan integration is tested separately.
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

interface HashCase {
  id: string;
  token: string;
  expect: { hash: string };
}
interface CandidateCase {
  id: string;
  input: string;
  expect: Array<{ hash: string; via: string }>;
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/canary.json'), 'utf-8'),
) as { hash_cases: HashCase[]; candidate_cases: CandidateCase[] };

describe('conformance: canonical token hash', () => {
  for (const c of fixture.hash_cases) {
    it(c.id, () => {
      expect(sha256Hex(c.token.toLowerCase())).toBe(c.expect.hash);
    });
  }
});

describe('conformance: candidate extraction (raw + views)', () => {
  for (const c of fixture.candidate_cases) {
    it(c.id, () => {
      expect(canaryCandidates(c.input)).toEqual(c.expect);
    });
  }
});

describe('canary mint + scan integration (stateful, not fixture-pinned)', () => {
  beforeEach(() => _resetCanaries());
  afterEach(() => _resetCanaries());

  it('a minted token leaks when it appears in scanned text; the raw token never rides the result', () => {
    const c = mintCanary({ label: 'system-prompt' });
    expect(canaryRegistrySize()).toBe(1);
    expect(scanForCanary('nothing here').leaked).toBe(false);
    const r = scanForCanary(`the model said: ${c.token}`);
    expect(r.leaked).toBe(true);
    expect(r.hits[0].id).toBe(c.id);
    expect(r.hits[0].label).toBe('system-prompt');
    expect(r.hits[0].via).toBe('raw');
    // Hygiene: the raw token never appears in the scan result.
    expect(JSON.stringify(r)).not.toContain(c.token);
    expect(JSON.stringify(r)).not.toContain(c.token.slice(CANARY_PREFIX.length));
  });

  it('catches a base64-encoded exfiltration of the token', () => {
    const c = mintCanary();
    const encoded = Buffer.from(c.token).toString('base64');
    const r = scanForCanary(`exfil: ${encoded}`);
    expect(r.leaked).toBe(true);
    expect(r.hits[0].via).toBe('base64');
  });

  it('an un-minted token that matches the format is NOT a leak (registry membership required)', () => {
    mintCanary();
    const fake = `${CANARY_PREFIX}00000000000000000000000000000000`;
    expect(scanForCanary(`sees ${fake}`).leaked).toBe(false);
  });

  it('mint returns a fresh 128-bit token each call', () => {
    const a = mintCanary();
    const b = mintCanary();
    expect(a.token).not.toBe(b.token);
    expect(a.token.length).toBe(CANARY_PREFIX.length + 32);
    expect(canaryRegistrySize()).toBe(2);
  });
});
