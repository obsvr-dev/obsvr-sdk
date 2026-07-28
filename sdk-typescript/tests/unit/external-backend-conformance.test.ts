import * as fs from 'fs';
import * as path from 'path';
import {
  mergeExternalBackendDecision,
  backendProvenance,
  type LocalDecision,
  type BackendOutcome,
  type ExternalPolicyBackendConfig,
} from '../../src/policy/external-backend';

/**
 * Cross-SDK conformance harness (TS side) for the inbound OPA/Cedar external
 * policy backend (ADR-4). Twin: sdk-python/tests/test_external_backend_conformance.py.
 * Both drive every case in conformance/fixtures/external_backend.json through the
 * DENY-WINS merge (mergeExternalBackendDecision) and the provenance computation
 * (backendProvenance) and must reach identical results. A divergence is a
 * release blocker.
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

interface MergeCase {
  id: string;
  desc: string;
  local: LocalDecision;
  outcome: BackendOutcome;
  shadow: boolean;
  expect: { decision: LocalDecision; blocked_by_backend: boolean };
}

interface ProvenanceCase {
  id: string;
  desc: string;
  backend: ExternalPolicyBackendConfig;
  expect: { identity: string; policy_hash: string };
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/external_backend.json'), 'utf-8'),
) as { merge_cases: MergeCase[]; provenance_cases: ProvenanceCase[] };

describe('conformance: external_backend deny-wins merge', () => {
  for (const c of fixture.merge_cases) {
    it(`${c.id}: ${c.desc}`, () => {
      const result = mergeExternalBackendDecision(c.local, c.outcome, c.shadow);
      expect({ where: c.id, ...result }).toEqual({ where: c.id, ...c.expect });
    });
  }
});

describe('conformance: external_backend provenance', () => {
  for (const c of fixture.provenance_cases) {
    it(`${c.id}: ${c.desc}`, () => {
      const prov = backendProvenance(c.backend);
      expect({ where: c.id, ...prov }).toEqual({ where: c.id, ...c.expect });
    });
  }
});
