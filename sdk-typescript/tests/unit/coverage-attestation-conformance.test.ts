import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { BindingEntry } from '../../src/binding-report.js';
import {
  buildCoverageAttestationBody,
  coverageAttestationBodyHash,
  signCoverageAttestation,
  verifyCoverageAttestation,
} from '../../src/governance/coverage-attestation.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';

const fixture = JSON.parse(readFileSync(
  new URL('../../../conformance/fixtures/coverage_attestation.json', import.meta.url),
  'utf8',
));

function snapshot(): Record<string, Record<string, BindingEntry>> {
  const out: Record<string, Record<string, BindingEntry>> = {};
  for (const binding of fixture.bindings) {
    out[binding.integration] ??= {};
    out[binding.integration][binding.symbol] = {
      bound: binding.bound,
      enforcementDepth: binding.enforcement_depth,
      integrationVersion: binding.integration_version,
      initializedAtMs: binding.initialized_at_ms,
      exclusions: binding.exclusions,
    };
  }
  return out;
}

describe('coverage attestation cross-language contract', () => {
  test('pins the canonical body and reports insufficient enforcement depth', () => {
    const body = buildCoverageAttestationBody(fixture.input, snapshot());
    expect(coverageAttestationBodyHash(body)).toBe(fixture.expected_body_hash);
    expect(body.coverage_complete).toBe(false);
    expect(body.failures).toEqual([{
      integration: 'langchain.models',
      symbol: 'langchain.callbacks',
      reason: 'insufficient_depth',
      required_depth: 'enforce',
      actual_depth: 'observe',
    }]);
  });

  test('signs, verifies, and detects tampering under a pinned device key', () => {
    const keyPath = join(mkdtempSync(join(tmpdir(), 'obsvr-coverage-')), 'key');
    writeFileSync(keyPath, '00'.repeat(32), 'ascii');
    const signer = loadDeviceSigner(keyPath);
    const envelope = signCoverageAttestation(fixture.input, signer, snapshot());
    expect(verifyCoverageAttestation(envelope, signer.rawPublicKey)).toMatchObject({
      valid: true,
      reason: 'valid',
      body_hash: fixture.expected_body_hash,
    });
    const tampered = structuredClone(envelope);
    tampered.body.workload_id = 'other-worker';
    expect(verifyCoverageAttestation(tampered, signer.rawPublicKey)).toMatchObject({
      valid: false,
      reason: 'body_hash_mismatch',
    });
  });

  test('does not treat legacy unknown-depth binds as enforcement coverage', () => {
    const legacy = snapshot();
    legacy['action:contract.send']['contract.send'].enforcementDepth = 'unknown';
    const body = buildCoverageAttestationBody(fixture.input, legacy);
    expect(body.failures).toContainEqual(expect.objectContaining({
      integration: 'action:contract.send',
      reason: 'insufficient_depth',
      actual_depth: 'unknown',
    }));
  });

  test('rejects extra fields and rewritten derived coverage results', () => {
    const keyPath = join(mkdtempSync(join(tmpdir(), 'obsvr-coverage-')), 'key');
    writeFileSync(keyPath, '00'.repeat(32), 'ascii');
    const signer = loadDeviceSigner(keyPath);
    const envelope = signCoverageAttestation(fixture.input, signer, snapshot());

    const extra = structuredClone(envelope) as typeof envelope & {
      body: typeof envelope.body & { trusted?: boolean };
    };
    extra.body.trusted = true;
    expect(verifyCoverageAttestation(extra, signer.rawPublicKey)).toMatchObject({
      valid: false,
      reason: 'invalid_body',
    });

    const rewritten = structuredClone(envelope);
    rewritten.body.coverage_complete = true;
    rewritten.body.failures = [];
    expect(verifyCoverageAttestation(rewritten, signer.rawPublicKey)).toMatchObject({
      valid: false,
      reason: 'invalid_body',
    });
  });
});
