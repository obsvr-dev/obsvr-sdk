import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';
import { WorkloadRegistryV1, buildWorkloadRegistrationV1, signWorkloadRegistrationV1, verifyWorkloadRegistrationV1, workloadRegistrationV1Hash } from '../../src/governance/workload-registry-v1.js';

const registration = {
  workload_id: 'spotdraft-contract-ai', owner_ref_hash: '1'.repeat(64), environment: 'production', deployment_id: 'deploy-7', autonomy: 'supervised' as const,
  entry_points: ['contract.review'], capabilities: ['contract.read', 'contract.redline'], providers: ['openai'], models: ['gpt-5'], tools: ['contract.send'], mcp_servers: [], data_zones: ['customer-contracts'], external_side_effects: ['email.send'], required_approvals: ['external-send'], policy_pack_hashes: ['2'.repeat(64)], coverage_attestation_hash: '3'.repeat(64), registered_at_ms: 1_788_131_200_000,
};

describe('workload registry v1', () => {
  test('is content addressed consistently', () => {
    expect(workloadRegistrationV1Hash(registration)).toBe('47df34cfc47fe72aaa57abc64d0c55854708aee7ee775141e7de09351b58db0e');
    expect(buildWorkloadRegistrationV1({ ...registration, capabilities: ['contract.redline', 'contract.read'] })).toEqual(buildWorkloadRegistrationV1(registration));
  });
  test('accepts only signed registrations and detects tampering', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'obsvr-registry-')), 'key'); writeFileSync(path, '11'.repeat(32));
    const signer = loadDeviceSigner(path); const envelope = signWorkloadRegistrationV1(registration, signer);
    expect(verifyWorkloadRegistrationV1(envelope, signer.rawPublicKey)).toBe(true);
    const registry = new WorkloadRegistryV1(); registry.register(envelope, signer.rawPublicKey); expect(registry.snapshot()).toHaveLength(1);
    const tampered = structuredClone(envelope); tampered.body.autonomy = 'autonomous';
    expect(verifyWorkloadRegistrationV1(tampered, signer.rawPublicKey)).toBe(false);
  });
  test('rejects raw inventory fields and empty control bindings', () => {
    expect(() => buildWorkloadRegistrationV1({ ...registration, prompt: 'secret' } as never)).toThrow('unsupported field');
    expect(() => buildWorkloadRegistrationV1({ ...registration, policy_pack_hashes: [] })).toThrow('must be nonempty');
  });
});
