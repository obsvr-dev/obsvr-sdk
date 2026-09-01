import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { jest } from '@jest/globals';
import { signCoverageAttestation } from '../../src/governance/coverage-attestation.js';
import {
  DeploymentProofPublishError,
  publishDeploymentProofs,
  type DeploymentProofPinnedTransport,
} from '../../src/governance/deployment-proof-client.js';
import { signWorkloadRegistrationV1 } from '../../src/governance/workload-registry-v1.js';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';

function proofs() {
  const path = join(mkdtempSync(join(tmpdir(), 'obsvr-deploy-proof-')), 'key');
  writeFileSync(path, '33'.repeat(32));
  const signer = loadDeviceSigner(path);
  const now = 1_788_131_200_000;
  const coverage = signCoverageAttestation({
    attestation_id: 'att-1', workload_id: 'contract-ai', environment: 'production',
    sdk_language: 'typescript', sdk_version: '0.16.0', generated_at_ms: now,
    valid_until_ms: now + 60_000, required: [], policy_pack_hashes: ['a'.repeat(64)],
  }, signer, {});
  const workload = signWorkloadRegistrationV1({
    workload_id: 'contract-ai', owner_ref_hash: 'b'.repeat(64), environment: 'production',
    deployment_id: 'deploy-1', autonomy: 'supervised', entry_points: ['contract.review'],
    capabilities: ['control'], providers: ['openai'], models: ['gpt-5'],
    tools: ['send_email'], mcp_servers: [], data_zones: ['contracts'],
    external_side_effects: ['email'], required_approvals: ['send_email'],
    policy_pack_hashes: ['a'.repeat(64)], coverage_attestation_hash: coverage.body_hash,
    registered_at_ms: now,
  }, signer);
  return { signer, coverage, workload };
}

function response(payload: unknown): Uint8Array {
  return Buffer.from(JSON.stringify(payload));
}

describe('deployment proof publication', () => {
  test('publishes accepted exact coverage before the workload over pinned requests', async () => {
    const { signer, coverage, workload } = proofs();
    const requests: Array<{ path: string; body: string; headers: Readonly<Record<string, string>> }> = [];
    const transport: DeploymentProofPinnedTransport = async (target, body, headers) => {
      requests.push({ path: target.url.pathname, body, headers });
      return target.url.pathname.endsWith('/coverage/attestations')
        ? { status: 202, body: response({
          ok: true, body_hash: coverage.body_hash, coverage_complete: true,
          trust: 'pinned',
        }) }
        : { status: 202, body: response({
          ok: true, body_hash: workload.body_hash, workload_id: 'contract-ai',
          deployment_id: 'deploy-1', trust: 'pinned',
        }) };
    };
    const result = await publishDeploymentProofs(coverage, workload, {
      ingest_url: 'https://ingest.example.test/base', api_key: 'api-test', signer,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: transport,
    });
    expect(result).toEqual({
      coverage: {
        disposition: 'accepted', kind: 'coverage', body_hash: coverage.body_hash,
        trust: 'pinned',
      },
      workload: {
        disposition: 'accepted', kind: 'workload', body_hash: workload.body_hash,
        trust: 'pinned',
      },
    });
    expect(requests.map(({ path }) => path)).toEqual([
      '/base/coverage/attestations', '/base/workloads/registrations',
    ]);
    expect(JSON.parse(requests[0].body)).toEqual(coverage);
    expect(requests[0].headers).toMatchObject({
      'X-API-Key': 'api-test',
      'X-Obsvr-Device-Public-Key': signer.publicKeyB64,
      'Idempotency-Key': coverage.body_hash,
    });
  });

  test('does not register a workload when coverage is rejected', async () => {
    const { signer, coverage, workload } = proofs();
    const paths: string[] = [];
    const result = await publishDeploymentProofs(coverage, workload, {
      ingest_url: 'https://ingest.example.test', api_key: 'api-test', signer,
      resolver: async () => ['8.8.8.8'],
      trusted_pinned_transport: async (target) => {
        paths.push(target.url.pathname);
        return { status: 403, body: response({ ok: false, error: 'coverage_key_revoked' }) };
      },
    });
    expect(result.coverage).toMatchObject({ disposition: 'rejected', http_status: 403 });
    expect(result.workload).toMatchObject({
      disposition: 'not_attempted', reason: 'coverage_not_accepted',
    });
    expect(paths).toEqual(['/coverage/attestations']);
  });

  test('refuses mismatched bindings and unsafe endpoints before transport', async () => {
    const { signer, coverage, workload } = proofs();
    const transport = jest.fn() as jest.MockedFunction<DeploymentProofPinnedTransport>;
    const mismatched = structuredClone(workload);
    mismatched.body.coverage_attestation_hash = 'f'.repeat(64);
    await expect(publishDeploymentProofs(coverage, mismatched, {
      ingest_url: 'https://ingest.example.test', api_key: 'api-test', signer,
      resolver: async () => ['8.8.8.8'], trusted_pinned_transport: transport,
    })).rejects.toBeInstanceOf(DeploymentProofPublishError);
    await expect(publishDeploymentProofs(coverage, undefined, {
      ingest_url: 'http://169.254.169.254', api_key: 'api-test', signer,
      trusted_pinned_transport: transport,
    })).rejects.toThrow('static security validation');
    expect(transport).not.toHaveBeenCalled();
  });

  test('bounds DNS resolution inside the total publication timeout', async () => {
    const { signer, coverage } = proofs();
    const transport = jest.fn() as jest.MockedFunction<DeploymentProofPinnedTransport>;
    const started = Date.now();
    const result = await publishDeploymentProofs(coverage, undefined, {
      ingest_url: 'https://ingest.example.test', api_key: 'api-test', signer,
      timeout_ms: 20,
      resolver: () => new Promise<string[]>(() => undefined),
      trusted_pinned_transport: transport,
    });
    expect(result.coverage).toMatchObject({
      disposition: 'uncertain', reason: 'transport_error',
    });
    expect(Date.now() - started).toBeLessThan(500);
    expect(transport).not.toHaveBeenCalled();
  });
});
