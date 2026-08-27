import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  reconstructStrictPolicyContinuityV21,
  StrictPolicyContinuityV21Error,
} from '../../src/governance/strict-policy-continuity-v2-1.js';
import {
  signStrictReceiptV21,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
} from '../../src/governance/strict-receipt-v2-1.js';
import type { StrictReceiptV21TrustOptions } from '../../src/governance/strict-receipt-v2-1-verify.js';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const FIXTURE = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8',
));
const clone = <T>(value: T): T => structuredClone(value);

function signer(): DeviceSigner {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-continuity-v21-'));
  const path = join(directory, 'public-test-seed.key');
  writeFileSync(path, FIXTURE.public_test_key.seed_hex, 'ascii');
  return loadDeviceSigner(path);
}

function trust(overrides: Partial<StrictReceiptV21TrustOptions> = {}): StrictReceiptV21TrustOptions {
  return {
    trusted_agent_keys: [{
      tenant_id: 'tenant-21',
      agent_ref_hash: 'b'.repeat(64),
      key_id: FIXTURE.public_test_key.key_id,
      public_key_b64: FIXTURE.public_test_key.public_key_b64,
      status: 'active',
    }],
    allowed_evaluator_manifest_hashes: [FIXTURE.evaluator_manifest_hash],
    ...overrides,
  };
}

function policyChain(): StrictReceiptV21Envelope[] {
  const device = signer();
  const first = signStrictReceiptV21(
    clone(FIXTURE.vector.body) as StrictReceiptV21Body,
    device,
  );
  const next = clone(first.body);
  next.receipt_id = 'session-21:2';
  next.sequence = 2;
  next.previous_receipt_hash = first.receipt_hash;
  next.action.action_id = 'action-22';
  next.evaluation.effective_policy.version = 'policy-v2';
  next.evaluation.effective_policy.artifact_hash = '7'.repeat(64);
  return [first, signStrictReceiptV21(next, device)];
}

describe('strict 2.1 policy continuity', () => {
  it('reconstructs each trusted snapshot and explicit policy transition', () => {
    const receipts = policyChain();
    const report = reconstructStrictPolicyContinuityV21(receipts, trust());

    expect(report).toMatchObject({
      schema: 'obsvr-strict-policy-continuity-v2-1',
      profile_version: '2.1',
      tenant_id: 'tenant-21',
      session_id: 'session-21',
      first_sequence: 1,
      last_sequence: 2,
      receipt_count: 2,
    });
    expect(report.snapshots.map((item) => item.receipt_hash)).toEqual(
      receipts.map((item) => item.receipt_hash),
    );
    expect(report.transitions).toEqual([{
      at_sequence: 2,
      receipt_hash: receipts[1].receipt_hash,
      from_policy_version: FIXTURE.vector.body.evaluation.effective_policy.version,
      from_policy_artifact_hash: FIXTURE.vector.body.evaluation.effective_policy.artifact_hash,
      from_evaluator_manifest_hash: FIXTURE.evaluator_manifest_hash,
      to_policy_version: 'policy-v2',
      to_policy_artifact_hash: '7'.repeat(64),
      to_evaluator_manifest_hash: FIXTURE.evaluator_manifest_hash,
    }]);
    expect(report.timeline_hash).toBe('2f4fad842cd5798f9a1094c887b89d99a15ab46c848bd69882348f2c4fd2e34c');
  });

  it('refuses incomplete, tampered, and untrusted histories', () => {
    const receipts = policyChain();
    expect(() => reconstructStrictPolicyContinuityV21([], trust()))
      .toThrow(StrictPolicyContinuityV21Error);
    expect(() => reconstructStrictPolicyContinuityV21([receipts[1]], trust()))
      .toThrow(/sequence_order_invalid/);
    const tampered = clone(receipts);
    tampered[1].body.evaluation.effective_policy.version = 'quiet-rewrite';
    expect(() => reconstructStrictPolicyContinuityV21(tampered, trust()))
      .toThrow(/receipt_hash_invalid/);
    expect(() => reconstructStrictPolicyContinuityV21(receipts, trust({
      allowed_evaluator_manifest_hashes: [],
    }))).toThrow(/receipt_evaluator_untrusted/);
  });
});
