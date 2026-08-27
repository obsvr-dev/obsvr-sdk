import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity.js';
import {
  createStrictEvidenceBundleV21,
  verifyStrictEvidenceBundleV21,
} from '../../src/governance/strict-evidence-bundle-v2-1.js';
import { signStrictExecutionOutcomeV21 } from '../../src/governance/strict-execution-outcome-v2-1.js';
import {
  signStrictReceiptV21,
  type StrictReceiptV21Body,
} from '../../src/governance/strict-receipt-v2-1.js';
import type { StrictReceiptV21TrustOptions } from '../../src/governance/strict-receipt-v2-1-verify.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const DECISION = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8',
));
const OUTCOME = JSON.parse(readFileSync(
  join(ROOT, 'conformance/fixtures/strict_execution_outcomes_v2_1.json'), 'utf8',
));
const clone = <T>(value: T): T => structuredClone(value);

function signer(seedHex = DECISION.public_test_key.seed_hex): DeviceSigner {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-bundle-v21-'));
  const path = join(directory, 'public-test-seed.key');
  writeFileSync(path, seedHex, 'ascii');
  return loadDeviceSigner(path);
}

function decisionBody(): StrictReceiptV21Body {
  const body = clone(DECISION.vector.body) as StrictReceiptV21Body;
  const patch = OUTCOME.decision_patch;
  body.evaluation.requested_outcome = patch.evaluation.requested_outcome;
  body.evaluation.outcome = patch.evaluation.outcome;
  body.evaluation.decision_reason_codes = clone(patch.evaluation.decision_reason_codes);
  body.outcome = patch.outcome;
  body.execution_authorized = patch.execution_authorized;
  for (const field of patch.remove) delete (body as unknown as Record<string, unknown>)[field];
  return body;
}

function trust(): StrictReceiptV21TrustOptions {
  return {
    trusted_agent_keys: [{
      tenant_id: 'tenant-21', agent_ref_hash: 'b'.repeat(64),
      key_id: DECISION.public_test_key.key_id,
      public_key_b64: DECISION.public_test_key.public_key_b64, status: 'active',
    }],
    allowed_evaluator_manifest_hashes: [DECISION.evaluator_manifest_hash],
  };
}

function evidence() {
  const device = signer();
  const receipt = signStrictReceiptV21(decisionBody(), device);
  const outcome = signStrictExecutionOutcomeV21(clone(OUTCOME.vector.body), device, receipt);
  return { device, receipt, outcome };
}

describe('strict evidence bundle profile 2.1', () => {
  it('pins a complete portable bundle across languages', () => {
    const { device, receipt, outcome } = evidence();
    const bundle = createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [outcome], trust: trust(), signer: device,
    });
    expect(bundle.body.complete).toBe(true);
    expect(bundle.body.head_receipt_hash).toBe(receipt.receipt_hash);
    expect(bundle.body.coverage).toEqual([{
      sequence: 1, receipt_hash: receipt.receipt_hash, record_type: 'decision',
      execution_authorized: true, execution_status: 'succeeded',
      outcome_hash: outcome.outcome_hash,
    }]);
    expect(bundle.body.policy_continuity.receipt_count).toBe(1);
    expect(verifyStrictEvidenceBundleV21(bundle, trust())).toMatchObject({
      trusted: true, complete: true, errors: [],
    });
    expect(bundle.bundle_hash).toBe('bb61c84ef82eb3f93d1c68a4c7c8c97d3ad285e0a879f0fda233f7adbe23ed8c');
    expect(bundle.signature.value).toBe(
      '256d1046b8ae2610d32204f7c0789446a657b0662baf9fa2cbc9aabaccfe3a64072ee74079e32c558942da7439e3b8f4f942a053eb7c5b865343dcc085da250e',
    );
  });

  it('keeps missing terminal outcomes visible without invalidating the bundle', () => {
    const { device, receipt } = evidence();
    const bundle = createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [], trust: trust(), signer: device,
    });
    expect(bundle.body.coverage[0].execution_status).toBe('missing');
    expect(verifyStrictEvidenceBundleV21(bundle, trust())).toMatchObject({
      trusted: true, complete: false,
    });
  });

  it('rejects component tampering and a signer different from the chain head', () => {
    const { device, receipt, outcome } = evidence();
    const bundle = createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [outcome], trust: trust(), signer: device,
    });
    const tampered = clone(bundle);
    tampered.body.coverage[0].execution_status = 'failed';
    expect(verifyStrictEvidenceBundleV21(tampered, trust()).trusted).toBe(false);
    expect(() => createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [outcome], trust: trust(),
      signer: signer('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'),
    })).toThrow(/must match the head receipt signer/);
  });

  it('rejects hostile component and envelope mutations', () => {
    const { device, receipt, outcome } = evidence();
    const bundle = createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [outcome], trust: trust(), signer: device,
    });

    const receiptTamper = clone(bundle);
    receiptTamper.body.receipts[0].body.action.name = 'substituted_action';
    expect(verifyStrictEvidenceBundleV21(receiptTamper, trust())).toMatchObject({
      trusted: false,
      complete: false,
      errors: expect.arrayContaining(['bundle_components_untrusted']),
    });

    const outcomeTamper = clone(bundle);
    const originalSignature = outcomeTamper.body.execution_outcomes[0].signature.value;
    outcomeTamper.body.execution_outcomes[0].signature.value =
      `${originalSignature[0] === '0' ? '1' : '0'}${originalSignature.slice(1)}`;
    expect(verifyStrictEvidenceBundleV21(outcomeTamper, trust())).toMatchObject({
      trusted: false,
      errors: expect.arrayContaining(['bundle_components_untrusted']),
    });

    const extraEnvelopeKey = clone(bundle) as unknown as Record<string, unknown>;
    extraEnvelopeKey.unexpected = true;
    expect(verifyStrictEvidenceBundleV21(extraEnvelopeKey, trust())).toMatchObject({
      schema_valid: false,
      trusted: false,
    });

    const extraBodyKey = clone(bundle);
    (extraBodyKey.body as unknown as Record<string, unknown>).unexpected = true;
    expect(verifyStrictEvidenceBundleV21(extraBodyKey, trust())).toMatchObject({
      semantic_valid: false,
      trusted: false,
    });

    const malformedKey = clone(bundle);
    malformedKey.public_key_b64 = 'not-a-public-key';
    expect(verifyStrictEvidenceBundleV21(malformedKey, trust())).toMatchObject({
      schema_valid: false,
      signature_valid: false,
      signer_binding_valid: false,
      trusted: false,
    });

    const malformedSignature = clone(bundle);
    malformedSignature.signature.value = '00';
    expect(verifyStrictEvidenceBundleV21(malformedSignature, trust())).toMatchObject({
      schema_valid: false,
      signature_valid: false,
      trusted: false,
    });
  });

  it('refuses duplicate, foreign, partial, and externally untrusted evidence', () => {
    const { device, receipt, outcome } = evidence();
    expect(() => createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [outcome, clone(outcome)],
      trust: trust(), signer: device,
    })).toThrow(/duplicate execution outcomes/);

    const foreign = clone(outcome);
    foreign.body.decision_receipt_hash = 'f'.repeat(64);
    expect(() => createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [foreign], trust: trust(), signer: device,
    })).toThrow(/outside the bundle/);

    const partialBody = decisionBody();
    partialBody.sequence = 2;
    partialBody.previous_receipt_hash = receipt.receipt_hash;
    const partial = signStrictReceiptV21(partialBody, device);
    expect(() => createStrictEvidenceBundleV21({
      receipts: [partial], execution_outcomes: [], trust: trust(), signer: device,
    })).toThrow(/receipt chain is not trusted/);

    const bundle = createStrictEvidenceBundleV21({
      receipts: [receipt], execution_outcomes: [outcome], trust: trust(), signer: device,
    });
    expect(verifyStrictEvidenceBundleV21(bundle, {
      trusted_agent_keys: [],
      allowed_evaluator_manifest_hashes: trust().allowed_evaluator_manifest_hashes,
    })).toMatchObject({ trusted: false, complete: false });
    expect(verifyStrictEvidenceBundleV21(bundle, {
      trusted_agent_keys: trust().trusted_agent_keys,
      allowed_evaluator_manifest_hashes: [],
    })).toMatchObject({ trusted: false, complete: false });
  });
});
