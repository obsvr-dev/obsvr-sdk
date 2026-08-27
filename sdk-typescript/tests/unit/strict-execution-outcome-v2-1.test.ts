import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity.js';
import {
  canonicalizeStrictExecutionOutcomeV21Body,
  signStrictExecutionOutcomeV21,
  strictExecutionOutcomeV21Hash,
  strictExecutionResultV21Hash,
  strictExecutionStartV21Hash,
  verifyStrictExecutionOutcomeV21,
  type StrictExecutionOutcomeV21Body,
} from '../../src/governance/strict-execution-outcome-v2-1.js';
import {
  signStrictReceiptV21,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
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
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-outcome-v21-'));
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

function decision(): StrictReceiptV21Envelope {
  return signStrictReceiptV21(decisionBody(), signer());
}

function outcomeBody(): StrictExecutionOutcomeV21Body {
  return clone(OUTCOME.vector.body) as StrictExecutionOutcomeV21Body;
}

function trust(): StrictReceiptV21TrustOptions {
  return {
    trusted_agent_keys: [{
      tenant_id: 'tenant-21',
      agent_ref_hash: 'b'.repeat(64),
      key_id: DECISION.public_test_key.key_id,
      public_key_b64: DECISION.public_test_key.public_key_b64,
      status: 'active',
    }],
    allowed_evaluator_manifest_hashes: [DECISION.evaluator_manifest_hash],
  };
}

describe('strict execution outcome profile 2.1', () => {
  it('pins cross-language start, result, body, hash, signature, and trust', () => {
    const admitted = decision();
    expect(admitted.receipt_hash).toBe(OUTCOME.decision_receipt_hash);
    expect(strictExecutionResultV21Hash(OUTCOME.result_projection))
      .toBe(OUTCOME.vector.body.result_hash);
    const body = outcomeBody();
    expect(strictExecutionStartV21Hash({
      tenant_id: body.tenant_id,
      session_id: body.session_id,
      action_id: body.action_id,
      decision_receipt_hash: body.decision_receipt_hash,
      operation_fingerprint: body.operation_fingerprint,
      attempt: 1,
      started_at_ms: body.started_at_ms,
    })).toBe(body.execution_start_hash);
    expect(createHash('sha256').update(canonicalizeStrictExecutionOutcomeV21Body(body)).digest('hex'))
      .toBe(OUTCOME.vector.canonical_sha256);
    expect(strictExecutionOutcomeV21Hash(body)).toBe(OUTCOME.vector.outcome_hash);
    const envelope = signStrictExecutionOutcomeV21(body, signer(), admitted);
    expect(envelope.signature.value).toBe(OUTCOME.vector.signature);
    expect(verifyStrictExecutionOutcomeV21(envelope, admitted, trust())).toMatchObject({
      integrity_valid: true,
      decision_trusted: true,
      trusted: true,
    });
  });

  it('represents success, failure, and uncertainty without ambiguous fields', () => {
    const admitted = decision();
    for (const patch of OUTCOME.terminal_error_patches) {
      const body = outcomeBody();
      body.status = patch.status;
      body.error_code = patch.error_code;
      delete body.result_hash;
      const envelope = signStrictExecutionOutcomeV21(body, signer(), admitted);
      expect(verifyStrictExecutionOutcomeV21(envelope, admitted, trust()).trusted).toBe(true);
    }
    const failedWithResult = outcomeBody();
    failedWithResult.status = 'failed';
    failedWithResult.error_code = 'provider_rejected';
    expect(() => signStrictExecutionOutcomeV21(failedWithResult, signer(), admitted))
      .toThrow(/cannot contain result_hash/);
    const successWithError = outcomeBody();
    successWithError.error_code = 'provider_rejected';
    expect(() => signStrictExecutionOutcomeV21(successWithError, signer(), admitted))
      .toThrow(/cannot contain error_code/);
  });

  it('rejects tampering, mismatched admission, and the wrong signing key', () => {
    const admitted = decision();
    const envelope = signStrictExecutionOutcomeV21(outcomeBody(), signer(), admitted);
    const tampered = clone(envelope);
    tampered.body.result_hash = '7'.repeat(64);
    expect(verifyStrictExecutionOutcomeV21(tampered, admitted, trust())).toMatchObject({
      hash_valid: false,
      trusted: false,
    });
    const wrongDecisionBody = decisionBody();
    wrongDecisionBody.action.action_id = 'different-action';
    const wrongDecision = signStrictReceiptV21(wrongDecisionBody, signer());
    expect(() => signStrictExecutionOutcomeV21(outcomeBody(), signer(), wrongDecision))
      .toThrow(/does not bind/);
    expect(() => signStrictExecutionOutcomeV21(
      outcomeBody(), signer('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'), admitted,
    )).toThrow(/signer does not match/);
    const tooEarly = outcomeBody();
    tooEarly.started_at_ms = admitted.body.timestamp_ms - 1;
    tooEarly.completed_at_ms = admitted.body.timestamp_ms;
    tooEarly.execution_start_hash = strictExecutionStartV21Hash({
      tenant_id: tooEarly.tenant_id,
      session_id: tooEarly.session_id,
      action_id: tooEarly.action_id,
      decision_receipt_hash: tooEarly.decision_receipt_hash,
      operation_fingerprint: tooEarly.operation_fingerprint,
      attempt: 1,
      started_at_ms: tooEarly.started_at_ms,
    });
    expect(() => signStrictExecutionOutcomeV21(tooEarly, signer(), admitted))
      .toThrow(/does not bind/);
  });

  it('keeps cryptographic integrity separate from external decision trust', () => {
    const admitted = decision();
    const envelope = signStrictExecutionOutcomeV21(outcomeBody(), signer(), admitted);
    expect(verifyStrictExecutionOutcomeV21(envelope, admitted, {
      ...trust(), trusted_agent_keys: [],
    })).toMatchObject({
      integrity_valid: true,
      decision_trusted: false,
      trusted: false,
    });
  });
});
