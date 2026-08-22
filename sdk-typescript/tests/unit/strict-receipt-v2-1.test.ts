import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDeviceSigner, type DeviceSigner } from '../../src/proxy/device-identity.js';
import {
  canonicalizeStrictReceiptV21Body,
  signStrictReceiptV21,
  strictReceiptV21Hash,
  type StrictReceiptV21Body,
  type StrictReceiptV21Envelope,
} from '../../src/governance/strict-receipt-v2-1.js';
import {
  verifyStrictReceiptV21,
  verifyStrictReceiptV21Chain,
  type StrictReceiptV21TrustOptions,
} from '../../src/governance/strict-receipt-v2-1-verify.js';
import { signStrictReceiptV2, type StrictReceiptV2Body } from '../../src/governance/strict-receipt-v2.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const FIXTURE = JSON.parse(readFileSync(join(ROOT, 'conformance/fixtures/strict_receipts_v2_1.json'), 'utf8'));
const V20 = JSON.parse(readFileSync(join(ROOT, 'conformance/fixtures/strict_receipts_v2.json'), 'utf8'));
const clone = <T>(value: T): T => structuredClone(value);
function signer(seedHex = FIXTURE.public_test_key.seed_hex): DeviceSigner {
  const directory = mkdtempSync(join(tmpdir(), 'obsvr-strict-v21-'));
  const path = join(directory, 'public-test-seed.key'); writeFileSync(path, seedHex, 'ascii');
  return loadDeviceSigner(path);
}
function body(): StrictReceiptV21Body { return clone(FIXTURE.vector.body) as StrictReceiptV21Body; }
function modifyBody(): StrictReceiptV21Body {
  const result = body(); const patch = FIXTURE.modify_vector.body_patch;
  result.receipt_id = patch.receipt_id; result.session_id = patch.session_id;
  result.action.action_id = patch.action_id;
  result.action.effective_arguments_hash = patch.effective_arguments_hash;
  result.evaluation.requested_outcome = patch.requested_outcome;
  result.evaluation.outcome = patch.outcome; result.outcome = patch.outcome;
  result.execution_authorized = patch.execution_authorized; delete result.suspension;
  return result;
}
function trust(overrides: Partial<StrictReceiptV21TrustOptions> = {}): StrictReceiptV21TrustOptions {
  return {
    trusted_agent_keys: [{ tenant_id: 'tenant-21', agent_ref_hash: 'b'.repeat(64),
      key_id: FIXTURE.public_test_key.key_id, public_key_b64: FIXTURE.public_test_key.public_key_b64,
      status: 'active' }],
    allowed_evaluator_manifest_hashes: [FIXTURE.evaluator_manifest_hash], ...overrides,
  };
}
function signed(): StrictReceiptV21Envelope { return signStrictReceiptV21(body(), signer()); }

describe('strict receipt profile 2.1 fixtures and trust', () => {
  it('pins cross-language canonical bytes, hash, signature, and non-conformance status', () => {
    const envelope = signed();
    expect(FIXTURE.claimable).toBe(false);
    expect(FIXTURE.description).toContain('not official AARM conformance vectors');
    expect(canonicalizeStrictReceiptV21Body(body())).toBe(FIXTURE.vector.canonical);
    expect(strictReceiptV21Hash(body())).toBe(FIXTURE.vector.receipt_hash);
    expect(envelope.receipt_hash).toBe(FIXTURE.vector.receipt_hash);
    expect(envelope.signature.value).toBe(FIXTURE.vector.signature);
  });

  it('separates cryptographic integrity from registry and evaluator trust', () => {
    const envelope = signed();
    const unknown = verifyStrictReceiptV21(envelope, {
      trusted_agent_keys: [], allowed_evaluator_manifest_hashes: [FIXTURE.evaluator_manifest_hash],
    });
    expect(unknown).toMatchObject({ integrity_valid: true, key_trust: 'unknown',
      evaluator_trust: 'allowlisted', trusted: false });
    expect(verifyStrictReceiptV21(envelope, trust())).toMatchObject({
      integrity_valid: true, key_trust: 'trusted', evaluator_trust: 'allowlisted', trusted: true,
    });
    expect(verifyStrictReceiptV21(envelope, trust({
      trusted_agent_keys: trust().trusted_agent_keys.map((entry) => ({ ...entry, status: 'revoked' })),
    }))).toMatchObject({ integrity_valid: true, key_trust: 'revoked', trusted: false });
    expect(verifyStrictReceiptV21(envelope, trust({ allowed_evaluator_manifest_hashes: [] })))
      .toMatchObject({ integrity_valid: true, evaluator_trust: 'unknown', trusted: false });
  });

  it('pins MODIFY effective execution bytes and refuses ambiguous action hashes', () => {
    const modified = signStrictReceiptV21(modifyBody(), signer());
    expect(canonicalizeStrictReceiptV21Body(modified.body)).toBe(FIXTURE.modify_vector.canonical);
    expect(modified.receipt_hash).toBe(FIXTURE.modify_vector.receipt_hash);
    expect(modified.signature.value).toBe(FIXTURE.modify_vector.signature);
    const tampered = clone(modified); tampered.body.action.effective_arguments_hash = '6'.repeat(64);
    expect(verifyStrictReceiptV21(tampered, trust())).toMatchObject({ hash_valid: false, trusted: false });
    const missing = modifyBody(); delete missing.action.effective_arguments_hash;
    expect(() => signStrictReceiptV21(missing, signer())).toThrow(/effective_arguments_hash/);
    const unchanged = modifyBody(); unchanged.action.effective_arguments_hash = unchanged.action.arguments_hash;
    expect(() => signStrictReceiptV21(unchanged, signer())).toThrow(/must differ/);
    const nonModify = body(); nonModify.action.effective_arguments_hash = '5'.repeat(64);
    expect(() => signStrictReceiptV21(nonModify, signer())).toThrow(/only for MODIFY/);
  });

  it.each([
    ['requester', (value: StrictReceiptV21Envelope) => { value.body.identity.requester.requester_ref_hash = '9'.repeat(64); }],
    ['delegation', (value: StrictReceiptV21Envelope) => { value.body.identity.delegation_chain[0]!.delegation_id_hash = '9'.repeat(64); }],
    ['policy', (value: StrictReceiptV21Envelope) => { value.body.evaluation.effective_policy.artifact_hash = '9'.repeat(64); }],
    ['detector', (value: StrictReceiptV21Envelope) => { value.body.evaluation.detectors[0]!.result_hash = '9'.repeat(64); }],
    ['manifest', (value: StrictReceiptV21Envelope) => { value.body.evaluation.evaluator_manifest_hash = '9'.repeat(64); }],
  ])('detects %s evidence tampering', (_label, mutate) => {
    const envelope = signed(); mutate(envelope);
    const result = verifyStrictReceiptV21(envelope, trust());
    expect(result.hash_valid).toBe(false); expect(result.trusted).toBe(false);
  });

  it('binds trust records to tenant, agent, key bytes, and unambiguous tuples', () => {
    const envelope = signed(); const base = trust().trusted_agent_keys[0]!;
    for (const changed of [
      { ...base, tenant_id: 'other' }, { ...base, agent_ref_hash: '8'.repeat(64) },
      { ...base, public_key_b64: Buffer.alloc(32, 7).toString('base64') },
    ]) expect(verifyStrictReceiptV21(envelope, trust({ trusted_agent_keys: [changed] })).trusted).toBe(false);
    expect(verifyStrictReceiptV21(envelope, trust({ trusted_agent_keys: [base, { ...base }] })))
      .toMatchObject({ key_trust: 'malformed', trusted: false });
  });
});

describe('strict receipt profile 2.1 resolution and isolation', () => {
  function resolution(target: StrictReceiptV21Envelope): StrictReceiptV21Body {
    const result = clone(target.body); result.record_type = 'resolution'; result.receipt_id = 'session-21:2';
    result.sequence = 2; result.previous_receipt_hash = target.receipt_hash; delete result.suspension;
    result.timestamp_ms += 100;
    result.evaluation = { ...result.evaluation, requested_outcome: 'ALLOW', outcome: 'ALLOW' };
    result.outcome = 'ALLOW'; result.execution_authorized = true;
    result.resolution = { resolves_receipt_hash: target.receipt_hash, suspension_id: 'approval-21',
      method: 'approval_granted', resolver_ref_hash: '4'.repeat(64), resolved_at_ms: result.timestamp_ms };
    return result;
  }

  it('accepts a resolution only when original identity and delegation bytes are preserved', () => {
    const target = signed(); const resolved = signStrictReceiptV21(resolution(target), signer());
    expect(verifyStrictReceiptV21Chain([target, resolved], trust())).toEqual({ valid: true, errors: [] });
    const changed = resolution(target); changed.identity = clone(changed.identity);
    changed.identity.requester.requester_ref_hash = '8'.repeat(64);
    changed.identity.delegation_chain[0]!.delegator_ref_hash = '8'.repeat(64);
    const resigned = signStrictReceiptV21(changed, signer());
    expect(verifyStrictReceiptV21Chain([target, resigned], trust()).errors)
      .toContain('resolution_identity_mismatch:session-21:2');
    const changedTime = resolution(target); changedTime.identity = clone(changedTime.identity);
    changedTime.identity.receipt_time_ms = changedTime.timestamp_ms;
    const resignedTime = signStrictReceiptV21(changedTime, signer());
    expect(verifyStrictReceiptV21Chain([target, resignedTime], trust()).errors)
      .toContain('resolution_identity_mismatch:session-21:2');
  });

  it('rejects unknown keys and evaluator manifests at chain trust boundary', () => {
    expect(verifyStrictReceiptV21Chain([signed()], trust({ trusted_agent_keys: [] })).errors)
      .toContain('receipt_key_untrusted:session-21:1');
    expect(verifyStrictReceiptV21Chain([signed()], trust({ allowed_evaluator_manifest_hashes: [] })).errors)
      .toContain('receipt_evaluator_untrusted:session-21:1');
  });

  it('keeps profile 2.0 canonical bytes, hash, and signature unchanged', () => {
    const input = clone(V20.vectors[0].body) as StrictReceiptV2Body;
    input.evaluation.rule_ids = clone(V20.vectors[0].input_rule_ids);
    const envelope = signStrictReceiptV2(input, signer(), true);
    expect(envelope.receipt_hash).toBe(V20.vectors[0].receipt_hash);
    expect(envelope.signature.value).toBe(V20.vectors[0].signature);
  });
});
