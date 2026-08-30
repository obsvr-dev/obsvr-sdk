import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadDeviceSigner } from '../../src/proxy/device-identity.js';
import { policyTemplateV1Hash, renderPolicyTemplateV1, signRenderedPolicyV1, verifyRenderedPolicyV1 } from '../../src/governance/policy-template-v1.js';

const template = { template_id: 'external-send', version: '1', parameters: [{ name: 'max_actions', type: 'integer' as const }, { name: 'review', type: 'enum' as const, enum_values: ['human', 'manager'] }], artifact: { rules: [{ id: 'send-limit', limit: { $obsvr_param: 'max_actions' }, approval: { $obsvr_param: 'review' } }] } };

describe('policy template v1', () => {
  test('renders typed whole-value parameters with full provenance', () => {
    const rendered = renderPolicyTemplateV1(template, { max_actions: 5, review: 'manager' }, 'a'.repeat(64), 'b'.repeat(64));
    expect(rendered.rendered_artifact).toEqual({ rules: [{ id: 'send-limit', limit: 5, approval: 'manager' }] });
    expect(rendered.template_hash).toBe(policyTemplateV1Hash(template));
    expect(rendered.template_hash).toBe('3cb8e4d81dea15ec1d070bae3de8bdd3c90ba73242e91368b7bf0f1c200443e8');
    expect(rendered.artifact_hash).toHaveLength(64);
  });
  test('signs exact rendered provenance and detects tampering', () => {
    const rendered = renderPolicyTemplateV1(template, { max_actions: 5, review: 'manager' }, 'a'.repeat(64), 'b'.repeat(64));
    const path = join(mkdtempSync(join(tmpdir(), 'obsvr-template-')), 'key'); writeFileSync(path, '22'.repeat(32));
    const signer = loadDeviceSigner(path); const envelope = signRenderedPolicyV1(rendered, signer);
    expect(verifyRenderedPolicyV1(envelope, signer.rawPublicKey)).toBe(true);
    envelope.body.rendered_artifact = { changed: true }; expect(verifyRenderedPolicyV1(envelope, signer.rawPublicKey)).toBe(false);
  });
  test('rejects missing, extra, and mistyped parameters', () => {
    expect(() => renderPolicyTemplateV1(template, { max_actions: 5 }, 'a'.repeat(64), 'b'.repeat(64))).toThrow('missing parameter');
    expect(() => renderPolicyTemplateV1(template, { max_actions: 5, review: 'human', raw: true }, 'a'.repeat(64), 'b'.repeat(64))).toThrow('undeclared');
    expect(() => renderPolicyTemplateV1(template, { max_actions: 'five', review: 'human' }, 'a'.repeat(64), 'b'.repeat(64))).toThrow('does not match');
  });
});
