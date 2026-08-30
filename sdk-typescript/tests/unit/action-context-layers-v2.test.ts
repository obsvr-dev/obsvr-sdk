import { readFileSync } from 'node:fs';
import {
  ActionContextV2ValidationError,
  actionContextV2Hash,
  buildActionContextV2,
  canonicalizeActionContextV2,
  type ActionContextV2Input,
} from '../../src/governance/action-context-v2.js';

const fixture = JSON.parse(readFileSync(
  new URL('../../../conformance/fixtures/action_context_layers_v2.json', import.meta.url),
  'utf8',
)) as {
  claimable: boolean;
  input: ActionContextV2Input;
  expect: { document: object; canonical: string; hash: string };
};

describe('layered v2 action context', () => {
  test('pins the same bounded identity, execution, and governance layers', () => {
    expect(fixture.claimable).toBe(false);
    expect(buildActionContextV2(fixture.input)).toEqual(fixture.expect.document);
    expect(canonicalizeActionContextV2(fixture.input)).toBe(fixture.expect.canonical);
    expect(actionContextV2Hash(fixture.input)).toBe(fixture.expect.hash);
  });

  test('keeps raw targets and arbitrary payload fields out of every layer', () => {
    const canonical = canonicalizeActionContextV2(fixture.input);
    expect(canonical).not.toContain('tenant/acme/contract/42');
    expect(() => buildActionContextV2({
      ...fixture.input,
      governance: {
        ...fixture.input.governance!,
        raw_prompt: 'do not store this',
      } as never,
    })).toThrow(ActionContextV2ValidationError);
  });

  test('rejects unknown enum values and malformed evidence hashes', () => {
    expect(() => buildActionContextV2({
      ...fixture.input,
      execution: { ...fixture.input.execution!, autonomy_level: 'unbounded' as never },
    })).toThrow('execution.autonomy_level is unsupported');
    expect(() => buildActionContextV2({
      ...fixture.input,
      governance: { ...fixture.input.governance!, coverage_claim_hash: 'not-a-hash' },
    })).toThrow('governance.coverage_claim_hash');
  });
});
