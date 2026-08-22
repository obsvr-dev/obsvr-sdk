import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  ActionContextV2ValidationError,
  actionContextV2Hash,
  actionTargetHash,
  buildActionContextV2,
  canonicalizeActionContextV2,
  type ActionContextV2Input,
} from '../../src/governance/action-context-v2';

function findFixture(relative: string): string {
  let directory = process.cwd();
  for (let index = 0; index < 6; index += 1) {
    const candidate = path.join(directory, relative);
    if (fs.existsSync(candidate)) return candidate;
    directory = path.dirname(directory);
  }
  throw new Error(`fixture not found: ${relative}`);
}

const FIXTURE = JSON.parse(fs.readFileSync(
  findFixture('conformance/fixtures/action_context_v2.json'), 'utf8',
)) as {
  claimable: boolean;
  target_hash_vectors: Array<{ target: string; target_hash: string }>;
  valid_case: {
    input: ActionContextV2Input;
    expect: { document: object; canonical: string; hash: string };
  };
};

function base(): ActionContextV2Input {
  return {
    agent_id: 'agent', active_intents: ['intent'],
    current_action: {
      kind: 'tool', name: 'send', arguments_hash: 'a'.repeat(64),
      target: 'workspace', data_classifications: [], requested_scopes: [],
    },
    run_id: 'run', prior_actions: [],
  };
}

describe('bounded v2 action context', () => {
  it('pins canonical bytes and exact domain-separated target hashes', () => {
    expect(FIXTURE.claimable).toBe(false);
    for (const vector of FIXTURE.target_hash_vectors) {
      expect(actionTargetHash(vector.target)).toBe(vector.target_hash);
    }
    expect(buildActionContextV2(FIXTURE.valid_case.input))
      .toEqual(FIXTURE.valid_case.expect.document);
    expect(canonicalizeActionContextV2(FIXTURE.valid_case.input))
      .toBe(FIXTURE.valid_case.expect.canonical);
    expect(actionContextV2Hash(FIXTURE.valid_case.input))
      .toBe(FIXTURE.valid_case.expect.hash);
  });

  it('never puts a raw target in the canonical document', () => {
    const canonical = canonicalizeActionContextV2(base());
    expect(canonical).not.toContain('workspace');
    expect(canonical).toContain(`"target_hash":"${actionTargetHash('workspace')}"`);
  });

  it('accepts a 1024-byte target and rejects 1025 bytes', () => {
    expect(buildActionContextV2({
      ...base(), current_action: { ...base().current_action, target: 'x'.repeat(1_024) },
    }).action.target_hash).toBe(actionTargetHash('x'.repeat(1_024)));
    expect(() => buildActionContextV2({
      ...base(), current_action: { ...base().current_action, target: 'x'.repeat(1_025) },
    })).toThrow(ActionContextV2ValidationError);
  });

  it('counts astral UTF-8 bytes and rejects unpaired surrogates', () => {
    expect(() => buildActionContextV2({
      ...base(), current_action: { ...base().current_action, target: '🚀'.repeat(256) },
    })).not.toThrow();
    expect(() => buildActionContextV2({
      ...base(), current_action: { ...base().current_action, target: '🚀'.repeat(257) },
    })).toThrow(ActionContextV2ValidationError);
    expect(() => buildActionContextV2({
      ...base(), current_action: { ...base().current_action, target: '\ud800' },
    })).toThrow(ActionContextV2ValidationError);
  });

  it('uses ASCII blankness and Unicode code-point sorting', () => {
    const input = base();
    input.active_intents = ['😀', '\ue000', '\u00a0'];
    expect(buildActionContextV2(input).agent.active_intents).toEqual(['\u00a0', '\ue000', '😀']);
  });

  it('caps identifiers, sets, prior actions, and canonical context bytes', () => {
    expect(() => buildActionContextV2({ ...base(), agent_id: 'x'.repeat(257) }))
      .toThrow(ActionContextV2ValidationError);
    expect(() => buildActionContextV2({
      ...base(), active_intents: Array.from({ length: 65 }, (_, index) => `i${index}`),
    })).toThrow(ActionContextV2ValidationError);
    const prior = Array.from({ length: 257 }, (_, sequence) => ({
      sequence, kind: 'tool', name: 'prior', outcome: 'ALLOW' as const,
      receipt_hash: 'b'.repeat(64), data_classifications: [],
    }));
    expect(() => buildActionContextV2({ ...base(), prior_actions: prior }))
      .toThrow(ActionContextV2ValidationError);
    const classifications = Array.from(
      { length: 64 }, (_, index) => `${index.toString().padStart(2, '0')}${'x'.repeat(240)}`,
    );
    const large = Array.from({ length: 256 }, (_, sequence) => ({
      sequence, kind: 'tool', name: 'prior', outcome: 'ALLOW' as const,
      receipt_hash: 'b'.repeat(64), data_classifications: classifications,
    }));
    expect(() => buildActionContextV2({ ...base(), prior_actions: large }))
      .toThrow('canonical action context exceeds 65536 UTF-8 bytes');
  });
});
