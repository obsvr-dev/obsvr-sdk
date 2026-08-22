import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  ACTION_CONTEXT_SCHEMA,
  ActionContextValidationError,
  actionContextHash,
  buildActionContext,
  canonicalizeActionContext,
  type ActionContextInput,
} from '../../src/governance/action-context';

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface ValidCase {
  id: string;
  input: ActionContextInput;
  expect: {
    document: Record<string, unknown>;
    canonical: string;
    hash: string;
  };
}

interface InvalidCase {
  id: string;
  mutation: {
    path: Array<string | number>;
    value?: unknown;
    delete?: boolean;
  };
}

const FIXTURE = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/action_context.json'), 'utf8'),
) as {
  claimable: boolean;
  description: string;
  valid_cases: ValidCase[];
  invalid_base: ActionContextInput;
  invalid_cases: InvalidCase[];
};

function mutated(case_: InvalidCase): ActionContextInput {
  const input = JSON.parse(JSON.stringify(FIXTURE.invalid_base)) as Record<string, unknown>;
  let cursor: unknown = input;
  for (const segment of case_.mutation.path.slice(0, -1)) {
    cursor = (cursor as Record<string | number, unknown>)[segment];
  }
  const last = case_.mutation.path[case_.mutation.path.length - 1];
  if (case_.mutation.delete === true) {
    delete (cursor as Record<string | number, unknown>)[last];
  } else {
    (cursor as Record<string | number, unknown>)[last] = case_.mutation.value;
  }
  return input as unknown as ActionContextInput;
}

describe('Obsvr-authored canonical action context', () => {
  it('pins the local schema without presenting the fixture as official vectors', () => {
    expect(ACTION_CONTEXT_SCHEMA).toBe('obsvr-action-context-v1');
    expect(FIXTURE.claimable).toBe(false);
    expect(FIXTURE.description).toContain('not an official AARM conformance vector');
  });

  for (const case_ of FIXTURE.valid_cases) {
    it(case_.id, () => {
      const document = buildActionContext(case_.input);
      const canonical = canonicalizeActionContext(case_.input);
      expect(document).toEqual(case_.expect.document);
      expect(Buffer.from(canonical, 'utf8')).toEqual(
        Buffer.from(case_.expect.canonical, 'utf8'),
      );
      expect(actionContextHash(case_.input)).toBe(case_.expect.hash);
      expect(createHash('sha256').update(case_.expect.canonical, 'utf8').digest('hex'))
        .toBe(case_.expect.hash);
      expect(canonical).not.toContain('"arguments"');
      expect(canonical).not.toContain('sensitive_content');
    });
  }

  for (const case_ of FIXTURE.invalid_cases) {
    it(`rejects ${case_.id}`, () => {
      expect(() => buildActionContext(mutated(case_)))
        .toThrow(ActionContextValidationError);
    });
  }
});
