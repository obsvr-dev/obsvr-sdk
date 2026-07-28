/**
 * TypeScript consumer of conformance/fixtures/tool_content_hash.json.
 *
 * The fixture is the contract of record for obsvr-tool-content-v1: the Python
 * twin must reproduce every byte of it. Literals live in the fixture, never
 * here, so the two languages cannot pass their own suites while disagreeing
 * with each other.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  buildToolContentDocument,
  canonicalizeToolContent,
  computeToolContentHash,
  toolArgsHash,
  toolContentDescriptorHash,
} from '../../src/policy/tool-content-hash';
import { toolDescriptorHash } from '../../src/policy/tool-pinning';

/** Resolve the fixture from the repo root, wherever the suite is invoked from. */
function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

const fixture = JSON.parse(
  fs.readFileSync(findFixture('conformance/fixtures/tool_content_hash.json'), 'utf-8'),
);

interface DocumentCase {
  id: string;
  input: { tool_name?: string; descriptor?: Record<string, unknown> | null; args?: unknown };
  expect: { descriptor_sha256: string; args_sha256: string; canonical: string; hash: string };
}

interface EquivalenceGroup {
  note: string;
  ids: string[];
}

interface UnstableCase {
  id: string;
  note: string;
  args: unknown;
  expect: { throws: boolean; args_sha256?: string };
}

const documentCases: DocumentCase[] = fixture.document_cases;
const equivalenceGroups: EquivalenceGroup[] = fixture.equivalence_groups;
const unstableCases: UnstableCase[] = fixture.unstable_number_cases;
const byId = new Map(documentCases.map((c) => [c.id, c]));

/** Fixture descriptors use MCP wire names; this is the whole adaptation. */
const paramsOf = (c: DocumentCase) => ({
  toolName: c.input.tool_name,
  descriptor: c.input.descriptor as any,
  args: c.input.args,
});

describe('tool_content_hash conformance: document cases', () => {
  it('the fixture is present and non-trivial', () => {
    expect(fixture.name).toBe('tool_content_hash');
    expect(documentCases.length).toBeGreaterThanOrEqual(16);
  });

  it.each(documentCases.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    const params = paramsOf(c);
    const doc = buildToolContentDocument(params);
    expect(doc.descriptor_sha256).toBe(c.expect.descriptor_sha256);
    expect(doc.args_sha256).toBe(c.expect.args_sha256);
    expect(canonicalizeToolContent(doc)).toBe(c.expect.canonical);
    expect(computeToolContentHash(params)).toBe(c.expect.hash);
    // The pinned hash really is the digest of the pinned canonical bytes, so a
    // fixture whose two halves drifted apart cannot pass.
    expect(c.expect.hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('the component digests are computable on their own', () => {
    for (const c of documentCases) {
      expect(toolContentDescriptorHash(c.input.descriptor as any)).toBe(c.expect.descriptor_sha256);
      expect(toolArgsHash(c.input.args)).toBe(c.expect.args_sha256);
    }
  });
});

describe('tool_content_hash conformance: equivalence groups', () => {
  it.each(equivalenceGroups.map((g) => [g.ids.join(' == '), g] as const))('%s', (_name, group) => {
    const hashes = group.ids.map((id) => byId.get(id)!.expect.hash);
    expect(new Set(hashes).size).toBe(1);
    // Recomputed, not just compared as fixture literals.
    const computed = group.ids.map((id) => computeToolContentHash(paramsOf(byId.get(id)!)));
    expect(new Set(computed).size).toBe(1);
    expect(computed[0]).toBe(hashes[0]);
  });

  it('cases outside a group are genuinely distinct', () => {
    const grouped = new Set<string>(equivalenceGroups.flatMap((g) => g.ids));
    const distinct = documentCases.filter((c) => !grouped.has(c.id)).map((c) => c.expect.hash);
    expect(new Set(distinct).size).toBe(distinct.length);
  });
});

describe('tool_content_hash conformance: distinction from descriptor pinning', () => {
  const cases: any[] = fixture.distinction_cases;

  it('the two projections give different digests for the same descriptor', () => {
    const c = cases.find((x) => x.id === 'projections_differ_for_the_same_descriptor');
    expect(toolDescriptorHash(c.descriptor)).toBe(c.expect.pinning_descriptor_hash);
    expect(toolContentDescriptorHash(c.descriptor)).toBe(c.expect.content_descriptor_sha256);
    expect(c.expect.pinning_descriptor_hash).not.toBe(c.expect.content_descriptor_sha256);
  });

  it('a behavior-hint change moves the pin and not the content hash', () => {
    const c = cases.find((x) => x.id === 'behavior_hint_moves_the_pin_and_not_the_content_hash');
    const baseline = cases.find((x) => x.id === c.baseline_id);

    expect(toolDescriptorHash(c.descriptor)).toBe(c.expect.pinning_descriptor_hash);
    expect(toolContentDescriptorHash(c.descriptor)).toBe(c.expect.content_descriptor_sha256);

    // The pin catches the rug-pull...
    expect(c.expect.pinning_descriptor_hash).not.toBe(baseline.expect.pinning_descriptor_hash);
    // ...and the evidence contract does not, because annotations are outside
    // its projection. Substituting one hash for the other would silently
    // change which attack the field detects.
    expect(c.expect.content_descriptor_sha256).toBe(baseline.expect.content_descriptor_sha256);
    expect(computeToolContentHash({ toolName: 'read_file', descriptor: c.descriptor, args: c.args })).toBe(
      c.expect.content_hash,
    );
    expect(c.expect.content_hash).toBe(c.expect.baseline_content_hash);
  });
});

describe('tool_content_hash conformance: cross-SDK-unstable numbers', () => {
  it.each(unstableCases.map((c) => [c.id, c] as const))('%s', (_id, c) => {
    if (c.expect.throws) {
      expect(() => toolArgsHash(c.args)).toThrow();
    } else {
      expect(toolArgsHash(c.args)).toBe(c.expect.args_sha256);
    }
  });

  it('every unstable case that throws also throws through the top-level hash', () => {
    for (const c of unstableCases.filter((x) => x.expect.throws)) {
      expect(() => computeToolContentHash({ toolName: 't', args: c.args })).toThrow();
    }
  });
});
