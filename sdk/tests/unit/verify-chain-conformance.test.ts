/**
 * Cross-language chain-verification conformance (TS side).
 *
 * Twin: sdk-python/tests/test_verify_chain.py. Both suites build the chain
 * from conformance/fixtures/signing_vectors.json, apply each case's
 * mutations, verify, and must produce the verdict the fixture pins. The
 * cases live in the fixture rather than in either test file so neither
 * language can drift its own expectations: a customer's evidence must
 * verify identically whichever verifier they run.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { verifyAuditChain } from "../../src/governance/verify-chain";
import type { AuditEvent } from "../../src/proxy/types";

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, rel);
    if (existsSync(candidate)) return candidate;
    dir = dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface Mutation {
  op: "set" | "delete" | "drop_event" | "reverse" | "api_key";
  index?: number;
  field?: string;
  value?: unknown;
}

interface VerificationCase {
  id: string;
  desc: string;
  mutations: Mutation[];
  expect: {
    valid: boolean;
    events_verified: number;
    broken_at?: number;
    reason?: string;
  };
}

const vectors = JSON.parse(
  readFileSync(findFixture("conformance/fixtures/signing_vectors.json"), "utf-8"),
) as {
  api_key: string;
  session_id: string;
  events: Array<Record<string, unknown>>;
  chain_verification: { cases: VerificationCase[] };
};

/** The shared vectors as an exported event chain. */
function chain(): Array<Record<string, unknown>> {
  return vectors.events.map((ev) => ({
    sdk_session_id: vectors.session_id,
    seq_no: ev.seq_no,
    timestamp_sdk: ev.timestamp_sdk,
    prompt: ev.prompt,
    response: ev.response,
    prev_sig: ev.prev_sig,
    sdk_sig: ev.sdk_sig,
  }));
}

/** Twin of the Python applier; same op vocabulary, same semantics. */
function applyMutations(
  mutations: Mutation[],
  events: Array<Record<string, unknown>>,
  apiKey: string,
): { events: Array<Record<string, unknown>>; apiKey: string } {
  for (const m of mutations) {
    switch (m.op) {
      case "set":
        events[m.index!][m.field!] = m.value;
        break;
      case "delete":
        delete events[m.index!][m.field!];
        break;
      case "drop_event":
        events.splice(m.index!, 1);
        break;
      case "reverse":
        events.reverse();
        break;
      case "api_key":
        apiKey = m.value as string;
        break;
      default:
        throw new Error(`unknown mutation op in fixture: ${(m as Mutation).op}`);
    }
  }
  return { events, apiKey };
}

describe("conformance: chain verification verdicts", () => {
  it("has cases to run", () => {
    expect(vectors.chain_verification.cases.length).toBeGreaterThan(0);
  });

  for (const testCase of vectors.chain_verification.cases) {
    it(`${testCase.id}: ${testCase.desc.slice(0, 80)}`, () => {
      const applied = applyMutations(testCase.mutations, chain(), vectors.api_key);
      const result = verifyAuditChain(applied.events as unknown as AuditEvent[], applied.apiKey);

      expect(result.valid).toBe(testCase.expect.valid);
      expect(result.eventsVerified).toBe(testCase.expect.events_verified);
      expect(result.brokenAt).toBe(testCase.expect.broken_at);
      expect(result.reason).toBe(testCase.expect.reason);
    });
  }
});
