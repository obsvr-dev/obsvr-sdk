/**
 * Cross-language audit-gap conformance (TS side).
 *
 * Twin: sdk-python/tests/test_audit_gap_conformance.py. The marker's canonical
 * statement goes through SHA-256 into the HMAC, so a single character of drift
 * between the two SDKs makes them sign different markers for the same loss -
 * and a chain would then verify in one language and not the other. The format
 * lives in conformance/fixtures/audit_gap.json rather than in either test file
 * so neither language can drift its own expectations.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  AUDIT_GAP_FORMAT,
  AUDIT_GAP_GOVERNANCE_EVENT,
  AUDIT_GAP_METADATA_KEY,
  AUDIT_GAP_OPERATION,
  AUDIT_GAP_REASON_QUEUE_OVERFLOW,
  formatAuditGapPrompt,
  parseAuditGapPrompt,
} from "../../src/proxy/audit-gap";
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
  op: "set";
  index: number;
  field: string;
  value: unknown;
}

const fixture = JSON.parse(
  readFileSync(findFixture("conformance/fixtures/audit_gap.json"), "utf-8"),
) as {
  constants: Record<string, string>;
  preimage_cases: Array<{ id: string; dropped: number; reason: string; prompt: string }>;
  parse_rejects: Array<{ id: string; prompt: string }>;
  marker_event_fields: Record<string, unknown>;
  signing: {
    api_key: string;
    session_id: string;
    events: Array<Record<string, unknown>>;
  };
  verification: {
    cases: Array<{
      id: string;
      mutations: Mutation[];
      expect: {
        valid: boolean;
        events_verified: number;
        broken_at?: number;
        reason?: string;
        gap_markers: number;
        events_declared_lost: number;
      };
    }>;
  };
};

/** The fixture's chain as an exported event list. */
function chain(): AuditEvent[] {
  return fixture.signing.events.map(
    (ev) =>
      ({
        sdk_session_id: fixture.signing.session_id,
        seq_no: ev.seq_no,
        timestamp_sdk: ev.timestamp_sdk,
        prompt: ev.prompt,
        response: ev.response,
        prev_sig: ev.prev_sig,
        sdk_sig: ev.sdk_sig,
      }) as unknown as AuditEvent,
  );
}

describe("audit gap conformance: constants", () => {
  it("matches the pinned wire constants", () => {
    expect(AUDIT_GAP_FORMAT).toBe(fixture.constants.format);
    expect(AUDIT_GAP_REASON_QUEUE_OVERFLOW).toBe(fixture.constants.reason_queue_overflow);
    expect(AUDIT_GAP_METADATA_KEY).toBe(fixture.constants.metadata_key);
    expect(AUDIT_GAP_GOVERNANCE_EVENT).toBe(fixture.constants.governance_event);
    expect(AUDIT_GAP_OPERATION).toBe(fixture.constants.operation);
  });
});

describe("audit gap conformance: canonical preimage", () => {
  for (const c of fixture.preimage_cases) {
    it(`produces the pinned statement: ${c.id}`, () => {
      expect(formatAuditGapPrompt(c.dropped, c.reason)).toBe(c.prompt);
    });

    it(`round-trips the pinned statement: ${c.id}`, () => {
      expect(parseAuditGapPrompt(c.prompt)).toEqual({
        dropped: c.dropped,
        reason: c.reason,
      });
    });
  }

  for (const c of fixture.parse_rejects) {
    it(`refuses to read a loss claim from: ${c.id}`, () => {
      expect(parseAuditGapPrompt(c.prompt)).toBeNull();
    });
  }
});

describe("audit gap conformance: signing and verification", () => {
  it("verifies the pinned chain and reports the loss it declares", () => {
    const result = verifyAuditChain(chain(), fixture.signing.api_key);
    const expected = fixture.verification.cases[0].expect;
    expect(result.valid).toBe(expected.valid);
    expect(result.eventsVerified).toBe(expected.events_verified);
    expect(result.gapMarkers).toBe(expected.gap_markers);
    expect(result.eventsDeclaredLost).toBe(expected.events_declared_lost);
  });

  for (const c of fixture.verification.cases) {
    it(`reaches the pinned verdict: ${c.id}`, () => {
      const events = chain();
      for (const m of c.mutations) {
        (events[m.index] as unknown as Record<string, unknown>)[m.field] = m.value;
      }
      const result = verifyAuditChain(events, fixture.signing.api_key);
      expect(result.valid).toBe(c.expect.valid);
      expect(result.eventsVerified).toBe(c.expect.events_verified);
      expect(result.gapMarkers).toBe(c.expect.gap_markers);
      expect(result.eventsDeclaredLost).toBe(c.expect.events_declared_lost);
      if (c.expect.broken_at !== undefined) expect(result.brokenAt).toBe(c.expect.broken_at);
      if (c.expect.reason !== undefined) expect(result.reason).toBe(c.expect.reason);
    });
  }
});
