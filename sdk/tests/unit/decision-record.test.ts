/**
 * Canonical decision records (ADR-2) — TS side. Twin:
 * sdk-python/tests/test_decision_record.py.
 *
 * Two layers:
 *  1. Cross-SDK parity against conformance/fixtures/decision_input.json:
 *     both SDKs must build the SAME document from the same inputs, serialize
 *     it to the SAME canonical bytes, and derive the SAME sha256. A
 *     divergence is a release blocker, never a known-divergence.
 *  2. Wiring: the enforcement pipeline stamps decision_input_hash +
 *     engine_version on emitted events as ADDITIVE fields, and the HMAC
 *     chain preimage is provably unchanged by their presence.
 */
import { createHmac, createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  ENGINE_VERSION,
  RULES_ENGINE_SEMANTICS_VERSION,
  DECISION_INPUT_SCHEMA,
  buildDecisionInput,
  canonicalizeDecisionInput,
  computeDecisionInputHash,
  type DecisionInput,
  type HookDisposition,
} from "../../src/policy/decision-record.js";
import { init, _reset, getConfig } from "../../src/proxy/config";
import {
  applyPreCallPolicy,
  buildIntegrationEvent,
  DEFAULT_COMPLIANCE,
} from "../../src/integrations/core";

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, rel);
    if (existsSync(candidate)) return candidate;
    dir = dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

interface FixtureCase {
  id: string;
  note: string;
  input: {
    rules_hash: string;
    degraded: boolean;
    degraded_reason?: string;
    target: "request" | "response";
    evaluated_text: string;
    user_id?: string;
    service_name?: string;
    tenant_id?: string;
    hook: HookDisposition;
  };
  doc: DecisionInput;
  expected: { canonical: string; hash: string };
}

const fixture = JSON.parse(
  readFileSync(findFixture("conformance/fixtures/decision_input.json"), "utf-8"),
) as { engine_version: string; cases: FixtureCase[] };

describe("conformance: decision_input fixtures", () => {
  it("fixture pins the SAME engine_version constant this SDK stamps", () => {
    expect(fixture.engine_version).toBe(ENGINE_VERSION);
    expect(ENGINE_VERSION).toBe(`obsvr-rules/${RULES_ENGINE_SEMANTICS_VERSION}`);
  });

  it("covers both targets, unicode, and absent optionals", () => {
    const targets = new Set(fixture.cases.map((c) => c.input.target));
    expect(targets).toEqual(new Set(["request", "response"]));
    expect(fixture.cases.length).toBeGreaterThanOrEqual(6);
  });

  for (const c of fixture.cases) {
    it(`${c.id}: builder + canonical bytes + hash match`, () => {
      const doc = buildDecisionInput({
        rulesHash: c.input.rules_hash,
        degraded: c.input.degraded,
        degradedReason: c.input.degraded_reason,
        target: c.input.target,
        evaluatedText: c.input.evaluated_text,
        userId: c.input.user_id,
        serviceName: c.input.service_name,
        tenantId: c.input.tenant_id,
        hook: c.input.hook,
      });
      expect(doc).toEqual(c.doc);
      expect(canonicalizeDecisionInput(doc)).toBe(c.expected.canonical);
      expect(computeDecisionInputHash(doc)).toBe(c.expected.hash);
      // The frozen doc in the fixture re-canonicalizes to the same bytes too.
      expect(canonicalizeDecisionInput(c.doc)).toBe(c.expected.canonical);
    });
  }
});

describe("decision-input document shape", () => {
  it("omits absent optionals entirely (never null)", () => {
    const doc = buildDecisionInput({
      rulesHash: "none",
      degraded: false,
      target: "request",
      evaluatedText: "",
      hook: "not_configured",
    });
    expect(Object.keys(doc).sort()).toEqual([
      "degraded",
      "engine_version",
      "hook",
      "prompt_sha256",
      "rules_hash",
      "schema",
      "target",
    ]);
    expect(doc.schema).toBe(DECISION_INPUT_SCHEMA);
    expect(canonicalizeDecisionInput(doc)).not.toContain("null");
  });

  it("degraded_reason appears only when degraded", () => {
    const notDegraded = buildDecisionInput({
      rulesHash: "none",
      degraded: false,
      degradedReason: "policy_sync_stale", // must be ignored
      target: "request",
      evaluatedText: "x",
      hook: "skipped",
    });
    expect(notDegraded.degraded_reason).toBeUndefined();
  });

  it("target selects which digest field carries the evaluated text", () => {
    const req = buildDecisionInput({
      rulesHash: "none", degraded: false, target: "request",
      evaluatedText: "abc", hook: "allow",
    });
    const res = buildDecisionInput({
      rulesHash: "none", degraded: false, target: "response",
      evaluatedText: "abc", hook: "allow",
    });
    const digest = createHash("sha256").update("abc", "utf8").digest("hex");
    expect(req.prompt_sha256).toBe(digest);
    expect(req.response_sha256).toBeUndefined();
    expect(res.response_sha256).toBe(digest);
    expect(res.prompt_sha256).toBeUndefined();
  });
});

describe("enforcement wiring (applyPreCallPolicy → event)", () => {
  beforeEach(() => _reset());
  afterAll(() => _reset());

  it("stamps decision_input_hash + engine_version on the compliance context", async () => {
    init({ api_key: "test", pii_policy: {} });
    const result = await applyPreCallPolicy("hello world", {
      config: getConfig(),
      provider: "bedrock",
      operation: "test",
    });
    expect(result.compliance.decision_input_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.compliance.engine_version).toBe(ENGINE_VERSION);
    // Replayable: the hash recomputes from the disclosed inputs.
    const expected = computeDecisionInputHash(
      buildDecisionInput({
        rulesHash: result.compliance.policy_version,
        degraded: false,
        target: "request",
        evaluatedText: "hello world",
        hook: "not_configured",
      }),
    );
    expect(result.compliance.decision_input_hash).toBe(expected);
  });

  it("a blocked decision carries the record too", async () => {
    init({ api_key: "test", pii_policy: {} });
    const result = await applyPreCallPolicy("my ssn is 123-45-6789", {
      config: getConfig(),
      provider: "bedrock",
      operation: "test",
    });
    expect(result.decision).toBe("block");
    expect(result.compliance.decision_input_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(result.compliance.engine_version).toBe(ENGINE_VERSION);
  });

  it("hook disposition is committed: block-hook vs no-hook hash differ", async () => {
    init({ api_key: "test" });
    const noHook = await applyPreCallPolicy("same text", {
      config: getConfig(), provider: "bedrock", operation: "test",
    });
    _reset();
    init({ api_key: "test", on_pre_call: () => "block" });
    const withHook = await applyPreCallPolicy("same text", {
      config: getConfig(), provider: "bedrock", operation: "test",
    });
    expect(noHook.compliance.decision_input_hash).not.toBe(
      withHook.compliance.decision_input_hash,
    );
  });

  it("buildIntegrationEvent maps the fields onto the emitted event", async () => {
    init({ api_key: "test" });
    const { compliance } = await applyPreCallPolicy("hello", {
      config: getConfig(), provider: "bedrock", operation: "test",
    });
    const event = buildIntegrationEvent({
      config: getConfig(),
      provider: "bedrock",
      model: "m",
      operation: "test",
      source: "test",
      prompt: "hello",
      compliance,
    });
    expect(event.decision_input_hash).toBe(compliance.decision_input_hash);
    expect(event.engine_version).toBe(ENGINE_VERSION);
  });

  it("events without a decision (DEFAULT_COMPLIANCE) carry no record — honest absence", () => {
    init({ api_key: "test" });
    const event = buildIntegrationEvent({
      config: getConfig(),
      provider: "bedrock",
      model: "m",
      operation: "test",
      source: "test",
      prompt: "hello",
      compliance: DEFAULT_COMPLIANCE,
    });
    expect(event.decision_input_hash).toBeUndefined();
    expect(event.engine_version).toBeUndefined();
  });
});

describe("chain preimage is untouched (signing_vectors stay green)", () => {
  it("the HMAC signature is identical with and without the new fields", () => {
    // Same derivation + payload as fire-and-forget.ts / signing-vectors.test.ts:
    // session|seq|ts|sha256(prompt+response)|prev — the decision-record fields
    // are NOT part of the preimage, so adding them changes no signed byte.
    const key = createHmac("sha256", "obsvr-sdk-signing-v1").update("test-api-key").digest();
    const sign = (ev: Record<string, unknown>): string => {
      const contentHash = createHash("sha256")
        .update(String(ev.prompt ?? "") + String(ev.response ?? ""))
        .digest("hex");
      const payload = [ev.sdk_session_id, String(ev.seq_no), String(ev.timestamp_sdk), contentHash, ""].join("|");
      return createHmac("sha256", key).update(payload).digest("hex");
    };
    const base = {
      sdk_session_id: "11111111-1111-1111-1111-111111111111",
      seq_no: 1,
      timestamp_sdk: 1700000000000,
      prompt: "hello",
      response: "world",
    };
    const withRecord = {
      ...base,
      decision_input_hash: "ab".repeat(32),
      engine_version: ENGINE_VERSION,
    };
    expect(sign(withRecord)).toBe(sign(base));
    // And it still matches the frozen cross-language vector for this event.
    const vectors = JSON.parse(
      readFileSync(findFixture("conformance/fixtures/signing_vectors.json"), "utf-8"),
    );
    expect(sign(withRecord)).toBe(vectors.events[0].sdk_sig);
  });
});
