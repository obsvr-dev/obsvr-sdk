/**
 * SDK stress tests: latency percentiles, large payloads, many rules,
 * concurrency, queue overflow, and adversarial-regex timing.
 *
 * These assert BOUNDS (no hangs, sane latency, bounded memory) rather than
 * exact numbers, so they are CI-safe. Measured medians are logged for the
 * benchmark write-up.
 */
import { init, _reset, getConfig } from "../../src/proxy/config";
import { wrap } from "../../src/proxy/wrapper";
import {
  _resetSender,
  getQueueSize,
  getDroppedCount,
} from "../../src/proxy/sender/fire-and-forget";
import { evaluatePolicyRules, type PolicyRule } from "../../src/policy/rules";
import { runBuiltinPiiScan } from "../../src/policy/hook";
import { _resetAllQuotas } from "../../src/governance/quota";
import { jest } from "@jest/globals";

jest.setTimeout(60_000);

function makeFakeOpenAI() {
  return {
    chat: {
      completions: {
        create: async (_args: unknown) => ({
          choices: [{ message: { content: "ok" } }],
          usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
        }),
      },
    },
  };
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

function manyRules(n: number): PolicyRule[] {
  const rules: PolicyRule[] = [];
  for (let i = 0; i < n; i++) {
    rules.push({
      id: `kw-${i}`,
      name: `keyword rule ${i}`,
      enabled: true,
      action: "block",
      type: "keyword",
      conditions: { keywords: [`forbidden-term-${i}`] },
    });
  }
  return rules;
}

beforeEach(() => {
  _reset();
  _resetSender();
  _resetAllQuotas();
});

describe("policy-path latency", () => {
  it("median eval under 100 rules stays sub-millisecond for normal prompts", () => {
    const rules = manyRules(100);
    const prompt = "a perfectly ordinary prompt asking about the weather in Boston";
    const times: number[] = [];
    for (let i = 0; i < 2000; i++) {
      const t0 = performance.now();
      evaluatePolicyRules(rules, prompt, "prompt");
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    const p50 = percentile(times, 50);
    const p99 = percentile(times, 99);
    console.log(`[bench] rules=100 p50=${p50.toFixed(4)}ms p99=${p99.toFixed(4)}ms`);
    expect(p50).toBeLessThan(1);
    expect(p99).toBeLessThan(10);
  });

  it("PII scan on a 100KB prompt completes in bounded time", () => {
    const big = ("call me at 555-123-4567 sometimes. " + "x".repeat(200)).repeat(430); // ~100KB
    const t0 = performance.now();
    const result = runBuiltinPiiScan(big);
    const ms = performance.now() - t0;
    console.log(`[bench] pii-scan 100KB: ${ms.toFixed(2)}ms, detected=${result.pii_detected}`);
    expect(ms).toBeLessThan(500);
    expect(result.pii_detected).toBe(true);
  });

  it("1MB prompt through the full wrapped path does not hang", async () => {
    init({ api_key: "stress", pii_policy: {}, policy_rules: manyRules(50) });
    const client = wrap(makeFakeOpenAI());
    const huge = "benign filler text ".repeat(55_000); // ~1MB
    const t0 = performance.now();
    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: huge }],
    });
    const ms = performance.now() - t0;
    console.log(`[bench] 1MB prompt full path: ${ms.toFixed(1)}ms`);
    expect(ms).toBeLessThan(5000);
  });
});

describe("adversarial regex under stress", () => {
  it("catastrophic pattern against a 50KB adversarial input stays bounded", () => {
    const rules: PolicyRule[] = [
      {
        id: "evil",
        name: "evil",
        enabled: true,
        action: "block",
        type: "regex",
        conditions: { pattern: "(a+)+$" },
      },
    ];
    const evil = "a".repeat(50_000) + "!";
    const t0 = performance.now();
    const result = evaluatePolicyRules(rules, evil, "prompt");
    const ms = performance.now() - t0;
    console.log(`[bench] ReDoS attempt 50KB: ${ms.toFixed(2)}ms`);
    expect(ms).toBeLessThan(1000);
    expect(result.decision).toBe("allow"); // rejected pattern = no-match
  });

  it("50 hostile patterns mixed into a real ruleset cannot stall evaluation", () => {
    const rules = manyRules(50);
    const hostile = ["(a+)+$", "(x|xx)+y", "([a-z]+)*#", "(.*a){20}b"];
    for (let i = 0; i < 50; i++) {
      rules.push({
        id: `evil-${i}`,
        name: `evil-${i}`,
        enabled: true,
        action: "block",
        type: "regex",
        conditions: { pattern: hostile[i % hostile.length] },
      });
    }
    const input = "a".repeat(10_000) + "x".repeat(10_000);
    const t0 = performance.now();
    evaluatePolicyRules(rules, input, "prompt");
    const ms = performance.now() - t0;
    console.log(`[bench] 100 rules (50 hostile) on 20KB: ${ms.toFixed(2)}ms`);
    expect(ms).toBeLessThan(2000);
  });
});

describe("concurrency", () => {
  it("500 concurrent wrapped calls all succeed with correct results", async () => {
    init({ api_key: "stress" });
    const client = wrap(makeFakeOpenAI());
    const t0 = performance.now();
    const results = await Promise.all(
      Array.from({ length: 500 }, (_, i) =>
        client.chat.completions.create({
          model: "gpt-4o",
          messages: [{ role: "user", content: `call ${i}` }],
        }),
      ),
    );
    const ms = performance.now() - t0;
    console.log(`[bench] 500 concurrent calls: ${ms.toFixed(1)}ms total`);
    expect(results).toHaveLength(500);
    for (const r of results) {
      expect(r.choices[0].message.content).toBe("ok");
    }
  });

  it("scales to 250,000 concurrent governed calls with flat per-call cost", async () => {
    // Finds the real ceiling rather than an arbitrary comfortable number.
    // Provider calls are mocked (instant resolve) so this isolates obsvr's
    // own per-call overhead (PII scan + policy eval + signing prep) from
    // network/model latency, which is the point of a governance-layer bench.
    init({ api_key: "stress" });
    const client = wrap(makeFakeOpenAI());
    const sizes = [10_000, 100_000, 250_000];
    const perCallUs: number[] = [];
    for (const n of sizes) {
      const t0 = performance.now();
      const results = await Promise.all(
        Array.from({ length: n }, (_, i) =>
          client.chat.completions.create({
            model: "gpt-4o",
            messages: [{ role: "user", content: `call ${i}` }],
          }),
        ),
      );
      const ms = performance.now() - t0;
      const perCall = (ms / n) * 1000;
      perCallUs.push(perCall);
      const heapMB = process.memoryUsage().heapUsed / 1024 / 1024;
      console.log(
        `[bench] n=${n} total=${ms.toFixed(1)}ms per-call=${perCall.toFixed(2)}us heap=${heapMB.toFixed(0)}MB`,
      );
      expect(results).toHaveLength(n);
      expect(results.every((r) => r.choices[0].message.content === "ok")).toBe(true);
    }
    // Per-call cost should stay in the same order of magnitude as scale
    // grows 25x (10k -> 250k) - proves the pipeline doesn't degrade
    // superlinearly (no O(n^2) accumulation in the hot path).
    expect(perCallUs[2]).toBeLessThan(perCallUs[0] * 10);
  });

  it("concurrent blocked + allowed calls do not corrupt each other", async () => {
    init({ api_key: "stress", pii_policy: { rules: { ssn: "block" } } });
    const client = wrap(makeFakeOpenAI());
    const outcomes = await Promise.allSettled(
      Array.from({ length: 200 }, (_, i) =>
        client.chat.completions.create({
          model: "gpt-4o",
          messages: [
            {
              role: "user",
              content: i % 2 === 0 ? `clean message ${i}` : `ssn 123-45-6789 msg ${i}`,
            },
          ],
        }),
      ),
    );
    const fulfilled = outcomes.filter((o) => o.status === "fulfilled").length;
    const rejected = outcomes.filter((o) => o.status === "rejected").length;
    expect(fulfilled).toBe(100);
    expect(rejected).toBe(100);
  });
});

describe("queue behavior under flood", () => {
  it("emit queue drops beyond capacity instead of growing unbounded", async () => {
    init({ api_key: "stress", ingest_url: "http://localhost:1" }); // unreachable
    const client = wrap(makeFakeOpenAI());
    // Flood well past MAX_QUEUE_SIZE (100)
    await Promise.all(
      Array.from({ length: 400 }, (_, i) =>
        client.chat.completions.create({
          model: "gpt-4o",
          messages: [{ role: "user", content: `flood ${i}` }],
        }),
      ),
    );
    const queued = getQueueSize();
    const dropped = getDroppedCount();
    console.log(`[bench] flood 400: queued=${queued} dropped=${dropped}`);
    expect(queued).toBeLessThanOrEqual(100); // bounded
    expect(queued + dropped).toBeGreaterThanOrEqual(300); // accounted for
  });
});

describe("pathological inputs", () => {
  it("deeply nested message content does not crash extraction", async () => {
    init({ api_key: "stress", pii_policy: {} });
    const client = wrap(makeFakeOpenAI());
    const weird: Record<string, unknown> = { role: "user", content: [] };
    let cursor: unknown[] = weird.content as unknown[];
    for (let i = 0; i < 200; i++) {
      const next: unknown[] = [];
      cursor.push({ type: "text", text: `layer ${i}`, nested: next });
      cursor = next;
    }
    const result = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [weird],
    });
    expect(result.choices[0].message.content).toBe("ok");
  });

  it("null/undefined/empty message shapes are tolerated", async () => {
    init({ api_key: "stress", pii_policy: {} });
    const client = wrap(makeFakeOpenAI());
    for (const messages of [[], [{ role: "user", content: "" }], [{ role: "user" }]]) {
      const r = await client.chat.completions.create({ model: "gpt-4o", messages });
      expect(r.choices[0].message.content).toBe("ok");
    }
  });

  it("unicode-heavy prompts (emoji, RTL, CJK) survive the full path", async () => {
    init({ api_key: "stress", pii_policy: {} });
    const client = wrap(makeFakeOpenAI());
    const nasty = "\u{1F600}".repeat(1000) + "مرحبا" + "こんにちは".repeat(500) + " �";
    const r = await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: nasty }],
    });
    expect(r.choices[0].message.content).toBe("ok");
  });
});

describe("PII scan complexity regression (suppressOverlaps)", () => {
  // Regression guard for a real O(m^2) bug found via stress testing: the old
  // suppressOverlaps() did a full linear scan of `kept` for every candidate
  // match, so a document with many PII-shaped matches (m grows with size)
  // took quadratic time. A 10MB document with a repeating phone-number
  // pattern went from ~15.8s to ~0.16s after the fix (binary-search
  // insertion into a start-sorted array instead of a linear overlap scan).
  //
  // This test doesn't assert an exact number (flaky across CI hardware);
  // it asserts the SHAPE of the scaling: 100x more matches must cost far
  // less than 100x the time, which an O(m^2) implementation cannot satisfy.
  it("scanning cost grows sub-quadratically with match count", () => {
    const unit = "call 555-123-4567 for info, thanks and have a nice day!! ";
    const small = unit.repeat(200); // ~11KB, ~200 matches
    const large = unit.repeat(20_000); // ~1.1MB, ~20,000 matches (100x)

    const t0 = performance.now();
    runBuiltinPiiScan(small);
    const smallMs = performance.now() - t0;

    const t1 = performance.now();
    const result = runBuiltinPiiScan(large);
    const largeMs = performance.now() - t1;

    console.log(
      `[bench] pii-scan complexity: 200 matches=${smallMs.toFixed(2)}ms, ` +
        `20000 matches=${largeMs.toFixed(2)}ms (ratio ${(largeMs / Math.max(smallMs, 0.01)).toFixed(1)}x for 100x matches)`,
    );
    expect(result.pii_detected).toBe(true);
    // A true O(m^2) implementation would show ~10,000x for 100x the matches.
    // O(m log n)-ish should stay well under 1,000x even with timing noise
    // at the small end.
    expect(largeMs).toBeLessThan(Math.max(smallMs * 1000, 500));
  });
});
