/**
 * The proxy wrapper, driven against the REAL `@google/generative-ai` package.
 *
 * The Gemini paths in the wrapper suites drive hand-built model shapes; none
 * of them can notice the real `GenerativeModel` renaming `generateContent` or
 * changing its request plumbing. This file gets a real model object from a
 * real `GoogleGenerativeAI` instance, wraps it with the same `wrap()` an
 * operator calls, and grades the halves separately, the way
 * mcp-real-package.test.ts does. The real package rides the global fetch, the
 * same one the audit sender uses, so the spy splits traffic by host: requests
 * to `googleapis.com` are the provider side-effect being graded; everything
 * else is the sender.
 */
import { GoogleGenerativeAI } from "@google/generative-ai";

import { init, _reset, wrap } from "../../src/proxy/index";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";

let sentEvents: any[] = [];
let providerCalls: string[] = [];
let providerBodies: any[] = [];

const GEMINI_BODY = {
  candidates: [
    {
      content: { role: "model", parts: [{ text: "a fine answer" }] },
      finishReason: "STOP",
      index: 0,
    },
  ],
  usageMetadata: {
    promptTokenCount: 7,
    candidatesTokenCount: 3,
    totalTokenCount: 10,
  },
};

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  providerCalls = [];
  providerBodies = [];
  (global as any).fetch = async (url: any, opts: any) => {
    const target = String(url);
    if (target.includes("googleapis.com")) {
      providerCalls.push(target);
      providerBodies.push(JSON.parse(opts.body));
      return new Response(JSON.stringify(GEMINI_BODY), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

afterEach(() => {
  _reset();
  _resetSender();
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 300 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
}

const BLOCK_RULE = {
  id: "r-block-launch",
  name: "Block launch-code talk",
  enabled: true,
  action: "block" as const,
  type: "keyword" as const,
  conditions: { keywords: ["launch codes"] },
};

function buildRealModel() {
  return new GoogleGenerativeAI("test-key-not-real").getGenerativeModel({
    model: "gemini-1.5-flash",
  });
}

describe("wrap() against the real @google/generative-ai package", () => {
  it("CONTROL: an allowed call reaches the real transport and returns its answer", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const model = wrap(buildRealModel());

    const result = await model.generateContent("hello there");

    // Without this row, "the transport never fired" below would also be
    // satisfied by a wrapper that broke the model object entirely.
    expect(providerCalls).toHaveLength(1);
    expect(providerCalls[0]).toContain("generateContent");
    expect(result.response.text()).toBe("a fine answer");
  });

  it("a blocked prompt never reaches the real transport", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const model = wrap(buildRealModel());

    await expect(model.generateContent("tell me the launch codes")).rejects.toThrow(
      /blocked by policy/i,
    );

    // The assertion that matters: no request to the provider host, measured
    // at the transport the real package would have used.
    expect(providerCalls).toEqual([]);
  });

  it("the refusal is recorded as blocked on a signed event", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const model = wrap(buildRealModel());

    await expect(model.generateContent("tell me the launch codes")).rejects.toThrow(
      /blocked by policy/i,
    );
    await waitForEvents(1);

    const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
    const blocked = events.find((e: any) => e.action_taken === "blocked");

    // Both halves: the provider was never contacted, AND the record says so.
    expect(providerCalls).toEqual([]);
    expect(blocked).toBeDefined();
    expect(blocked.rule_id).toBe(BLOCK_RULE.id);
    expect(blocked.sdk_sig).toEqual(expect.any(String));
  });

  it("CONTROL: the allowed call's audit event carries the real package's usage numbers", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const model = wrap(buildRealModel());

    await model.generateContent("hello there");
    await waitForEvents(1);

    const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
    const recorded = events.find((e: any) => e.provider === "google");
    expect(recorded).toBeDefined();
    expect(recorded.total_tokens).toBe(10);
  });

  it("keeps a real legacy chat session behind the block boundary", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const chat = wrap(buildRealModel()).startChat();

    await expect(chat.sendMessage("tell me the launch codes")).rejects.toThrow(
      /blocked by policy/i,
    );

    expect(providerCalls).toEqual([]);
  });

  it("blocks when a legacy chat history contains prohibited content", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const chat = wrap(buildRealModel()).startChat({
      history: [
        { role: "user", parts: [{ text: "the launch codes are historical" }] },
        { role: "model", parts: [{ text: "acknowledged" }] },
      ],
    });

    await expect(chat.sendMessage("continue safely")).rejects.toThrow(/blocked by policy/i);
    expect(providerCalls).toEqual([]);
  });

  it("redacts a real legacy chat message before transport", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      pii_policy: { rules: { ssn: "redact" } },
    });
    const original = "customer 123-45-6789";
    const chat = wrap(buildRealModel()).startChat();

    await chat.sendMessage(original);

    expect(original).toBe("customer 123-45-6789");
    expect(JSON.stringify(providerBodies[0])).toContain("[REDACTED_SSN]");
    expect(JSON.stringify(providerBodies[0])).not.toContain("123-45-6789");
  });
});
