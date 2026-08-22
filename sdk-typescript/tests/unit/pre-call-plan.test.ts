import { jest } from "@jest/globals";

import { _reset, getConfig, init } from "../../src/proxy/config.js";
import {
  _buildDirectCallPreCallPlan,
  type PathContext,
  wrap,
} from "../../src/proxy/wrapper.js";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget.js";

function context(): PathContext {
  return {
    path: ["chat", "completions", "create"],
    options: {},
    rootClient: {},
    config: getConfig(),
    provider: "openai",
    recordedProvider: "openai",
    providerAttribution: {},
  };
}

describe("direct-call pre-call plan", () => {
  beforeEach(() => {
    _reset();
    _resetSender();
  });

  afterEach(() => {
    delete (globalThis as { fetch?: unknown }).fetch;
  });

  it("returns the exact cleaned invocation without calling the provider", async () => {
    init({ api_key: "test", sample_rate: 0 });
    const provider = jest.fn();
    const secondArgument = { signal: "preserved" };
    const request = {
      model: "gpt-4o",
      messages: [{ role: "user", content: "hello" }],
      request_id: "audit-only",
      temperature: 0.25,
    };

    const plan = await _buildDirectCallPreCallPlan(
      [request, secondArgument],
      {},
      context(),
      "openai",
      "chat.completions.create",
    );

    expect(plan.disposition).toBe("ready");
    if (plan.disposition !== "ready") throw new Error("expected ready plan");
    expect(plan.cleaned_args).toEqual([
      {
        model: "gpt-4o",
        messages: [{ role: "user", content: "hello" }],
        temperature: 0.25,
      },
      secondArgument,
    ]);
    expect(plan.audit_fields).toEqual({ request_id: "audit-only" });
    expect(plan.detectedClassifications).toEqual([]);
    expect(provider).not.toHaveBeenCalled();
  });

  it("returns the exact redacted provider-bound invocation and classifications", async () => {
    init({
      api_key: "test",
      sample_rate: 0,
      pii_policy: { rules: { email: "redact" } },
    });

    const plan = await _buildDirectCallPreCallPlan(
      [{
        model: "gpt-4o",
        messages: [{ role: "user", content: "mail a@b.com" }],
      }],
      {},
      context(),
      "openai",
      "chat.completions.create",
    );

    expect(plan.disposition).toBe("ready");
    if (plan.disposition !== "ready") throw new Error("expected ready plan");
    const outbound = plan.cleaned_args[0] as {
      messages: Array<{ content: string }>;
    };
    expect(outbound.messages[0].content).toBe("mail [REDACTED_EMAIL]");
    expect(plan.detectedClassifications).toContain("email");
  });

  it("returns a block without emission, while the existing wrapper throws the same error", async () => {
    const sends: unknown[] = [];
    (globalThis as { fetch?: unknown }).fetch = jest.fn(async (...args: unknown[]) => {
      sends.push(args);
      return { ok: true, status: 200, json: async () => ({}) };
    });
    init({
      api_key: "test",
      ingest_url: "https://example.invalid",
      pii_policy: { rules: { ssn: "block" } },
    });
    const request = {
      model: "gpt-4o",
      messages: [{ role: "user", content: "ssn 123-45-6789" }],
      request_id: "audit-only",
    };

    const plan = await _buildDirectCallPreCallPlan(
      [request],
      {},
      context(),
      "openai",
      "chat.completions.create",
    );
    expect(plan.disposition).toBe("blocked");
    if (plan.disposition !== "blocked") throw new Error("expected blocked plan");
    expect(plan.cleaned_args[0]).toEqual({
      model: "gpt-4o",
      messages: [{ role: "user", content: "ssn 123-45-6789" }],
    });
    expect(plan.audit_fields).toEqual({ request_id: "audit-only" });
    expect(plan.detectedClassifications).toContain("ssn");
    expect(sends).toEqual([]);

    const create = jest.fn(async () => ({}));
    const wrapped = wrap({ chat: { completions: { create } } } as any);
    let thrown: unknown;
    try {
      await wrapped.chat.completions.create({ ...request });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe(plan.error.message);
    expect((thrown as { reason_code?: string }).reason_code).toBe(
      (plan.error as Error & { reason_code?: string }).reason_code,
    );
    expect(create).not.toHaveBeenCalled();
  });
});
