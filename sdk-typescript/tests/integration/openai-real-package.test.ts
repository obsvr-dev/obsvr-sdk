/**
 * The proxy wrapper, driven against the REAL `openai` package.
 *
 * The wrapper suites drive hand-built client shapes, so none of them can
 * notice the real client renaming a path or changing what `create` returns.
 * This file constructs a real `OpenAI` client with an injected transport (the
 * constructor's own `fetch` option), wraps it with the same `wrap()` an
 * operator calls, and grades the halves separately, the way
 * mcp-real-package.test.ts does: a denied call is asserted at the TRANSPORT
 * (the provider fetch never fired), not from the caller's exception, and the
 * control rows prove the same transport genuinely carries an allowed call.
 */
import OpenAI from "openai";

import { init, _reset, wrap } from "../../src/proxy/index";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  // The audit sender's transport. The provider transport is injected into the
  // OpenAI constructor below and never touches this.
  (global as any).fetch = async (_url: any, opts: any) => {
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

const COMPLETION_BODY = {
  id: "chatcmpl-real-pkg-test",
  object: "chat.completion",
  created: 1720000000,
  model: "gpt-4o-mini",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: "a fine answer" },
      finish_reason: "stop",
    },
  ],
  usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
};

const TOOL_CALL_BODY = {
  id: "chatcmpl-real-pkg-tool-test",
  object: "chat.completion",
  created: 1720000000,
  model: "gpt-4o-mini",
  choices: [
    {
      index: 0,
      message: {
        role: "assistant",
        content: null,
        tool_calls: [
          {
            id: "call_secret",
            type: "function",
            function: { name: "return_secret", arguments: "{}" },
          },
        ],
      },
      finish_reason: "tool_calls",
    },
  ],
  usage: { prompt_tokens: 7, completion_tokens: 3, total_tokens: 10 },
};

/** A real OpenAI client whose network layer is a spy. */
function buildRealClient(
  providerCalls: string[],
  providerBodies: string[] = [],
  responseBody: unknown = COMPLETION_BODY,
): OpenAI {
  const providerFetch = (async (url: any, init?: any) => {
    providerCalls.push(String(url));
    if (typeof init?.body === "string") providerBodies.push(init.body);
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as unknown as typeof fetch;
  return new OpenAI({ apiKey: "sk-test-not-real", fetch: providerFetch });
}

const BLOCK_RULE = {
  id: "r-block-launch",
  name: "Block launch-code talk",
  enabled: true,
  action: "block" as const,
  type: "keyword" as const,
  conditions: { keywords: ["launch codes"] },
};

describe("wrap() against the real openai package", () => {
  it("CONTROL: an allowed call reaches the real client's transport and returns its answer", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const providerCalls: string[] = [];
    const client = wrap(buildRealClient(providerCalls));

    const result = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hello there" }],
    });

    // Without this row, "the transport never fired" below would also be
    // satisfied by a wrapper that broke the client entirely.
    expect(providerCalls).toHaveLength(1);
    expect(providerCalls[0]).toContain("chat/completions");
    expect(result.choices[0].message.content).toBe("a fine answer");
  });

  it("a blocked prompt never reaches the real client's transport", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const providerCalls: string[] = [];
    const client = wrap(buildRealClient(providerCalls));

    await expect(
      client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "tell me the launch codes" }],
      }),
    ).rejects.toThrow(/blocked by policy/i);

    // The assertion that matters: the refusal is measured at the transport
    // the real package would have used, not at the caller's exception.
    expect(providerCalls).toEqual([]);
  });

  it("the refusal is recorded as blocked on a signed event", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const providerCalls: string[] = [];
    const client = wrap(buildRealClient(providerCalls));

    await expect(
      client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "tell me the launch codes" }],
      }),
    ).rejects.toThrow(/blocked by policy/i);
    await waitForEvents(1);

    const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
    const blocked = events.find((e: any) => e.action_taken === "blocked");

    // Both halves: the transport never fired, AND the record says blocked.
    expect(providerCalls).toEqual([]);
    expect(blocked).toBeDefined();
    expect(blocked.rule_id).toBe(BLOCK_RULE.id);
    expect(blocked.sdk_sig).toEqual(expect.any(String));
  });

  it("CONTROL: the allowed call's audit event carries the real package's usage numbers", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const providerCalls: string[] = [];
    const client = wrap(buildRealClient(providerCalls));

    await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "hello there" }],
    });
    await waitForEvents(1);

    const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
    const recorded = events.find((e: any) => e.operation === "chat.completions.create");
    expect(recorded).toBeDefined();
    expect(recorded.total_tokens).toBe(10);
  });

  it("blocks a later runTools turn before the real package reaches transport again", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      pii_policy: { rules: { ssn: "block" } },
    });
    const providerCalls: string[] = [];
    const providerFetch = (async (url: any, _init?: any) => {
      providerCalls.push(String(url));
      return new Response(JSON.stringify(TOOL_CALL_BODY), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    const client = wrap(new OpenAI({ apiKey: "sk-test-not-real", fetch: providerFetch }));

    const runner = client.chat.completions.runTools({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "return the tool result" }],
      tools: [
        {
          type: "function",
          function: {
            name: "return_secret",
            description: "Return test data",
            parameters: { type: "object", properties: {} },
            function: async () => "123-45-6789",
          },
        },
      ],
      maxChatCompletions: 2,
    } as any);

    await expect(runner.done()).rejects.toThrow(/blocked by policy/i);
    expect(providerCalls).toHaveLength(1);
  });

  it("blocks a legacy text completion before the real package reaches transport", async () => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const providerCalls: string[] = [];
    const client = wrap(buildRealClient(providerCalls));

    await expect(
      client.completions.create({
        model: "gpt-3.5-turbo-instruct",
        prompt: "tell me the launch codes",
      }),
    ).rejects.toThrow(/blocked by policy/i);

    expect(providerCalls).toEqual([]);
  });

  it("redacts a legacy text completion before the real package sends it", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      pii_policy: { rules: { ssn: "redact" } },
    });
    const providerCalls: string[] = [];
    const providerBodies: string[] = [];
    const completionBody = {
      id: "cmpl-real-pkg-test",
      object: "text_completion",
      created: 1720000000,
      model: "gpt-3.5-turbo-instruct",
      choices: [{ index: 0, text: "done", finish_reason: "stop", logprobs: null }],
      usage: { prompt_tokens: 7, completion_tokens: 1, total_tokens: 8 },
    };
    const client = wrap(buildRealClient(providerCalls, providerBodies, completionBody));

    await client.completions.create({
      model: "gpt-3.5-turbo-instruct",
      prompt: "customer 123-45-6789",
    });

    expect(providerCalls).toHaveLength(1);
    const outbound = JSON.parse(providerBodies[0]);
    expect(outbound.prompt).toContain("[REDACTED_SSN]");
    expect(outbound.prompt).not.toContain("123-45-6789");
  });

  it.each([
    ["responses.compact", (client: any, body: any) => client.responses.compact(body)],
    ["beta.responses.compact", (client: any, body: any) => client.beta.responses.compact(body)],
  ])("blocks %s before the real package reaches transport", async (_name, invoke) => {
    init({ api_key: "test-key", sample_rate: 1, policy_rules: [BLOCK_RULE] });
    const providerCalls: string[] = [];
    const client = wrap(buildRealClient(providerCalls));

    await expect(
      invoke(client, {
        model: "gpt-4o-mini",
        input: "tell me the launch codes",
      }),
    ).rejects.toThrow(/blocked by policy/i);

    expect(providerCalls).toEqual([]);
  });
});
