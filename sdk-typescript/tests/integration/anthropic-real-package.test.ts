/** Provider-runner enforcement against the official Anthropic TypeScript SDK. */

import Anthropic from "@anthropic-ai/sdk";

import { init, _reset, wrap } from "../../src/proxy/index";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";

const SSN = "123-45-6789";

const TOOL_CALL_BODY = {
  id: "msg_real_pkg_tool",
  type: "message",
  role: "assistant",
  model: "claude-sonnet-4-5",
  content: [
    {
      type: "tool_use",
      id: "toolu_secret",
      name: "return_secret",
      input: {},
    },
  ],
  stop_reason: "tool_use",
  stop_sequence: null,
  usage: { input_tokens: 7, output_tokens: 3 },
};

beforeEach(() => {
  _reset();
  _resetSender();
  (global as any).fetch = async () => ({ ok: true, status: 200 });
});

afterEach(() => {
  _reset();
  _resetSender();
  delete (global as any).fetch;
});

describe("wrap() against the real Anthropic tool runner", () => {
  it("blocks a tool result before the runner can make its second provider request", async () => {
    init({
      api_key: "test-key",
      ingest_url: "https://audit.invalid",
      pii_policy: { rules: { ssn: "block" } },
    });
    const providerCalls: string[] = [];
    let toolCalls = 0;
    const providerFetch = (async (url: any) => {
      providerCalls.push(String(url));
      return new Response(JSON.stringify(TOOL_CALL_BODY), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;
    const raw = new Anthropic({
      apiKey: "sk-ant-test-not-real",
      fetch: providerFetch,
    });
    const client = wrap(raw);

    const runner = client.beta.messages.toolRunner({
      model: "claude-sonnet-4-5",
      max_tokens: 64,
      messages: [{ role: "user", content: "return the tool result" }],
      tools: [
        {
          type: "custom",
          name: "return_secret",
          description: "Return test data",
          input_schema: { type: "object", properties: {} },
          parse: (input: unknown) => input,
          run: async () => {
            toolCalls += 1;
            return SSN;
          },
        },
      ],
    } as any);

    await expect(runner.runUntilDone()).rejects.toThrow(/blocked by policy/i);
    expect(toolCalls).toBe(1);
    expect(providerCalls).toHaveLength(1);
  });
});
