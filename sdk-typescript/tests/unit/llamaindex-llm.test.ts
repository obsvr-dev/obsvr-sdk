import { init, _reset } from "../../src/proxy/config";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";
import {
  obsvrGovernLlamaIndexLLM,
  type LlamaIndexLLMLike,
} from "../../src/integrations/llamaindex-llm";

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: unknown, opts: { body: string }) => {
    sentEvents.push(JSON.parse(opts.body));
    return { ok: true, status: 200 };
  };
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length < n; i++) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

class TransportSpy implements LlamaIndexLLMLike {
  metadata = { model: "gpt-4o-mini" };
  chatCalls: Record<string, unknown>[] = [];
  completeCalls: Record<string, unknown>[] = [];

  async chat(params: Record<string, unknown>): Promise<unknown> {
    this.chatCalls.push(params);
    if (params.stream) {
      return (async function* () {
        yield { delta: "hel", raw: null };
        yield { delta: "lo", raw: null };
      })();
    }
    return { message: { role: "assistant", content: "ok" }, raw: null };
  }

  async complete(params: Record<string, unknown>): Promise<unknown> {
    this.completeCalls.push(params);
    return { text: "ok", raw: null };
  }
}

describe("obsvrGovernLlamaIndexLLM", () => {
  it("requires the stable chat and complete boundary", () => {
    expect(() => obsvrGovernLlamaIndexLLM({} as LlamaIndexLLMLike)).toThrow(
      "requires a LlamaIndex LLM",
    );
  });

  it("blocks completion content before the model body", async () => {
    init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    await expect(
      governed.complete({ prompt: "SSN 123-45-6789" }),
    ).rejects.toThrow("Request blocked by policy");

    expect(body.completeCalls).toHaveLength(0);
    await waitForEvents();
    expect(sentEvents[0]).toMatchObject({
      source: "llamaindex_ts",
      operation: "llamaindex.llm",
      action_taken: "blocked",
      success: false,
    });
    expect(sentEvents[0].prompt).not.toContain("123-45-6789");
  });

  it("blocks chat content before the model body", async () => {
    init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    await expect(
      governed.chat({
        messages: [{ role: "user", content: "SSN 123-45-6789" }],
      }),
    ).rejects.toThrow("Request blocked by policy");

    expect(body.chatCalls).toHaveLength(0);
  });

  it("rewrites completion content before model dispatch", async () => {
    init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "redact" } } });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    await governed.complete({ prompt: "SSN 123-45-6789" });

    expect(body.completeCalls).toHaveLength(1);
    expect(body.completeCalls[0].prompt).toContain("[REDACTED_SSN]");
    expect(body.completeCalls[0].prompt).not.toContain("123-45-6789");
    await waitForEvents();
    expect(sentEvents[0].action_taken).toBe("redacted");
  });

  it("rewrites chat content before model dispatch", async () => {
    init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "redact" } } });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    await governed.chat({
      messages: [
        { role: "system", content: "help" },
        { role: "user", content: "SSN 123-45-6789" },
      ],
    });

    expect(body.chatCalls).toHaveLength(1);
    const wire = JSON.stringify(body.chatCalls[0]);
    expect(wire).toContain("[REDACTED_SSN]");
    expect(wire).not.toContain("123-45-6789");
  });

  it("replaces all outbound text when a hook requests spanless redaction", async () => {
    init({
      api_key: "test",
      sample_rate: 1,
      on_pre_call: async () => ({ decision: "redact" as const }),
    });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    await governed.chat({
      messages: [
        { role: "system", content: "private system text" },
        { role: "user", content: "private user text" },
      ],
    });

    const wire = JSON.stringify(body.chatCalls[0]);
    expect(wire).toContain("[REDACTED_BY_POLICY]");
    expect(wire).not.toContain("private system text");
    expect(wire).not.toContain("private user text");
  });

  it("lets an allowed request reach the model exactly once", async () => {
    init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    await expect(governed.complete({ prompt: "hello" })).resolves.toMatchObject({
      text: "ok",
    });

    expect(body.completeCalls).toEqual([{ prompt: "hello" }]);
    await waitForEvents();
    expect(sentEvents[0].action_taken).toBe("allowed");
  });

  it("preserves streaming while recording the completed response", async () => {
    init({ api_key: "test", sample_rate: 1 });
    const body = new TransportSpy();
    const governed = obsvrGovernLlamaIndexLLM(body);

    const stream = (await governed.chat({
      messages: [{ role: "user", content: "hello" }],
      stream: true,
    })) as AsyncIterable<unknown>;
    const chunks: unknown[] = [];
    for await (const chunk of stream) chunks.push(chunk);

    expect(chunks).toHaveLength(2);
    expect(body.chatCalls).toHaveLength(1);
    await waitForEvents();
    expect(sentEvents[0].response).toBe("hello");
  });
});
