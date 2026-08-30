/**
 * The tool gate, driven against the REAL `@openai/agents` package.
 *
 * openai-agents-tool-gate.test.ts drives the guardrail contract against
 * hand-modeled tool shapes and says so in its own header: "The live proof
 * lives in the integration harness, not here." This is that harness. A real
 * `Agent` built from real `tool()` objects runs through the real `run()`
 * executor, with only the MODEL stubbed (the `Model` interface exists for
 * exactly that); `attachToolGate` installs obsvr's guardrail into the real
 * package's own `inputGuardrails` arrays, so this file fails the day the real
 * executor stops consulting them or the real `tool()` stops carrying them.
 *
 * The grading follows mcp-real-package.test.ts: what matters is whether the
 * TOOL BODY ran, asserted from the tool's own side-effect spy, and — because
 * a rejected tool comes back to the model as the tool's result rather than as
 * an exception — that the real executor delivered the block message to the
 * model on the next turn.
 */
import {
  Agent,
  run,
  setTracingDisabled,
  tool,
  Usage,
  type Model,
  type ModelRequest,
  type ModelResponse,
} from "@openai/agents";

import { init, _reset } from "../../src/proxy/config";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";
import {
  attachToolGate,
  governModel,
  governModelProvider,
} from "../../src/integrations/openai-agents";

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  setTracingDisabled(true);
  sentEvents = [];
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

/**
 * A Model stub for the real executor: turn one asks for the `send_money`
 * tool; turn two answers in prose. Every request is captured so the test can
 * read what the real framework fed back as the tool's result.
 */
function buildScriptedModel(requests: ModelRequest[]): Model {
  let turn = 0;
  return {
    async getResponse(request: ModelRequest): Promise<ModelResponse> {
      requests.push(request);
      turn += 1;
      if (turn === 1) {
        return {
          usage: new Usage(),
          output: [
            {
              type: "function_call",
              callId: "call-1",
              name: "send_money",
              arguments: JSON.stringify({ amount: 100 }),
              status: "completed",
            },
          ],
        };
      }
      return {
        usage: new Usage(),
        output: [
          {
            type: "message",
            role: "assistant",
            status: "completed",
            content: [{ type: "output_text", text: "done" }],
          },
        ],
      };
    },
    // eslint-disable-next-line require-yield
    async *getStreamedResponse(): AsyncIterable<never> {
      throw new Error("streaming is not part of this harness");
    },
  } as Model;
}

/** A real agent carrying one destructive-shaped real tool. */
function buildRealAgent(executed: string[], requests: ModelRequest[]): Agent {
  const sendMoney = tool({
    name: "send_money",
    description: "Transfer funds. Stands in for a destructive capability.",
    parameters: {
      type: "object",
      properties: { amount: { type: "number" } },
      required: ["amount"],
      additionalProperties: false,
    },
    strict: true,
    execute: async () => {
      executed.push("send_money");
      return "sent";
    },
  });
  return new Agent({
    name: "obsvr-test-agent",
    instructions: "Use the tools you are given.",
    model: buildScriptedModel(requests),
    tools: [sendMoney],
  });
}

function emptyResponse(): ModelResponse {
  return {
    usage: new Usage(),
    output: [
      {
        type: "message",
        role: "assistant",
        status: "completed",
        content: [{ type: "output_text", text: "done" }],
      },
    ],
  };
}

function countingModel(
  requests: ModelRequest[],
  streamRequests: ModelRequest[] = [],
): Model {
  return {
    async getResponse(request: ModelRequest): Promise<ModelResponse> {
      requests.push(request);
      return emptyResponse();
    },
    async *getStreamedResponse(request: ModelRequest): AsyncIterable<never> {
      streamRequests.push(request);
    },
  };
}

function request(input: ModelRequest["input"]): ModelRequest {
  return {
    systemInstructions: "Keep the answer concise.",
    input,
    modelSettings: {},
    tools: [],
    outputType: "text",
    handoffs: [],
    tracing: false,
  };
}

describe("attachToolGate against the real @openai/agents package", () => {
  it("CONTROL: with no agent policy, the real executor runs the tool body", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const executed: string[] = [];
    const requests: ModelRequest[] = [];
    const agent = buildRealAgent(executed, requests);
    attachToolGate(agent);

    const result = await run(agent, "transfer one hundred");

    // Without this row, "the tool did not run" below would also be satisfied
    // by an executor that never consulted the model at all.
    expect(executed).toEqual(["send_money"]);
    expect(result.finalOutput).toBe("done");
  });

  it("a denied tool's body is never entered, and the model receives the block message", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      agent_policy: { deniedTools: ["send_money"] },
    } as any);
    const executed: string[] = [];
    const requests: ModelRequest[] = [];
    const agent = buildRealAgent(executed, requests);
    attachToolGate(agent);

    const result = await run(agent, "transfer one hundred");

    // The assertion that matters: the real executor consulted the real
    // inputGuardrails array where the gate was installed, so the callable
    // was never entered — and the run CONTINUED, because a rejected tool
    // comes back to the model as the tool's result.
    expect(executed).toEqual([]);
    expect(result.finalOutput).toBe("done");

    // The second model turn carries the refusal as the tool's result.
    expect(requests.length).toBe(2);
    const fedBack = JSON.stringify(requests[1].input);
    expect(fedBack).toContain("[obsvr] Tool 'send_money' blocked by agent policy");
  });

  it("the refusal is recorded as blocked on a signed event", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      agent_policy: { deniedTools: ["send_money"] },
    } as any);
    const executed: string[] = [];
    const requests: ModelRequest[] = [];
    const agent = buildRealAgent(executed, requests);
    attachToolGate(agent);

    await run(agent, "transfer one hundred");
    await waitForEvents(1);

    const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
    const blocked = events.find((e: any) => e.action_taken === "blocked");

    // Both halves: the tool body never ran, AND the record says so.
    expect(executed).toEqual([]);
    expect(blocked).toBeDefined();
    expect(blocked.operation).toBe("openai_agents.agent.policy.tool_blocked");
    expect(blocked.metadata.tool_name).toBe("send_money");
    expect(blocked.sdk_sig).toEqual(expect.any(String));
  });

  it("CONTROL: under the same deny policy, an undenied tool still runs", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      agent_policy: { deniedTools: ["some_other_tool"] },
    } as any);
    const executed: string[] = [];
    const requests: ModelRequest[] = [];
    const agent = buildRealAgent(executed, requests);
    attachToolGate(agent);

    await run(agent, "transfer one hundred");

    // Without this, "send_money did not run" would also be satisfied by a
    // gate that had stopped letting anything through.
    expect(executed).toEqual(["send_money"]);
  });
});

describe("model boundary against the real @openai/agents package", () => {
  const SSN = "123-45-6789";

  it("blocks before the real runner enters a direct Model", async () => {
    init({ api_key: "test-key", pii_policy: { rules: { ssn: "block" } } });
    const requests: ModelRequest[] = [];
    const agent = new Agent({
      name: "governed-model-agent",
      instructions: "Answer the user.",
      model: governModel(countingModel(requests), { model: "gpt-4o-mini" }),
    });

    await expect(run(agent, `my ssn is ${SSN}`)).rejects.toThrow("obsvr");
    expect(requests).toHaveLength(0);
  });

  it("redacts every provider-bound input turn before a direct Model runs", async () => {
    init({ api_key: "test-key", pii_policy: { rules: { ssn: "redact" } } });
    const requests: ModelRequest[] = [];
    const model = governModel(countingModel(requests), { model: "gpt-4o-mini" });
    const outbound = request([
      { role: "user", content: [{ type: "input_text", text: `old ${SSN}` }] },
      { role: "assistant", content: [{ type: "output_text", text: "noted" }], status: "completed" },
      { role: "user", content: [{ type: "input_text", text: "continue" }] },
    ] as any);
    outbound.systemInstructions = `system ${SSN}`;
    outbound.prompt = {
      promptId: "pmpt_test",
      variables: { customer: SSN },
    };

    await model.getResponse(outbound);

    expect(requests).toHaveLength(1);
    expect(JSON.stringify(requests[0])).not.toContain(SSN);
    expect(JSON.stringify(requests[0])).toContain("[REDACTED_SSN]");
  });

  it("governs models returned by a ModelProvider", async () => {
    init({ api_key: "test-key", pii_policy: { rules: { ssn: "block" } } });
    const requests: ModelRequest[] = [];
    const provider = governModelProvider({
      getModel: (_modelName?: string) => countingModel(requests),
    });
    const model = await provider.getModel("gpt-4o-mini");

    await expect(model.getResponse(request(`my ssn is ${SSN}`))).rejects.toThrow(
      "obsvr",
    );
    expect(requests).toHaveLength(0);
  });

  it("fails closed when a redact verdict has no safe structured rewrite", async () => {
    init({
      api_key: "test-key",
      on_pre_call: async () => ({ decision: "redact" as const }),
    });
    const requests: ModelRequest[] = [];
    const model = governModel(countingModel(requests), { model: "gpt-4o-mini" });

    await expect(model.getResponse(request("ordinary text"))).rejects.toThrow("obsvr");
    expect(requests).toHaveLength(0);
  });

  it("blocks a streamed request before the Model async iterator starts", async () => {
    init({ api_key: "test-key", pii_policy: { rules: { ssn: "block" } } });
    const streamRequests: ModelRequest[] = [];
    const model = governModel(countingModel([], streamRequests), {
      model: "gpt-4o-mini",
    });

    const consume = async () => {
      for await (const _event of model.getStreamedResponse(request(`ssn ${SSN}`))) {
        // The block must happen before the wrapped iterator yields or starts.
      }
    };
    await expect(consume()).rejects.toThrow("obsvr");
    expect(streamRequests).toHaveLength(0);
  });
});
