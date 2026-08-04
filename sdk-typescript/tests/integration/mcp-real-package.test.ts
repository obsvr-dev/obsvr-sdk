/**
 * The MCP tool gate, driven against the REAL `@modelcontextprotocol/sdk`.
 *
 * Every other MCP test in this tree drives hand-written fakes, and
 * `mcp-integration.test.ts` carries its own copy of the policy check annotated
 * "mirrors mcp.ts logic" — a check that passes whether or not the module under
 * test still agrees with it. Measured: with the gate returning "allowed" for
 * every tool, that file still passes 18 of 18. This surface is the one
 * `SECURITY.md` tells operators to put a destructive capability behind, so it is
 * the one least able to afford a test that cannot fail for the right reason.
 *
 * The grading is not "the client raised". It is whether the SERVER executed the
 * tool body: each tool appends to `executed`, so a refusal is asserted from the
 * far side of a real transport rather than from the caller's exception. A gate
 * that threw after delegating would satisfy an exception-only assertion and
 * fail this one.
 *
 * No `inputSchema` is declared on these tools, so nothing here depends on the
 * MCP SDK's own schema library resolving through hoisting. The handlers record
 * their name, which is all the "did the body run" question needs.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";

import { init, _reset, getConfig } from "../../src/proxy/config";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";
import { obsvrGovernMCP } from "../../src/integrations/mcp";

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
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

/** A real server carrying one destructive-shaped tool and one benign one. */
function buildRealServer(executed: string[]): McpServer {
  const server = new McpServer({ name: "obsvr-test-server", version: "1.0.0" });
  server.registerTool(
    "send_money",
    { description: "Transfer funds. Stands in for a destructive capability." },
    async () => {
      executed.push("send_money");
      return { content: [{ type: "text" as const, text: "sent" }] };
    },
  );
  server.registerTool(
    "read_file",
    { description: "Read a file. Stands in for a benign capability." },
    async () => {
      executed.push("read_file");
      return { content: [{ type: "text" as const, text: "contents" }] };
    },
  );
  return server;
}

/** Stand up a real server + real client over a real in-memory transport pair. */
async function connectRealPair(): Promise<{
  client: Client;
  executed: string[];
  close: () => Promise<void>;
}> {
  const executed: string[] = [];
  const server = buildRealServer(executed);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "obsvr-test-client", version: "1.0.0" }, { capabilities: {} });

  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

  return {
    client,
    executed,
    close: async () => {
      await client.close();
      await server.close();
    },
  };
}

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 300 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("MCP tool gate against the real @modelcontextprotocol/sdk", () => {
  it("CONTROL: with no tool policy, the real server executes the tool", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      const result: any = await governed.callTool({
        name: "send_money",
        arguments: { amount: 100 },
      });

      // Without this row, "the tool did not run" below would also be satisfied
      // by a transport that never worked at all.
      expect(executed).toEqual(["send_money"]);
      expect(result.content[0].text).toBe("sent");
    } finally {
      await close();
    }
  });

  it("a denied tool is refused and the real server never executes its body", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());

      await expect(
        governed.callTool({ name: "send_money", arguments: { amount: 100 } }),
      ).rejects.toThrow();

      // The assertion that matters: the far side of a real transport reports
      // that the tool body was never entered.
      expect(executed).toEqual([]);
    } finally {
      await close();
    }
  });

  it("CONTROL: under the same deny policy, an undenied tool still runs", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await governed.callTool({ name: "read_file", arguments: { path: "/tmp/x" } });

      // Without this, "send_money did not run" would also be satisfied by a
      // gate that had stopped letting anything through.
      expect(executed).toEqual(["read_file"]);
    } finally {
      await close();
    }
  });

  it("the refusal is recorded as blocked on a signed event", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await expect(
        governed.callTool({ name: "send_money", arguments: { amount: 100 } }),
      ).rejects.toThrow();
      await waitForEvents(1);

      const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
      const blocked = events.find((e: any) => e.action_taken === "blocked");

      // Both halves, because either alone has already shipped as a defect
      // somewhere in this tree: the tool did not run, AND the record says so.
      expect(executed).toEqual([]);
      expect(blocked).toBeDefined();
      expect(blocked.operation).toBe("mcp.tool.call");
      expect(blocked.sdk_sig).toEqual(expect.any(String));
    } finally {
      await close();
    }
  });

  it("the allowlist form refuses a tool that is simply not on it", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { allowedTools: ["read_file"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await expect(
        governed.callTool({ name: "send_money", arguments: { amount: 100 } }),
      ).rejects.toThrow();
      expect(executed).toEqual([]);

      await governed.callTool({ name: "read_file", arguments: { path: "/tmp/x" } });
      expect(executed).toEqual(["read_file"]);
    } finally {
      await close();
    }
  });

  it("the real Client class can be governed as a class, not only as an instance", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });

    const executed: string[] = [];
    const server = buildRealServer(executed);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const GovernedClient = obsvrGovernMCP(Client, getConfig());
    const client = new GovernedClient({ name: "c", version: "1.0.0" }, { capabilities: {} });

    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      await expect(
        client.callTool({ name: "send_money", arguments: { amount: 100 } }),
      ).rejects.toThrow();
      expect(executed).toEqual([]);
    } finally {
      await client.close();
      await server.close();
    }
  });
});

/**
 * The routes `callTool` does not cover.
 *
 * `callTool` is a convenience: `client/index.js` builds
 * `{ method: "tools/call", params }` and hands it to `this.request`. Two other
 * public routes reach the same frame without passing through it — a
 * hand-built frame given to `request`, and the package's own task API, whose
 * `callToolStream` goes through `requestStream` and thence to `this.request`.
 * Driven against the real server with the tool denied and the client governed,
 * both executed the tool body AND returned its result to the caller.
 *
 * Each row grades BOTH halves, because they fail independently: a swallowed
 * error can produce zero executions while the caller still holds the payload,
 * and that reads as a perfect refusal if only the execution is checked.
 */
describe("MCP tool gate on the routes around callTool", () => {
  /** Drain the task API's stream into its messages. */
  async function drain(stream: AsyncIterable<any>): Promise<any[]> {
    const messages: any[] = [];
    for await (const m of stream) messages.push(m);
    return messages;
  }

  const rawFrame = (name: string, args: Record<string, unknown>) =>
    ({ method: "tools/call" as const, params: { name, arguments: args } });

  it("CONTROL: ungoverned, both routes reach the tool and return its result", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const { client, executed, close } = await connectRealPair();
    try {
      const viaRequest: any = await client.request(
        rawFrame("send_money", { amount: 100 }),
        CallToolResultSchema,
      );
      const viaStream = await drain(
        client.experimental.tasks.callToolStream({
          name: "send_money",
          arguments: { amount: 100 },
        }),
      );

      // Without this row, every refusal below would also be satisfied by a
      // route that never worked in the first place.
      expect(executed).toEqual(["send_money", "send_money"]);
      expect(viaRequest.content[0].text).toBe("sent");
      expect(viaStream.find((m) => m.type === "result")?.result.content[0].text).toBe("sent");
    } finally {
      await close();
    }
  });

  it("a denied tool is refused on the raw request route, body and payload both", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await expect(
        governed.request(rawFrame("send_money", { amount: 100 }), CallToolResultSchema),
      ).rejects.toThrow(/\[obsvr\]/);

      expect(executed).toEqual([]);
    } finally {
      await close();
    }
  });

  it("a denied tool is refused on the task-API stream route", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      const messages = await drain(
        governed.experimental.tasks.callToolStream({
          name: "send_money",
          arguments: { amount: 100 },
        }),
      );

      expect(executed).toEqual([]);
      // The stream's contract is to end in a result or an error. The refusal
      // has to arrive as the error, and no result may carry the payload.
      expect(messages.find((m) => m.type === "result")).toBeUndefined();
      expect(String(messages.find((m) => m.type === "error")?.error?.message)).toContain("[obsvr]");
    } finally {
      await close();
    }
  });

  it("the class-governed client refuses on both routes too", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });

    const executed: string[] = [];
    const server = buildRealServer(executed);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const GovernedClient = obsvrGovernMCP(Client, getConfig());
    const client: any = new GovernedClient({ name: "c", version: "1.0.0" }, { capabilities: {} });

    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      await expect(
        client.request(rawFrame("send_money", { amount: 100 }), CallToolResultSchema),
      ).rejects.toThrow(/\[obsvr\]/);
      const messages = await drain(
        client.experimental.tasks.callToolStream({
          name: "send_money",
          arguments: { amount: 100 },
        }),
      );
      expect(messages.find((m) => m.type === "result")).toBeUndefined();
      expect(executed).toEqual([]);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("CONTROL: under the same deny policy, an undenied tool still runs on both routes", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await governed.request(rawFrame("read_file", { path: "/tmp/x" }), CallToolResultSchema);
      await drain(
        governed.experimental.tasks.callToolStream({
          name: "read_file",
          arguments: { path: "/tmp/x" },
        }),
      );

      // Without this, the refusals above would also be satisfied by a gate
      // that had stopped letting anything through either route.
      expect(executed).toEqual(["read_file", "read_file"]);
    } finally {
      await close();
    }
  });

  it("a frame that is not tools/call passes through ungoverned", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      // The gate exists to catch tool calls, not to stand in front of the
      // whole protocol: discovery over the same route must still work.
      const listed: any = await governed.listTools();
      expect(listed.tools.map((t: any) => t.name).sort()).toEqual(["read_file", "send_money"]);
      expect(executed).toEqual([]);
    } finally {
      await close();
    }
  });

  it("one tool call records exactly one event, whichever route built it", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());

      // callTool delegates to request internally. Without the reentrancy
      // guard the gate would judge that frame a second time and this call
      // would emit two records for one execution.
      await governed.callTool({ name: "read_file", arguments: { path: "/tmp/x" } });
      await waitForEvents(1);

      const events = sentEvents
        .flatMap((b: any) => b.events ?? [b])
        .filter((e: any) => e.operation === "mcp.tool.call");
      expect(executed).toEqual(["read_file"]);
      expect(events).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it("governing the same client twice still records one event per call", async () => {
    init({ api_key: "test-key", sample_rate: 1 });
    const { client, executed, close } = await connectRealPair();
    try {
      // Two independent callers each governing the same client is the shape
      // that puts one gate underneath another. The inner gate has to let the
      // frame the outer gate is already running pass through, or one tool call
      // is judged twice and recorded twice.
      const once = obsvrGovernMCP(client, getConfig());
      const twice = obsvrGovernMCP(once, getConfig());

      await twice.request(rawFrame("read_file", { path: "/tmp/x" }), CallToolResultSchema);
      await waitForEvents(1);

      const events = sentEvents
        .flatMap((b: any) => b.events ?? [b])
        .filter((e: any) => e.operation === "mcp.tool.call");
      expect(executed).toEqual(["read_file"]);
      expect(events).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it("governing the same client twice still refuses a denied tool once", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const twice = obsvrGovernMCP(obsvrGovernMCP(client, getConfig()), getConfig());
      await expect(
        twice.request(rawFrame("send_money", { amount: 100 }), CallToolResultSchema),
      ).rejects.toThrow(/\[obsvr\]/);
      await waitForEvents(1);

      // The pass-through must not become a way past the gate: nesting changes
      // how many records a call leaves, never whether it is refused.
      const events = sentEvents
        .flatMap((b: any) => b.events ?? [b])
        .filter((e: any) => e.action_taken === "blocked");
      expect(executed).toEqual([]);
      expect(events).toHaveLength(1);
    } finally {
      await close();
    }
  });

  it("the raw-route refusal is recorded as blocked on a signed event", async () => {
    init({
      api_key: "test-key",
      sample_rate: 1,
      mcpToolPolicy: { deniedTools: ["send_money"] },
    });
    const { client, executed, close } = await connectRealPair();
    try {
      const governed = obsvrGovernMCP(client, getConfig());
      await expect(
        governed.request(rawFrame("send_money", { amount: 100 }), CallToolResultSchema),
      ).rejects.toThrow();
      await waitForEvents(1);

      const events = sentEvents.flatMap((b: any) => b.events ?? [b]);
      const blocked = events.find((e: any) => e.action_taken === "blocked");

      // Both halves: the tool did not run, AND the record says so. A route
      // that refused without recording would be a silence, not enforcement.
      expect(executed).toEqual([]);
      expect(blocked).toBeDefined();
      expect(blocked.operation).toBe("mcp.tool.call");
      expect(blocked.metadata.tool_name).toBe("send_money");
      expect(blocked.sdk_sig).toEqual(expect.any(String));
    } finally {
      await close();
    }
  });
});
