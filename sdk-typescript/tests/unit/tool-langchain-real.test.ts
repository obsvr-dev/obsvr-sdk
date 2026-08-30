/** Generic tool governance on the official LangChain invoke boundary. */

import { DynamicStructuredTool } from "@langchain/core/tools";
import { z } from "zod";

import { init, _reset } from "../../src/proxy/config";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";
import { obsvrGovernTool } from "../../src/integrations/tools";

beforeEach(() => {
  _reset();
  _resetSender();
  (global as any).fetch = async () => ({ ok: true, status: 200 });
});

afterEach(() => {
  delete (global as any).fetch;
  _reset();
  _resetSender();
});

function langChainTool(entries: Array<{ secret: string }>) {
  return new DynamicStructuredTool({
    name: "store_secret",
    description: "Stores a value",
    schema: z.object({ secret: z.string() }),
    func: async (input) => {
      entries.push(input);
      return "stored";
    },
  });
}

it("blocks LangChain invoke input before the tool body", async () => {
  init({ api_key: "test", pii_policy: { rules: { ssn: "block" } } });
  const entries: Array<{ secret: string }> = [];
  const governed = obsvrGovernTool(langChainTool(entries));

  await expect(
    governed.invoke({ secret: "123-45-6789" }, {}),
  ).rejects.toThrow(/blocked by policy/);

  expect(entries).toHaveLength(0);
});

it("redacts LangChain invoke input before the tool body", async () => {
  init({ api_key: "test", pii_policy: { rules: { ssn: "redact" } } });
  const entries: Array<{ secret: string }> = [];
  const governed = obsvrGovernTool(langChainTool(entries));

  await expect(
    governed.invoke({ secret: "123-45-6789" }, {}),
  ).resolves.toBe("stored");

  expect(entries).toEqual([{ secret: "[REDACTED_SSN]" }]);
});

it("allows LangChain invoke input exactly once", async () => {
  init({ api_key: "test", pii_policy: { rules: { ssn: "block" } } });
  const entries: Array<{ secret: string }> = [];
  const governed = obsvrGovernTool(langChainTool(entries));

  await expect(governed.invoke({ secret: "safe" }, {})).resolves.toBe("stored");

  expect(entries).toEqual([{ secret: "safe" }]);
});
