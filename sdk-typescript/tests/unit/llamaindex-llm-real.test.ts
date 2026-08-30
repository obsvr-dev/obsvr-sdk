/** Real LlamaIndex Settings path with a local provider-body spy. */

import { Settings } from "llamaindex";

import { init, _reset } from "../../src/proxy/config";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";
import {
  obsvrGovernLlamaIndexLLM,
  type LlamaIndexLLMLike,
} from "../../src/integrations/llamaindex-llm";

class RealSettingsSpy implements LlamaIndexLLMLike {
  metadata = {
    model: "gpt-4o-mini",
    temperature: 0,
    topP: 1,
    contextWindow: 128000,
    tokenizer: undefined,
    structuredOutput: false,
  };
  entries = 0;

  async chat(_params: Record<string, unknown>): Promise<unknown> {
    this.entries += 1;
    return { message: { role: "assistant", content: "ok" }, raw: null };
  }

  async complete(_params: Record<string, unknown>): Promise<unknown> {
    this.entries += 1;
    return { text: "ok", raw: null };
  }
}

beforeEach(() => {
  _reset();
  _resetSender();
  (global as any).fetch = async () => ({ ok: true, status: 200 });
});

it("stops the official Settings LLM path before provider dispatch", async () => {
  init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
  const body = new RealSettingsSpy();
  Settings.llm = obsvrGovernLlamaIndexLLM(body) as any;

  await expect(
    Settings.llm.complete({ prompt: "SSN 123-45-6789" }),
  ).rejects.toThrow("Request blocked by policy");

  expect(body.entries).toBe(0);
});

it("allows the official Settings LLM path exactly once", async () => {
  init({ api_key: "test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
  const body = new RealSettingsSpy();
  Settings.llm = obsvrGovernLlamaIndexLLM(body) as any;

  await Settings.llm.complete({ prompt: "hello" });

  expect(body.entries).toBe(1);
});
