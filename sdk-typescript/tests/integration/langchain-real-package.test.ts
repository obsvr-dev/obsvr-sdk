/**
 * LangChain's real model boundary, with only the provider transport stubbed.
 *
 * The framework awaits `handleChatModelStart` before `_generate` and propagates
 * errors from handlers whose `raiseError` flag is true. These tests prove the
 * obsvr handler uses that seam: a denied prompt never reaches the model body,
 * while a permitted prompt reaches it exactly once.
 */
import { AIMessage } from "@langchain/core/messages";
import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import type { BaseMessage } from "@langchain/core/messages";
import type { ChatResult } from "@langchain/core/outputs";

import { init, _reset } from "../../src/proxy/config";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";
import { ObsvrCallbackHandler } from "../../src/integrations/langchain";

class TransportSpyModel extends BaseChatModel {
  calls = 0;

  _llmType(): string {
    return "transport-spy";
  }

  async _generate(_messages: BaseMessage[]): Promise<ChatResult> {
    this.calls += 1;
    return {
      generations: [{ text: "ok", message: new AIMessage("ok") }],
      llmOutput: { tokenUsage: { promptTokens: 1, completionTokens: 1, totalTokens: 2 } },
    };
  }
}

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: unknown, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200 };
  };
});

async function settle(): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length === 0; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

describe("LangChain real-package model enforcement", () => {
  it("blocks PII before the model transport is entered", async () => {
    init({ api_key: "test", ingest_url: "https://ingest.test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
    const model = new TransportSpyModel({
      callbacks: [new ObsvrCallbackHandler() as any],
    });

    await expect(model.invoke("my SSN is 123-45-6789")).rejects.toThrow(
      /Request blocked by policy/,
    );
    await settle();

    expect(model.calls).toBe(0);
    expect(sentEvents).toHaveLength(1);
    expect(sentEvents[0]).toMatchObject({
      source: "langchain_js",
      operation: "llm",
      action_taken: "blocked",
      action_reason: "pii_detected",
      success: false,
    });
    expect(sentEvents[0].prompt).not.toContain("123-45-6789");
  });

  it("lets a permitted prompt reach the model exactly once", async () => {
    init({ api_key: "test", ingest_url: "https://ingest.test", sample_rate: 1, pii_policy: { rules: { ssn: "block" } } });
    const model = new TransportSpyModel({
      callbacks: [new ObsvrCallbackHandler() as any],
    });

    await expect(model.invoke("hello")).resolves.toMatchObject({ content: "ok" });
    await settle();

    expect(model.calls).toBe(1);
    expect(sentEvents).toHaveLength(1);
    expect(sentEvents[0].action_taken).toBe("allowed");
  });

  it("fails closed when callback-level redaction cannot rewrite the request", async () => {
    init({ api_key: "test", ingest_url: "https://ingest.test", sample_rate: 1, pii_policy: { rules: { ssn: "redact" } } });
    const model = new TransportSpyModel({
      callbacks: [new ObsvrCallbackHandler() as any],
    });

    await expect(model.invoke("my SSN is 123-45-6789")).rejects.toThrow(
      /Request blocked by policy/,
    );
    await settle();

    expect(model.calls).toBe(0);
    expect(sentEvents).toHaveLength(1);
    expect(sentEvents[0]).toMatchObject({
      source: "langchain_js",
      operation: "llm",
      action_taken: "blocked",
      success: false,
    });
    expect(sentEvents[0].prompt).not.toContain("123-45-6789");
    expect(sentEvents[0].redacted_types).toEqual([]);
    expect(sentEvents[0].blocked_types).toContain("ssn");
  });
});
