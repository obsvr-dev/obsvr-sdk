/**
 * The bar for this package: a NATIVE tool call is genuinely REFUSED by obsvr
 * policy, and the refusal is recorded on the SAME signed audit chain as
 * everything else — verifiable by the shipped verifier, offline, with the
 * API key. These tests drive the real `@obsvr/sdk` policy engine (no fakes)
 * and capture the emitted event off the sender's delivery path.
 */
import assert from "node:assert/strict";
import { test, beforeEach, afterEach } from "node:test";
import { obsvr, verifyAuditChain } from "@obsvr/sdk";
import { governToolCall, isNativeTool, toolCallText } from "../src/index.js";

const API_KEY = "hook-test-key";
// A native shell tool call carrying a command an operator would refuse.
const DESTRUCTIVE_BASH = {
  hook_event_name: "PreToolUse",
  tool_name: "Bash",
  tool_input: { command: "rm -rf /important/data" },
  session_id: "s-1",
};

let sent: any[];
const originalFetch = globalThis.fetch;

function captureFetch(): void {
  sent = [];
  globalThis.fetch = (async (_url: unknown, opts?: { body?: string }) => {
    try {
      const body = JSON.parse(opts?.body ?? "null");
      if (Array.isArray(body)) sent.push(...body);
      else if (body) sent.push(body);
    } catch {
      /* not an event body */
    }
    return { ok: true, status: 200, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
}

/** obsvr with one keyword rule that blocks the destructive command. */
function initWithBlockingPolicy(): void {
  obsvr.init({
    api_key: API_KEY,
    ingest_url: "https://localhost:1",
    sample_rate: 1,
    policy_rules: [
      {
        id: "no-recursive-delete",
        name: "block recursive force delete",
        enabled: true,
        action: "block",
        type: "keyword",
        conditions: { keywords: ["rm -rf"] },
      },
    ],
  } as never);
}

beforeEach(() => captureFetch());
afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("a native tool name is classified as native, an MCP one is not", () => {
  assert.equal(isNativeTool("Bash"), true);
  assert.equal(isNativeTool("Write"), true);
  assert.equal(isNativeTool("mcp__measure__write_secret_note"), false);
});

test("the evaluated text carries the tool name and its input", () => {
  const text = toolCallText(DESTRUCTIVE_BASH);
  assert.match(text, /^Bash /);
  assert.match(text, /rm -rf/);
});

test("a native tool call matching policy is refused with the deny contract", async () => {
  initWithBlockingPolicy();
  const result = await governToolCall(DESTRUCTIVE_BASH);

  assert.equal(result.blocked, true);
  assert.ok(result.output, "a block must produce the deny output");
  // Exact contract spellings — a typo here is silent non-enforcement.
  assert.equal(result.output!.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(result.output!.hookSpecificOutput.permissionDecision, "deny");
  // The reason carries the deciding rule (its name/reason), so an operator
  // reading the agent's transcript sees WHY the tool was refused.
  assert.ok(
    result.output!.hookSpecificOutput.permissionDecisionReason.length > 0,
    "the deny must carry a reason",
  );
  assert.match(
    result.output!.hookSpecificOutput.permissionDecisionReason,
    /delete|rm -rf|policy|block/i,
  );
});

test("the refusal is recorded on the obsvr signed chain and verifies", async () => {
  initWithBlockingPolicy();
  await governToolCall(DESTRUCTIVE_BASH);
  await obsvr.flush(2000);

  const blocked = sent.filter((e) => e.action_taken === "blocked");
  assert.ok(blocked.length >= 1, "the refusal must be on the audit stream");
  assert.ok(typeof blocked[0].sdk_sig === "string", "the event must be signed");

  // The shipped verifier, offline, with the API key: the recorded refusal is
  // genuine and in order on the same chain format as every other obsvr event.
  const chain = sent.filter((e) => e.sdk_session_id);
  const result = verifyAuditChain(chain, API_KEY);
  assert.equal(result.valid, true, result.reason ?? "chain must verify");
  assert.ok(result.eventsVerified >= 1);
});

test("a tool call that does not match policy is not refused (obsvr never loosens)", async () => {
  initWithBlockingPolicy();
  const result = await governToolCall({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "ls -la" },
    session_id: "s-2",
  });
  assert.equal(result.blocked, false);
  assert.equal(result.output, null, "no policy match must yield no output, deferring to the agent");
});
