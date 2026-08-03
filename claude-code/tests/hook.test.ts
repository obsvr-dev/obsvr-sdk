/**
 * The bar for this package: a NATIVE tool call is genuinely REFUSED by obsvr
 * policy, and the refusal is recorded on the SAME signed audit chain as
 * everything else — verifiable by the shipped verifier, offline, with the
 * API key. These tests drive the real `@obsvr/sdk` policy engine (no fakes)
 * and capture the emitted event off the sender's delivery path.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { test, beforeEach, afterEach } from "node:test";
import { obsvr, verifyAuditChain } from "@obsvr/sdk";
import { denyOutput, governToolCall, isNativeTool, toolCallText } from "../src/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOK_BIN = join(HERE, "..", "bin", "pretooluse.js");

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

test("an MCP-delivered tool matching policy is REFUSED, not merely classified", async () => {
  // The refusal path is tool-name-agnostic: an mcp__ tool the policy names is
  // blocked exactly like a native one. Classifying it as non-native
  // (isNativeTool) is a different, weaker claim — this asserts the deny.
  obsvr.init({
    api_key: API_KEY,
    ingest_url: "https://localhost:1",
    sample_rate: 1,
    policy_rules: [
      {
        id: "no-secret-writes",
        name: "block the secret-note MCP tool",
        enabled: true,
        action: "block",
        type: "keyword",
        conditions: { keywords: ["mcp__measure__write_secret_note"] },
      },
    ],
  } as never);

  const mcpTool = "mcp__measure__write_secret_note";
  assert.equal(isNativeTool(mcpTool), false, "it is an MCP tool, by name");
  const result = await governToolCall({
    hook_event_name: "PreToolUse",
    tool_name: mcpTool,
    tool_input: { note: "exfiltrate" },
    session_id: "s-mcp",
  });
  assert.equal(result.blocked, true, "the MCP tool must be refused, not just classified");
  assert.equal(result.output!.hookSpecificOutput.permissionDecision, "deny");

  await obsvr.flush(2000);
  const blocked = sent.filter((e) => e.action_taken === "blocked");
  assert.ok(blocked.length >= 1, "the MCP refusal must be on the signed audit stream too");
});

test("the only decision the hook can emit is deny — never an allow override", () => {
  // Structural: the deny builder is the one construction site, and its type
  // permits only "deny". An allow that overrode the agent's own decision
  // would be a downgrade channel; there is no code path that produces one.
  const out = denyOutput("because");
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  // @ts-expect-error — "allow" is not assignable; the invariant is type-enforced.
  const _forbidden: typeof out.hookSpecificOutput.permissionDecision = "allow";
  void _forbidden;
});

// ── The built binary's un-signable posture (real subprocess, real stdin) ──
function runHook(
  stdin: string,
  env: Record<string, string> = {},
): { stdout: string; stderr: string; status: number | null } {
  const r = spawnSync(process.execPath, [HOOK_BIN], {
    input: stdin,
    encoding: "utf-8",
    env: { ...process.env, ...env },
  });
  return { stdout: r.stdout, stderr: r.stderr, status: r.status };
}

const A_TOOL_CALL = JSON.stringify({
  hook_event_name: "PreToolUse",
  tool_name: "Bash",
  tool_input: { command: "echo hi" },
  session_id: "sub-1",
});

test("with no API key the hook DEFERS: empty stdout, exit 0, no allow", () => {
  const r = runHook(A_TOOL_CALL, { OBSVR_API_KEY: "", OBSVR_FAIL_CLOSED: "" });
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), "", "a deferral writes NOTHING — it never grants permission");
  assert.match(r.stderr, /OBSVR_API_KEY unset/);
});

test("under OBSVR_FAIL_CLOSED an un-signable call is DENIED, not deferred", () => {
  const r = runHook(A_TOOL_CALL, { OBSVR_API_KEY: "", OBSVR_FAIL_CLOSED: "1" });
  assert.equal(r.status, 0);
  const out = JSON.parse(r.stdout);
  assert.equal(out.hookSpecificOutput.permissionDecision, "deny");
  assert.match(out.hookSpecificOutput.permissionDecisionReason, /could not evaluate/i);
});

test("malformed stdin defers by default and denies under fail-closed", () => {
  const defer = runHook("this is not json", { OBSVR_API_KEY: "k" });
  assert.equal(defer.status, 0);
  assert.equal(defer.stdout.trim(), "");

  const closed = runHook("this is not json", { OBSVR_API_KEY: "k", OBSVR_FAIL_CLOSED: "1" });
  assert.equal(closed.status, 0);
  assert.equal(JSON.parse(closed.stdout).hookSpecificOutput.permissionDecision, "deny");
});
