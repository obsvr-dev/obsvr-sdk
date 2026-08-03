#!/usr/bin/env node
/**
 * PreToolUse hook entry for Claude Code.
 *
 * Register it in settings.json (a PreToolUse hook, matcher ".*") so the agent
 * invokes it before every tool call. It reads the PreToolUse JSON on stdin,
 * governs the call through the obsvr policy engine, and — on a policy block —
 * writes the deny contract to stdout, which stops the tool BEFORE it runs.
 * A blocking deny holds even under the agent's permission-bypass modes and
 * cannot be loosened by them, which is exactly the property that makes a hook
 * a real enforcement point rather than a suggestion.
 *
 * Configuration is read from the environment so the hook needs no obsvr code
 * changes to point at a deployment:
 *   OBSVR_API_KEY               required to sign and deliver the record
 *   OBSVR_INGEST_URL            where the signed events go
 *   OBSVR_CLAUDE_CODE_POLICY    path to a JSON file: { "policyRules": [...] }
 *                               (the obsvr policy that decides a refusal)
 *   OBSVR_DEVICE_SIGNING_KEY_FILE  optional device seal (non-repudiation)
 *
 * Fail posture: this hook is enforcement, so a defect in it must not silently
 * open the gate. If obsvr cannot render a decision, the hook writes NOTHING
 * and exits 0 — the agent's own permission flow then decides — because a hook
 * that emitted a bogus "allow" would be worse than one that deferred. It
 * never emits "allow" as an override; obsvr only ever ADDS a refusal.
 */
import { readFileSync } from "node:fs";
import { obsvr } from "@obsvr/sdk";
import { governToolCall, type PreToolUseInput } from "../src/index.js";

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf-8");
}

function loadPolicy(): Record<string, unknown> {
  const path = process.env.OBSVR_CLAUDE_CODE_POLICY;
  if (!path) return {};
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as Record<string, unknown>;
  } catch (err) {
    // A policy file that was configured but cannot be read is an operator
    // error worth surfacing, but on stderr only — stdout is the agent's
    // decision channel and must stay clean so the call is not mis-governed.
    process.stderr.write(
      `[obsvr] could not read OBSVR_CLAUDE_CODE_POLICY (${path}): ${String(err)}\n`,
    );
    return {};
  }
}

async function main(): Promise<void> {
  const raw = await readStdin();
  let input: PreToolUseInput;
  try {
    input = JSON.parse(raw) as PreToolUseInput;
  } catch {
    // Not a hook payload we can read: defer to the agent's own flow.
    return;
  }

  const apiKey = process.env.OBSVR_API_KEY;
  if (!apiKey) {
    // No credentials means no record could be signed. Enforcement without a
    // record is not what this hook promises, so it defers rather than
    // blocking blind — and says why, on stderr.
    process.stderr.write("[obsvr] OBSVR_API_KEY unset; deferring to the agent's permission flow\n");
    return;
  }

  obsvr.init({
    api_key: apiKey,
    ingest_url: process.env.OBSVR_INGEST_URL,
    ...(process.env.OBSVR_DEVICE_SIGNING_KEY_FILE
      ? { device_signing_key_file: process.env.OBSVR_DEVICE_SIGNING_KEY_FILE }
      : {}),
    ...loadPolicy(),
  } as never);

  const result = await governToolCall(input);
  if (result.output) {
    process.stdout.write(JSON.stringify(result.output));
  }
  // Flush the signed audit event before the short-lived hook process exits —
  // the record is the point, and a fire-and-forget send that never left the
  // queue would drop exactly the refusal we just made.
  await obsvr.flush(2000);
}

main().catch((err) => {
  // A crash in the hook must not wedge the agent: report and defer.
  process.stderr.write(`[obsvr] pretooluse hook error: ${String(err)}\n`);
  process.exit(0);
});
