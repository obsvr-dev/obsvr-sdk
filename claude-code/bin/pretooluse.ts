#!/usr/bin/env node
/**
 * PreToolUse hook entry for Claude Code.
 *
 * Register it in settings.json (a PreToolUse hook, matcher ".*") so the agent
 * invokes it before every tool call. It reads the PreToolUse JSON on stdin,
 * governs the call through the obsvr policy engine, and — on a policy block —
 * writes the deny contract to stdout, which stops the tool BEFORE it runs
 * rather than recording that it ran. That is what makes a pre-tool hook a
 * real enforcement point rather than an audit tap. (Whether a hook deny also
 * overrides the agent's own permission-bypass modes is the agent's contract
 * to state, not this package's to promise.)
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
 * open the gate. When obsvr cannot render a signed decision (no API key, an
 * unreadable payload, an engine that threw), the DEFAULT is to DEFER — write
 * nothing, exit 0 — so the agent's own permission flow decides, exactly as if
 * this hook were not installed; a bogus "allow" would be worse than a
 * deferral, and the hook never emits one. Set OBSVR_FAIL_CLOSED=1 to turn
 * those paths into a hard deny instead, for a deployment that would rather
 * block a tool obsvr could not evaluate. Either way the hook only ever ADDS a
 * refusal; it never emits an "allow" that loosens the agent's own decision.
 *   OBSVR_FAIL_CLOSED           deny (not defer) when obsvr cannot decide
 */
import { readFileSync } from "node:fs";
import { obsvr } from "@obsvr/sdk";
import { denyOutput, governToolCall, type PreToolUseInput } from "../src/index.js";

/**
 * Posture when obsvr cannot render a signed decision (no API key, an
 * unreadable payload, an engine that threw). Default is DEFER: the hook
 * writes nothing and the agent's OWN permission settings decide the call,
 * exactly as if this hook were not installed — obsvr adds no refusal and,
 * critically, grants no permission (it never emits an allow). Setting
 * OBSVR_FAIL_CLOSED=1 flips that path to a hard deny, for a high-assurance
 * deployment that would rather block a tool obsvr could not evaluate than let
 * the agent's baseline decide it. It is opt-in because a hook that hard-denies
 * whenever it is misconfigured — an unset OBSVR_API_KEY, say — would brick the
 * agent, the same production hazard obsvr's own fail_mode defaults away from.
 */
function failClosed(): boolean {
  const v = (process.env.OBSVR_FAIL_CLOSED ?? "").trim().toLowerCase();
  return v === "1" || v === "true";
}

/** Resolve an un-signable situation: defer (nothing) by default, or emit a
 *  deny under the fail-closed posture. Never emits an allow. */
function resolveUnsignable(reason: string): void {
  if (failClosed()) {
    process.stdout.write(JSON.stringify(denyOutput(`obsvr could not evaluate this call: ${reason}`)));
  }
  // else: defer — the agent's own permission flow applies.
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf-8");
}

function loadPolicy(): Record<string, unknown> {
  const path = process.env.OBSVR_CLAUDE_CODE_POLICY;
  if (!path) return {};
  try {
    // The policy file is spread into a camelCase init() below (apiKey,
    // ingestUrl, …), and the SDK reads a config's convention from whether
    // `apiKey` is present — so the file's keys must be camelCase too
    // (`policyRules`, not `policy_rules`), or the SDK reads them as the wrong
    // convention and silently ignores them. That is the convention the README
    // documents; keep the two in lockstep.
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
    // Not a hook payload we can read: cannot govern it, so defer (or, under
    // the fail-closed posture, deny) — never silently allow.
    resolveUnsignable("the PreToolUse payload was not readable JSON");
    return;
  }

  const apiKey = process.env.OBSVR_API_KEY;
  if (!apiKey) {
    // No credentials means no record could be signed. Enforcement without a
    // record is not what this hook promises, so it defers rather than
    // blocking blind — and says why, on stderr.
    process.stderr.write("[obsvr] OBSVR_API_KEY unset; deferring to the agent's permission flow\n");
    resolveUnsignable("OBSVR_API_KEY is not set");
    return;
  }

  // camelCase throughout — the natural convention for a TypeScript package,
  // and the one the documented policy file uses. Mixing in a snake_case key
  // here would flip the SDK's whole-config convention detection and silently
  // drop the policy file's rules.
  obsvr.init({
    apiKey,
    ingestUrl: process.env.OBSVR_INGEST_URL,
    ...(process.env.OBSVR_DEVICE_SIGNING_KEY_FILE
      ? { deviceSigningKeyFile: process.env.OBSVR_DEVICE_SIGNING_KEY_FILE }
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
  // A crash in the hook must not wedge the agent. Report, then resolve the
  // un-signable situation by the configured posture: defer by default, deny
  // under OBSVR_FAIL_CLOSED. Exit 0 either way so the agent proceeds by its
  // own rules rather than treating the hook as failed — a non-zero exit from
  // a hook is itself an implicit block on some agents, which would be a
  // fail-closed we did not choose.
  process.stderr.write(`[obsvr] pretooluse hook error: ${String(err)}\n`);
  try {
    resolveUnsignable(`hook error: ${String(err)}`);
  } catch {
    /* resolving must not itself throw */
  }
  process.exit(0);
});
