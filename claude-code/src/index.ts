/**
 * obsvr for Claude Code — govern a coding agent's NATIVE tool calls.
 *
 * WHY THIS PACKAGE EXISTS (measured, not assumed). obsvr's SDKs are
 * client-side libraries: they govern the MCP `ClientSession` an application
 * constructs in its OWN process. A coding agent like Claude Code runs as a
 * separate binary with its own MCP client; obsvr is not loaded into it, so
 * obsvr governs NONE of that agent's tool traffic — not its MCP calls and
 * certainly not its native tools (file edits, shell, search), which never
 * traverse MCP at all. The boundary the agent DOES expose to an outside
 * governor is its pre-tool hook: a separate process the agent invokes before
 * each tool call, which can refuse it. This package is that hook, and it
 * refuses by the SAME obsvr policy engine and records on the SAME signed
 * audit chain as everything else, so a coding agent's native tool calls join
 * the evidence stream instead of sitting outside it.
 *
 * Scope is deliberately ONE agent. Eight agents means eight config formats
 * and eight refusal protocols, none a versioned contract; that surface is
 * entered on purpose, not by momentum.
 *
 * @packageDocumentation
 */
import { evaluate } from "@obsvr/sdk";
import type { EvaluateResponse } from "@obsvr/sdk";

/** The PreToolUse payload Claude Code delivers on stdin (the fields we read;
 *  the contract carries more). Field names are the agent's, not obsvr's. */
export interface PreToolUseInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  cwd?: string;
  tool_use_id?: string;
}

/** The deny half of the PreToolUse hook contract. Field spellings are exact —
 *  a typo here is silent non-enforcement, so they are pinned by test. The
 *  decision is `"deny"` ONLY, by type: this hook can add a refusal but can
 *  never emit an `"allow"` that overrides a decision the agent would
 *  otherwise have made, and narrowing the type here makes that invariant
 *  impossible to break by a later edit, not merely a convention the current
 *  code happens to follow. */
export interface HookDecisionOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "deny";
    permissionDecisionReason: string;
  };
}

/** Build the deny half of the contract. The one place a decision output is
 *  constructed, so the "deny only, never allow" invariant lives in exactly
 *  one spot. */
export function denyOutput(reason: string): HookDecisionOutput {
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

/** Native tool names, for the record's own classification. An MCP tool name
 *  is `mcp__<server>__<tool>`; anything else the agent dispatches is native
 *  (Bash, Edit, Write, Read, Glob, Grep, WebFetch, …) — and native tools are
 *  exactly the traffic obsvr's client-side gates cannot see. */
export function isNativeTool(toolName: string): boolean {
  return !toolName.startsWith("mcp__");
}

/**
 * The text obsvr's policy engine evaluates for a tool call. The tool NAME
 * leads so a rule can gate a whole tool by name; the serialized input
 * follows so a keyword/regex rule can gate by content (e.g. a destructive
 * shell command). Deterministic and injective enough that two different
 * calls do not collapse to one evaluated string.
 */
export function toolCallText(input: PreToolUseInput): string {
  const name = input.tool_name ?? "unknown";
  let args = "";
  try {
    args = JSON.stringify(input.tool_input ?? {});
  } catch {
    args = String(input.tool_input);
  }
  return `${name} ${args}`;
}

/** What governing one tool call produced: the agent-facing decision and the
 *  obsvr verdict behind it. `null` output means "no decision" — the agent's
 *  own permission flow proceeds (obsvr never loosens, only refuses). */
export interface GovernResult {
  /** Present only on a refusal; printed to stdout as the deny contract. */
  output: HookDecisionOutput | null;
  /** The obsvr verdict, for the caller's logging/exit decisions. */
  verdict: EvaluateResponse;
  blocked: boolean;
}

/**
 * Govern one PreToolUse event through the obsvr policy engine, and emit the
 * signed audit event as a side effect of `evaluate()`. A BLOCKED verdict
 * becomes the deny contract; anything else yields no output (the agent's own
 * permission flow decides). This never returns "allow" as an override — a
 * hook must not be able to loosen a restriction, only add one.
 *
 * `evaluate()` is the reuse point: it runs the identical policy pipeline the
 * SDKs run (floor, rules, PII, hook) and emits a signed event on the obsvr
 * chain. So the refusal and the record are the shipped engine's, not a
 * second implementation that could disagree with it.
 */
export async function governToolCall(input: PreToolUseInput): Promise<GovernResult> {
  const verdict = await evaluate({
    action_type: input.tool_name ?? "unknown",
    payload: { tool_call: toolCallText(input) },
  });

  if (verdict.decision === "BLOCKED") {
    const reason =
      verdict.reason ??
      `Refused by obsvr policy (${verdict.reason_code}${verdict.rule_id ? `, ${verdict.rule_id}` : ""})`;
    return { output: denyOutput(reason), verdict, blocked: true };
  }

  return { output: null, verdict, blocked: false };
}
