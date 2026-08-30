/**
 * Observation for the provider TOOL RUNNERS — `chat.completions.runTools` and
 * `beta.messages.toolRunner`.
 *
 * These differ from the `.stream()` helpers in `runner-wrapper.ts` in one way
 * that decides everything about the shape of this file: a stream helper is ONE
 * model call whose text arrives in pieces, so it emits one event at the end. A
 * tool runner is a LOOP — N model calls and M tool executions per invocation —
 * and one event for the whole thing would record the first prompt and the last
 * answer while hiding every decision in between, including which tools ran and
 * what they returned.
 *
 * GRANULARITY: one event per model call, one per tool call, and a run-level
 * start/finish pair carrying a shared `agent_run_id`. That is the same shape
 * the `@openai/agents` tracing integration already emits
 * (`openai_agents.agent.run.start` -> `llm` -> `openai_agents.tool.call` ->
 * `openai_agents.agent.run.finish`), so a consumer that can already read an
 * agent run can read one of these without learning a second convention.
 *
 * WHY THE TWO PROVIDERS ARE OBSERVED DIFFERENTLY. This is not a style choice;
 * the two runner objects expose genuinely different surfaces.
 *
 *   - OpenAI's `ChatCompletionRunner` extends the SDK's own `EventStream` and
 *     emits `chatCompletion` and `message` events. Attaching listeners to its
 *     public `.on()` is enough, and nothing has to mediate the caller's access.
 *
 *   - Anthropic's `BetaToolRunner` has no event emitter at all. It is an async
 *     iterable, and it advances ONLY while something consumes it — `done()`
 *     waits on an iteration that never starts by itself. It also cannot be
 *     wrapped in a Proxy: the class stores its state in `#private` fields, and
 *     private-field access through a Proxy throws. `runUntilDone()` iterates
 *     `this` directly, so even a Proxy that survived would not see the turns.
 *     The only remaining seam is to OWN the iteration, which is what the
 *     `complete` hook exists for.
 *
 * WHAT IS GOVERNED. Pre-call governance runs on the invocation before the
 * runner is constructed. The wrapper also substitutes the raw client the
 * provider runner would retain, so every later model turn returns through the
 * same provider boundary after tool results are appended. Local callbacks are
 * separately wrapped by `runner-tool-gate.ts`. A refusal on a later turn aborts
 * the run before that turn reaches the provider, even though earlier tools may
 * already have produced side effects.
 *
 * @packageDocumentation
 */

import type { RunnerLike } from "./runner-wrapper.js";

/** One observed model call inside a run. */
export interface ObservedModelCall {
  /** The request as the runner sent it, for the dialect's prompt extractor. */
  request: unknown;
  /** The provider's completed response object. */
  response: unknown;
}

/** One observed tool execution inside a run. */
export interface ObservedToolCall {
  /** The tool's name as the model asked for it. */
  name: string;
  /** The arguments the model supplied, rendered as text. */
  args: string;
  /** What the tool returned, rendered as text. */
  result: string;
  /** The provider's own correlation id for this call, when it has one. */
  toolCallId?: string;
}

/** Where an observer reports what it saw. Never throws back into the run. */
export interface ToolRunSink {
  modelCall(call: ObservedModelCall): void;
  toolCall(call: ObservedToolCall): void;
}

/** Render a tool argument/result payload as text without inventing structure. */
export function renderToolPayload(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/**
 * Anthropic renders tool results as content BLOCKS. Flatten the text ones and
 * name the rest rather than dropping them, so a result that was an image is
 * visible in the record as an image instead of as an empty string.
 */
function renderAnthropicBlocks(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return renderToolPayload(content);
  return content
    .map((block) => {
      const b = block as { type?: string; text?: string };
      if (b?.type === "text" && typeof b.text === "string") return b.text;
      return `[${b?.type ?? "unknown"}]`;
    })
    .join("");
}

// ============================================================================
// OpenAI — chat.completions.runTools
// ============================================================================

/**
 * Attach to an OpenAI `ChatCompletionRunner` through its own public event
 * surface. Nothing is mutated and nothing is intercepted; the caller's access
 * to the runner is untouched.
 *
 * Tool calls are paired by `tool_call_id` rather than by arrival order. The
 * runner emits `functionToolCall` and `functionToolCallResult` as separate
 * events with no id on either, so pairing those positionally would mis-attribute
 * every result the moment a model requests two tools in one turn — which is the
 * normal case for parallel tool calls, not an edge case. The `message` stream
 * carries the ids, so it is read instead.
 */
export function observeOpenAIToolRun(runner: RunnerLike, sink: ToolRunSink): void {
  if (typeof runner.on !== "function") return;

  const pending = new Map<string, { name: string; args: string }>();

  runner.on("chatCompletion", (...a: unknown[]) => {
    try {
      const completion = a[0];
      // The runner's `messages` array is its live conversation state, so it is
      // snapshotted here rather than referenced — by the time this event is
      // read the loop may have appended the next turn.
      const messages = Array.isArray((runner as { messages?: unknown }).messages)
        ? [...((runner as { messages: unknown[] }).messages)]
        : [];
      const model = (completion as { model?: string } | undefined)?.model;
      sink.modelCall({ request: { model, messages }, response: completion });
    } catch {
      /* observation must never break the run it is observing */
    }
  });

  runner.on("message", (...a: unknown[]) => {
    try {
      const msg = a[0] as {
        role?: string;
        content?: unknown;
        tool_call_id?: string;
        tool_calls?: { id?: string; function?: { name?: string; arguments?: string } }[];
      };
      if (msg?.role === "assistant" && Array.isArray(msg.tool_calls)) {
        for (const tc of msg.tool_calls) {
          if (!tc?.id) continue;
          pending.set(tc.id, {
            name: tc.function?.name ?? "unknown",
            args: tc.function?.arguments ?? "",
          });
        }
        return;
      }
      if (msg?.role === "tool" && msg.tool_call_id) {
        const asked = pending.get(msg.tool_call_id);
        pending.delete(msg.tool_call_id);
        sink.toolCall({
          name: asked?.name ?? "unknown",
          args: asked?.args ?? "",
          result: renderToolPayload(msg.content),
          toolCallId: msg.tool_call_id,
        });
      }
    } catch {
      /* observation must never break the run it is observing */
    }
  });
}

// ============================================================================
// Anthropic — beta.messages.toolRunner
// ============================================================================

interface AnthropicToolRunner extends RunnerLike {
  params?: { messages?: unknown[] };
  done?(): Promise<unknown>;
}

/**
 * Walk the runner's own conversation state and report tool calls not yet seen.
 *
 * The runner does not announce tool execution, but it does record it: the
 * assistant turn carries `tool_use` blocks (id, name, input) and the following
 * user turn carries `tool_result` blocks keyed by `tool_use_id`. Pairing those
 * by id recovers both halves of every tool call exactly once, and is immune to
 * how many tools a single turn requested.
 */
function harvestAnthropicToolCalls(
  runner: AnthropicToolRunner,
  sink: ToolRunSink,
  seen: Set<string>,
): void {
  try {
    const messages = runner.params?.messages;
    if (!Array.isArray(messages)) return;

    const asked = new Map<string, { name: string; args: string }>();
    for (const m of messages) {
      const content = (m as { content?: unknown })?.content;
      if (!Array.isArray(content)) continue;
      for (const block of content) {
        const b = block as {
          type?: string;
          id?: string;
          name?: string;
          input?: unknown;
          tool_use_id?: string;
          content?: unknown;
          is_error?: boolean;
        };
        if (b?.type === "tool_use" && b.id) {
          asked.set(b.id, { name: b.name ?? "unknown", args: renderToolPayload(b.input) });
        } else if (b?.type === "tool_result" && b.tool_use_id) {
          if (seen.has(b.tool_use_id)) continue;
          seen.add(b.tool_use_id);
          const a = asked.get(b.tool_use_id);
          sink.toolCall({
            name: a?.name ?? "unknown",
            args: a?.args ?? "",
            result: renderAnthropicBlocks(b.content),
            toolCallId: b.tool_use_id,
          });
        }
      }
    }
  } catch {
    /* observation must never break the run it is observing */
  }
}

/** Whether a yielded value is a message STREAM rather than a finished message. */
function isMessageStream(value: unknown): value is { finalMessage(): Promise<unknown> } {
  return (
    !!value &&
    typeof value === "object" &&
    typeof (value as { finalMessage?: unknown }).finalMessage === "function"
  );
}

/**
 * Drive an Anthropic `BetaToolRunner` to completion, observing every turn, and
 * resolve with the final message — the same value `await runner` produces.
 *
 * This OWNS the iteration because it has to. The runner advances only while
 * something consumes it, it can be consumed exactly once, and its private
 * state makes it unproxyable, so there is no way to both let the caller drive
 * and see the turns. Callers that iterate the stand-in are served from this
 * same single pass; nothing iterates the real runner twice.
 */
export async function driveAnthropicToolRun(
  runner: AnthropicToolRunner,
  sink: ToolRunSink,
  onTurn?: (value: unknown) => void,
): Promise<unknown> {
  const seen = new Set<string>();
  let last: unknown;
  let first = true;

  try {
    for await (const turn of runner as AsyncIterable<unknown>) {
      // Tool results for the PREVIOUS turn are pushed while the runner is
      // producing this one, so they are available now rather than then.
      if (!first) harvestAnthropicToolCalls(runner, sink, seen);
      first = false;

      const message = isMessageStream(turn) ? await turn.finalMessage() : turn;
      last = message;
      try {
        sink.modelCall({ request: { ...(runner.params ?? {}) }, response: message });
      } catch {
        /* observation must never break the run it is observing */
      }
      onTurn?.(turn);
    }
  } finally {
    // The last turn's tool results (and, on an early exit, whatever the run
    // did reach) are recorded rather than lost.
    harvestAnthropicToolCalls(runner, sink, seen);
  }

  return last;
}
