/**
 * Put obsvr back on the tool boundary a provider tool runner takes it off.
 *
 * THE MEASURED GAP THIS CLOSES. A tool runner holds the raw provider client and
 * invokes its tools itself, so pre-call governance ran once on the invocation
 * and every tool the loop executed afterwards ran outside every tool-level
 * control. Measured: with the session latch armed and `action: "flag"` — the
 * default, and the composition the latch exists to provide — a session obsvr had
 * already marked tainted executed a tool named in `destructiveTools`.
 *
 * WHERE THE GATE GOES, AND WHY IT IS THE ONLY PLACE IT CAN GO. Both runners
 * snapshot their tool set when the method is applied: one builds a name→function
 * map before its completion loop starts, the other resolves against the params it
 * was constructed with. A swap performed after construction is not seen. There is
 * exactly one seam — between governance resolving the arguments and the provider
 * method being applied to them — and this runs in it.
 *
 * THE GATE ITSELF IS NOT REIMPLEMENTED HERE. Every entry is handed to
 * `obsvrGovernTool`, the same wrapper the documented mitigation uses. A second
 * implementation of the destructive-capability check is the one thing that must
 * not happen, because the two would drift and only one of them would be the one
 * anybody tested.
 *
 * WHAT THIS DOES NOT REACH. The model calls the loop makes on turns 2..N. Those
 * stay observed and audited but ungated: reaching them means substituting the
 * runner's own client, and a refusal arriving on turn 3 aborts a loop that has
 * already executed tools with real side effects. A block that lands after money
 * moved is not a block, so that needs a stated position before it ships and does
 * not ship here.
 */

import { obsvrGovernTool } from "../integrations/tools.js";
import type { IntegrationOptions } from "../integrations/core.js";
import type { ResolvedConfig } from "./types.js";

/** What the gate managed to do, so the emitted record can say it accurately. */
export interface RunnerToolGateReport {
  /** True when at least one tool callback is now behind the gate. */
  installed: boolean;
  /** Tool names now gated. */
  gated: string[];
  /**
   * Entries left untouched because they expose no callback obsvr can wrap — a
   * server-side or hosted tool the provider runs itself, or a shape this file
   * does not recognise. Named rather than counted: "some tools are ungated" is
   * not a statement anybody can act on.
   */
  ungatable: string[];
  /** Why no gate was installed, when none was. */
  reason?: "no_tools_in_request" | "no_gateable_tool";
}

const NOT_INSTALLED = (reason: RunnerToolGateReport["reason"]): RunnerToolGateReport => ({
  installed: false,
  gated: [],
  ungatable: [],
  reason,
});

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function stringOr(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

/**
 * Gate every tool callback in a tool-runner request.
 *
 * Returns a NEW argument list. Nothing the caller passed is mutated: the first
 * argument is rebuilt and so is its `tools` array, because the upstream argument
 * filter returns the caller's own object by identity when it is not a plain
 * object — so writing through would reach the caller's state on exactly the
 * inputs least likely to be tested.
 */
export function governRunnerTools(
  args: unknown[],
  _config: ResolvedConfig,
  options: IntegrationOptions,
): { args: unknown[]; report: RunnerToolGateReport } {
  const first = args[0];
  if (!isPlainObject(first) || !Array.isArray(first.tools) || first.tools.length === 0) {
    return { args, report: NOT_INSTALLED("no_tools_in_request") };
  }

  const gated: string[] = [];
  const ungatable: string[] = [];

  const tools = first.tools.map((entry) => {
    if (!isPlainObject(entry)) {
      ungatable.push(String(entry));
      return entry;
    }

    // A provider schema helper's tool. Checked first: it also carries
    // `type: "function"` and a `function` object, but that object holds a
    // descriptor rather than a callback, so the shape below would not match it
    // and the entry would fall through ungated. Gated through the proxy rather
    // than rebuilt, because whatever brand the runner recognises it by has to
    // survive.
    if (typeof entry.$callback === "function") {
      const descriptor = isPlainObject(entry.function) ? entry.function : undefined;
      const name = stringOr(descriptor?.name, "unknown_tool");
      gated.push(name);
      return obsvrGovernTool(entry, { ...options, name });
    }

    // `{ type: "function", function: { function, name, parse?, parameters? } }`.
    // The INNER object is what gets gated — it is what the runner puts in its
    // name→function map and what it dispatches through.
    if (isPlainObject(entry.function) && typeof entry.function.function === "function") {
      const inner = entry.function;
      const name = stringOr(inner.name, "unknown_tool");
      gated.push(name);
      return { ...entry, function: obsvrGovernTool(inner, { ...options, name }) };
    }

    // `{ name, description, input_schema, run, parse? }` — the callback is
    // top-level, so the entry itself is the thing to gate.
    if (typeof entry.run === "function") {
      const name = stringOr(entry.name, "unknown_tool");
      gated.push(name);
      return obsvrGovernTool(entry, { ...options, name });
    }

    // No local callback. A hosted or server-side tool the provider executes on
    // its own infrastructure is genuinely not on this boundary, and saying so is
    // more useful than pretending the set is covered.
    ungatable.push(stringOr(entry.name, stringOr(entry.mcp_server_name, "unnamed_tool")));
    return entry;
  });

  if (gated.length === 0) {
    return { args, report: { installed: false, gated, ungatable, reason: "no_gateable_tool" } };
  }

  return {
    args: [{ ...first, tools }, ...args.slice(1)],
    report: { installed: true, gated, ungatable },
  };
}
