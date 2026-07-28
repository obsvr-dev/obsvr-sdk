/**
 * Together AI Integration
 *
 * Thin wrapper over the OpenAI-compatible interceptor with
 * provider/source labels set to "together".
 *
 * @example
 * ```ts
 * import Together from "together-ai";
 * import { obsvr } from "@obsvr/sdk";
 * import { wrapTogether } from "@obsvr/sdk/together";
 *
 * obsvr.init({ apiKey: "..." });
 * const client = wrapTogether(new Together());
 * ```
 *
 * @packageDocumentation
 */

// Interception: ES Proxy (non-mutating) - delegates to wrapOpenAICompatible.

import { wrapOpenAICompatible } from "./openai-compat.js";
import type { IntegrationOptions } from "./core.js";

export function wrapTogether<T extends object>(
  client: T,
  opts: IntegrationOptions = {},
): T {
  return wrapOpenAICompatible(client, {
    ...opts,
    provider: "together",
    source: opts.source ?? "together",
  });
}
