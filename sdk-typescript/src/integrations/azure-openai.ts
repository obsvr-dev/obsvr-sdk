/**
 * Azure OpenAI Integration
 *
 * Thin wrapper over the OpenAI-compatible interceptor with
 * provider/source labels set to "azure_openai".
 *
 * @example
 * ```ts
 * import { AzureOpenAI } from "openai";
 * import { obsvr } from "@obsvr/sdk";
 * import { wrapAzureOpenAI } from "@obsvr/sdk/azure-openai";
 *
 * obsvr.init({ apiKey: "..." });
 * const client = wrapAzureOpenAI(new AzureOpenAI({ ... }));
 * ```
 *
 * @packageDocumentation
 */

// Interception: ES Proxy (non-mutating) - delegates to wrapOpenAICompatible.

import { wrapOpenAICompatible } from "./openai-compat.js";
import type { IntegrationOptions } from "./core.js";

export function wrapAzureOpenAI<T extends object>(
  client: T,
  opts: IntegrationOptions = {},
): T {
  return wrapOpenAICompatible(client, {
    ...opts,
    provider: "azure_openai",
    source: opts.source ?? "azure_openai",
  });
}
