/**
 * Together AI Integration
 *
 * Thin wrapper over the OpenAI-compatible interceptor.
 *
 * THE PROVIDER LABEL COMES FROM THE ENDPOINT, NOT FROM THIS WRAPPER. It used to
 * be hardcoded here, so every call through it recorded `provider: "together"`
 * whatever the client pointed at — demonstrated with one wrapper against two
 * endpoints: Groq's API recorded "together", and a localhost server recorded
 * "together" too, filing a local model as served by a US cloud vendor. That is
 * the field a compliance reviewer reads for data residency.
 *
 * `provider` below is now a FALLBACK, used only when the client exposes no
 * readable base URL. When the endpoint can be read the record follows it, states
 * the host in `metadata.endpoint_host`, and says in
 * `metadata.provider_attribution` whether the label was checked against the
 * endpoint or merely declared.
 *
 * Worth knowing: Together's own API has never been called in this repo's
 * verification: the OpenAI-compatible path was proven against Groq and a local
 * server, because no Together credential exists here. The wrapper is
 * OpenAI-shaped and the shared path underneath it is exercised; the vendor
 * itself is untested.
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
    // Fallback only. Overridden by the endpoint whenever one can be read.
    provider: "together",
    source: opts.source ?? "together",
  });
}
