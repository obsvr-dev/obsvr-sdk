/**
 * OpenAI-compatible client wrapper.
 *
 * Named compatibility entry points share the generic wrapper's governed path
 * table and enforcement pipeline. `provider` is only the destination fallback
 * when the client exposes no readable base URL; endpoint attribution wins.
 *
 * @packageDocumentation
 */

import { wrapWithProviderHint } from "../proxy/wrapper.js";
import type { IntegrationOptions, IntegrationProvider } from "./core.js";

export interface OpenAICompatConfig extends IntegrationOptions {
  /** Destination fallback used only when the endpoint cannot be read. */
  provider: IntegrationProvider;
  source: string;
}

/** Wrap every OpenAI-shaped method supported by the generic governance table. */
export function wrapOpenAICompatible<T extends object>(
  client: T,
  opts: OpenAICompatConfig,
): T {
  return wrapWithProviderHint(
    client,
    {
      source: opts.source,
      region: opts.region,
      service_name: opts.service_name,
      user_id: opts.user_id,
      metadata: opts.metadata,
    },
    opts.provider,
  );
}
