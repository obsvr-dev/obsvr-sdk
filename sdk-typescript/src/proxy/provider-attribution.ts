/**
 * Where did this call actually go? — the one place that decides.
 *
 * Twin: sdk-python/obsvr/provider_attribution.py.
 *
 * THE DEFECT THIS REPLACES, IN TWO PARTS.
 *
 * Part one was the compat integrations: `wrapTogether` stamped
 * `provider: "together"` on every call regardless of endpoint. Pointed at one
 * vendor's API it recorded "together", and pointed at a localhost server it
 * also recorded "together" — a local model logged as served by a US cloud
 * vendor, in the field a compliance reviewer reads for data residency.
 *
 * Part two is why this logic now lives here rather than inside
 * `integrations/openai-compat.ts`, where it was first written. The FRONT DOOR —
 * `obsvr.wrap()` — never used it. It labels through `detectProvider()`, which
 * duck-types on the client's shape: anything exposing `chat.completions.create`
 * is "openai", whatever host it points at. Measured against a local server, the
 * front door recorded `provider: "openai"` next to `model:
 * "qwen2.5-coder:14b"` — a model that endpoint does not serve, beside a vendor
 * the request never reached. Fixing one path and leaving the documented entry
 * point on the old behaviour is how the first repair read as complete while the
 * defect stayed reachable through the door most callers use.
 *
 * So both paths resolve here, and there is one copy of the endpoint table.
 *
 * WHAT IS RECORDED. The provider is taken from the endpoint whenever the
 * endpoint can be read, and the caller's or duck-type's label is a fallback
 * rather than an assertion. Where the host is visible but cannot be named,
 * `unknown` is recorded: vague is a lesser fault than wrong.
 * `provider_attribution` states which of those happened, borrowing the trust
 * vocabulary `provenance_source` already uses for `model_resolved`, so a reader
 * can tell a checked value from a declared one.
 *
 * @packageDocumentation
 */
import type { AuditEvent } from "./types.js";

/** The ingest canonical enum. Mirrors `AuditEvent["provider"]` exactly. */
export type CanonicalProvider = AuditEvent["provider"];

/**
 * Hosts whose identity we can state, and what to call them.
 *
 * `provider` is constrained to the ingest canonical enum. A destination the
 * enum cannot express records `provider: "unknown"` and keeps its real identity
 * in `provider_detail` — the same carriage MCP already uses, rather than
 * widening a union the backend would reject.
 */
const KNOWN_ENDPOINTS: Array<{
  pattern: RegExp;
  provider: CanonicalProvider;
  detail: string;
}> = [
  { pattern: /(^|\.)together\.(xyz|ai)$/i, provider: "together", detail: "together" },
  { pattern: /(^|\.)openai\.azure\.com$/i, provider: "azure_openai", detail: "azure_openai" },
  { pattern: /(^|\.)openai\.com$/i, provider: "openai", detail: "openai" },
  { pattern: /(^|\.)anthropic\.com$/i, provider: "anthropic", detail: "anthropic" },
  { pattern: /(^|\.)googleapis\.com$/i, provider: "google", detail: "google" },
  { pattern: /(^|\.)cloudflare\.com$/i, provider: "cloudflare", detail: "cloudflare" },
  // Real destinations the canonical enum has no member for.
  { pattern: /(^|\.)groq\.com$/i, provider: "unknown", detail: "groq" },
  { pattern: /(^|\.)mistral\.ai$/i, provider: "unknown", detail: "mistral" },
  { pattern: /(^|\.)fireworks\.ai$/i, provider: "unknown", detail: "fireworks" },
  { pattern: /(^|\.)perplexity\.ai$/i, provider: "unknown", detail: "perplexity" },
  { pattern: /(^|\.)deepseek\.com$/i, provider: "unknown", detail: "deepseek" },
];

/** A local server is a destination too, and a materially different one. */
const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|host\.docker\.internal)$/i;

/**
 * The client's configured base URL, if it will tell us.
 *
 * Read defensively: this runs against any client shape at all, a getter may
 * throw, and a wrapper that crashed while working out what to call something
 * would be a worse failure than a vague label.
 */
export function readBaseUrl(client: unknown): string | undefined {
  for (const key of ["baseURL", "baseUrl", "base_url"]) {
    try {
      const value = (client as Record<string, unknown>)?.[key];
      if (typeof value === "string" && value.length > 0) return value;
    } catch {
      /* a throwing getter is a non-answer, not a failure */
    }
  }
  return undefined;
}

/**
 * Host and port only — never credentials, path or query.
 *
 * A base URL is a place users put secrets (`https://user:token@host/v1`), and
 * this value goes into an audit record that gets shipped and stored. Only the
 * destination is wanted here, and only the destination is taken.
 */
function safeHost(baseUrl: string): { host?: string; hostname?: string } {
  try {
    const url = new URL(baseUrl);
    return { host: url.host, hostname: url.hostname };
  } catch {
    return {};
  }
}

/**
 * Decide what to record about where this call is going.
 *
 * `declared` is the fallback: the wrapper's configured label on the integration
 * path, or the duck-typed detection on the front door. It is used only when no
 * base URL can be read, and the record says so when it is.
 */
export function resolveDestination(
  client: unknown,
  declared: CanonicalProvider,
): { provider: CanonicalProvider; attribution: Record<string, unknown> } {
  const baseUrl = readBaseUrl(client);
  if (!baseUrl) {
    // Nothing to check against. The declared label is all there is, and the
    // record says so rather than presenting it as verified.
    return {
      provider: declared,
      attribution: { provider_attribution: "client_declared" },
    };
  }

  const { host, hostname } = safeHost(baseUrl);
  if (!hostname) {
    return {
      provider: declared,
      attribution: { provider_attribution: "client_declared" },
    };
  }

  if (LOCAL_HOSTS.test(hostname)) {
    return {
      provider: "unknown",
      attribution: {
        provider_attribution: "endpoint",
        provider_detail: "local",
        endpoint_host: host,
      },
    };
  }

  const match = KNOWN_ENDPOINTS.find((entry) => entry.pattern.test(hostname));
  if (match) {
    return {
      provider: match.provider,
      attribution: {
        provider_attribution: "endpoint",
        provider_detail: match.detail,
        endpoint_host: host,
      },
    };
  }

  // A host we have no name for — a private gateway, a proxy, a new vendor.
  // Recording the caller's guess here is what produced the original defect.
  return {
    provider: "unknown",
    attribution: {
      provider_attribution: "endpoint",
      provider_detail: "unrecognized_endpoint",
      endpoint_host: host,
    },
  };
}
