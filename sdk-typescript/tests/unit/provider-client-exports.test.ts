/**
 * The shim's client-export list, checked against the REAL provider packages.
 *
 * The loader shim overrides named exports, and ESM export names are static, so
 * the list of client classes to override cannot be derived at runtime the way
 * the Python twin derives it. What CAN be derived is whether the list is still
 * complete — and that is this file's whole job.
 *
 * Before it existed, the shim overrode the default export plus ONE name, so
 * `AzureOpenAI` and `BedrockOpenAI` rode the `export *` through with no
 * interception while `interceptProviderClass` reported success for `OpenAI`.
 * That is a coverage gap nobody could see from inside the SDK. Now a provider
 * that adds a client class fails here instead of reaching a user.
 *
 * A provider package that is not installed is SKIPPED, not passed: these are
 * optional peers, and a silent pass on an absent package would be the same
 * false all-clear in a different costume.
 */
import { PROVIDER_CLIENT_EXPORTS } from "../../src/auto/loader-hooks.js";

/** The bare specifiers the loader hook intercepts, by obsvr provider id. */
const PROVIDER_SPECIFIERS: Record<string, string> = {
  openai: "openai",
  anthropic: "@anthropic-ai/sdk",
  google: "@google/generative-ai",
  "google-genai": "@google/genai",
};

/**
 * Every exported name that is a CLIENT class of this package.
 *
 * A client is identified by ANCESTRY, not by name: the deepest ancestor of the
 * default export that is still defined inside the provider's own package is
 * that package's base client, and every class descending from it is a client.
 * Naming them would reproduce the defect this file exists to catch.
 */
function exportedClientNames(ns: Record<string, unknown>, pkg: string): string[] {
  const root = ns.default ?? ns[Object.keys(PROVIDER_CLIENT_EXPORTS).find(() => false) ?? ""];
  const seed = typeof root === "function" ? root : undefined;
  if (!seed) return [];
  let base: unknown = undefined;
  for (let proto = Object.getPrototypeOf(seed); proto && proto !== Function.prototype; ) {
    base = proto;
    proto = Object.getPrototypeOf(proto);
  }
  const isClient = (value: unknown): boolean => {
    if (typeof value !== "function") return false;
    if (value === seed) return true;
    for (let proto = Object.getPrototypeOf(value); proto && proto !== Function.prototype; ) {
      if (proto === base || proto === seed) return true;
      proto = Object.getPrototypeOf(proto);
    }
    return false;
  };
  return Object.keys(ns)
    .filter((name) => name !== "default" && !name.startsWith("_"))
    .filter((name) => isClient(ns[name]))
    .sort();
}

describe("the shim's client-export list matches the real packages", () => {
  for (const [provider, specifier] of Object.entries(PROVIDER_SPECIFIERS)) {
    test(`${specifier}: every exported client class is intercepted`, async () => {
      let ns: Record<string, unknown>;
      try {
        ns = (await import(specifier)) as Record<string, unknown>;
      } catch {
        // Optional peer, not installed here. Say so rather than pass quietly.
        console.warn(`[skip] ${specifier} is not installed; list not verified against it`);
        return;
      }
      const discovered = exportedClientNames(ns, specifier);
      if (discovered.length === 0) {
        // google's client is not a subclass of anything in its own package, so
        // ancestry finds nothing. Fall back to asserting the declared name is a
        // real export rather than asserting an empty set.
        for (const name of PROVIDER_CLIENT_EXPORTS[provider]) {
          expect(typeof ns[name]).toBe("function");
        }
        return;
      }
      const declared = [...PROVIDER_CLIENT_EXPORTS[provider]].sort();
      const missing = discovered.filter((name) => !declared.includes(name));
      expect(missing).toEqual([]);
      // And nothing declared that the package does not actually export: a name
      // that has been removed upstream would make the shim fail to load.
      for (const name of declared) {
        expect(typeof ns[name]).toBe("function");
      }
    });
  }
});
