/**
 * Node module customization hooks for zero-code provider interception.
 *
 * Registered by `@obsvr/sdk/register` via `module.register()`. Runs on
 * Node's loader thread, not in the application. When the app imports a
 * supported provider package, `resolve` tags the resolved URL and `load`
 * serves a tiny ESM shim in its place — and only for a URL `resolve` itself
 * tagged, so a hand-written `?obsvr-intercept` on any other specifier loads
 * normally instead of being shimmed. The shim imports the real module
 * untouched and re-exports the provider class behind a construct-trap Proxy
 * from auto/index.js (main thread, same module instance the SDK itself uses).
 *
 * Nothing in the provider package is modified: same source, same prototype,
 * same statics. Other tools that instrument these SDKs see the real class.
 *
 * @packageDocumentation
 */

const INTERCEPT_PARAM = 'obsvr-intercept';

/**
 * Bare specifiers we intercept, mapped to obsvr provider ids.
 *
 * Google ships two SDKs. The maintained `@google/genai` and legacy
 * `@google/generative-ai` packages have different client exports and method
 * paths, so they keep distinct shim ids while both route to provider `google`.
 *
 * The legacy line is end-of-life: last published 0.24.1 in April 2025,
 * upstream repo renamed to `deprecated-generative-ai-js`, ended August 2025.
 * It stays intercepted (and declared as an optional peer) because applications
 * still run it, and instrumenting what people run is the job. npm carries no
 * deprecation flag on any version of either package, so neither `npm outdated`
 * nor `npm audit` says a word about which one a project is on — hence this
 * note.
 */
const PROVIDER_SPECIFIERS: Record<string, string> = {
  openai: 'openai',
  '@anthropic-ai/sdk': 'anthropic',
  '@google/generative-ai': 'google',
  '@google/genai': 'google-genai',
};

/** Shim id -> canonical provider passed to the runtime interceptor. */
const CANONICAL_PROVIDER: Record<string, string> = {
  openai: 'openai',
  anthropic: 'anthropic',
  google: 'google',
  'google-genai': 'google',
};

/**
 * The provider ids `buildShim` knows. `load` refuses anything else rather than
 * falling through to a bare `export * from`, which would silently drop the
 * module's DEFAULT export — a substitution in its own right.
 */
const KNOWN_PROVIDERS = new Set(Object.values(PROVIDER_SPECIFIERS));

/**
 * Resolved URLs THIS hook tagged during `resolve`.
 *
 * `load` used to serve a shim for any URL carrying `?obsvr-intercept`, from
 * wherever it came. The parameter is part of a specifier, so an import written
 * as `./app-module.js?obsvr-intercept=openai` — from application code, or from
 * any dependency that builds a specifier out of data — was answered with a shim
 * that re-exported the target's default binding wrapped in a construct trap and
 * added an `OpenAI` export to it. That is module substitution over an
 * application module, not a provider one, and it needed no privilege beyond
 * writing an import.
 *
 * Membership is the fix: `resolve` records what it tagged, `load` serves a shim
 * only for those. The set is bounded by the number of distinct provider module
 * URLs in the process (four specifiers), and hooks registered with
 * `module.register()` share one module instance on the loader thread, so the
 * two halves see the same set. A worker that registers separately gets its own
 * instance and its own `resolve`, so it is self-consistent too.
 */
const taggedUrls = new Set<string>();

interface ResolveResult {
  url: string;
  format?: string | null;
  shortCircuit?: boolean;
  importAttributes?: Record<string, string>;
}

interface LoadResult {
  format: string;
  source: string;
  shortCircuit?: boolean;
}

type NextResolve = (specifier: string, context: unknown) => Promise<ResolveResult>;
type NextLoad = (url: string, context: unknown) => Promise<LoadResult>;

export async function resolve(
  specifier: string,
  context: unknown,
  nextResolve: NextResolve,
): Promise<ResolveResult> {
  const provider = PROVIDER_SPECIFIERS[specifier];
  if (!provider) return nextResolve(specifier, context);

  const resolved = await nextResolve(specifier, context);
  const url = new URL(resolved.url);
  if (url.searchParams.has(INTERCEPT_PARAM)) return resolved;
  url.searchParams.set(INTERCEPT_PARAM, provider);
  taggedUrls.add(url.href);
  return { ...resolved, url: url.href, shortCircuit: true };
}

export async function load(
  url: string,
  context: unknown,
  nextLoad: NextLoad,
): Promise<LoadResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return nextLoad(url, context);
  }

  const provider = parsed.searchParams.get(INTERCEPT_PARAM);
  if (!provider) return nextLoad(url, context);

  // The parameter is not authority — `resolve` having written it is. Checked
  // against both spellings because the URL arriving here has been through
  // Node's own normalisation and need not be byte-identical to what `resolve`
  // returned. An untagged URL carrying the parameter is a crafted specifier and
  // is loaded normally, exactly as if this hook were not installed.
  if (!taggedUrls.has(parsed.href) && !taggedUrls.has(url)) {
    return nextLoad(url, context);
  }
  if (!KNOWN_PROVIDERS.has(provider)) return nextLoad(url, context);

  parsed.searchParams.delete(INTERCEPT_PARAM);
  const originalUrl = parsed.href;
  const runtimeUrl = new URL('./index.js', import.meta.url).href;

  return {
    format: 'module',
    shortCircuit: true,
    source: buildShim(provider, originalUrl, runtimeUrl),
  };
}

/**
 * Every CLIENT CLASS each provider package exports, beside the default.
 *
 * The shim used to override the default export plus ONE named export, so every
 * other client class on a governed package rode the `export *` through
 * ungoverned — `AzureOpenAI` and `BedrockOpenAI` reach the same auditable
 * methods as `OpenAI` and were constructed with no interception at all, while
 * interception reported success for the name it did replace.
 *
 * WHY THIS IS A LIST HERE AND NOT IN THE PYTHON TWIN. Python resolves the class
 * objects at runtime and rebinds every module attribute that IS one, so it needs
 * no names. ESM export names are static: a module cannot decide at evaluation
 * time which bindings to export, and the shim source is generated before the
 * real module has been loaded. So the list is unavoidable — what is avoidable is
 * it being WRONG without anyone noticing, which is what
 * `tests/unit/provider-client-exports.test.ts` is for: it loads each real
 * provider package, finds every exported class descending from that package's
 * base client, and fails when one is missing from this table. A new upstream
 * client class breaks a test instead of reaching a user.
 */
const PROVIDER_CLIENT_EXPORTS: Record<string, readonly string[]> = {
  openai: ['OpenAI', 'AzureOpenAI', 'BedrockOpenAI'],
  anthropic: ['Anthropic'],
  google: ['GoogleGenerativeAI'],
  'google-genai': ['GoogleGenAI'],
};

/**
 * Build the replacement module source for a provider.
 *
 * `export * from` forwards every named export of the real module untouched.
 * Local exports take precedence over star exports, so each client class binding
 * named above is overridden with its own construct-trap Proxy.
 *
 * Each class is intercepted SEPARATELY rather than aliased to the default: they
 * are distinct classes (Azure and Bedrock flavours are not the base client), so
 * one Proxy standing for all of them would hand callers the wrong constructor.
 */
function buildShim(provider: string, originalUrl: string, runtimeUrl: string): string {
  const orig = JSON.stringify(originalUrl);
  const runtime = JSON.stringify(runtimeUrl);
  const names = PROVIDER_CLIENT_EXPORTS[provider];
  if (!names) return `export * from ${orig};`;

  const lines = [
    `export * from ${orig};`,
    `import { interceptProviderClass as $obsvrIntercept } from ${runtime};`,
  ];
  // The default export is the primary client for openai and anthropic; google
  // has no default and is reached only through its named export.
  const canonicalProvider = CANONICAL_PROVIDER[provider] ?? provider;
  const hasDefault = canonicalProvider !== 'google';
  if (hasDefault) {
    lines.push(
      `import { default as $obsvrDefault } from ${orig};`,
      `const $obsvrPatchedDefault = $obsvrIntercept(${JSON.stringify(canonicalProvider)}, $obsvrDefault);`,
      `export default $obsvrPatchedDefault;`,
    );
  }
  names.forEach((name, index) => {
    // The first named export IS the default class on the packages that have a
    // default, so it reuses that Proxy and stays `===` to the default export —
    // callers compare them.
    if (hasDefault && index === 0) {
      lines.push(`export { $obsvrPatchedDefault as ${name} };`);
      return;
    }
    lines.push(
      `import { ${name} as $obsvrOriginal${index} } from ${orig};`,
      `const $obsvrPatched${index} = $obsvrIntercept(${JSON.stringify(canonicalProvider)}, $obsvrOriginal${index});`,
      `export { $obsvrPatched${index} as ${name} };`,
    );
  });
  return lines.join('\n');
}

export { PROVIDER_CLIENT_EXPORTS, buildShim };
