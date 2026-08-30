/**
 * Auto-Instrumentation (startup module interception)
 *
 * obsvr never mutates provider SDK prototypes, classes, or module objects.
 * Provider-construction coverage is delivered by Node ESM and CommonJS module
 * hooks:
 *
 *     node --import @obsvr/sdk/register app.js
 *
 * The ESM hook (see loader-hooks.ts) swaps documented exported classes for
 * construct-trap Proxy objects built here. The CommonJS hook chains Node's
 * module loader for documented provider specifiers. That loader chaining is
 * monkey-patching; provider classes, prototypes, module objects, and the
 * underlying instances remain untouched so other instrumentation can operate
 * underneath.
 *
 * Instances constructed before `obsvr.init()` pass calls through to the raw
 * client and pick up governance automatically on the first call after init.
 *
 * `obsvr.wrap()` remains the explicit per-instance path and is unaffected.
 *
 * @packageDocumentation
 */

import type { ResolvedConfig } from '../proxy/types.js';
import { wrap } from '../proxy/wrapper.js';
import { isInitialized, getConfig, markWrapped } from '../proxy/config.js';
import { recordBinding } from '../binding-report.js';
import {
  _MCP_GOVERNED_SYMBOL,
  obsvrGovernMCP,
} from '../integrations/mcp.js';
import { attachToolGate } from '../integrations/openai-agents.js';

/** Providers the module interceptor knows how to govern. */
export type InterceptedProvider = 'openai' | 'anthropic' | 'google';

export type InterceptorKind = 'esm' | 'cjs';

/** Hooks installed before application modules load. */
const installedInterceptors = new Set<InterceptorKind>();
const boundProviders = new Set<InterceptedProvider>();

/** Set once an installed hook has substituted at least one provider class. */
let interceptionActive = false;

/** Record that a startup hook is ready to intercept future provider loads. */
export function markInterceptorInstalled(kind: InterceptorKind): void {
  installedInterceptors.add(kind);
}

/** True when at least one supported startup hook is armed. */
export function isInterceptorInstalled(kind?: InterceptorKind): boolean {
  return kind ? installedInterceptors.has(kind) : installedInterceptors.size > 0;
}

export interface AutoGovernanceStatus {
  interceptors: Record<InterceptorKind, boolean>;
  boundProviders: InterceptedProvider[];
  active: boolean;
}

/** Distinguish startup hooks that are armed from providers actually resolved. */
export function autoGovernanceStatus(): AutoGovernanceStatus {
  return {
    interceptors: {
      esm: installedInterceptors.has('esm'),
      cjs: installedInterceptors.has('cjs'),
    },
    boundProviders: [...boundProviders].sort(),
    active: interceptionActive,
  };
}

/** True when `--import @obsvr/sdk/register` substituted a provider class. */
export function isInterceptionActive(): boolean {
  return interceptionActive;
}

/** Test hook. */
export function _resetInterception(): void {
  interceptionActive = false;
  installedInterceptors.clear();
  boundProviders.clear();
}

/**
 * Whether governance should apply to this provider under the current config.
 * With the interceptor loaded, all supported providers are governed unless
 * the customer narrows the list via `config.providers`.
 */
function providerEnabled(provider: InterceptedProvider, config: ResolvedConfig): boolean {
  if (!config.providers || config.providers.length === 0) return true;
  return config.providers.includes(provider);
}

/**
 * Per-instance lazy governance proxy.
 *
 * Delegates to the raw instance until `obsvr.init()` has run, then
 * materializes the standard `wrap()` proxy once and delegates to it. The raw
 * instance is never modified. Raw-path method access binds `this` to the
 * underlying instance so private-field brand checks in provider SDKs hold.
 */
function lazyGovern<T extends object>(instance: T, provider: InterceptedProvider): T {
  let governed: T | null = null;
  // Once init has run and told us not to govern (disabled / provider not
  // listed), stop re-checking on every access.
  let passthroughForever = false;

  const materialize = (): T | null => {
    if (governed) return governed;
    if (passthroughForever) return null;
    if (!isInitialized()) return null;
    const config = getConfig();
    if (config.disabled || !providerEnabled(provider, config)) {
      passthroughForever = true;
      return null;
    }
    governed = wrap(instance, {});
    return governed;
  };

  const proxy = new Proxy(instance, {
    get(target, prop, _receiver) {
      const g = materialize();
      if (g) return Reflect.get(g, prop, g);
      const value = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
    set(target, prop, value) {
      return Reflect.set(target, prop, value, target);
    },
    has(target, prop) {
      return Reflect.has(target, prop);
    },
    getOwnPropertyDescriptor(target, prop) {
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
    ownKeys(target) {
      return Reflect.ownKeys(target);
    },
    getPrototypeOf(target) {
      return Reflect.getPrototypeOf(target);
    },
  });

  // Register with the double-wrap guard so `obsvr.wrap()` on an already
  // intercepted instance returns it unchanged instead of stacking a second
  // audit layer.
  markWrapped(proxy);

  return proxy;
}

/** Govern either Google client shape without mutating the provider instance. */
function interceptGoogleClient<T extends object>(client: T): T {
  const models = (client as Record<string, unknown>).models as
    | Record<string, unknown>
    | undefined;
  if (typeof models?.generateContent === "function") {
    // Maintained @google/genai keeps generation methods under client.models.
    return lazyGovern(client, "google");
  }
  // Legacy @google/generative-ai creates a separate model object.
  const proxy = new Proxy(client, {
    get(target, prop, _receiver) {
      const value = Reflect.get(target, prop, target);
      if (prop === 'getGenerativeModel' && typeof value === 'function') {
        return (...args: unknown[]) => {
          const model = (value as (...a: unknown[]) => object).apply(target, args);
          return lazyGovern(model, 'google');
        };
      }
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
  markWrapped(proxy);
  return proxy;
}

/**
 * Wrap a provider class in a construct-trap Proxy.
 *
 * Called by the loader-hook shim on the main thread. The returned Proxy
 * forwards everything (statics, prototype, instanceof) to the real class and
 * only intercepts construction, returning a lazily governed instance.
 */
export function interceptProviderClass<T>(provider: InterceptedProvider, cls: T): T {
  if (typeof cls !== 'function') return cls;
  interceptionActive = true;
  boundProviders.add(provider);
  recordBinding(provider, `${provider}.${(cls as Function).name || 'client'}`);

  return new Proxy(cls as object, {
    construct(target, args, newTarget) {
      const instance = Reflect.construct(
        target as new (...a: unknown[]) => object,
        args,
        newTarget,
      );
      if (provider === 'google') return interceptGoogleClient(instance);
      return lazyGovern(instance, provider);
    },
  }) as T;
}

/**
 * Intercept client constructors exposed as properties of a namespace object.
 *
 * Some CommonJS-compatible subpaths expose an object such as
 * `{ OpenAI }` as their default export. Wrapping only the ESM named export
 * would leave `default.OpenAI` raw, so the loader uses this helper for that
 * shape. The namespace and its properties are not mutated.
 */
export function interceptProviderNamespace<T>(
  provider: InterceptedProvider,
  namespace: T,
  clientExports: readonly string[],
): T {
  if ((typeof namespace !== 'object' || namespace === null) && typeof namespace !== 'function') {
    return namespace;
  }
  const cache = new Map<PropertyKey, unknown>();
  return new Proxy(namespace as object, {
    get(target, prop, receiver) {
      if (typeof prop === 'string' && clientExports.includes(prop)) {
        if (cache.has(prop)) return cache.get(prop);
        const original = Reflect.get(target, prop, receiver);
        const intercepted = interceptProviderClass(provider, original);
        cache.set(prop, intercepted);
        return intercepted;
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as T;
}

/**
 * Lazily govern an MCP Client constructed through the startup module hook.
 * The instance may be created before explicit init when callers use the
 * register-only preload, so governance materializes on first access after init
 * just like direct-provider interception. The raw Client and its prototype are
 * never mutated.
 */
function lazyGovernMcp<T extends object>(instance: T): T {
  let governed: T | null = null;
  let passthroughForever = false;

  const materialize = (): T | null => {
    if (governed) return governed;
    if (passthroughForever || !isInitialized()) return null;
    const config = getConfig();
    if (config.disabled) {
      passthroughForever = true;
      return null;
    }
    governed = obsvrGovernMCP(instance, config);
    return governed;
  };

  return new Proxy(instance, {
    get(target, prop, _receiver) {
      if (prop === _MCP_GOVERNED_SYMBOL) return true;
      const active = materialize();
      if (active) return Reflect.get(active, prop, active);
      const value = Reflect.get(target, prop, target);
      return typeof value === 'function' ? value.bind(target) : value;
    },
    set(target, prop, value) {
      return Reflect.set(target, prop, value, target);
    },
    has(target, prop) {
      return prop === _MCP_GOVERNED_SYMBOL || Reflect.has(target, prop);
    },
    getOwnPropertyDescriptor(target, prop) {
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
    ownKeys(target) {
      return Reflect.ownKeys(target);
    },
    getPrototypeOf(target) {
      return Reflect.getPrototypeOf(target);
    },
  }) as T;
}

/** Replace only construction of the documented MCP Client export. */
export function interceptMcpClientClass<T>(cls: T): T {
  if (typeof cls !== 'function') return cls;
  recordBinding('mcp', '@modelcontextprotocol/sdk/client.Client');
  return new Proxy(cls as object, {
    construct(target, args, newTarget) {
      const instance = Reflect.construct(
        target as new (...a: unknown[]) => object,
        args,
        newTarget,
      );
      return lazyGovernMcp(instance);
    },
  }) as T;
}

/** Intercept Client on a CommonJS MCP namespace without mutating that object. */
export function interceptMcpNamespace<T>(namespace: T): T {
  if ((typeof namespace !== 'object' || namespace === null) && typeof namespace !== 'function') {
    return namespace;
  }
  let interceptedClient: unknown;
  return new Proxy(namespace as object, {
    get(target, prop, receiver) {
      if (prop !== 'Client') return Reflect.get(target, prop, receiver);
      if (interceptedClient) return interceptedClient;
      interceptedClient = interceptMcpClientClass(Reflect.get(target, prop, receiver));
      return interceptedClient;
    },
  }) as T;
}

/**
 * Attach obsvr's real pre-execution tool guardrail to each newly constructed
 * OpenAI Agents Agent. The guardrail reads policy at execution time, so this is
 * safe even when construction happens before explicit init under register-only
 * startup. Hosted tools remain outside the client-side boundary.
 */
export function interceptOpenAIAgentClass<T>(cls: T): T {
  if (typeof cls !== 'function') return cls;
  recordBinding('openai_agents', '@openai/agents.Agent');
  return new Proxy(cls as object, {
    construct(target, args, newTarget) {
      const agent = Reflect.construct(
        target as new (...a: unknown[]) => object,
        args,
        newTarget,
      );
      attachToolGate(agent);
      return agent;
    },
  }) as T;
}

/** Intercept Agent on the package namespace without mutating that namespace. */
export function interceptOpenAIAgentsNamespace<T>(namespace: T): T {
  if ((typeof namespace !== 'object' || namespace === null) && typeof namespace !== 'function') {
    return namespace;
  }
  let interceptedAgent: unknown;
  return new Proxy(namespace as object, {
    get(target, prop, receiver) {
      if (prop !== 'Agent') return Reflect.get(target, prop, receiver);
      if (interceptedAgent) return interceptedAgent;
      interceptedAgent = interceptOpenAIAgentClass(Reflect.get(target, prop, receiver));
      return interceptedAgent;
    },
  }) as T;
}

/**
 * Called by `init()` after configuration is resolved.
 *
 * No patching happens here. Its only job is to tell the customer when their
 * config asks for provider coverage that the module interceptor is not in
 * place to deliver.
 */
export function autoInstrument(config: ResolvedConfig): void {
  if (config.disabled) return;

  const requested = config.providers ?? [];
  if (requested.length > 0 && !interceptionActive && !isInterceptorInstalled()) {
    console.warn(
      `[obsvr] config.providers lists [${requested.join(', ')}] but the module ` +
        'interceptor is not loaded, so those providers are not globally governed. ' +
        'Start Node with "--import @obsvr/sdk/register" for zero-code coverage, ' +
        'or wrap each client explicitly with obsvr.wrap().',
    );
  }
}
