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
import {
  attachToolGate,
  governModel,
} from '../integrations/openai-agents.js';
import { obsvrGovernLlamaIndexLLM } from '../integrations/llamaindex-llm.js';

/** Providers the module interceptor knows how to govern. */
export type InterceptedProvider = 'openai' | 'anthropic' | 'google';

export type InterceptorKind = 'esm' | 'cjs';

/** Hooks installed before application modules load. */
const installedInterceptors = new Set<InterceptorKind>();
const boundProviders = new Set<InterceptedProvider>();
const boundStartupSurfaces = new Set<string>();

const AUTO_STARTUP_SURFACES = [
  'openai.client',
  'anthropic.client',
  'google.client',
  'mcp.client',
  'openai_agents.tools',
  'openai_agents.model',
  'llamaindex.models',
] as const;

const EXPLICIT_STARTUP_SURFACES = {
  'langchain.models': 'LangChain exposes callbacks per model or invocation, not a process-global pre-call registration point',
  'llamaindex.tools': 'TypeScript LlamaIndex agent tools require an explicit pre-invocation wrapper',
} as const;

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
  bindings: Record<
    string,
    { state: 'armed' | 'bound' | 'not-applicable'; detail?: string }
  >;
  active: boolean;
}

/** Distinguish startup hooks that are armed from providers actually resolved. */
export function autoGovernanceStatus(): AutoGovernanceStatus {
  const armed = installedInterceptors.size > 0;
  const bindings: AutoGovernanceStatus['bindings'] = {};
  for (const surface of AUTO_STARTUP_SURFACES) {
    bindings[surface] = boundStartupSurfaces.has(surface)
      ? { state: 'bound' }
      : armed
        ? { state: 'armed' }
        : {
            state: 'not-applicable',
            detail: 'startup module interception is not installed',
          };
  }
  for (const [surface, detail] of Object.entries(EXPLICIT_STARTUP_SURFACES)) {
    bindings[surface] = { state: 'not-applicable', detail };
  }
  return {
    interceptors: {
      esm: installedInterceptors.has('esm'),
      cjs: installedInterceptors.has('cjs'),
    },
    boundProviders: [...boundProviders].sort(),
    bindings,
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
  boundStartupSurfaces.clear();
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
  boundStartupSurfaces.add(`${provider}.client`);
  recordBinding(
    `${provider}.client`,
    `${provider}.${(cls as Function).name || 'client'}`,
    undefined,
    {
      enforcementDepth: 'enforce',
      initializedAtMs: Date.now(),
      exclusions: [
        'instances created through saved pre-interceptor constructors',
        'unlisted provider methods',
        'custom transports that bypass the intercepted client',
      ],
    },
  );

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
  interceptionActive = true;
  boundStartupSurfaces.add('mcp.client');
  recordBinding('mcp.client', '@modelcontextprotocol/sdk/client.Client', undefined, {
    enforcementDepth: 'enforce',
    initializedAtMs: Date.now(),
    exclusions: ['hosted or provider-side tools outside the client session'],
  });
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

const governedLlamaIndexLlms = new WeakSet<object>();

function governLlamaIndexSetting(value: unknown): unknown {
  if (!value || typeof value !== 'object') return value;
  if (governedLlamaIndexLlms.has(value)) return value;
  const candidate = value as Record<string, unknown>;
  if (typeof candidate.chat !== 'function' || typeof candidate.complete !== 'function') {
    recordBinding(
      'llamaindex.models',
      'llamaindex.Settings.llm',
      new TypeError('assigned value does not expose chat() and complete()'),
      { enforcementDepth: 'unknown', initializedAtMs: Date.now() },
    );
    return value;
  }
  const governed = obsvrGovernLlamaIndexLLM(
    value as Parameters<typeof obsvrGovernLlamaIndexLLM>[0],
  );
  governedLlamaIndexLlms.add(governed);
  boundStartupSurfaces.add('llamaindex.models');
  interceptionActive = true;
  recordBinding('llamaindex.models', 'llamaindex.Settings.llm', undefined, {
    enforcementDepth: 'enforce',
    initializedAtMs: Date.now(),
    exclusions: [
      'LLMs assigned through saved pre-interceptor Settings references',
      'agent tools, which require an explicit pre-invocation wrapper',
      'tracing callbacks, which remain observe-only',
    ],
  });
  return governed;
}

/**
 * Govern LLMs assigned through the documented root `Settings.llm` boundary.
 * The Settings object is proxied, not mutated; the assigned LLM is replaced
 * with the existing pre-call wrapper before LlamaIndex can use it.
 */
export function interceptLlamaIndexSettings<T>(settings: T): T {
  if (!settings || typeof settings !== 'object') return settings;
  return new Proxy(settings as object, {
    get(target, prop, receiver) {
      return Reflect.get(target, prop, receiver);
    },
    set(target, prop, value, receiver) {
      const next = prop === 'llm' ? governLlamaIndexSetting(value) : value;
      return Reflect.set(target, prop, next, receiver);
    },
  }) as T;
}

/** Intercept the root LlamaIndex namespace without mutating its exports. */
export function interceptLlamaIndexNamespace<T>(namespace: T): T {
  if (!namespace || (typeof namespace !== 'object' && typeof namespace !== 'function')) {
    return namespace;
  }
  let settingsProxy: unknown;
  return new Proxy(namespace as object, {
    get(target, prop, receiver) {
      if (prop !== 'Settings') return Reflect.get(target, prop, receiver);
      settingsProxy ??= interceptLlamaIndexSettings(Reflect.get(target, prop, receiver));
      return settingsProxy;
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
  interceptionActive = true;
  boundStartupSurfaces.add('openai_agents.tools');
  boundStartupSurfaces.add('openai_agents.model');
  recordBinding('openai_agents.tools', '@openai/agents.Agent.tools', undefined, {
    enforcementDepth: 'enforce',
    initializedAtMs: Date.now(),
    exclusions: ['hosted tools', 'tools executed outside the governed Agent boundary'],
  });
  recordBinding('openai_agents.model', '@openai/agents.Agent.model', undefined, {
    enforcementDepth: 'enforce',
    initializedAtMs: Date.now(),
    exclusions: ['string model aliases resolved through an ungoverned provider client'],
  });

  const governModelValue = (value: unknown): unknown => {
    if (!value || typeof value !== 'object') return value;
    const candidate = value as Record<string, unknown>;
    if (
      typeof candidate.getResponse !== 'function' ||
      typeof candidate.getStreamedResponse !== 'function'
    ) {
      return value;
    }
    return governModel(value as Parameters<typeof governModel>[0]);
  };

  const listMutators = new Set<PropertyKey>([
    'copyWithin',
    'fill',
    'pop',
    'push',
    'reverse',
    'shift',
    'sort',
    'splice',
    'unshift',
  ]);

  const guardAgent = (agent: Record<string, unknown>): Record<string, unknown> => {
    let proxy: Record<string, unknown>;
    const refreshToolGate = (): void => {
      attachToolGate(proxy);
    };
    const guardedList = (values: unknown[]): unknown[] => {
      const target = values;
      const rollback = (snapshot: unknown[]): void => {
        target.splice(0, target.length, ...snapshot);
      };
      return new Proxy(target, {
        get(list, property, receiver) {
          const value = Reflect.get(list, property, receiver);
          if (!listMutators.has(property) || typeof value !== 'function') return value;
          return (...args: unknown[]) => {
            const snapshot = list.slice();
            try {
              const result = Reflect.apply(value, list, args);
              refreshToolGate();
              return result;
            } catch (error) {
              rollback(snapshot);
              throw error;
            }
          };
        },
        set(list, property, value) {
          const snapshot = list.slice();
          try {
            const changed = Reflect.set(list, property, value, list);
            refreshToolGate();
            return changed;
          } catch (error) {
            rollback(snapshot);
            throw error;
          }
        },
        deleteProperty(list, property) {
          const snapshot = list.slice();
          try {
            const changed = Reflect.deleteProperty(list, property);
            refreshToolGate();
            return changed;
          } catch (error) {
            rollback(snapshot);
            throw error;
          }
        },
      });
    };

    const rawTools = Array.isArray(agent.tools) ? agent.tools : [];
    const rawHandoffs = Array.isArray(agent.handoffs) ? agent.handoffs : [];
    agent.tools = guardedList(rawTools);
    agent.handoffs = guardedList(rawHandoffs);
    agent.model = governModelValue(agent.model);

    proxy = new Proxy(agent, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (property === 'clone' && typeof value === 'function') {
          return (...args: unknown[]) => {
            const cloned = Reflect.apply(value, target, args);
            return cloned && typeof cloned === 'object'
              ? guardAgent(cloned as Record<string, unknown>)
              : cloned;
          };
        }
        return typeof value === 'function' ? value.bind(target) : value;
      },
      set(target, property, value, receiver) {
        if (property === 'model') {
          return Reflect.set(target, property, governModelValue(value), receiver);
        }
        if ((property === 'tools' || property === 'handoffs') && Array.isArray(value)) {
          const previous = Reflect.get(target, property, receiver);
          const governed = guardedList(value);
          try {
            const changed = Reflect.set(target, property, governed, receiver);
            refreshToolGate();
            return changed;
          } catch (error) {
            Reflect.set(target, property, previous, receiver);
            throw error;
          }
        }
        return Reflect.set(target, property, value, receiver);
      },
    });
    refreshToolGate();
    return proxy;
  };

  return new Proxy(cls as object, {
    construct(target, args, newTarget) {
      const agent = Reflect.construct(
        target as new (...a: unknown[]) => object,
        args,
        newTarget,
      );
      return guardAgent(agent as Record<string, unknown>);
    },
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      if (property === 'create' && typeof value === 'function') {
        return (...args: unknown[]) => {
          const agent = Reflect.apply(value, target, args);
          return agent && typeof agent === 'object'
            ? guardAgent(agent as Record<string, unknown>)
            : agent;
        };
      }
      return value;
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
  const productionAgentStartup =
    config.environment === 'production' &&
    (config.agentPolicy !== undefined || config.mcpToolPolicy !== undefined);
  if (
    (requested.length > 0 || productionAgentStartup) &&
    !interceptionActive &&
    !isInterceptorInstalled()
  ) {
    const scope = requested.length > 0
      ? `config.providers lists [${requested.join(', ')}]`
      : 'production agent or MCP policy is configured';
    console.warn(
      `[obsvr] ${scope} but the startup module ` +
        'interceptor is not loaded, so those providers are not globally governed. ' +
        'Only explicitly wrapped clients and bound gates enforce. Start Node with ' +
        '"--import @obsvr/sdk/register" for automatic coverage, ' +
        'or wrap each client explicitly with obsvr.wrap().',
    );
  }
}
