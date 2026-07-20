/**
 * Auto-Instrumentation (module-level interception, no monkey patching)
 *
 * obsvr never mutates provider SDK prototypes, classes, or module objects.
 * Global coverage is delivered by a Node module hook:
 *
 *     node --import @obsvr/sdk/register app.js
 *
 * The hook (see loader-hooks.ts) swaps the provider's exported class for a
 * construct-trap Proxy built here. Every `new OpenAI()` anywhere in the
 * process then returns a governed instance. The real class, its prototype,
 * and the underlying instance stay untouched, so APM, tracing, and other
 * instrumentation that patches the same SDKs keeps working underneath.
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

/** Providers the module interceptor knows how to govern. */
export type InterceptedProvider = 'openai' | 'anthropic' | 'google';

/** Set once the loader hook has substituted at least one provider class. */
let interceptionActive = false;

/** True when `--import @obsvr/sdk/register` substituted a provider class. */
export function isInterceptionActive(): boolean {
  return interceptionActive;
}

/** Test hook. */
export function _resetInterception(): void {
  interceptionActive = false;
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

/**
 * Google's client hands out models via `getGenerativeModel()`; governance
 * applies to the model object (same shape `obsvr.wrap()` documents), so the
 * client proxy intercepts that one factory method and governs its result.
 */
function interceptGoogleClient<T extends object>(client: T): T {
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
 * Called by `init()` after configuration is resolved.
 *
 * No patching happens here. Its only job is to tell the customer when their
 * config asks for provider coverage that the module interceptor is not in
 * place to deliver.
 */
export function autoInstrument(config: ResolvedConfig): void {
  if (config.disabled) return;

  const requested = config.providers ?? [];
  if (requested.length > 0 && !interceptionActive) {
    console.warn(
      `[obsvr] config.providers lists [${requested.join(', ')}] but the module ` +
        'interceptor is not loaded, so those providers are not globally governed. ' +
        'Start Node with "--import @obsvr/sdk/register" for zero-code coverage, ' +
        'or wrap each client explicitly with obsvr.wrap().',
    );
  }
}
