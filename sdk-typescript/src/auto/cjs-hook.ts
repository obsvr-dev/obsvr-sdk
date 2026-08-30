/** CommonJS construction interception for supported provider entry points. */

import * as nodeModule from 'node:module';
import {
  interceptProviderClass,
  interceptProviderNamespace,
  markInterceptorInstalled,
  type InterceptedProvider,
} from './index.js';

interface ModuleLoader {
  _load(request: string, parent: unknown, isMain: boolean): unknown;
}

interface CjsTarget {
  provider: InterceptedProvider;
  clientExports: readonly string[];
  constructDefault: boolean;
}

const CJS_TARGETS: Readonly<Record<string, CjsTarget>> = {
  openai: {
    provider: 'openai',
    clientExports: ['default', 'OpenAI', 'AzureOpenAI', 'BedrockOpenAI'],
    constructDefault: true,
  },
  'openai/index': {
    provider: 'openai',
    clientExports: ['default', 'OpenAI', 'AzureOpenAI', 'BedrockOpenAI'],
    constructDefault: true,
  },
  'openai/client': {
    provider: 'openai',
    clientExports: ['OpenAI'],
    constructDefault: false,
  },
  'openai/client.js': {
    provider: 'openai',
    clientExports: ['OpenAI'],
    constructDefault: false,
  },
  'openai/azure': {
    provider: 'openai',
    clientExports: ['AzureOpenAI'],
    constructDefault: false,
  },
  '@anthropic-ai/sdk': {
    provider: 'anthropic',
    clientExports: ['default', 'Anthropic'],
    constructDefault: true,
  },
  '@google/generative-ai': {
    provider: 'google',
    clientExports: ['GoogleGenerativeAI'],
    constructDefault: false,
  },
};

interface InstalledState {
  installed: true;
}

const STATE_KEY = Symbol.for('@obsvr/sdk/cjs-construction-hook/v1');

/**
 * Patch Node's CommonJS module loader before application code runs.
 *
 * This is intentionally an import/constructor interceptor. It does not mutate
 * provider classes, prototypes, or returned namespace objects. Exact supported
 * specifiers are substituted after Node loads them normally; other modules are
 * untouched. The global marker prevents hook stacking across duplicate SDK
 * copies.
 */
export function installCjsHook(): boolean {
  const globalState = globalThis as typeof globalThis & {
    [STATE_KEY]?: InstalledState;
  };
  if (globalState[STATE_KEY]?.installed) {
    markInterceptorInstalled('cjs');
    return false;
  }

  const Module = (nodeModule as unknown as { Module?: ModuleLoader }).Module;
  if (!Module || typeof Module._load !== 'function') return false;

  const previousLoad = Module._load;
  const namespaceCache = new WeakMap<object, unknown>();

  Module._load = function obsvrCjsLoad(
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    const loaded = previousLoad.call(this, request, parent, isMain);
    const target = CJS_TARGETS[request];
    if (!target) return loaded;
    if ((typeof loaded !== 'object' || loaded === null) && typeof loaded !== 'function') {
      return loaded;
    }
    const cached = namespaceCache.get(loaded as object);
    if (cached) return cached;

    const base = target.constructDefault && typeof loaded === 'function'
      ? interceptProviderClass(target.provider, loaded)
      : loaded;
    const intercepted = interceptProviderNamespace(
      target.provider,
      base,
      target.clientExports,
    );
    namespaceCache.set(loaded as object, intercepted);
    return intercepted;
  };

  globalState[STATE_KEY] = { installed: true };
  markInterceptorInstalled('cjs');
  return true;
}

export { CJS_TARGETS };
