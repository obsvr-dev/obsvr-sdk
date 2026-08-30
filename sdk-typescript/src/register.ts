/**
 * Zero-code global interception entry point.
 *
 * Usage:
 *
 *     node --import @obsvr/sdk/register app.js
 *
 * Registers module customization hooks that serve supported provider
 * packages (openai, @anthropic-ai/sdk, @google/genai, and the legacy
 * @google/generative-ai) behind a
 * construct-trap Proxy. It also intercepts exact supported CommonJS
 * `require()` entry points by chaining Node's module loader. Provider
 * prototypes, classes, and module objects are never mutated, so other
 * instrumentation keeps working underneath.
 *
 * WHAT THIS GOVERNS, and what it does not. This comment previously said
 * "every client instance created anywhere in the process", which is not
 * true and was measured to be untrue on three counts. What is governed is
 * the documented root and OpenAI subpath client exports, for ESM and for
 * CommonJS entry points that the provider actually publishes. Unsupported
 * subpaths and saved constructor references acquired before this preload are
 * outside coverage.
 *
 * None of these makes the record lie — an escaped client emits no event
 * rather than a false one. They are coverage gaps, and `obsvr.wrap()` on
 * the client governs every one of them.
 *
 * Must be loaded via the --import flag (or NODE_OPTIONS="--import ...").
 * A plain `import '@obsvr/sdk/register'` inside application code is too
 * late: static imports in the entry module resolve before it runs.
 *
 * @packageDocumentation
 */

import * as nodeModule from 'node:module';
import { installCjsHook } from './auto/cjs-hook.js';
import { markInterceptorInstalled } from './auto/index.js';

const register = (nodeModule as { register?: (specifier: string, parent: string) => void })
  .register;

if (typeof register === 'function') {
  register('./auto/loader-hooks.js', import.meta.url);
  markInterceptorInstalled('esm');
} else {
  console.warn(
    '[obsvr] --import @obsvr/sdk/register requires Node >=22. ' +
      'Global interception is not active; use obsvr.wrap() per client instead.',
  );
}

installCjsHook();
