/**
 * Zero-code global interception entry point.
 *
 * Usage:
 *
 *     node --import @obsvr/sdk/register app.js
 *
 * Registers module customization hooks that serve supported provider
 * packages (openai, @anthropic-ai/sdk, @google/generative-ai) behind a
 * construct-trap Proxy, with no monkey patching: provider prototypes,
 * classes, and module objects are never mutated, so other instrumentation
 * keeps working.
 *
 * WHAT THIS GOVERNS, and what it does not. This comment previously said
 * "every client instance created anywhere in the process", which is not
 * true and was measured to be untrue on three counts. What is governed is
 * the DEFAULT and NAMED client export of each of the three specifiers
 * above, imported by that exact specifier, from an ESM entry point.
 * Escaping it, each reproduced live against a real provider with a
 * governed control in the same run:
 *
 *   - `require()`. module.register() hooks do not intercept CommonJS at
 *     all. A CJS entry point reaches the provider with nothing recorded
 *     and interception never activates. Not fixable here — see the
 *     ESM-only section of the TypeScript README.
 *   - SUBPATH imports. The specifier table is exact-match, so
 *     `openai/index.mjs`, `openai/index`, `openai/client`, `openai/client.mjs`,
 *     `openai/client.js` and `openai/azure` all resolve to the untouched
 *     module.
 *   - OTHER CLIENT CLASSES on a governed package. The openai shim overrides
 *     `default` and `OpenAI`; `AzureOpenAI` and `BedrockOpenAI` ride the
 *     `export *` through ungoverned.
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

const register = (nodeModule as { register?: (specifier: string, parent: string) => void })
  .register;

if (typeof register === 'function') {
  register('./auto/loader-hooks.js', import.meta.url);
} else {
  console.warn(
    '[obsvr] --import @obsvr/sdk/register requires Node >=22. ' +
      'Global interception is not active; use obsvr.wrap() per client instead.',
  );
}
