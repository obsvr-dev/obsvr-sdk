/**
 * Zero-code global interception entry point.
 *
 * Usage:
 *
 *     node --import @obsvr/sdk/register app.js
 *
 * Registers module customization hooks that serve supported provider
 * packages (openai, @anthropic-ai/sdk, @google/generative-ai) behind a
 * construct-trap Proxy. Every client instance created anywhere in the
 * process is then governed by obsvr with no code changes and no monkey
 * patching: provider prototypes, classes, and module objects are never
 * mutated, so other instrumentation keeps working.
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
    '[obsvr] --import @obsvr/sdk/register requires Node >=18.19 or >=20.6. ' +
      'Global interception is not active; use obsvr.wrap() per client instead.',
  );
}
