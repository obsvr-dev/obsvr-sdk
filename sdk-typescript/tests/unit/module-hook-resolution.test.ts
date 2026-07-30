/**
 * The `--import @obsvr/sdk/register` module hook, tested by RESOLVING rather
 * than by injecting.
 *
 * `auto-intercept.test.ts` proves the construct-trap design by calling
 * `interceptProviderClass` with a `FakeOpenAI`. That is the right test for the
 * design and the wrong test for the WIRING: it never loads `register.js`, never
 * resolves `./auto/loader-hooks.js`, and never matches a real package specifier.
 * Every one of those is a resolution step that fails quietly —
 * `register()` on a moved file, or a specifier key that no longer matches what
 * the app imports, leaves the process running with interception simply off.
 *
 * Three defects this cycle had exactly that shape (OTel's indirect-eval
 * `import.meta`, both MCP specifiers, a pruned symlink reported as "0 suites"),
 * so this drives the real thing: a child process started with the real
 * `--import` flag, importing the real `openai` package, asserting the real
 * class was substituted.
 *
 * It runs against `dist/`, because that is what `--import` loads and what a
 * consumer gets. `npm test` runs after `npm run build` in the gate.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'path';

const PKG = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const REGISTER = path.join(PKG, 'dist', 'register.js');

/**
 * Run a script inside the package directory (so provider packages resolve) with
 * the register hook loaded, and return whatever it prints after RESULT_JSON:.
 */
function runWithHook(source: string): Record<string, unknown> {
  const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
  const file = path.join(dir, 'probe.mjs');
  try {
    writeFileSync(file, source, 'utf-8');
    const out = execFileSync(process.execPath, ['--import', REGISTER, file], {
      cwd: PKG,
      encoding: 'utf-8',
      timeout: 60_000,
    });
    const line = out.split('\n').find((l) => l.startsWith('RESULT_JSON:'));
    if (!line) throw new Error(`probe printed no result:\n${out}`);
    return JSON.parse(line.slice('RESULT_JSON:'.length));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const PROBE = `
import OpenAI from "openai";
const auto = await import("${PKG}/dist/auto/index.js");
const { init } = await import("${PKG}/dist/proxy/config.js");
const { wrap } = await import("${PKG}/dist/proxy/wrapper.js");
init({ apiKey: "k", ingestUrl: "http://127.0.0.1:1", environment: "development" });
const client = new OpenAI({ apiKey: "x" });
console.log("RESULT_JSON:" + JSON.stringify({
  interceptionActive: auto.isInterceptionActive(),
  // wrap() on an ALREADY-intercepted instance returns it unchanged. If the hook
  // did nothing, wrap() would hand back a new proxy and this would be false —
  // which is the difference between "governed" and "governable".
  wrapIsIdentity: wrap(client) === client,
  clientUsable: typeof client.chat?.completions?.create === "function",
}));
`;

describe('the register hook actually substitutes a real provider class', () => {
  it('has a built dist to test against', () => {
    // A missing dist would make every assertion below vacuous rather than
    // failing, which is the pattern this file exists to catch.
    expect(existsSync(REGISTER)).toBe(true);
  });

  it('intercepts the real openai package under --import', () => {
    const result = runWithHook(PROBE);
    // The load-bearing one: the hook matched the specifier and served a
    // substituted class.
    expect(result.interceptionActive).toBe(true);
    // And the substitution is the governed one, not merely some proxy.
    expect(result.wrapIsIdentity).toBe(true);
    // And the client still works as a client.
    expect(result.clientUsable).toBe(true);
  });

  it('leaves interception INACTIVE without the flag, so the check is meaningful', () => {
    // If this also reported active, the assertion above would prove nothing.
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const file = path.join(dir, 'probe.mjs');
    try {
      writeFileSync(file, PROBE, 'utf-8');
      const out = execFileSync(process.execPath, [file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
      });
      const line = out.split('\n').find((l) => l.startsWith('RESULT_JSON:'))!;
      expect(JSON.parse(line.slice('RESULT_JSON:'.length)).interceptionActive).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the load hook serves a shim only for specifiers resolve tagged', () => {
  /**
   * `load` used to key off `?obsvr-intercept` in ANY url. The parameter is part
   * of a specifier, so an import written as
   * `./app-module.mjs?obsvr-intercept=openai` — by application code, or by any
   * dependency that builds a specifier out of data — was answered with a
   * generated module that re-exported the target's default binding behind
   * obsvr's construct trap and added an `OpenAI` export to it. That is module
   * substitution over an application module, and it needed no privilege beyond
   * writing an import.
   *
   * The application module has no `OpenAI` export of its own, so the appearance
   * of one is unambiguous proof that a shim was served in its place.
   */
  const APP_MODULE = [
    `export default class AppThing { static MARKER = 'ORIGINAL_APP_DEFAULT'; }`,
    `export const helper = () => 'app-helper-ok';`,
  ].join('\n');

  function importAppModule(query: string): Record<string, unknown> {
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const app = path.join(dir, 'app-module.mjs');
    const file = path.join(dir, 'probe.mjs');
    try {
      writeFileSync(app, APP_MODULE, 'utf-8');
      writeFileSync(
        file,
        [
          `const mod = await import(${JSON.stringify('file://' + app)} + ${JSON.stringify(query)});`,
          `console.log("RESULT_JSON:" + JSON.stringify({`,
          `  substituted: "OpenAI" in mod,`,
          `  defaultMarker: mod.default?.MARKER ?? null,`,
          `  namedExport: typeof mod.helper === "function" ? mod.helper() : null,`,
          `}));`,
        ].join('\n'),
        'utf-8',
      );
      const out = execFileSync(process.execPath, ['--import', REGISTER, file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
      });
      const line = out.split('\n').find((l) => l.startsWith('RESULT_JSON:'));
      if (!line) throw new Error(`probe printed no result:\n${out}`);
      return JSON.parse(line.slice('RESULT_JSON:'.length));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('does not shim an application module carrying a crafted intercept parameter', () => {
    const result = importAppModule('?obsvr-intercept=openai');
    expect(result.substituted).toBe(false);
    // Loaded normally, not merely refused: the real bindings are intact.
    expect(result.defaultMarker).toBe('ORIGINAL_APP_DEFAULT');
    expect(result.namedExport).toBe('app-helper-ok');
  });

  it('loads the same module untouched with no parameter, so the check is meaningful', () => {
    const result = importAppModule('');
    expect(result.substituted).toBe(false);
    expect(result.defaultMarker).toBe('ORIGINAL_APP_DEFAULT');
  });

  it('still intercepts the real provider package, so the fix did not disable the feature', () => {
    // The failure mode a membership check invites is closing the hole by never
    // serving a shim at all. This is the same assertion as the first describe
    // block, restated here because it is THIS change's control.
    expect(runWithHook(PROBE).interceptionActive).toBe(true);
  });
});

describe('the hook registration itself resolves', () => {
  it('register.js resolves ./auto/loader-hooks.js without throwing', () => {
    // `module.register()` resolves its specifier eagerly, so a moved or
    // unbuilt loader file surfaces here rather than as silently-absent
    // interception later.
    const out = execFileSync(
      process.execPath,
      ['--import', REGISTER, '-e', 'console.log("RESULT_JSON:{\\"ok\\":true}")'],
      { cwd: PKG, encoding: 'utf-8', timeout: 60_000 },
    );
    expect(out).toContain('RESULT_JSON:{"ok":true}');
  });
});
