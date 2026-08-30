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
const INITIALIZE = path.join(PKG, 'dist', 'initialize.js');

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

const GOOGLE_GENAI_PROBE = `
import { GoogleGenAI } from "@google/genai";
const auto = await import("${PKG}/dist/auto/index.js");
const { init } = await import("${PKG}/dist/proxy/config.js");
const { wrap } = await import("${PKG}/dist/proxy/wrapper.js");
init({ apiKey: "k", ingestUrl: "http://127.0.0.1:1", environment: "development" });
const client = new GoogleGenAI({ apiKey: "test-key-not-real" });
console.log("RESULT_JSON:" + JSON.stringify({
  interceptionActive: auto.isInterceptionActive(),
  wrapIsIdentity: wrap(client) === client,
  clientUsable: typeof client.models?.generateContent === "function",
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

  it('intercepts the maintained @google/genai client under --import', () => {
    const result = runWithHook(GOOGLE_GENAI_PROBE);
    expect(result.interceptionActive).toBe(true);
    expect(result.wrapIsIdentity).toBe(true);
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

describe('documented OpenAI ESM entry points enforce before transport', () => {
  const subpaths = [
    'openai/index',
    'openai/index.mjs',
    'openai/client',
    'openai/client.mjs',
    'openai/client.js',
    'openai/azure',
  ];

  it.each(subpaths)('%s is governed by the preload', (specifier) => {
    const source = `
const provider = await import(${JSON.stringify(specifier)});
const { obsvr } = await import(${JSON.stringify(PKG + '/dist/index.js')});
obsvr.init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:1', piiPolicy: {}, policyRefreshIntervalMs: 0 });
const Client = provider.OpenAI ?? provider.AzureOpenAI ?? provider.default?.OpenAI ?? provider.default;
let transportCalls = 0;
const options = ${JSON.stringify(specifier)} === 'openai/azure'
  ? { apiKey: 'x', endpoint: 'https://example.openai.azure.com', apiVersion: '2024-01-01', fetch: async () => { transportCalls++; throw new Error('transport reached'); } }
  : { apiKey: 'x', fetch: async () => { transportCalls++; throw new Error('transport reached'); } };
const client = new Client(options);
let blocked = false;
try {
  await client.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: 'SSN 123-45-6789' }] });
} catch (error) {
  blocked = error?.name === 'ObsvrPolicyError';
}
console.log('RESULT_JSON:' + JSON.stringify({ blocked, transportCalls, wrapIsIdentity: obsvr.wrap(client) === client }));
process.exit(0);
`;
    const result = runWithHook(source);
    expect(result.blocked).toBe(true);
    expect(result.transportCalls).toBe(0);
    expect(result.wrapIsIdentity).toBe(true);
  });
});

describe('CommonJS provider construction interception', () => {
  it('governs require("openai") before transport', () => {
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const file = path.join(dir, 'probe.cjs');
    try {
      writeFileSync(file, `
(async () => {
  const OpenAI = require('openai');
  const { obsvr } = await import(${JSON.stringify(PKG + '/dist/index.js')});
  obsvr.init({ apiKey: 'k', ingestUrl: 'http://127.0.0.1:1', piiPolicy: {}, policyRefreshIntervalMs: 0 });
  let transportCalls = 0;
  const client = new OpenAI({ apiKey: 'x', fetch: async () => { transportCalls++; throw new Error('transport reached'); } });
  let blocked = false;
  try {
    await client.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: 'SSN 123-45-6789' }] });
  } catch (error) {
    blocked = error?.name === 'ObsvrPolicyError';
  }
  console.log('RESULT_JSON:' + JSON.stringify({ blocked, transportCalls, wrapIsIdentity: obsvr.wrap(client) === client }));
  process.exit(0);
})();
`, 'utf-8');
      const out = execFileSync(process.execPath, ['--import', REGISTER, file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
      });
      const line = out.split('\n').find((value) => value.startsWith('RESULT_JSON:'))!;
      const result = JSON.parse(line.slice('RESULT_JSON:'.length));
      expect(result.blocked).toBe(true);
      expect(result.transportCalls).toBe(0);
      expect(result.wrapIsIdentity).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('governs a real CommonJS MCP Client before server execution', () => {
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const file = path.join(dir, 'mcp-probe.cjs');
    try {
      writeFileSync(file, `
(async () => {
  const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
  const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
  const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
  const executed = [];
  const server = new McpServer({ name: 'server', version: '1.0.0' });
  server.registerTool('send_contract', { description: 'Send a contract' }, async () => {
    executed.push('send_contract');
    return { content: [{ type: 'text', text: 'sent' }] };
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'client', version: '1.0.0' }, { capabilities: {} });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  let blocked = false;
  try {
    await client.callTool({ name: 'send_contract', arguments: {} });
  } catch (error) {
    blocked = String(error).includes('[obsvr] MCP tool blocked by policy');
  }
  await client.close();
  await server.close();
  console.log('RESULT_JSON:' + JSON.stringify({ blocked, executed }));
  process.exit(0);
})();
`, 'utf-8');
      const out = execFileSync(process.execPath, ['--import', INITIALIZE, file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
        env: {
          ...process.env,
          OBSVR_API_KEY: 'k',
          OBSVR_INGEST_URL: 'http://127.0.0.1:1',
          OBSVR_MCP_TOOL_POLICY: '{"deniedTools":["send_contract"]}',
          OBSVR_REQUIRED_BINDINGS: 'mcp',
        },
      });
      const line = out.split('\n').find((value) => value.startsWith('RESULT_JSON:'))!;
      const result = JSON.parse(line.slice('RESULT_JSON:'.length));
      expect(result).toEqual({ blocked: true, executed: [] });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('@obsvr/sdk/initialize one-step preload', () => {
  it('initializes and blocks a real provider call before transport', () => {
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const file = path.join(dir, 'probe.mjs');
    try {
      writeFileSync(file, `
import OpenAI from 'openai';
let transportCalls = 0;
const client = new OpenAI({ apiKey: 'x', fetch: async () => { transportCalls++; throw new Error('transport reached'); } });
let blocked = false;
try {
  await client.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: 'SSN 123-45-6789' }] });
} catch (error) {
  blocked = error?.name === 'ObsvrPolicyError';
}
console.log('RESULT_JSON:' + JSON.stringify({ blocked, transportCalls }));
process.exit(0);
`, 'utf-8');
      const out = execFileSync(process.execPath, ['--import', INITIALIZE, file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
        env: {
          ...process.env,
          OBSVR_API_KEY: 'k',
          OBSVR_INGEST_URL: 'http://127.0.0.1:1',
          OBSVR_PROVIDERS: 'openai',
          OBSVR_PII_POLICY: '{}',
        },
      });
      const line = out.split('\n').find((value) => value.startsWith('RESULT_JSON:'))!;
      const result = JSON.parse(line.slice('RESULT_JSON:'.length));
      expect(result.blocked).toBe(true);
      expect(result.transportCalls).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails startup when its required API key is absent', () => {
    expect(() => execFileSync(process.execPath, ['--import', INITIALIZE, '-e', '0'], {
      cwd: PKG,
      encoding: 'utf-8',
      timeout: 60_000,
      env: { ...process.env, OBSVR_API_KEY: '' },
      stdio: 'pipe',
    })).toThrow(/OBSVR_API_KEY is required/);
  });

  it('fails startup when a required binding is unsupported or absent', () => {
    expect(() => execFileSync(process.execPath, ['--import', INITIALIZE, '-e', '0'], {
      cwd: PKG,
      encoding: 'utf-8',
      timeout: 60_000,
      env: {
        ...process.env,
        OBSVR_API_KEY: 'k',
        OBSVR_INGEST_URL: 'http://127.0.0.1:1',
        OBSVR_REQUIRED_BINDINGS: 'not-installed',
      },
      stdio: 'pipe',
    })).toThrow(/not-installed was never bound/);
  });

  it('loads and verifies a required provider before application startup', () => {
    const out = execFileSync(
      process.execPath,
      ['--import', INITIALIZE, '--input-type=module', '-e', `
        import { autoGovernanceStatus } from ${JSON.stringify(PKG + '/dist/index.js')};
        console.log('RESULT_JSON:' + JSON.stringify(autoGovernanceStatus()));
        process.exit(0);
      `],
      {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
        env: {
          ...process.env,
          OBSVR_API_KEY: 'k',
          OBSVR_INGEST_URL: 'http://127.0.0.1:1',
          OBSVR_REQUIRED_BINDINGS: 'openai',
        },
      },
    );
    const line = out.split('\n').find((value) => value.startsWith('RESULT_JSON:'))!;
    const status = JSON.parse(line.slice('RESULT_JSON:'.length));
    expect(status.boundProviders).toContain('openai');
    expect(status.active).toBe(true);
  });

  it('auto-governs a real MCP Client before the server executes a denied tool', () => {
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const file = path.join(dir, 'mcp-probe.mjs');
    try {
      writeFileSync(file, `
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const executed = [];
const server = new McpServer({ name: 'server', version: '1.0.0' });
server.registerTool('send_contract', { description: 'Send a contract' }, async () => {
  executed.push('send_contract');
  return { content: [{ type: 'text', text: 'sent' }] };
});
server.registerTool('read_contract', { description: 'Read a contract' }, async () => {
  executed.push('read_contract');
  return { content: [{ type: 'text', text: 'read' }] };
});

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const client = new Client({ name: 'client', version: '1.0.0' }, { capabilities: {} });
await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

let blocked = false;
try {
  await client.callTool({ name: 'send_contract', arguments: {} });
} catch (error) {
  blocked = String(error).includes('[obsvr] MCP tool blocked by policy');
}
await client.callTool({ name: 'read_contract', arguments: {} });
await client.close();
await server.close();
console.log('RESULT_JSON:' + JSON.stringify({ blocked, executed }));
process.exit(0);
`, 'utf-8');

      const out = execFileSync(process.execPath, ['--import', INITIALIZE, file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
        env: {
          ...process.env,
          OBSVR_API_KEY: 'k',
          OBSVR_INGEST_URL: 'http://127.0.0.1:1',
          OBSVR_MCP_TOOL_POLICY: '{"deniedTools":["send_contract"]}',
          OBSVR_REQUIRED_BINDINGS: 'mcp',
        },
      });
      const line = out.split('\n').find((value) => value.startsWith('RESULT_JSON:'))!;
      const result = JSON.parse(line.slice('RESULT_JSON:'.length));
      expect(result.blocked).toBe(true);
      expect(result.executed).toEqual(['read_contract']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('auto-attaches the real OpenAI Agents pre-tool guardrail', () => {
    const dir = mkdtempSync(path.join(PKG, '.hook-probe-'));
    const file = path.join(dir, 'agents-probe.mjs');
    try {
      writeFileSync(file, `
import { Agent, Usage, run, setTracingDisabled, tool } from '@openai/agents';
setTracingDisabled(true);

const executed = [];
const requests = [];
let turn = 0;
const model = {
  async getResponse(request) {
    requests.push(request);
    turn += 1;
    if (turn === 1) {
      return {
        usage: new Usage(),
        output: [{
          type: 'function_call', callId: 'call-1', name: 'send_contract',
          arguments: '{}', status: 'completed',
        }],
      };
    }
    return {
      usage: new Usage(),
      output: [{
        type: 'message', role: 'assistant', status: 'completed',
        content: [{ type: 'output_text', text: 'done' }],
      }],
    };
  },
  async *getStreamedResponse() { throw new Error('not used'); },
};
const sendContract = tool({
  name: 'send_contract',
  description: 'Send a contract',
  parameters: { type: 'object', properties: {}, additionalProperties: false },
  strict: true,
  execute: async () => { executed.push('send_contract'); return 'sent'; },
});
const agent = new Agent({
  name: 'agent', instructions: 'Use the tool.', model, tools: [sendContract],
});
const result = await run(agent, 'send it');
console.log('RESULT_JSON:' + JSON.stringify({
  executed,
  finalOutput: result.finalOutput,
  refusalReturned: JSON.stringify(requests[1]?.input ?? '').includes('[obsvr]'),
}));
process.exit(0);
`, 'utf-8');
      const out = execFileSync(process.execPath, ['--import', INITIALIZE, file], {
        cwd: PKG,
        encoding: 'utf-8',
        timeout: 60_000,
        env: {
          ...process.env,
          OBSVR_API_KEY: 'k',
          OBSVR_INGEST_URL: 'http://127.0.0.1:1',
          OBSVR_AGENT_POLICY: '{"deniedTools":["send_contract"]}',
          OBSVR_REQUIRED_BINDINGS: 'openai_agents',
        },
      });
      const line = out.split('\n').find((value) => value.startsWith('RESULT_JSON:'))!;
      const result = JSON.parse(line.slice('RESULT_JSON:'.length));
      expect(result).toEqual({
        executed: [],
        finalOutput: 'done',
        refusalReturned: true,
      });
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
