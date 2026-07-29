/**
 * The SDK's two guarded runtime resolution sites, tested by RESOLVING rather
 * than by injecting.
 *
 * Both optional dependencies are reached through a `try { require(...) } catch`
 * that degrades silently — which is correct behaviour for something optional,
 * and is also why two separate defects lived there undetected:
 *
 *   1. `otel-mirror.ts` read `import.meta.url` through an indirect eval, which
 *      evaluates its argument as a SCRIPT in global scope where `import.meta`
 *      is a SyntaxError. Every pure-ESM consumer threw on the first mirrored
 *      event and had OTel mirroring disabled for the process lifetime.
 *
 *   2. `mcp.ts` required `@modelcontextprotocol/sdk-typescript/client/index.js`,
 *      a package that does not exist — collateral from a repo-directory rename
 *      that rewrote a third-party package specifier. The coarse fallback on the
 *      next line caught it, so every MCP consumer silently ran through the
 *      fallback and the deep-import path was dead.
 *
 * Neither was visible to the existing suites, and for the same reason: those
 * tests supply the dependency directly (`_setOtelApi`) or accept the
 * not-installed branch as a pass. A test that only ever exercises the injected
 * path cannot fail when resolution is broken.
 *
 * So these tests assert the SUCCESSFUL path: the specifier resolves, and the
 * feature works end to end against the real package.
 */
import { createRequire } from 'node:module';
import * as fs from 'fs';
import * as path from 'path';
import { mirrorToOtel, _resetOtelMirror } from '../../src/proxy/otel-mirror';
import type { AuditEvent, ResolvedConfig } from '../../src/proxy/types';

const require_ = createRequire(import.meta.url);
const SRC = path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', 'src');

/** Every non-relative specifier the source passes to require()/import(). */
function declaredSpecifiers(): { file: string; specifier: string }[] {
  const found: { file: string; specifier: string }[] = [];
  const walk = (dir: string) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.ts')) {
        const text = fs.readFileSync(full, 'utf-8');
        for (const m of text.matchAll(/\b(?:require|import)\(\s*["']([^"']+)["']\s*\)/g)) {
          const spec = m[1];
          if (!spec.startsWith('.') && !spec.startsWith('node:')) {
            found.push({ file: path.relative(SRC, full), specifier: spec });
          }
        }
      }
    }
  };
  walk(SRC);
  return found;
}

describe('every package specifier the SDK requires at runtime actually resolves', () => {
  // This is the generic guard. A rename that rewrites a third-party specifier
  // — which is exactly what happened to the MCP deep import — fails here
  // immediately, in whichever file it happened, without anyone having to think
  // to write a test for that specific dependency.
  const specifiers = declaredSpecifiers();

  it('finds at least the two known optional dependencies', () => {
    expect(specifiers.length).toBeGreaterThanOrEqual(2);
  });

  it.each(declaredSpecifiers())('resolves $specifier (from $file)', ({ specifier, file }) => {
    // Resolved explicitly rather than with `expect(...).not.toThrow(msg)`:
    // that form reads its argument as a MESSAGE MATCHER, so it passes whenever
    // the thrown error does not contain the given text — which for a
    // MODULE_NOT_FOUND is always. Written that way this assertion could not
    // fail, and did not when the broken specifier was reintroduced to check it.
    let resolved: string | undefined;
    let error: unknown;
    try {
      resolved = require_.resolve(specifier);
    } catch (e) {
      error = e;
    }
    if (error !== undefined) {
      throw new Error(
        `${file} requires "${specifier}", which does not resolve. ` +
          `The runtime catch would swallow this and the feature would go quietly ` +
          `dead. Original: ${(error as Error).message.split('\n')[0]}`,
      );
    }
    expect(typeof resolved).toBe('string');
  });
});

describe('MCP: the deep-import specifier resolves to a real Client class', () => {
  it('exposes Client through the subpath, not only through the package root', () => {
    // The bug was that the deep path was wrong and the ROOT fallback carried
    // everything. Asserting the root would have passed throughout. This asserts
    // the subpath specifically.
    const mod = require_('@modelcontextprotocol/sdk/client/index.js');
    const ClientClass = mod?.Client ?? mod?.default?.Client ?? mod?.default;
    expect(typeof ClientClass).toBe('function');
    expect(ClientClass.prototype).toBeDefined();
    expect(typeof ClientClass.prototype.callTool).toBe('function');
  });
});

describe('OTel: the mirror resolves the real API without injection', () => {
  afterEach(() => _resetOtelMirror());

  it('emits a span through the genuinely-required @opentelemetry/api', () => {
    // No _setOtelApi here — that is the point. This drives resolveOtel's own
    // require, which is what was broken.
    _resetOtelMirror();
    const otel = require_('@opentelemetry/api');
    const captured: Record<string, unknown>[] = [];
    const registered = otel.trace.setGlobalTracerProvider({
      getTracer: () => ({
        startSpan: (_name: string, options?: { attributes?: Record<string, unknown> }) => {
          captured.push(options?.attributes ?? {});
          return { setStatus: () => undefined, end: () => undefined };
        },
      }),
    });
    expect(registered).toBe(true);

    try {
      const config = { otel: { enabled: true }, debug: false } as unknown as ResolvedConfig;
      mirrorToOtel(config, {
        operation: 'chat.completions.create',
        provider: 'openai',
        model: 'gpt-4o',
        input_tokens: 7,
        output_tokens: 2,
        event_type: 'llm_call',
        action_taken: 'allowed',
        action_reason: 'none',
        seq_no: 1,
        sdk_session_id: 'sess',
        environment: 'test',
        timestamp_sdk: Date.now(),
        latency_ms: 5,
        success: true,
      } as unknown as AuditEvent);

      // A span reached the provider, which can only happen if resolveOtel's
      // own require succeeded.
      expect(captured).toHaveLength(1);
      expect(captured[0]['gen_ai.usage.input_tokens']).toBe(7);
    } finally {
      otel.trace.disable?.();
    }
  });
});
