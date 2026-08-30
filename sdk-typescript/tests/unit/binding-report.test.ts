/**
 * An optional integration that fails to bind must say WHY, not just that it
 * did. Three different situations otherwise produce one indistinguishable
 * silent skip: the package is not installed (normal), the package is
 * installed but the symbol this integration patches moved (an obsvr defect -
 * the integration is inert while the manifest advertises support), or the
 * package is installed and broken (upstream's problem). Only the middle one
 * is obsvr's to fix, and a bare boolean cannot tell them apart.
 *
 * Twin: sdk-python/tests/test_binding_report.py.
 */
import {
  _resetBindings,
  RequiredBindingsError,
  assertRequiredBindings,
  integrationBindings,
  recordBinding,
  requiredBindingFailures,
  unboundSymbols,
} from "../../src/binding-report";
import { patchMCP, _resetPatchMCPDeprecationWarning } from "../../src/integrations/mcp";
import { init } from "../../src/proxy/config";
import { getConfig } from "../../src/proxy/index";
import * as sdk from "../../src/index";

beforeEach(() => {
  _resetBindings();
});

describe("recording", () => {
  test("a successful bind records no reason", () => {
    recordBinding("demo", "pkg.Symbol");
    expect(integrationBindings()).toEqual({
      demo: { "pkg.Symbol": { bound: true } },
    });
    expect(unboundSymbols()).toEqual([]);
  });

  test("a failed bind keeps the error type and message", () => {
    recordBinding("demo", "pkg.Symbol", new TypeError("Symbol is not a constructor"));
    const entry = integrationBindings().demo["pkg.Symbol"];
    expect(entry.bound).toBe(false);
    expect(entry.errorType).toBe("TypeError");
    expect(entry.error).toContain("not a constructor");
  });

  test("the three causes are distinguishable", () => {
    // The whole point: these used to be one indistinguishable silent skip.
    const notInstalled = new Error("Cannot find module '@vendor/pkg'");
    (notInstalled as NodeJS.ErrnoException).code = "MODULE_NOT_FOUND";
    recordBinding("a", "s", notInstalled);
    recordBinding("b", "s", new Error("@vendor/pkg resolved but exports no Client class"));
    recordBinding("c", "s", new Error("Cannot find module 'transitive-dep'"));
    const byIntegration = Object.fromEntries(
      unboundSymbols().map((u) => [u.integration, u]),
    );
    expect(byIntegration.a.error).toContain("@vendor/pkg");
    expect(byIntegration.b.error).toContain("no Client class");
    expect(byIntegration.c.error).toContain("transitive-dep");
  });

  test("a non-Error failure is still recorded", () => {
    recordBinding("demo", "pkg.Symbol", "resolver returned a string");
    const entry = integrationBindings().demo["pkg.Symbol"];
    expect(entry.bound).toBe(false);
    expect(entry.errorType).toBe("string");
    expect(entry.error).toContain("resolver returned a string");
  });

  test("recording never throws", () => {
    class Hostile extends Error {
      get message(): string {
        throw new Error("boom");
      }
    }
    expect(() => recordBinding("demo", "pkg.Symbol", new Hostile())).not.toThrow();
    // Recorded as a failure even though the message was unrenderable - a
    // bind that failed must never leave no trace.
    const entry = integrationBindings().demo["pkg.Symbol"];
    expect(entry.bound).toBe(false);
    expect(entry.errorType).toBe("Hostile");
  });

  test("the report is a copy, not a live view", () => {
    recordBinding("demo", "pkg.Symbol");
    const report = integrationBindings();
    report.demo["pkg.Symbol"].bound = false;
    expect(integrationBindings().demo["pkg.Symbol"].bound).toBe(true);
  });
});

describe("package surface", () => {
  test("integrationBindings and unboundSymbols are exported from the index", () => {
    expect(sdk.integrationBindings).toBe(integrationBindings);
    expect(sdk.unboundSymbols).toBe(unboundSymbols);
    expect(sdk.requiredBindingFailures).toBe(requiredBindingFailures);
    expect(sdk.assertRequiredBindings).toBe(assertRequiredBindings);
  });
});

describe("required binding assertions", () => {
  test("passes only after every required integration reports bound", () => {
    recordBinding("openai", "openai.OpenAI");
    recordBinding("langchain", "langchain_core.callbacks.BaseCallbackHandler");

    expect(requiredBindingFailures(["openai", "langchain"])).toEqual([]);
    expect(() => assertRequiredBindings(["openai", "langchain"])).not.toThrow();
  });

  test("distinguishes a missing integration from an unbound symbol", () => {
    recordBinding(
      "langchain",
      "langchain_core.callbacks.BaseCallbackHandler",
      new TypeError("symbol moved"),
    );

    expect(requiredBindingFailures(["openai", "langchain"])).toEqual([
      { integration: "openai", symbol: "", reason: "missing" },
      {
        integration: "langchain",
        symbol: "langchain_core.callbacks.BaseCallbackHandler",
        reason: "unbound",
        errorType: "TypeError",
        error: "symbol moved",
      },
    ]);
  });

  test("throws a typed error carrying a defensive copy of every failure", () => {
    expect(() => assertRequiredBindings(["openai"])).toThrow(RequiredBindingsError);
    try {
      assertRequiredBindings(["openai"]);
    } catch (error) {
      expect(error).toBeInstanceOf(RequiredBindingsError);
      const typed = error as RequiredBindingsError;
      expect(typed.failures).toEqual([
        { integration: "openai", symbol: "", reason: "missing" },
      ]);
      typed.failures[0].integration = "mutated";
      expect(requiredBindingFailures(["openai"])[0].integration).toBe("openai");
    }
  });

  test("deduplicates requirements and refuses blank names", () => {
    expect(requiredBindingFailures(["openai", "openai"])).toHaveLength(1);
    expect(() => requiredBindingFailures([" "])).toThrow(TypeError);
  });
});

describe("the MCP auto-patch records every exit of its resolve path", () => {
  test("patchMCP leaves a binding entry whether or not the SDK resolved", () => {
    // Under this test runner the module system decides which exit runs
    // (require may be unavailable under ESM); the invariant is that EVERY
    // exit records - a silent skip is the state the report exists to name.
    init({ api_key: "test-key", sample_rate: 1 });
    _resetPatchMCPDeprecationWarning();
    const originalWarn = console.warn;
    console.warn = () => undefined; // the deprecation warning is not under test
    try {
      patchMCP(getConfig());
    } finally {
      console.warn = originalWarn;
    }
    const entry =
      integrationBindings().mcp?.["@modelcontextprotocol/sdk/client.Client"];
    expect(entry).toBeDefined();
    if (!entry!.bound) {
      // Unbound must always say why, with the exception type.
      expect(entry!.errorType).toBeTruthy();
      expect(entry!.error).toBeTruthy();
    }
  });
});
