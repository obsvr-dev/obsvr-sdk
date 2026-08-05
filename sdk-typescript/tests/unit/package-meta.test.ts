/**
 * Package metadata + README accuracy guards.
 *
 * Locks the pre-launch invariants: the published package is Apache-2.0
 * everywhere (package.json, LICENSE, NOTICE, README), the npm "files"
 * allowlist ships the license files, and the README's "What Gets Governed"
 * section stays in lockstep with the real AUDITABLE_METHODS in
 * src/proxy/wrapper.ts (so a governed-surface change cannot silently
 * leave the docs stale).
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Jest runs with cwd = sdk-typescript/.
const pkg = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf-8"));
const license = readFileSync(join(process.cwd(), "LICENSE"), "utf-8");
const notice = readFileSync(join(process.cwd(), "NOTICE"), "utf-8");
const readme = readFileSync(join(process.cwd(), "README.md"), "utf-8");
const wrapperSrc = readFileSync(join(process.cwd(), "src/proxy/wrapper.ts"), "utf-8");

describe("license normalization (Apache-2.0)", () => {
  it("package.json declares Apache-2.0", () => {
    expect(pkg.license).toBe("Apache-2.0");
  });

  it("LICENSE is the Apache-2.0 text with the Obsvr copyright line", () => {
    expect(license).toContain("Apache License");
    expect(license).toContain("Version 2.0, January 2004");
    expect(license).toContain("Copyright 2026 Obsvr");
    expect(license).not.toContain("MIT License");
  });

  it("NOTICE names the product and copyright", () => {
    expect(notice).toContain("Obsvr SDK");
    expect(notice).toContain("Copyright 2026 Obsvr");
  });

  it('npm "files" allowlist ships LICENSE and NOTICE', () => {
    expect(pkg.files).toContain("LICENSE");
    expect(pkg.files).toContain("NOTICE");
    expect(pkg.files).toContain("README.md");
  });

  it("README license section says Apache-2.0, not MIT", () => {
    expect(readme).toContain("Apache-2.0");
    expect(readme).not.toMatch(/## License\s+MIT/);
  });
});

describe("exports map is reachable", () => {
  // Every subpath must name a build output the compiler actually produces.
  // `wrapOpenAICompatible` shipped for a while with no subpath and no root
  // re-export: the source existed, the README advertised it, and both
  // specifiers raised ERR_PACKAGE_PATH_NOT_EXPORTED. This asserts the shape
  // that makes that state impossible rather than checking the one symbol.
  const subpaths = Object.entries(pkg.exports as Record<string, { import: { types: string; default: string } }>);

  it("declares the ./openai-compat subpath", () => {
    expect(Object.keys(pkg.exports)).toContain("./openai-compat");
  });

  it.each(subpaths)("%s has a src entry file behind its dist target", (subpath, entry) => {
    // ./dist/foo/bar.js is emitted by tsc from src/foo/bar.ts. If no such
    // source exists the target can never be built and the subpath is dead.
    const rel = entry.import.default.replace(/^\.\/dist\//, "").replace(/\.js$/, ".ts");
    expect(existsSync(join(process.cwd(), "src", rel))).toBe(true);
    expect(entry.import.types).toBe(entry.import.default.replace(/\.js$/, ".d.ts"));
  });

  it("the npm files allowlist ships every subpath target", () => {
    // dist/**/*.js and dist/**/*.d.ts cover every target above; assert the
    // globs are present rather than re-deriving them per subpath.
    expect(pkg.files).toContain("dist/**/*.js");
    expect(pkg.files).toContain("dist/**/*.d.ts");
  });
});

describe("README accuracy", () => {
  it("does not reference the removed patchMCPWithClient API", () => {
    expect(readme).not.toContain("patchMCPWithClient");
  });

  it("documents an importable specifier for the OpenAI-compatible wrapper", () => {
    // The README advertises "any OpenAI-compatible API". The wrapper behind
    // that claim shipped once with no subpath and no root re-export, so both
    // specifiers raised ERR_PACKAGE_PATH_NOT_EXPORTED while the docs sold it.
    // Assert the claim, the specifier and the export together.
    expect(readme).toContain("OpenAI-compatible API");
    expect(readme).toContain("wrapOpenAICompatible");
    expect(readme).toContain("@obsvr/sdk/openai-compat");
    expect(Object.keys(pkg.exports)).toContain("./openai-compat");
    const index = readFileSync(join(process.cwd(), "src/index.ts"), "utf-8");
    expect(index).toContain("wrapOpenAICompatible");
  });

  it("documents the real MCP governance API (obsvrGovernMCP)", () => {
    expect(readme).toContain("obsvrGovernMCP");
  });

  it('"What Gets Governed" lists every AUDITABLE_METHODS entry from wrapper.ts', () => {
    // Extract the table literal from source so this test tracks the code,
    // not a hand-maintained copy of it. Each entry is [path, shape]; only the
    // path is documented, so take the first string of each pair.
    const tableMatch = wrapperSrc.match(
      /const AUDITABLE_METHODS = new Map<string, ApiShape>\(\[([\s\S]*?)^\]\);/m,
    );
    expect(tableMatch).not.toBeNull();
    const methods = [...tableMatch![1].matchAll(/\[\s*"([^"]+)"\s*,/g)].map(
      (m) => m[1],
    );
    expect(methods.length).toBeGreaterThanOrEqual(4);
    for (const method of methods) {
      expect(readme).toContain(`\`${method}\``);
    }
  });
});

/**
 * The MCP peer range is a SECURITY bound, and it is asserted as one.
 *
 * It previously read `>=1.0.0 <1.25.0 || >=1.30.0`, which is the inverse of
 * what it was meant to encode: the first clause admitted the whole vulnerable
 * span, and the excluded window `[1.25.0, 1.30.0)` contained exactly the
 * releases that had been PATCHED — so a consumer who upgraded away from the
 * advisories could no longer install this package, and one who had not was
 * waved through.
 *
 * Version literals rather than a re-derived range: the point is to pin the
 * advisory boundaries themselves, so that widening the range to admit a
 * vulnerable release has to fail here and be argued.
 */
describe("the @modelcontextprotocol/sdk peer range excludes the advisory window", () => {
  const range: string = pkg.peerDependencies["@modelcontextprotocol/sdk"];

  /**
   * Minimal matcher for the ONE range shape this bound is allowed to take:
   * `>=A <B`. Anything else throws rather than returning a verdict, so a
   * rewritten range cannot quietly pass this file by being unparseable — the
   * previous range was a two-clause `||` and that is exactly the shape that
   * hid the inversion.
   */
  const num = (v: string) => v.split(".").map(Number);
  const cmp = (a: string, b: string) => {
    const [x, y] = [num(a), num(b)];
    for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
    return 0;
  };
  const satisfies = (v: string): boolean => {
    const m = /^>=(\d+\.\d+\.\d+) <(\d+\.\d+\.\d+)$/.exec(range.trim());
    if (!m) {
      throw new Error(
        `the MCP peer range is no longer a single ">=A <B" bound (${range}). ` +
          "Re-derive it from the advisories and update this test deliberately.",
      );
    }
    return cmp(v, m[1]) >= 0 && cmp(v, m[2]) < 0;
  };

  // Affected by at least one of GHSA-w48q-cv73-mx4w (<1.24.0),
  // GHSA-8r9q-7v3j-jr4g (>=1.3.0 <1.25.2), GHSA-345p-7cg4-v4c7 (<=1.25.3).
  const VULNERABLE = [
    "1.0.0", "1.3.0", "1.10.0", "1.20.0", "1.23.1",
    "1.24.0", "1.24.3", "1.25.0", "1.25.1", "1.25.2", "1.25.3",
  ];
  // Clean of all three.
  const PATCHED = ["1.26.0", "1.27.0", "1.27.1", "1.28.0", "1.29.0", "1.30.0"];

  it.each(VULNERABLE)("refuses %s", (v) => {
    expect(satisfies(v)).toBe(false);
  });

  it.each(PATCHED)("admits %s", (v) => {
    // The other half, and the one the old range failed: a consumer who
    // patched must still be able to install.
    expect(satisfies(v)).toBe(true);
  });

  it("stops below the next major, which has not been driven", () => {
    expect(satisfies("2.0.0")).toBe(false);
  });

  it("the development pin is inside the range it declares", () => {
    const dev: string = pkg.devDependencies["@modelcontextprotocol/sdk"];
    expect(satisfies(dev.replace(/^[\^~]/, ""))).toBe(true);
  });
});

/**
 * The root README's auto-governance claim, held to what the code does.
 *
 * It read "Auto-governed by `init()` alone - TypeScript: OpenAI · Anthropic ·
 * Google Gemini", which is false for TypeScript: `autoInstrument()` patches
 * nothing, and zero-code coverage comes from the `--import` module hook, which
 * must run before the application's own imports resolve. Measured with only
 * `init()`: a call carrying an SSN under a `block` rule reached the provider
 * with the SSN still in the body and emitted zero events.
 *
 * Both halves are asserted, so the pair cannot drift apart: if `init()` ever
 * does install interception, the behavioural row fails and the sentence has to
 * be revisited deliberately rather than left stale.
 */
describe("root README: TypeScript auto-governance", () => {
  const rootReadme = readFileSync(join(process.cwd(), "..", "README.md"), "utf-8");

  it("init() installs no interception on its own", async () => {
    // The PUBLIC entry point, which is what the README tells the reader to
    // call; the lower-level config init() does not run the coverage check.
    const { obsvr } = await import("../../src/index");
    const { _reset } = await import("../../src/proxy/config");
    const { isInterceptionActive, _resetInterception } = await import("../../src/auto/index");
    _reset();
    _resetInterception();
    const warnings: string[] = [];
    const realWarn = console.warn;
    console.warn = (...a: unknown[]) => void warnings.push(a.join(" "));
    try {
      obsvr.init({ apiKey: "k", ingestUrl: "https://x", providers: ["openai"] } as never);
      expect(isInterceptionActive()).toBe(false);
      // And it says so rather than leaving the caller to find out from traffic.
      expect(warnings.join("\n")).toContain("--import @obsvr/sdk/register");
    } finally {
      console.warn = realWarn;
      _reset();
    }
  });

  it("the README sends TypeScript readers to the module interceptor", () => {
    expect(rootReadme).toContain("TypeScript needs the module interceptor");
    expect(rootReadme).toContain("--import @obsvr/sdk/register");
  });

  it("the README does not claim init() alone auto-governs TypeScript", () => {
    // The exact shape of the old claim: the init()-alone line naming
    // TypeScript. Python genuinely does auto-govern on that line and is
    // measured doing so, so the assertion is scoped to that one line rather
    // than to the phrase.
    const line = rootReadme
      .split("\n")
      .find((l) => l.includes("Auto-governed by `init()` alone"));
    expect(line).toBeDefined();
    expect(line).not.toContain("TypeScript");
  });
});
