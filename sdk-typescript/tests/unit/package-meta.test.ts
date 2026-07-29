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
