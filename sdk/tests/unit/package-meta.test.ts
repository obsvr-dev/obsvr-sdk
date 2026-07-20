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
import { readFileSync } from "node:fs";
import { join } from "node:path";

// Jest runs with cwd = sdk/.
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

describe("README accuracy", () => {
  it("does not reference the removed patchMCPWithClient API", () => {
    expect(readme).not.toContain("patchMCPWithClient");
  });

  it("documents the real MCP governance API (obsvrGovernMCP)", () => {
    expect(readme).toContain("obsvrGovernMCP");
  });

  it('"What Gets Governed" lists every AUDITABLE_METHODS entry from wrapper.ts', () => {
    // Extract the set literal from source so this test tracks the code,
    // not a hand-maintained copy of it.
    const setMatch = wrapperSrc.match(
      /const AUDITABLE_METHODS = new Set\(\[([\s\S]*?)\]\)/,
    );
    expect(setMatch).not.toBeNull();
    const methods = [...setMatch![1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    expect(methods.length).toBeGreaterThanOrEqual(4);
    for (const method of methods) {
      expect(readme).toContain(`\`${method}\``);
    }
  });
});
