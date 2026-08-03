/**
 * The published manifest must point at files tsc actually emits.
 *
 * tsconfig builds with rootDir "." and include ["src","bin","tests"], so the
 * entry lands at dist/src/index.js — NOT dist/index.js. package.json once
 * declared main/types/exports as dist/index.js, so `import { governToolCall }
 * from "@obsvr/claude-code"` resolved to a file that was never emitted and
 * threw ERR_MODULE_NOT_FOUND, while the bin entry (which imports ../src/index.js
 * relative to itself) kept working and hid it. This test pins every manifest
 * target to an on-disk emitted file, imports the declared entry to prove it is
 * the REAL one (not merely a file that happens to exist), and checks the packed
 * tarball ships the library but not the tests. It runs after `npm run build`.
 *
 * No twin: this is a Node/npm packaging contract, not governance behaviour, so
 * it has no Python counterpart (the Python SDK is packaged by pyproject, tested
 * separately). Recorded as such rather than left to look like a parity gap.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test } from "node:test";

const HERE = dirname(fileURLToPath(import.meta.url)); // dist/tests
const PKG_ROOT = resolve(HERE, "..", ".."); // dist/tests -> dist -> package root
const pkg = JSON.parse(readFileSync(join(PKG_ROOT, "package.json"), "utf8"));

const onDisk = (relative: string) => join(PKG_ROOT, relative.replace(/^\.\//, ""));

test("main points to an emitted file", () => {
  const target = onDisk(pkg.main);
  assert.ok(existsSync(target), `main "${pkg.main}" is not an emitted file (${target})`);
});

test("types points to an emitted declaration", () => {
  const target = onDisk(pkg.types);
  assert.ok(existsSync(target), `types "${pkg.types}" is not an emitted file (${target})`);
});

test("every exports target is an emitted file", () => {
  const entry = pkg.exports["."].import;
  for (const key of ["types", "default"] as const) {
    const target = onDisk(entry[key]);
    assert.ok(existsSync(target), `exports["."].import.${key} "${entry[key]}" is not emitted`);
  }
});

test("each bin target is an emitted file", () => {
  for (const [name, rel] of Object.entries(pkg.bin as Record<string, string>)) {
    const target = onDisk(rel);
    assert.ok(existsSync(target), `bin "${name}" -> "${rel}" is not an emitted file`);
  }
});

test("the declared main entry is the real one and exports the public API", async () => {
  const mod = await import(pathToFileURL(onDisk(pkg.main)).href);
  for (const name of ["governToolCall", "denyOutput", "isNativeTool", "toolCallText"]) {
    assert.equal(typeof mod[name], "function", `main entry must export ${name}()`);
  }
});

test("the packed tarball ships the library but not the tests", () => {
  const packed = spawnSync("npm", ["pack", "--dry-run", "--json"], {
    cwd: PKG_ROOT,
    encoding: "utf8",
  });
  assert.equal(packed.status, 0, `npm pack failed: ${packed.stderr}`);
  // npm's shape varies: older versions emit [{ files: [...] }], newer ones a
  // map keyed by package name. Accept either.
  const parsed = JSON.parse(packed.stdout);
  const record = Array.isArray(parsed)
    ? parsed[0]
    : (parsed[pkg.name] ?? Object.values(parsed)[0]);
  const shipped: string[] = record.files.map((f: { path: string }) => f.path);
  assert.ok(
    shipped.includes("dist/src/index.js"),
    "the library entry must be in the tarball",
  );
  const tests = shipped.filter((p) => p.startsWith("dist/tests/"));
  assert.deepEqual(tests, [], `test artifacts must not ship: ${tests.join(", ")}`);
});
