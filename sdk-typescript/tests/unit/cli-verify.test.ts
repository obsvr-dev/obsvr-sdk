/**
 * obsvr-verify CLI: modes, exit codes, and what the success banner claims.
 *
 * Contract of record shared with sdk-python/obsvr/cli_verify.py; byte-level
 * parity over one export is asserted separately by
 * scripts/check-cli-verify-parity.mjs, which drives BOTH binaries. These tests
 * pin the TS side's own behavior.
 *
 * It runs against `dist/`, because that is what `npx obsvr-verify` executes
 * and what a consumer gets. `npm test` runs after `npm run build` in the gate
 * (same arrangement as module-hook-resolution.test.ts).
 *
 * The chain under test comes from conformance/fixtures/signing_vectors.json,
 * not from per-language literals - a CLI that verifies a chain only its own
 * language produced proves nothing about a customer's export.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "path";

const PKG = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..", "..");
const CLI = path.join(PKG, "dist", "cli-verify.js");

function findFixture(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(dir, rel);
    if (existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  throw new Error(`fixture not found upward from ${process.cwd()}: ${rel}`);
}

const vectors = JSON.parse(
  readFileSync(findFixture("conformance/fixtures/signing_vectors.json"), "utf-8"),
);
const API_KEY: string = vectors.api_key;

function chain(): Array<Record<string, unknown>> {
  return vectors.events.map((e: Record<string, unknown>) => ({
    ...e,
    sdk_session_id: vectors.session_id,
  }));
}

let workdir: string;
beforeAll(() => {
  workdir = mkdtempSync(path.join(tmpdir(), "obsvr-cli-verify-test-"));
});
afterAll(() => {
  rmSync(workdir, { recursive: true, force: true });
});

let fileSeq = 0;
function write(value: unknown): string {
  const p = path.join(workdir, `case-${fileSeq++}.json`);
  writeFileSync(p, JSON.stringify(value));
  return p;
}

function run(args: string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf-8" });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

test("dist CLI exists - the gate builds before it tests", () => {
  expect(existsSync(CLI)).toBe(true);
});

describe("exit codes, one per documented outcome", () => {
  test("valid chain, keyless: 0", () => {
    const r = run([write(chain())]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("STRUCTURAL verification passed");
  });

  test("valid chain, --api-key: 0", () => {
    const r = run([write(chain()), "--api-key", API_KEY]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("CONTENT + CHAIN verification passed");
  });

  test("tampered content, --api-key: 1", () => {
    const c = chain();
    c[1].prompt = "tampered";
    const r = run([write(c), "--api-key", API_KEY]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Signature mismatch");
  });

  test("seq gap, keyless: 1", () => {
    const c = chain();
    c[1].seq_no = 5;
    const r = run([write(c)]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("seq_no gap");
  });

  test("usage error: 2", () => {
    expect(run([]).status).toBe(2);
  });
});

describe("the success banner states the preimage boundary", () => {
  // The banner must say what the format-3 preimage covers (content, order,
  // the eight decision/attribution fields) and what it does not (tenant_id
  // and the other fields sealed only by the server countersignature).
  test("names what IS covered and what is NOT", () => {
    const r = run([write(chain()), "--api-key", API_KEY]);
    expect(r.status).toBe(0);
    expect(r.stdout).not.toContain("does NOT cover the decision");
    for (const covered of ["action_taken", "rule_id", "policy_version", "user_id"]) {
      expect(r.stdout).toContain(covered);
    }
    expect(r.stdout).toContain("does NOT cover tenant_id");
    for (const uncovered of ["token", "metadata", "operation", "content_provenance"]) {
      expect(r.stdout).toContain(uncovered);
    }
  });
});
