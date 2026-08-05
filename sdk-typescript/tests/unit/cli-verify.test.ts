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

describe("the keyless tier requires linkage after the first event", () => {
  test("unsigned insertion without prev_sig is detected", () => {
    // An appended event with a plausible seq_no, a well-formed sdk_sig and NO
    // prev_sig is an insertion, and the keyless tier must refuse it: every
    // event after the first has to link to its predecessor.
    const c = chain();
    const last = c[c.length - 1];
    c.push({
      sdk_session_id: vectors.session_id,
      seq_no: (last.seq_no as number) + 1,
      timestamp_sdk: (last.timestamp_sdk as number) + 1,
      prompt: "inserted",
      response: "",
      sdk_sig: "a".repeat(64),
    });
    const r = run([write(c)]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("missing prev_sig");
  });

  test("first event legitimately carries no prev_sig", () => {
    // The chain start is the one position with no predecessor to link to, so
    // an absent prev_sig there is legitimate, not an insertion.
    const c = chain();
    delete c[0].prev_sig;
    const r = run([write(c)]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("STRUCTURAL verification passed");
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

describe("every break in one run, and --json", () => {
  /** Two independent tampers: a content edit at event 0 and a forged
   *  signature at event 1. */
  function twoBreakChain(): Array<Record<string, unknown>> {
    const c = chain();
    c[0].prompt = "tampered";
    c[1].sdk_sig = "0".repeat(64);
    return c;
  }

  test("every break is rendered, not just the first", () => {
    const r = run([write(twoBreakChain()), "--api-key", API_KEY]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("Signature mismatch at event 0 (event index 0)");
    expect(r.stderr).toContain("Signature mismatch at event 1 (event index 1)");
    expect(r.stderr.indexOf("(event index 0)")).toBeLessThan(
      r.stderr.indexOf("(event index 1)"),
    );
  });

  test("--json reports the full break list", () => {
    const r = run([write(twoBreakChain()), "--api-key", API_KEY, "--json"]);
    expect(r.status).toBe(1);
    const doc = JSON.parse(r.stdout);
    expect(doc.mode).toBe("content+chain");
    expect(doc.valid).toBe(false);
    expect(doc.exitCode).toBe(1);
    expect(doc.sessions).toHaveLength(1);
    expect(doc.sessions[0].breaks.map((b: { index: number }) => b.index)).toEqual([0, 1]);
    // First-break fields stay what they always were.
    expect(doc.sessions[0].brokenAt).toBe(0);
    expect(doc.sessions[0].reason).toBe("Signature mismatch at event 0");
  });

  test("--json on a valid keyed chain", () => {
    const r = run([write(chain()), "--api-key", API_KEY, "--json"]);
    expect(r.status).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc.mode).toBe("content+chain");
    expect(doc.valid).toBe(true);
    expect(doc.eventsVerified).toBe(2);
    expect(doc.exitCode).toBe(0);
    expect(doc.sessions[0].breaks).toEqual([]);
  });

  test("--json keyless is the structural tier", () => {
    const r = run([write(chain()), "--json"]);
    expect(r.status).toBe(0);
    const doc = JSON.parse(r.stdout);
    expect(doc.mode).toBe("structural");
    expect(doc.valid).toBe(true);
    expect(doc.events).toBe(2);
    expect(doc.exitCode).toBe(0);
  });

  test("--json keeps exit 3 and the --allow-gaps 3->0 mapping", () => {
    // Exit 3 (valid but incomplete) and the --allow-gaps mapping are the
    // exit-code contract; --json must carry them unchanged.
    const gapFixture = JSON.parse(
      readFileSync(findFixture("conformance/fixtures/audit_gap.json"), "utf-8"),
    );
    const gapChain = gapFixture.signing.events.map((e: Record<string, unknown>) => ({
      ...e,
      sdk_session_id: gapFixture.signing.session_id,
    }));
    const p = write(gapChain);
    const strict = run([p, "--api-key", gapFixture.signing.api_key, "--json"]);
    expect(strict.status).toBe(3);
    const strictDoc = JSON.parse(strict.stdout);
    expect(strictDoc.valid).toBe(true);
    expect(strictDoc.exitCode).toBe(3);

    const allowed = run([
      p,
      "--api-key",
      gapFixture.signing.api_key,
      "--json",
      "--allow-gaps",
    ]);
    expect(allowed.status).toBe(0);
    const allowedDoc = JSON.parse(allowed.stdout);
    expect(allowedDoc.valid).toBe(true);
    expect(allowedDoc.allowGaps).toBe(true);
    expect(allowedDoc.exitCode).toBe(0);
  });
});

describe("an explicitly passed --api-key that carries no key", () => {
  /** A valid chain whose middle event's content has been altered. */
  function tamperedChain(): Array<Record<string, unknown>> {
    const c = chain();
    c[1] = { ...c[1], prompt: "TAMPERED - not what was signed" };
    return c;
  }

  test("an empty value is a usage error, not a silent downgrade", () => {
    // `--api-key "$SECRET"` with the secret unset is the ordinary CI shape.
    // The empty string is falsy, so the run used to fall through to structural
    // verification and exit 0 - on a TAMPERED chain, with the printed text
    // honestly saying "STRUCTURAL". Nothing lied; the exit code, which is the
    // whole interface for the CI use the README recommends, could not tell
    // "verified" from "could not verify".
    const r = run([write(tamperedChain()), "--api-key", ""]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("--api-key was passed with no key");
  });

  test("the flag with no value at all is a usage error", () => {
    // Same failure, other spelling: a dropped variable can leave the flag
    // trailing with nothing after it, which also read as absent.
    const r = run([write(tamperedChain()), "--api-key"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("--api-key was passed with no key");
  });

  test("it is refused before --json can report a pass", () => {
    const r = run([write(tamperedChain()), "--api-key", "", "--json"]);
    expect(r.status).toBe(2);
    // The refusal must not be dressed as a verification document: a consumer
    // parsing stdout must find nothing that reads as a verdict.
    expect(r.stdout.trim()).toBe("");
  });

  test("CONTROL: the absent flag still means structural verification", () => {
    // Without this, the three rows above would also be satisfied by a CLI that
    // had simply stopped accepting keyless runs - which is a documented mode.
    const r = run([write(tamperedChain())]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("STRUCTURAL verification passed");
  });

  test("CONTROL: a real key still detects the tamper", () => {
    // And without THIS, they would be satisfied by a CLI that had stopped
    // verifying anything at all.
    const r = run([write(tamperedChain()), "--api-key", API_KEY]);
    expect(r.status).toBe(1);
  });
});
