#!/usr/bin/env node
/**
 * Hash-pin the conformance corpus, and verify the pin in CI.
 *
 * conformance/ is the single authority for cross-language behavior. The
 * failure mode it has already suffered is not a wrong fixture but a FORKED
 * one: a copy drifts, both copies keep passing their own suites, and the
 * "shared" contract silently stops being shared. A hash pin makes that loud -
 * a stale or forked copy fails a check instead of passing quietly.
 *
 * Three artifacts, one command:
 *   conformance/MANIFEST.sha256   per-file sha256 of every corpus file, sorted
 *   sdk-typescript/conformance.pin           the corpus hash, committed by the TS consumer
 *   sdk-python/conformance.pin    the corpus hash, committed by the Py consumer
 *
 * Usage:
 *   node scripts/generate-conformance-manifest.mjs           regenerate all three
 *   node scripts/generate-conformance-manifest.mjs --check    verify, exit 1 on drift
 *
 * --check also enforces the coverage rule: every fixture must have an in-repo
 * consumer, or live where its consumer lives. A fixture nothing reads is not a
 * contract, it is a file.
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, relative, sep } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const CONFORMANCE_DIR = join(root, "conformance");
const MANIFEST_PATH = join(CONFORMANCE_DIR, "MANIFEST.sha256");
const PIN_PATHS = [join(root, "sdk-typescript", "conformance.pin"), join(root, "sdk-python", "conformance.pin")];
const TEST_DIRS = [join(root, "sdk-typescript", "tests"), join(root, "sdk-python", "tests")];

/**
 * Fixtures with no in-repo consumer, each with the reason it is exempt. An
 * entry here is a debt marker, not an escape hatch: it names where the fixture
 * is going, so the exemption ends rather than accumulating.
 */
const COVERAGE_EXEMPT = new Map([
  [
    "effective_policy.json",
    "Executed by the platform repo's ingest suite, not by either SDK (see its own description). " +
      "Flagged for relocation next to that consumer; delete this exemption when it moves.",
  ],
]);

const manifestHeader = (hash) => `# Conformance corpus manifest - the hash pin of the cross-language contract.
#
# GENERATED. Do not hand-edit: run
#   node scripts/generate-conformance-manifest.mjs
# and commit the result.
#
# UPDATE PROTOCOL. A fixture change is a cross-language change, so it lands as
# ONE coordinated commit: edit the fixture, update both language suites,
# regenerate this manifest AND the two pin files (sdk-typescript/conformance.pin,
# sdk-python/conformance.pin), and commit them together. Changing a fixture
# without regenerating fails CI; regenerating without both pins fails CI.
#
# Format: "<sha256>  <path relative to conformance/>", sorted by path.
#
# corpus_sha256 = ${hash}
#   sha256 of the lines below (this header excluded, so editing these comments
#   does not invalidate the pins). This is the value both conformance.pin files
#   must carry.
`;

/** Every corpus file, POSIX-relative to conformance/, sorted deterministically. */
function corpusFiles() {
  const out = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      if (full === MANIFEST_PATH) continue; // the manifest never pins itself
      out.push(relative(CONFORMANCE_DIR, full).split(sep).join("/"));
    }
  };
  walk(CONFORMANCE_DIR);
  // Sort on the POSIX path so the order does not depend on the host separator.
  return out.sort();
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

/** The manifest body: one "<hash>  <path>" line per file, newline-terminated. */
function manifestBody(files) {
  return files.map((p) => `${sha256(readFileSync(join(CONFORMANCE_DIR, p)))}  ${p}\n`).join("");
}

/**
 * The corpus hash pinned by each consumer: sha256 of the manifest BODY, so a
 * change to the header comment (documentation) never invalidates the pins,
 * while any change to a fixture's content or to the file list does.
 */
const corpusHash = (body) => sha256(body);

function pinContents(hash) {
  return `# Hash pin of the shared conformance corpus.
#
# This records the corpus content this package's test suite was written
# against. It must equal the corpus hash in conformance/MANIFEST.sha256, and
# must equal the sibling package's pin. A copy of the corpus that has drifted
# no longer matches, so it fails loudly instead of passing its own suite.
#
# GENERATED: node scripts/generate-conformance-manifest.mjs
corpus_sha256 = ${hash}
`;
}

/** Files under the test directories, read once, for the coverage grep. */
function testCorpus() {
  const texts = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else texts.push(readFileSync(full, "utf8"));
    }
  };
  for (const dir of TEST_DIRS) walk(dir);
  return texts;
}

function checkCoverage(files) {
  const fixtures = files.filter((p) => p.startsWith("fixtures/"));
  const texts = testCorpus();
  const problems = [];
  for (const fixture of fixtures) {
    const base = fixture.slice("fixtures/".length);
    const referenced = texts.some((t) => t.includes(fixture) || t.includes(base));
    const exempt = COVERAGE_EXEMPT.get(base);
    if (!referenced && !exempt) {
      problems.push(`  ${fixture}: no in-repo consumer. Add one, or move the fixture next to its consumer.`);
    }
    if (referenced && exempt) {
      problems.push(`  ${fixture}: now has an in-repo consumer, so its coverage exemption is stale. Delete it from COVERAGE_EXEMPT.`);
    }
  }
  return problems;
}

const check = process.argv.includes("--check");
const files = corpusFiles();
const body = manifestBody(files);
const hash = corpusHash(body);
const wantManifest = manifestHeader(hash) + body;
const wantPin = pinContents(hash);

if (!check) {
  writeFileSync(MANIFEST_PATH, wantManifest);
  for (const p of PIN_PATHS) writeFileSync(p, wantPin);
  console.log(`✓ pinned ${files.length} conformance files`);
  console.log(`  corpus_sha256 = ${hash}`);
  for (const [name, why] of COVERAGE_EXEMPT) console.log(`  note: ${name} is coverage-exempt - ${why}`);
  process.exit(0);
}

const failures = [];
const read = (p) => {
  try {
    return readFileSync(p, "utf8");
  } catch {
    return null;
  }
};

const actualManifest = read(MANIFEST_PATH);
if (actualManifest === null) {
  failures.push("conformance/MANIFEST.sha256 is missing. Run: node scripts/generate-conformance-manifest.mjs");
} else if (actualManifest !== wantManifest) {
  failures.push(
    "conformance/MANIFEST.sha256 does not match the corpus. A fixture changed without regenerating the pin.\n" +
      diff(actualManifest, wantManifest),
  );
}

for (const p of PIN_PATHS) {
  const actual = read(p);
  const rel = relative(root, p).split(sep).join("/");
  if (actual === null) failures.push(`${rel} is missing. Run: node scripts/generate-conformance-manifest.mjs`);
  else if (actual !== wantPin) failures.push(`${rel} does not pin the current corpus (expected corpus_sha256 = ${hash}).`);
}

const coverage = checkCoverage(files);
if (coverage.length) failures.push("fixture coverage rule violated:\n" + coverage.join("\n"));

/** Line-level diff, trimmed, so CI shows what moved rather than two blobs. */
function diff(actual, want) {
  const a = actual.split("\n");
  const b = want.split("\n");
  const lines = [];
  for (let i = 0; i < Math.max(a.length, b.length) && lines.length < 20; i++) {
    if (a[i] !== b[i]) {
      if (a[i] !== undefined) lines.push(`   - ${a[i]}`);
      if (b[i] !== undefined) lines.push(`   + ${b[i]}`);
    }
  }
  return lines.join("\n");
}

if (failures.length) {
  console.error("✗ conformance pin check FAILED");
  for (const f of failures) console.error(` - ${f}`);
  process.exit(1);
}
console.log(`✓ conformance pin verified: ${files.length} files, corpus_sha256 = ${hash}`);
