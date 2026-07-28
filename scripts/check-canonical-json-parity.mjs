#!/usr/bin/env node
/**
 * Differential property test over the two canonicalizers.
 *
 * `stableStringify` (sdk-typescript/src/policy/rules.ts) and `_canonical_json`
 * (sdk-python/obsvr/rules.py) must produce byte-identical output, because
 * policy_version and rules_hash are SHA-256 over that output. A rule set that
 * canonicalizes differently in the two SDKs stamps two different
 * policy_versions on audit events for the same policy, and the whole evidence
 * chain rests on those agreeing.
 *
 * Hand-written vectors are the wrong instrument for a property that has to
 * hold universally, so both languages generate here: fast-check on this side,
 * hypothesis on the Python side (scripts/canonical_json_parity.py). Each
 * generator explores shapes the other does not, and the corpus is JSON TEXT
 * that both languages parse with their own parser -- which is how policy rules
 * actually arrive, and the only formulation under which parse-time divergence
 * (JS rounding an integer past 2^53) is visible at all.
 *
 * Usage:  node scripts/check-canonical-json-parity.mjs [--cases N] [--seed N]
 * Exit 0 when every case agrees, 1 on any divergence (with the inputs).
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import fc from "../sdk-typescript/node_modules/fast-check/lib/fast-check.js";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const { stableStringify } = await import(join(REPO, "sdk-typescript/dist/policy/rules.js"));

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  return i === -1 ? dflt : Number(argv[i + 1]);
};
const CASES = argOf("--cases", 4000);
const SEED = argOf("--seed", 20260727);

// -- Generation (fast-check half) --------------------------------------------
// Emits JSON TEXT. Number literals are generated as text on purpose: "1.0"
// and "1" are the same JS value but different Python values, and that
// distinction only exists before parsing.

const numberText = fc.oneof(
  fc.integer({ min: -9007199254740991, max: 9007199254740991 }).map(String),
  // Past 2^53, where JS loses the value at parse time.
  fc.bigInt({ min: 9007199254740992n, max: 1180591620717411303424n }).map(String),
  fc.bigInt({ min: -1180591620717411303424n, max: -9007199254740992n }).map(String),
  // Whole-valued decimals: identical to an integer in JS, a distinct float in
  // Python.
  fc.integer({ min: -1000000, max: 1000000 }).map((i) => `${i}.0`),
  fc.double({ noNaN: true, noDefaultInfinity: true }).map((d) => {
    const s = String(d);
    return s.includes("e") || s.includes(".") ? s : `${s}.0`;
  }),
  // Exponent forms on both sides of each language's switch-to-exponent
  // threshold (JS: >=1e21 and <1e-6; Python: >=1e16 and <1e-4).
  fc
    .tuple(
      fc.constantFrom("1", "3", "1.5", "9.99", "2.5"),
      fc.integer({ min: 0, max: 320 }),
      fc.constantFrom("+", "-", ""),
    )
    .map(([m, e, sign]) => `${m}e${sign}${e}`),
  fc.constantFrom("-0", "-0.0", "0.0", "1.0", "100.0", "1e16", "1e21", "1e-4",
    "1e-6", "1e-7", "3e-5", "0.00003"),
);

// Characters aimed at where the two string/key handlers can part company: the
// top of the BMP next to an astral character (UTF-16 code-unit order vs code
// point order once keys are sorted), the JS line separators, and controls.
// Written as escapes, never as literals: several of these are invisible
// in a diff, and a reviewer cannot check a character they cannot see.
const CHARS = [
  ..."abzAZ09_-. ",
  "\u00e9", // non-ASCII, emitted raw by both languages
  "\u2028", // LINE SEPARATOR - JSON.stringify leaves this raw in a string
  "\u2029", // PARAGRAPH SEPARATOR - likewise
  "\ud7ff", // last code point below the surrogate block
  "\uffff", // top of the BMP: sorts before an astral key in JS, after it in Python
  "\u{1f600}",
  "\u{10000}",
  "\t",
  "\n",
  '"',
  "\\",
];
const textValue = fc.array(fc.constantFrom(...CHARS), { maxLength: 6 }).map((cs) => cs.join(""));

const scalarText = fc.oneof(
  fc.constantFrom("null", "true", "false"),
  numberText,
  textValue.map((s) => JSON.stringify(s)),
);

const documentText = fc.letrec((tie) => ({
  node: fc.oneof(
    { maxDepth: 3, depthSize: "small" },
    scalarText,
    fc.array(tie("node"), { maxLength: 4 }).map((xs) => `[${xs.join(",")}]`),
    fc
      .array(fc.tuple(textValue, tie("node")), { maxLength: 4 })
      .map((kvs) => {
        const seen = new Map();
        for (const [k, v] of kvs) seen.set(k, v);
        return `{${[...seen].map(([k, v]) => `${JSON.stringify(k)}:${v}`).join(",")}}`;
      }),
  ),
})).node;

function generateCorpus(count, seed) {
  const out = [];
  fc.assert(
    fc.property(documentText, (doc) => {
      if (out.length < count && !/[\n\r]/.test(doc)) out.push(doc);
      return true;
    }),
    { numRuns: count * 2, seed, verbose: false },
  );
  return out.slice(0, count);
}

// -- Comparison --------------------------------------------------------------

/** ASCII-only rendering, so an unpaired surrogate survives the file round-trip
 *  exactly as Python's ensure_ascii output does. */
function asciiJson(s) {
  return JSON.stringify(s).replace(/[\u0080-\uffff]/g, (c) =>
    "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
}

function canonicalizeTs(docs) {
  return docs.map((doc) => {
    let value;
    try {
      value = JSON.parse(doc);
    } catch (e) {
      return `!!PARSE_ERROR:${e.constructor.name}`;
    }
    try {
      return stableStringify(value);
    } catch (e) {
      return `!!CANONICALIZE_ERROR:${e.constructor.name}`;
    }
  });
}

const python = process.env.PYTHON ?? "python3";
const driver = join(REPO, "scripts/canonical_json_parity.py");
const work = mkdtempSync(join(tmpdir(), "obsvr-canon-"));

/** Run one corpus through both languages and return the divergences. */
function compare(label, docs) {
  const corpusPath = join(work, `${label}.jsonl`);
  const pyOutPath = join(work, `${label}.py.jsonl`);
  writeFileSync(corpusPath, docs.join("\n") + "\n", "utf8");
  execFileSync(python, [driver, "canonicalize", corpusPath, pyOutPath], { stdio: "inherit" });

  const pyLines = readFileSync(pyOutPath, "utf8").split("\n").filter((l) => l !== "");
  const tsLines = canonicalizeTs(docs);
  if (pyLines.length !== tsLines.length) {
    throw new Error(`corpus length mismatch: ts=${tsLines.length} py=${pyLines.length}`);
  }

  const divergences = [];
  for (let i = 0; i < docs.length; i++) {
    const py = JSON.parse(pyLines[i]);
    if (tsLines[i] !== py) divergences.push({ input: docs[i], ts: tsLines[i], py });
  }
  return divergences;
}

try {
  const corpora = [];

  corpora.push(["fast-check", generateCorpus(CASES, SEED)]);

  const hypoPath = join(work, "hypothesis.jsonl");
  execFileSync(python, [driver, "generate", String(CASES), hypoPath, String(SEED)], {
    stdio: "inherit",
  });
  corpora.push([
    "hypothesis",
    readFileSync(hypoPath, "utf8").split("\n").filter((l) => l !== ""),
  ]);

  let total = 0;
  let failed = 0;
  for (const [label, docs] of corpora) {
    const divergences = compare(label, docs);
    total += docs.length;
    failed += divergences.length;
    if (divergences.length === 0) {
      console.log(`✓ ${label}: ${docs.length} generated documents canonicalize identically`);
      continue;
    }
    console.error(`✗ ${label}: ${divergences.length}/${docs.length} documents diverge`);
    // Group by (ts, py) shape so a thousand instances of one bug read as one
    // bug with an example, not as a thousand lines of scroll.
    const byShape = new Map();
    for (const d of divergences) {
      const key = JSON.stringify([d.ts, d.py]);
      if (!byShape.has(key)) byShape.set(key, { ...d, count: 0 });
      byShape.get(key).count++;
    }
    const shapes = [...byShape.values()].sort((a, b) => b.count - a.count).slice(0, 15);
    for (const s of shapes) {
      console.error(`    input ${s.input}`);
      console.error(`      ts  ${asciiJson(s.ts)}`);
      console.error(`      py  ${asciiJson(s.py)}    (x${s.count})`);
    }
    if (byShape.size > shapes.length) {
      console.error(`    ... and ${byShape.size - shapes.length} further distinct shapes`);
    }
  }

  if (failed > 0) {
    console.error(
      `\ncanonicalizer parity FAILED: ${failed}/${total} documents diverge (seed ${SEED})`,
    );
    process.exit(1);
  }
  console.log(`✓ canonicalizer parity: ${total} generated documents identical in both languages`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
