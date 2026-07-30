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
import { resolvePython, requirePythonModules } from "./python-interpreter.mjs";
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

const { python, source: pythonSource } = resolvePython(REPO);
// hypothesis drives the generated corpus on the Python side. Checking up
// front turns "ModuleNotFoundError" — which reads like a divergence — into a
// message that names the dependency and the interpreter it is missing from.
requirePythonModules(python, pythonSource, ["hypothesis"]);
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

// -- Attribution -------------------------------------------------------------
// A divergence found in a BATCH run is not yet an obsvr finding. Both sides
// parse thousands of documents in one process, so a host parser whose behaviour
// depends on what it parsed earlier will produce a difference that has nothing
// to do with either canonicalizer — and this harness would print
// "canonicalizer parity FAILED", which reads as a parity defect and burns a
// reviewer on every clean checkout.
//
// That is not hypothetical. On V8 14.1.146.11 (Node 25.9.0), parsing an object
// whose second key is a lone backslash poisons a later parse of an object whose
// second key is a lone quote: the second object inherits the first's property
// NAME, so the value binds to a key the document never contained. Reproduced
// here in four lines with no obsvr code in the process, surviving --jitless,
// and NOT present on V8 12.4.254.21 (Node 22.23.1).
//
// So every divergence is re-canonicalized in a FRESH process on each side, where
// the document is the only thing that process parses. Still differs → real, and
// this exits 1. Agrees in isolation → the batch run's own parse history caused
// it, which is a property of the runtime rather than of this repository.
const ISO_TS = join(work, "iso-canonicalize.mjs");
writeFileSync(
  ISO_TS,
  `import { readFileSync } from "node:fs";
import { stableStringify } from ${JSON.stringify(join(REPO, "sdk-typescript/dist/policy/rules.js"))};
const doc = readFileSync(process.argv[2], "utf8").replace(/\\n$/, "");
let v; try { v = JSON.parse(doc); } catch (e) { console.log("!!PARSE_ERROR:" + e.constructor.name); process.exit(0); }
try { console.log(stableStringify(v)); } catch (e) { console.log("!!CANONICALIZE_ERROR:" + e.constructor.name); }
`,
  "utf8",
);

/** Re-canonicalize ONE document in a process that has parsed nothing else. */
function recheckInIsolation(label, d, idx) {
  const one = join(work, `${label}-iso-${idx}.jsonl`);
  const pyOut = join(work, `${label}-iso-${idx}.py.jsonl`);
  writeFileSync(one, d.input + "\n", "utf8");
  const tsIso = execFileSync(process.execPath, [ISO_TS, one], { encoding: "utf8" }).replace(/\n$/, "");
  execFileSync(python, [driver, "canonicalize", one, pyOut], { stdio: "pipe" });
  const pyIso = JSON.parse(readFileSync(pyOut, "utf8").split("\n").filter((l) => l !== "")[0]);
  return { tsIso, pyIso, reproduces: tsIso !== pyIso };
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
  let real = 0;
  let artifacts = 0;
  for (const [label, docs] of corpora) {
    const divergences = compare(label, docs);
    total += docs.length;
    if (divergences.length === 0) {
      console.log(`✓ ${label}: ${docs.length} generated documents canonicalize identically`);
      continue;
    }
    // Group by (ts, py) shape so a thousand instances of one bug read as one
    // bug with an example, not as a thousand lines of scroll.
    const byShape = new Map();
    for (const d of divergences) {
      const key = JSON.stringify([d.ts, d.py]);
      if (!byShape.has(key)) byShape.set(key, { ...d, count: 0 });
      byShape.get(key).count++;
    }
    const shapes = [...byShape.values()].sort((a, b) => b.count - a.count);

    // Attribute BEFORE declaring anything. One re-check per distinct shape.
    let idx = 0;
    for (const s of shapes) {
      try {
        const iso = recheckInIsolation(label, s, idx++);
        s.reproduces = iso.reproduces;
        s.tsIso = iso.tsIso;
        s.pyIso = iso.pyIso;
      } catch (e) {
        // A re-check that cannot run must not silently downgrade a divergence
        // to an artifact: unknown attribution counts as real.
        s.reproduces = true;
        s.recheckError = e instanceof Error ? e.message : String(e);
      }
      if (s.reproduces) real += s.count;
      else artifacts += s.count;
    }

    const realShapes = shapes.filter((s) => s.reproduces);
    const artifactShapes = shapes.filter((s) => !s.reproduces);

    if (realShapes.length > 0) {
      console.error(
        `✗ ${label}: ${realShapes.reduce((n, s) => n + s.count, 0)}/${docs.length} documents diverge and REPRODUCE IN ISOLATION`,
      );
      for (const s of realShapes.slice(0, 15)) {
        console.error(`    input ${s.input}`);
        console.error(`      ts  ${asciiJson(s.ts)}`);
        console.error(`      py  ${asciiJson(s.py)}    (x${s.count})`);
        if (s.recheckError) console.error(`      re-check could not run: ${s.recheckError}`);
      }
      if (realShapes.length > 15) {
        console.error(`    ... and ${realShapes.length - 15} further distinct shapes`);
      }
    }
    if (artifactShapes.length > 0) {
      const n = artifactShapes.reduce((acc, s) => acc + s.count, 0);
      console.warn(
        `! ${label}: ${n}/${docs.length} documents diverged in the BATCH run and canonicalize IDENTICALLY in isolation.`,
      );
      console.warn(
        `  Not a parity defect: the two canonicalizers agree on every one of these when it is the`,
      );
      console.warn(
        `  only document the process parses, so what differed is the host's parse history.`,
      );
      console.warn(`  Runtime: node ${process.version} / v8 ${process.versions.v8}.`);
      for (const s of artifactShapes.slice(0, 5)) {
        console.warn(`    input ${s.input}   (x${s.count})`);
        console.warn(`      batch    ts ${asciiJson(s.ts)}  py ${asciiJson(s.py)}`);
        console.warn(`      isolated ts ${asciiJson(s.tsIso)}  py ${asciiJson(s.pyIso)}`);
      }
      if (artifactShapes.length > 5) {
        console.warn(`    ... and ${artifactShapes.length - 5} further distinct shapes`);
      }
    }
  }

  if (real > 0) {
    console.error(
      `\ncanonicalizer parity FAILED: ${real}/${total} documents diverge and reproduce in isolation (seed ${SEED})`,
    );
    process.exit(1);
  }
  if (artifacts > 0) {
    console.log(
      `✓ canonicalizer parity: ${total} generated documents identical in both languages ` +
        `(${artifacts} batch-only divergence(s) attributed to the runtime, see above)`,
    );
  } else {
    console.log(`✓ canonicalizer parity: ${total} generated documents identical in both languages`);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
