#!/usr/bin/env node
/**
 * Differential property test over the two regex engines.
 *
 * A customer `regex` rule is authored ONCE and run by TWO engines, so a rule
 * that matches in one and not the other blocks a call on one SDK and allows it
 * on the other — the same rule, the same input, a different enforcement verdict,
 * with nothing on the record to say so. The SYNTAX half of that split is closed
 * by rejection in both validators (`crossDialectViolation` /
 * `cross_dialect_violation`). The SEMANTIC half — `\d` `\w` `\s` `\b` `$` `.`,
 * which read differently in `re` and `RegExp` and carry no syntactic marker — is
 * closed by normalizing the Python side to ECMAScript's meaning at its one
 * compile call (`_ecmascript_equivalent` in sdk-python/obsvr/safe_regex.py).
 *
 * A fixture pins the cases someone thought of. This runs the CROSS PRODUCT of a
 * pattern corpus and an input corpus through both real matchers and compares
 * every verdict, which is the only formulation under which "one behaviour" is a
 * measurement rather than an assertion. The input corpus is built from the
 * codepoints the two engines were measured to disagree on before the fix —
 * Arabic-Indic digits, `café`, U+0085, U+00A0, U+FEFF, U+2028, a trailing
 * newline, a bare CR — so a regression re-opens a case rather than sliding past
 * an ASCII-only sample.
 *
 * ECMAScript runs in `u` mode so both engines match over Unicode code points.
 * Astral inputs are part of the corpus: removing the flag makes those rows fail
 * immediately. The validators also refuse legacy-JS identity escapes, unmatched
 * brackets/braces, braced codepoint escapes, and surrogate escapes that the two
 * engines cannot compile with one meaning.
 *
 * Usage:  node scripts/check-regex-dialect-parity.mjs
 * Exit 0 when every verdict agrees, 1 on any divergence (with the inputs).
 */

import { execFileSync } from "node:child_process";
import { resolvePython } from "./python-interpreter.mjs";
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DIST = join(REPO, "sdk-typescript/dist/utils/safe-regex.js");
if (!existsSync(DIST)) {
  console.error(`✗ ${DIST} is missing — run \`npm run build\` in sdk-typescript first.`);
  process.exit(1);
}
const { safeRegexTest, validateRegexPattern } = await import(DIST);

/**
 * Patterns. The six semantic families first, then ordinary rules of the shape
 * customers actually write, then the constructs the validator governs — so a
 * change that started REJECTING something portable shows up here too.
 */
const PATTERNS = [
  // \d / \D — Unicode-aware in Python, ASCII in ECMAScript
  "\\d+", "\\D+", "^\\d{3}-\\d{2}-\\d{4}$", "\\d{3}[-. ]?\\d{4}", "[\\d]+", "[^\\d]+",
  // \w / \W
  "\\w+", "\\W+", "^\\w+$", "[\\w]+", "[^\\w]+", "^[\\w.]+@[\\w.]+$", "user[_-]?id",
  // \s / \S — neither Python set equals the ECMAScript one
  "\\s+", "\\S+", "a\\sb", "a\\Sb", "[\\s]", "[^\\s]", "[\\s\\S]", "[^\\s\\S]", "\\s*,\\s*",
  // \b / \B
  "\\bcat\\b", "cat\\b", "\\Bcat", "x\\b", "\\bsecret\\b",
  // $ — Python also matches before a trailing newline
  "secret$", "^secret$", "secret\\b$", "\\d+$",
  // . — ECMAScript excludes all four LineTerminators
  "a.b", "^.$", "^[^a]$", "^.+$", "a.*b", "^.{3}$",
  // ordinary rules, as controls
  "secret", "[a-z]{2,8}", "(?<=USD)\\d+", "\\$[0-9]+\\.[0-9]{2}",
  "(foo|bar)baz", "[A-Z][a-z]+", "wire transfer",
  // constructs the validator REFUSES: both sides must refuse them identically
  "(?P<x>secret)", "(?<x>secret)", "(?i)secret", "a*+b", "(?>a+)b", "\\Asecret",
  "secret\\Z", "\\hello", "\\p{L}+", "a{,3}b", "(?<=USD\\s*)\\d+", "[\\w--[0-9]]",
  "[\\S]", "[a\\S]", "[^\\S]", "(a+)+$", "(a|aa)+",
  // accepted by legacy JS mode but deliberately refused by the shared `u` dialect
  "\\_", "a]b", "a{b", "\\u{1F600}", "\\uD83D",
];

/**
 * Inputs. Every codepoint the two engines were MEASURED to disagree on before
 * the normalization landed, plus enough ordinary text that a match verdict of
 * `false` everywhere would not pass as agreement.
 */
const INPUTS = [
  // Written as \u escapes THROUGHOUT: this file's whole job is to detect a
  // codepoint-level disagreement, so a literal invisible character sitting in
  // the source is one editor away from changing what is measured.
  "", "abc", "123", "secret", "wire transfer", "Hello", "A", "_", "-", " ",
  // \d: Arabic-Indic and Devanagari digits. Python's \d matched these and
  // ECMAScript's did not, so an SSN rule blocked on one SDK and allowed on the
  // other for exactly this input.
  "\u0660\u0661\u0662\u0663", "\u0966\u0967\u0968",
  "\u0660\u0661\u0662-\u0663\u0664-\u0665\u0666\u0667\u0668", "123-45-6789",
  // \w and \b: non-ASCII letters. `x\b` matched inside "x\u00e9" in
  // ECMAScript and not in Python.
  "caf\u00e9", "\u65e5\u672c\u8a9e", "x\u00e9", "x y", "cat", "cats", "concat",
  // \s: every codepoint on either side of the split. U+001C-U+001F and U+0085
  // are Python-only whitespace; U+00A0, U+1680, U+2028, U+202F, U+3000 and
  // U+FEFF are ECMAScript-only.
  "a\u001cb", "a\u0085b", "a\u00a0b", "a\ufeffb", "a\u1680b", "a\u3000b",
  "a\u202fb", "a\tb", "a\u000bb", "a , b", "   ",
  // $: a trailing newline is inside Python's `$` and outside ECMAScript's.
  "secret\n", "secret\n ", "\n", "42\n", "line1\nline2",
  // .: CR and the two Unicode line separators, which ECMAScript's dot excludes
  // and Python's does not.
  "\r", "\u2028", "\u2029", "a\rb", "a\u2029b", "abc\n",
  // Code-point parity: each single-character construct consumes one astral
  // character in both engines. Without JS `u`, these are the historical split.
  "\ud83d\ude00", "a\ud83d\ude00b",
  // ordinary rule inputs
  "USD42", "$19.99", "foobaz", "a@b.co", "user_id", "user-id", "SSN 123-45-6789",
];

const corpus = [];
for (const pattern of PATTERNS) for (const text of INPUTS) corpus.push([pattern, text]);

const tsVerdicts = corpus.map(([pattern, text]) => {
  const verdict = validateRegexPattern(pattern);
  return { ok: verdict.ok, match: verdict.ok ? safeRegexTest(pattern, text) : null };
});

const { python, source } = resolvePython(REPO);
const dir = mkdtempSync(join(tmpdir(), "obsvr-regex-parity-"));
let pyVerdicts;
try {
  const corpusPath = join(dir, "corpus.json");
  writeFileSync(corpusPath, JSON.stringify(corpus));
  const driver = `
import json, sys
sys.path.insert(0, ${JSON.stringify(join(REPO, "sdk-python"))})
from obsvr.safe_regex import safe_regex_search, validate_regex_pattern
out = []
for pattern, text in json.load(open(${JSON.stringify(corpusPath)}, encoding="utf-8")):
    ok, _reason = validate_regex_pattern(pattern)
    out.append({"ok": ok, "match": safe_regex_search(pattern, text) if ok else None})
json.dump(out, open(${JSON.stringify(join(dir, "py.json"))}, "w"))
`;
  execFileSync(python, ["-c", driver], { stdio: ["ignore", "inherit", "inherit"] });
  pyVerdicts = JSON.parse(readFileSync(join(dir, "py.json"), "utf-8"));
} finally {
  rmSync(dir, { recursive: true, force: true });
}

const show = (s) =>
  JSON.stringify(s).replace(/[\u0080-\uffff]/g, (c) =>
    `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );

const validatorSplits = [];
const matchSplits = [];
for (let i = 0; i < corpus.length; i++) {
  const [pattern, text] = corpus[i];
  const ts = tsVerdicts[i];
  const py = pyVerdicts[i];
  if (ts.ok !== py.ok) {
    validatorSplits.push({ pattern, ts: ts.ok, py: py.ok });
  } else if (ts.ok && ts.match !== py.match) {
    matchSplits.push({ pattern, text, ts: ts.match, py: py.match });
  }
}

if (validatorSplits.length > 0 || matchSplits.length > 0) {
  console.error(
    `✗ ${validatorSplits.length} validator and ${matchSplits.length} MATCH ` +
      `divergence(s) across ${corpus.length} pattern/input pairs:\n`,
  );
  for (const d of validatorSplits.slice(0, 20)) {
    console.error(`  validator  ${show(d.pattern)}  ts.ok=${d.ts}  py.ok=${d.py}`);
  }
  for (const d of matchSplits.slice(0, 40)) {
    console.error(
      `  MATCH      ${show(d.pattern)}  on ${show(d.text)}  ts=${d.ts}  py=${d.py}`,
    );
  }
  console.error(
    "\nA rule that matches in one engine and not the other blocks a call on one " +
      "SDK and allows it on the other.",
  );
  process.exit(1);
}

// A corpus that matched nothing would agree perfectly and prove nothing.
const matched = tsVerdicts.filter((v) => v.match === true).length;
const rejected = tsVerdicts.filter((v) => v.ok === false).length / INPUTS.length;
if (matched === 0) {
  console.error("✗ no pattern matched any input — the corpus proves nothing.");
  process.exit(1);
}

console.log(
  `✓ ${corpus.length} pattern/input pairs (${PATTERNS.length} patterns x ` +
    `${INPUTS.length} inputs) agree in both engines — ${matched} matching, ` +
    `${rejected} patterns refused by both validators. Python: ${python} (${source})`,
);
