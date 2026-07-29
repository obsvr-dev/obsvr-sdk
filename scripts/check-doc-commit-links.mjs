#!/usr/bin/env node
/**
 * Every commit hash a tracked document names must resolve to an ancestor of
 * HEAD.
 *
 * Why this exists: this branch's history was rewritten twice, and every hash
 * written by a commit ON the branch died with the rewrite while the prose
 * around it stayed correct. The result reads perfectly — a changelog entry
 * with a tidy `([`abc1234`](.../commit/abc1234))` backlink — and 404s the
 * moment anyone follows it. Nothing else in CI looks at these, because they
 * are prose to every other check.
 *
 * The test is ancestry, not existence. A commit can sit in the local object
 * database (dangling, reachable only through the reflog) and still be absent
 * from what gets pushed, so `git cat-file -t` passing proves nothing. The
 * predecessors of a rewrite fail exactly that way.
 *
 * REQUIRES FULL HISTORY. Under `actions/checkout` at its default depth of 1
 * there are no ancestors to find, so the job that runs this sets
 * `fetch-depth: 0`. A shallow clone FAILS here rather than skipping: a guard
 * that cannot see history must not report that history is fine, and someone
 * dropping the fetch-depth line is precisely how this would rot back into a
 * check that passes without checking anything.
 *
 * Fixing a failure: if the commit survived a rewrite it kept its tree, so
 * `git log --format='%H %T' HEAD` finds the successor by tree. Repoint the
 * link at that. If the content moved, point at where it moved. If neither,
 * delete the backlink and keep the prose — a dead link is worse than none.
 * Never substitute a hash you have not resolved.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const git = (args) =>
  execFileSync("git", args, { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim();

// Two tiers, because "is this token a hash?" is only answerable sometimes.
//
// TIER A — unambiguous references. A `…/commit/<hash>` URL, or a backtick span
// whose FIRST token is a hash (`abc1234`, or `abc1234 Some subject line` — the
// shape a generated commit list uses). These are hash references by
// construction, so they must exist AND be ancestors. An earlier version of
// this file matched only whole-span backticks and so walked straight past
// `abc1234 Some subject`, which is how five dead references survived a sweep.
const TIER_A = [
  /commit\/([0-9a-f]{7,40})\b/g,
  /`([0-9a-f]{7,40})(?:[ \n][^`]*)?`/g,
];
// TIER B — a bare hex token loose in prose. Might be a hash, might be a
// truncated digest (`corpus_sha256 = 1120116f…`) or a plain number. Judged only
// if git resolves it to a commit: a token that is not an object at all is
// ignored, because nothing distinguishes a dead hash from a number here. That
// is a real limit, and it is why writing a hash as a bare token is discouraged
// — tier A is the shape that gets checked properly.
const TIER_B = /(?<![0-9a-zA-Z`/])([0-9a-f]{7,40})(?![0-9a-zA-Z`])/g;

if (git(["rev-parse", "--is-shallow-repository"]) === "true") {
  console.error("✗ shallow clone — ancestry is unknowable here, so this guard cannot run.");
  console.error("  Check out with fetch-depth: 0 (or `git fetch --unshallow`) and re-run.");
  process.exit(1);
}

const files = git(["ls-files"]).split("\n").filter((f) => f.endsWith(".md"));

const refs = [];
for (const file of files) {
  const lines = readFileSync(file, "utf-8").split("\n");
  lines.forEach((line, idx) => {
    const strict = new Set();
    for (const pattern of TIER_A) {
      for (const m of line.matchAll(pattern)) strict.add(m[1]);
    }
    const loose = new Set();
    for (const m of line.matchAll(TIER_B)) if (!strict.has(m[1])) loose.add(m[1]);
    for (const [set, tier] of [[strict, "A"], [loose, "B"]]) {
      for (const hash of set) {
        if (hash.length === 64) continue; // a full sha256 is never a commit ref
        refs.push({ file, line: idx + 1, hash, tier });
      }
    }
  });
}

const verdicts = new Map();
for (const { hash, tier } of refs) {
  if (verdicts.has(hash)) continue;
  let type = "";
  try {
    type = git(["cat-file", "-t", hash]);
  } catch {
    // Tier A said this is a reference, so a missing object is a dead one.
    // Tier B cannot tell a dead hash from a number, so it stays quiet.
    verdicts.set(
      hash,
      tier === "A"
        ? { ok: false, why: "no such object in this repository" }
        : { ok: true, why: "not an object — treated as prose, not a hash" },
    );
    continue;
  }
  if (type !== "commit") {
    // Not a commit hash at all — a blob or tree id quoted in prose. Not this
    // guard's business; only commit references can rot into a dead link.
    verdicts.set(hash, { ok: true, why: `${type}, not a commit — skipped` });
    continue;
  }
  try {
    git(["merge-base", "--is-ancestor", hash, "HEAD"]);
    verdicts.set(hash, { ok: true, why: git(["log", "-1", "--format=%s", hash]) });
  } catch {
    verdicts.set(hash, {
      ok: false,
      why: `exists but is NOT an ancestor of HEAD (${git(["log", "-1", "--format=%s", hash])})`,
    });
  }
}

const broken = refs.filter(({ hash }) => !verdicts.get(hash).ok);
if (broken.length > 0) {
  console.error(`✗ ${broken.length} dead commit reference(s) in tracked docs:\n`);
  for (const { file, line, hash } of broken) {
    console.error(`  ${file}:${line}  ${hash} — ${verdicts.get(hash).why}`);
  }
  console.error("\nRepoint by tree, or delete the backlink and keep the prose.");
  console.error("Never substitute a hash you have not resolved.");
  process.exit(1);
}

const distinct = verdicts.size;
console.log(
  `✓ ${refs.length} commit reference(s) across ${distinct} distinct hashes in ` +
    `${files.length} tracked docs — every one an ancestor of HEAD`,
);
