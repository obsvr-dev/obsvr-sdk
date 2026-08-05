#!/usr/bin/env node
/**
 * Every link a tracked document names must resolve for the reader who will
 * follow it. Two checks, because a document has two kinds of link that rot in
 * two different ways.
 *
 * ── 1. COMMIT REFERENCES ────────────────────────────────────────────────────
 *
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
 *
 * ── 2. FILE REFERENCES ──────────────────────────────────────────────────────
 *
 * A relative link must point at a file that is in the tree, AND the two README
 * files that ship inside a package may not use one at all.
 *
 * The second half is the one that needed a guard. `sdk-typescript/README.md` and
 * `sdk-python/README.md` are the packages' declared readmes, so they are
 * rendered where the repository is not: PyPI renders the long description
 * standalone with no base URL, so `](../SECURITY.md)` 404s for certain, and
 * npm's rewriting above the package directory cannot be relied on. Ten links of
 * that shape shipped in those two files. On GitHub — where they were written and
 * reviewed — every one of them worked, which is exactly why nothing caught it.
 *
 * The root README is deliberately NOT in that set. It is not shipped by either
 * package (`files` in package.json, `readme` in pyproject.toml), so it is only
 * ever rendered by GitHub, where a repo-relative link is the correct spelling
 * and an absolute one would pin readers to `main` from a tag. It gets the
 * target-exists check and nothing more.
 *
 * The published set is checked against the manifests rather than trusted, so a
 * third package, or a readme pointed somewhere else, cannot leave this list
 * silently stale.
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

// ── 2. FILE REFERENCES ───────────────────────────────────────────────────────

/**
 * Where a link out of a published README has to point instead. `blob/main`
 * rather than a tag: one release train, and a reader following a link from an
 * installed package wants the current document, not the one that shipped.
 */
const REPO_BLOB = "https://github.com/obsvr-dev/obsvr-sdk/blob/main";

/** Repo-root-relative path for `target` written inside `dir`, or null if it escapes. */
function resolveRepoPath(dir, target) {
  const parts = [];
  for (const segment of `${dir}/${target}`.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (parts.length === 0) return null;
      parts.pop();
      continue;
    }
    parts.push(segment);
  }
  return parts.join("/");
}

/**
 * The READMEs that ship inside a package, and the manifest key that says so.
 * Verified below rather than asserted: a package that stops shipping its readme,
 * or a third one that starts, must move this list rather than slip past it.
 */
const PUBLISHED_READMES = [
  {
    file: "sdk-typescript/README.md",
    manifest: "sdk-typescript/package.json",
    // npm ships what `files` allows; the readme is included by name.
    declares: (raw) => (JSON.parse(raw).files ?? []).includes("README.md"),
    where: "npm",
  },
  {
    file: "sdk-python/README.md",
    manifest: "sdk-python/pyproject.toml",
    // PyPI renders whatever `readme` points at as the long description.
    declares: (raw) => /^\s*readme\s*=\s*"README\.md"\s*$/m.test(raw),
    where: "PyPI",
  },
];

const manifestProblems = PUBLISHED_READMES.filter(
  (p) => !p.declares(readFileSync(p.manifest, "utf-8")),
);
if (manifestProblems.length > 0) {
  console.error("✗ the published-readme list no longer matches the manifests:\n");
  for (const p of manifestProblems) {
    console.error(`  ${p.manifest} no longer declares ${p.file} as the package readme.`);
  }
  console.error(
    "\nThe absolute-link rule below applies to whatever a package actually ships.",
  );
  console.error("Update PUBLISHED_READMES in this file to match, then re-run.");
  process.exit(1);
}
const publishedByFile = new Map(PUBLISHED_READMES.map((p) => [p.file, p]));

/** Markdown link targets, ignoring anything inside a fenced code block. */
function linkTargets(text) {
  const out = [];
  let fenced = false;
  text.split("\n").forEach((line, idx) => {
    if (/^\s*(```|~~~)/.test(line)) {
      fenced = !fenced;
      return;
    }
    if (fenced) return;
    // Inline `](target)` / `](target "title")`, and reference definitions.
    for (const m of line.matchAll(/\]\(\s*([^)\s]+)(?:\s+"[^"]*")?\s*\)/g)) {
      out.push({ target: m[1], line: idx + 1 });
    }
    const ref = /^\[[^\]]+\]:\s*(\S+)/.exec(line);
    if (ref) out.push({ target: ref[1], line: idx + 1 });
  });
  return out;
}

const ABSOLUTE = /^(https?:|mailto:|tel:|ftp:)/i;
const trackedPaths = new Set(git(["ls-files"]).split("\n"));
const linkProblems = [];

for (const file of files) {
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : "";
  const published = publishedByFile.get(file);

  for (const { target, line } of linkTargets(readFileSync(file, "utf-8"))) {
    if (ABSOLUTE.test(target) || target.startsWith("#")) continue;

    if (published) {
      linkProblems.push({
        file,
        line,
        target,
        why:
          `relative link in a README that ${published.where} renders standalone — ` +
          `there is no repository around it, so this resolves to nothing`,
        fix: `write it absolute: ${REPO_BLOB}/${resolveRepoPath(dir, target)}`,
      });
      continue;
    }

    // Everything else is read on GitHub, where relative is correct — but the
    // target still has to be there.
    const path = target.split("#")[0].replace(/\/$/, "");
    if (path === "") continue;
    const resolved = resolveRepoPath(dir, path);
    if (resolved === null) {
      linkProblems.push({ file, line, target, why: "escapes the repository root", fix: "" });
      continue;
    }
    // A directory link is satisfied by anything tracked beneath it.
    const isDir = [...trackedPaths].some((p) => p.startsWith(`${resolved}/`));
    if (!trackedPaths.has(resolved) && !isDir) {
      linkProblems.push({
        file,
        line,
        target,
        why: "no such tracked file or directory",
        fix: "point at where the content moved, or drop the link",
      });
    }
  }
}

if (linkProblems.length > 0) {
  console.error(`\n✗ ${linkProblems.length} broken file reference(s) in tracked docs:\n`);
  for (const p of linkProblems) {
    console.error(`  ${p.file}:${p.line}  ${p.target} — ${p.why}`);
    if (p.fix) console.error(`      ${p.fix}`);
  }
  process.exit(1);
}

console.log(
  `✓ file references resolve, and the ${PUBLISHED_READMES.length} published ` +
    `READMEs carry no relative link`,
);
