#!/usr/bin/env node
/**
 * fail a publish (or CI) if the version is not identical across every
 * source of truth, so a release can never encode a self-contradictory version.
 *
 * Checks: sdk/package.json .version  ==  sdk/src/constants.ts SDK_VERSION
 *         ==  sdk-python/obsvr/_version.py __version__
 *
 * Optionally, when a release TAG is provided (env TAG, or the GITHUB_REF_NAME
 * on a tag push), the tag's version must match too. Accepted tag shapes:
 *   v<ver>, sdk-v<ver>, sdk-python-v<ver>  (e.g. sdk-v0.9.0).
 *
 * Exit 0 = consistent; exit 1 = mismatch (with a diff printed).
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(root, p), "utf8");
const fail = (msg) => {
  console.error(`✗ version check FAILED: ${msg}`);
  process.exit(1);
};

const pkg = JSON.parse(read("sdk/package.json")).version;

const constantsMatch = read("sdk/src/constants.ts").match(
  /SDK_VERSION\s*=\s*['"]([^'"]+)['"]/,
);
if (!constantsMatch) fail("could not find SDK_VERSION in sdk/src/constants.ts");
const constants = constantsMatch[1];

const versionPyMatch = read("sdk-python/obsvr/_version.py").match(
  /__version__\s*=\s*['"]([^'"]+)['"]/,
);
if (!versionPyMatch) fail("could not find __version__ in sdk-python/obsvr/_version.py");
const versionPy = versionPyMatch[1];

const sources = {
  "sdk/package.json": pkg,
  "sdk/src/constants.ts (SDK_VERSION)": constants,
  "sdk-python/obsvr/_version.py (__version__)": versionPy,
};

const distinct = [...new Set(Object.values(sources))];
if (distinct.length !== 1) {
  for (const [k, v] of Object.entries(sources)) console.error(`   ${v}\t${k}`);
  fail(`versions disagree: found ${JSON.stringify(distinct)}`);
}
const version = distinct[0];

// Optional tag check.
const tag = process.env.TAG || (process.env.GITHUB_REF_TYPE === "tag" ? process.env.GITHUB_REF_NAME : "");
if (tag) {
  const tagVersion = tag.replace(/^(sdk-python-v|sdk-v|v)/, "");
  if (tagVersion !== version) {
    fail(`tag "${tag}" (=> ${tagVersion}) does not match source version ${version}`);
  }
  console.log(`✓ version ${version} consistent across all sources and matches tag "${tag}"`);
} else {
  console.log(`✓ version ${version} consistent across all sources`);
}
