#!/usr/bin/env node
/**
 * obsvr integration + verification test runner (vendored offline group).
 *
 *   node run.mjs offline             # the whole vendored group — what CI runs
 *   node run.mjs list                # list available suites
 *   node run.mjs mcp chain-verify    # a subset, by folder name
 *
 * Each integrations/<name>/test.mjs is a self-contained, readable script that
 * exports `async function run()` returning [{ check, status, detail? }], and
 * exports `const meta = { offline: true }`. You can also run any one on its
 * own, e.g.  node integrations/mcp/test.mjs
 *
 * See README.md: this is a VENDORED COPY of the keyless half of a harness that
 * lives outside this repository, trimmed to the suites that need no provider
 * credential and no network.
 */
import { existsSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { printIntegrationHeader, printChecks, printSummary } from "./lib/report.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const INTEGRATIONS_DIR = join(HERE, "integrations");

// Deterministic ordering, and a DECLARATION of what this group contains.
//
// Every name here must exist on disk: `ordered()` below deliberately keeps an
// ORDER entry that has no directory and reports it MISSING, which fails the
// run. That is the point — a suite that is declared and never written is how a
// whole governance surface disappears from a green summary.
//
// The list therefore holds exactly the vendored suites. The upstream harness
// declares the keyed provider/framework suites here too; they are absent from
// this copy on purpose (they need credentials), so naming them here would fail
// every run rather than skip them.
const ORDER = [
  // ── offline verification suites ──
  "chain-verify",
  "decision-records",
  "normalization-security",
  "reason-codes",
  "rules-suite",
  "quota-escrow",
  "external-backend",
  "execution-tokens",
  "spans",
  "sender-semantics",
  "degraded-mode",
  "streaming",
  "error-paths",
  "concurrency",
  "offline-shims",
  // ── enforcement/signing capabilities (keyless) ──
  "device-seal",
  "require-principal",
  "approval-wait",
  "enforcement-mode",
  "deny-wins",
  "use-subject",
  // ── auto-discovery + the in-memory MCP server ──
  "register-hook",
  "mcp",
];

const _modCache = new Map();

function available() {
  return readdirSync(INTEGRATIONS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name);
}

function exists(name) {
  return existsSync(join(INTEGRATIONS_DIR, name, "test.mjs"));
}

/**
 * Every declared suite plus every on-disk one, in the declared order.
 *
 * ORDER entries are kept even when nothing exists for them on disk. Filtering
 * ORDER down to what happens to be present is how a whole surface disappears
 * from a run: the suite is declared, the directory was never written, and the
 * summary reports cleanly on the suites that remain — a green run over a
 * governance surface nobody tested. The Python runner (py/run.py) got this
 * right first; ported back so a missing suite is reported as MISSING and fails
 * the run, exactly as an unimportable one is reported as DID NOT RUN.
 */
function ordered(names) {
  return ORDER.filter((n) => names.includes(n) || !exists(n)).concat(
    names.filter((n) => !ORDER.includes(n)),
  );
}

/** Import a suite once, caching module or import error. */
async function load(name) {
  if (_modCache.has(name)) return _modCache.get(name);
  let entry;
  if (!exists(name)) {
    entry = { error: `MISSING: declared in ORDER, but no suite at integrations/${name}/test.mjs`, missing: true };
    _modCache.set(name, entry);
    return entry;
  }
  try {
    entry = { mod: await import(join(INTEGRATIONS_DIR, name, "test.mjs")) };
  } catch (e) {
    entry = { error: `import failed: ${e.message}` };
  }
  _modCache.set(name, entry);
  return entry;
}

async function isOffline(name) {
  const { mod } = await load(name);
  return mod?.meta?.offline === true;
}

async function selection(argv) {
  const args = argv.slice(2).filter(Boolean);
  const avail = ordered(available());

  if (args[0] === "list") {
    const rows = [];
    for (const n of avail) {
      if (!exists(n)) rows.push(`  ✗ MISSING   ${n}`);
      else rows.push(`  ${(await isOffline(n)) ? "○ offline " : "· keyed   "} ${n}`);
    }
    console.log(
      "Available suites (○ = runs with no provider key, ✗ = declared but not written):\n" +
        rows.join("\n"),
    );
    process.exit(0);
  }

  if (args.length === 0 || args[0] === "all") return avail;

  if (args[0] === "offline") {
    // A missing suite's offline-ness is unknowable — it has no meta to read.
    // It is included anyway rather than quietly dropped: "not written yet" is
    // exactly the state that must not pass as a clean offline run.
    const out = [];
    for (const n of avail) if (!exists(n) || (await isOffline(n))) out.push(n);
    return out;
  }

  const unknown = args.filter((a) => !avail.includes(a));
  if (unknown.length) {
    console.error(`Unknown suite(s): ${unknown.join(", ")}`);
    console.error(`Available: ${avail.join(", ")}`);
    process.exit(2);
  }
  return avail.filter((n) => args.includes(n));
}

async function main() {
  const chosen = await selection(process.argv);
  const mode = process.argv[2] === "offline" ? "  \x1b[2m(offline group)\x1b[0m" : "";
  console.log(`\n\x1b[1mobsvr integration pipeline test\x1b[0m  \x1b[2m(${chosen.length} suites)\x1b[0m${mode}`);

  const rollup = [];
  for (const name of chosen) {
    printIntegrationHeader(name);
    const { mod, error, missing } = await load(name);
    if (error) {
      console.log(`   \x1b[31m${missing ? "MISSING" : "ERROR"}\x1b[0m  ${error}`);
      rollup.push({ name, error, missing, results: [], ms: 0 });
      continue;
    }
    const start = performance.now();
    try {
      const results = (await mod.run()) ?? [];
      const ms = Math.round(performance.now() - start);
      printChecks(results);
      rollup.push({ name, results, ms });
    } catch (e) {
      const ms = Math.round(performance.now() - start);
      console.log(`   \x1b[31mERROR\x1b[0m  ${e.message}`);
      rollup.push({ name, error: e.message, results: [], ms });
    }
  }

  const ok = printSummary(rollup);
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
