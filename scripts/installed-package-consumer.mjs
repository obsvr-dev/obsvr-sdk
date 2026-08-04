/**
 * Drive the INSTALLED @obsvr/sdk exactly as an external consumer does.
 *
 * This file is copied out of the repository into a scratch directory whose
 * only dependency is the packed tarball, so every import resolves through
 * node_modules rather than through `src/` or a relative path. The suites that
 * run in CI import from the checkout, so they can say nothing about what
 * `npm install @obsvr/sdk` actually delivers: a subpath export that no longer
 * resolves, a declaration file left out of `files`, a bin entry pointing at a
 * module that was never compiled are all invisible there and total for the
 * caller.
 *
 * WHAT MAKES A PASS MEAN SOMETHING. A refusal check can go green for the wrong
 * reason: if the import fails, or the config is rejected, the governed call
 * also does not happen, and a naive "the payload did not run" assertion reads
 * that as perfect enforcement. Four things rule that out, each a hard failure:
 *
 *   1. the package is located and proven to resolve out of node_modules;
 *   2. an ALLOWED tool runs first and must write exactly one marker line and
 *      return its payload to the caller — the positive control that proves the
 *      instrument, the config and the governor are all live;
 *   3. the DENIED tool must refuse with the SDK's own block, never with a
 *      module-resolution or type error;
 *   4. the refusal must be on the record — the blocked audit event is
 *      collected from a loopback ingest sink and graded TOOL_DENIED there.
 *
 * THE INSTRUMENT IS THE TOOL'S OWN SIDE EFFECT, in the style the integration
 * drivers use: the tool appends a line to a marker file and returns a secret
 * string. Both halves are checked, because they fail differently — a swallowed
 * error can produce zero executions while the caller still holds the payload,
 * and that reads as a perfect refusal if only the line count is checked.
 *
 * Exit code 0 on success; 1 with a diagnosis on any failure.
 */

import { fileURLToPath } from "node:url";
import { createServer } from "node:http";
import { appendFileSync, existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";

const DENIED_TOOL = "write_marker";
const ALLOWED_TOOL = "write_marker_benign";
const SECRET = "SECRET-PAYLOAD-42";

// Every name the READMEs teach a first-time caller to reach for, plus the
// subpath exports a consumer is told to import. A tarball that resolves but no
// longer carries these is broken for its documented usage.
const REQUIRED_PUBLIC_NAMES = [
  "obsvr",
  "obsvrGovernTool",
  "obsvrGovernTools",
  "obsvrGovernMCP",
  "patchMCP",
  "useSubject",
  "agentRun",
  "withSpan",
  "verifyAuditChain",
  "ObsvrPolicyError",
  "ReasonCode",
  "explain",
  "defineConfig",
];
const REQUIRED_SUBPATHS = ["@obsvr/sdk/register", "@obsvr/sdk/mcp", "@obsvr/sdk/proxy"];

const failures = [];
function check(label, ok, detail = "") {
  console.log(`  [${ok ? "ok  " : "FAIL"}] ${label}${detail ? `  (${detail})` : ""}`);
  if (!ok) failures.push(label + (detail ? ` — ${detail}` : ""));
  return ok;
}
function fatal(message) {
  console.error(`\nINSTALL-PATH CHECK FAILED: ${message}`);
  process.exit(1);
}

/** Execution count, read off the instrument rather than inferred. */
function writes(marker) {
  if (!existsSync(marker)) return 0;
  return readFileSync(marker, "utf8").split("\n").filter(Boolean).length;
}

/** An `execute`-shaped tool object, the shape the tool-calling frameworks
 *  produce. Its body is the instrument: one appended line per execution. */
function markerTool(name, marker) {
  return {
    name,
    description: "appends one line per invocation",
    execute(note) {
      appendFileSync(marker, `invoked: ${JSON.stringify(note)}\n`, "utf8");
      return SECRET;
    },
  };
}

async function main() {
  console.log("Installed-package consumer check (TypeScript)");
  console.log(`  runtime: node ${process.versions.node}`);
  console.log(`  working dir: ${process.cwd()}`);

  const repoRoot = process.env.OBSVR_REPO_ROOT || "";
  if (repoRoot && process.cwd().startsWith(repoRoot + path.sep)) {
    fatal(
      `this check runs from a directory outside the repository; cwd ${process.cwd()} is inside ${repoRoot}`,
    );
  }

  // 1) Import. A resolution failure here is the packaging defect, so it is
  // reported as one rather than allowed to look like a refusal further down.
  let sdk;
  try {
    sdk = await import("@obsvr/sdk");
  } catch (err) {
    fatal(`the installed package does not import: ${err && err.code ? err.code + ": " : ""}${err}`);
  }

  // 2) Provenance. The package under test has to be the INSTALLED one.
  // Resolved through the ESM resolver, because the package publishes only an
  // `import` condition in its export map — `require.resolve` cannot see it.
  const entry = fileURLToPath(import.meta.resolve("@obsvr/sdk"));
  const nodeModules = path.join(process.cwd(), "node_modules") + path.sep;
  check("@obsvr/sdk resolves from node_modules, not a checkout", entry.startsWith(nodeModules), entry);
  check(
    "the entry point is the compiled artifact, never TypeScript source",
    entry.endsWith(".js") && !entry.includes(`${path.sep}src${path.sep}`),
    path.basename(entry),
  );
  if (repoRoot) {
    check("the resolved entry point is outside the repository", !entry.startsWith(repoRoot + path.sep));
  }

  const installedRoot = path.join(process.cwd(), "node_modules", "@obsvr", "sdk");
  const manifest = JSON.parse(readFileSync(path.join(installedRoot, "package.json"), "utf8"));
  const expected = process.env.OBSVR_EXPECTED_VERSION || "";
  if (expected) {
    check(
      "installed version matches the version in the tree",
      manifest.version === expected,
      `installed=${manifest.version} tree=${expected}`,
    );
  }

  // 3) Artifacts only the packed tarball can be missing.
  check(
    "type declarations ship alongside the entry point",
    existsSync(path.join(installedRoot, "dist", "index.d.ts")),
  );
  const missingBins = Object.entries(manifest.bin || {})
    .filter(([, rel]) => !existsSync(path.join(installedRoot, rel)))
    .map(([name]) => name);
  check("every declared bin points at a shipped file", missingBins.length === 0, `missing=${missingBins}`);

  // 4) The documented public surface, and the subpath exports with it: an
  // export map entry that stops resolving fails only here.
  const missing = REQUIRED_PUBLIC_NAMES.filter((n) => sdk[n] === undefined);
  check("every documented public name is importable from @obsvr/sdk", missing.length === 0, `missing=${missing}`);
  if (missing.length) fatal("the installed package no longer exports its documented surface");

  const unresolvable = [];
  for (const subpath of REQUIRED_SUBPATHS) {
    try {
      await import(subpath);
    } catch (err) {
      unresolvable.push(`${subpath} (${err && err.code ? err.code : err})`);
    }
  }
  check("every documented subpath export resolves", unresolvable.length === 0, `failed=${unresolvable}`);

  const { obsvr, obsvrGovernTool, ReasonCode } = sdk;

  // 5) Drive the governed calls against a loopback sink, so the refusal can be
  // asserted on the RECORD as well as on the raise.
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (Array.isArray(body)) received.push(...body);
        else if (body && typeof body === "object") received.push(body);
      } catch {
        /* a body we cannot parse is reported as an absent record below */
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"status":"ok"}');
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  const scratch = mkdtempSync(path.join(tmpdir(), "obsvr-install-check-"));
  const deniedMarker = path.join(scratch, "denied.marker");
  const allowedMarker = path.join(scratch, "allowed.marker");

  obsvr.init({
    apiKey: "install-path-check",
    ingestUrl: `http://127.0.0.1:${port}`,
    sampleRate: 1,
    agentPolicy: { deniedTools: [DENIED_TOOL] },
  });
  check("the SDK reports itself initialized", obsvr.isInitialized() === true);

  // 5a) POSITIVE CONTROL. This is what makes the deny leg mean something: a
  // process where everything throws would pass the deny leg and fail here.
  const allowed = obsvrGovernTool(markerTool(ALLOWED_TOOL, allowedMarker));
  let allowedReturned;
  let allowError = "";
  try {
    allowedReturned = await allowed.execute("control");
  } catch (err) {
    allowError = String(err);
  }
  check(
    "an allowed governed tool executes exactly once",
    writes(allowedMarker) === 1,
    `writes=${writes(allowedMarker)} error=${allowError || "none"}`,
  );
  check("and its payload reaches the caller", allowedReturned === SECRET, `returned=${allowedReturned}`);

  // 5b) THE REFUSAL.
  const denied = obsvrGovernTool(markerTool(DENIED_TOOL, deniedMarker));
  let raised = null;
  let returned;
  try {
    returned = await denied.execute("should never happen");
  } catch (err) {
    raised = err;
  }

  check("a denied governed tool refuses instead of returning", raised !== null, `returned=${returned}`);
  check(
    "the refusal is the SDK's own block, not a module or type error",
    raised instanceof Error &&
      raised.code === undefined &&
      !(raised instanceof TypeError) &&
      !(raised instanceof ReferenceError) &&
      String(raised.message).includes("[obsvr]") &&
      String(raised.message).includes(DENIED_TOOL),
    `raised=${raised && raised.constructor ? raised.constructor.name : typeof raised}: ${raised && raised.message}`,
  );
  check("the denied tool's body never ran", writes(deniedMarker) === 0, `writes=${writes(deniedMarker)}`);
  check(
    "and its payload never reached the caller",
    returned !== SECRET && !String(raised && raised.message).includes(SECRET),
    `returned=${returned}`,
  );

  // 5c) THE RECORD. A refusal nothing recorded is a silence, not a block, and
  // this is where TypeScript's reason code is asserted: the tool gate refuses
  // with a plain Error, so the graded verdict lives only on the event.
  await obsvr.flush(15000);
  await new Promise((resolve) => server.close(resolve));
  const blocked = received.filter((e) => e && e.operation === "tool.policy.tool_blocked");
  check(
    "the installed sender delivered a blocked-tool record",
    blocked.length > 0,
    `events=${received.length} operations=${JSON.stringify([...new Set(received.map((e) => e && e.operation))])}`,
  );
  if (blocked.length) {
    const record = blocked[0];
    check(
      "the record names the denied tool and grades it TOOL_DENIED",
      (record.metadata || {}).tool_name === DENIED_TOOL &&
        record.reason_code === ReasonCode.TOOL_DENIED &&
        record.action_taken === "blocked",
      `tool_name=${(record.metadata || {}).tool_name} reason_code=${record.reason_code} action_taken=${record.action_taken}`,
    );
  }

  if (failures.length) {
    console.error("");
    for (const failure of failures) console.error(`  - ${failure}`);
    fatal(`${failures.length} assertion(s) failed against the installed package`);
  }
  console.log("\nAll assertions passed against the installed package.");
}

main().catch((err) => fatal(`${err && err.stack ? err.stack : err}`));
