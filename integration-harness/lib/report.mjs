/**
 * Terminal report: a header per integration, the per-check lines each test
 * prints, and a final roll-up. Exit code is 1 if any check failed or an
 * integration errored. SKIP never fails the run.
 */
const C = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

const MARK = {
  pass: `${C.green}PASS${C.reset}`,
  fail: `${C.red}FAIL${C.reset}`,
  skip: `${C.yellow}SKIP${C.reset}`,
};

export function printIntegrationHeader(name) {
  console.log(`\n${C.bold}${C.cyan}▎ ${name}${C.reset}`);
}

export function printChecks(results) {
  for (const r of results) {
    const mark = MARK[r.status] ?? r.status;
    let line = `   ${mark}  ${r.check}`;
    if (r.detail && r.status !== "pass") line += `  ${C.dim}(${r.detail})${C.reset}`;
    console.log(line);
  }
}

export function printSummary(rollup) {
  let pass = 0,
    fail = 0,
    skip = 0,
    errored = 0,
    missing = 0;

  console.log(`\n${C.bold}${"═".repeat(60)}${C.reset}`);
  console.log(`${C.bold}Summary${C.reset}`);
  console.log(`${"─".repeat(60)}`);

  for (const r of rollup) {
    const p = r.results.filter((x) => x.status === "pass").length;
    const f = r.results.filter((x) => x.status === "fail").length;
    const s = r.results.filter((x) => x.status === "skip").length;
    pass += p;
    fail += f;
    skip += s;

    let status;
    if (r.missing) {
      // A suite declared but never written is NOT the same defect as one that
      // fails to import, and reporting both as ERROR loses the only
      // distinction that tells you what to do next: write it, or fix it.
      missing++;
      status = `${C.red}MISSING${C.reset}  ${C.dim}declared in ORDER, no test.mjs${C.reset}`;
    } else if (r.error) {
      errored++;
      status = `${C.red}ERROR${C.reset}  ${C.dim}${r.error}${C.reset}`;
    } else if (s > 0 && p === 0 && f === 0) {
      status = `${C.yellow}SKIP${C.reset}   ${C.dim}${r.results[0]?.detail ?? ""}${C.reset}`;
    } else {
      status = `${f > 0 ? C.red : C.green}${p} pass${C.reset}${f ? `, ${C.red}${f} fail${C.reset}` : ""}`;
    }
    const t = typeof r.ms === "number" ? `${C.dim}${String(r.ms).padStart(6)}ms${C.reset}  ` : "";
    console.log(`  ${r.name.padEnd(24)} ${t}${status}`);
  }

  console.log(`${"─".repeat(60)}`);
  console.log(
    `  ${C.green}${pass} passed${C.reset}, ${fail ? C.red : C.dim}${fail} failed${C.reset}, ${C.yellow}${skip} skipped${C.reset}${errored ? `, ${C.red}${errored} errored${C.reset}` : ""}${missing ? `, ${C.red}${missing} missing${C.reset}` : ""}`,
  );
  // An errored suite DID NOT RUN, and "0 failed" is the part of the line above
  // that gets read. Two suites imported symbols the SDK has never exported and
  // sat erroring under a green-looking headline for as long as anyone had
  // looked — the same shape as the npm-pruned symlink that reported
  // "0 suites / 0 passed, 0 failed". The exit code was always right; what was
  // wrong was that a human skimming the output could not tell.
  if (errored > 0 || fail > 0 || missing > 0) {
    const parts = [];
    if (fail > 0) parts.push(`${fail} check${fail === 1 ? "" : "s"} failed`);
    if (errored > 0)
      parts.push(
        `${errored} suite${errored === 1 ? "" : "s"} DID NOT RUN (import or setup error)`,
      );
    if (missing > 0)
      parts.push(
        `${missing} suite${missing === 1 ? "" : "s"} DECLARED BUT NOT WRITTEN (surface has no live evidence)`,
      );
    console.log(`  ${C.red}${C.bold}NOT OK — ${parts.join("; ")}${C.reset}`);
  }
  console.log(`${C.bold}${"═".repeat(60)}${C.reset}\n`);

  return fail === 0 && errored === 0 && missing === 0;
}
