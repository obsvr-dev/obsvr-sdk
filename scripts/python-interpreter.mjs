/**
 * Which Python the cross-language checks should run.
 *
 * These scripts shell out to the Python SDK to compare its output against the
 * TypeScript one. They used to invoke a bare `python3`, which is whatever the
 * shell resolves — usually a system interpreter with none of the dev
 * dependencies installed. The canonicalizer parity check then died on
 * `ModuleNotFoundError: hypothesis` and printed a stack trace, which reads
 * exactly like a real parity failure. It is not one: nothing was compared at
 * all.
 *
 * Resolution order, most specific first:
 *   1. $PYTHON            — an explicit override always wins.
 *   2. sdk-python/.venv   — the repo's own dev environment, where
 *                           `pip install -e ".[dev]"` puts hypothesis.
 *   3. python3            — the previous behaviour, kept so a CI job that
 *                           installs into the ambient interpreter still works.
 *
 * @packageDocumentation
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

/** The interpreter to use, and where that choice came from (for diagnostics). */
export function resolvePython(repoRoot) {
  if (process.env.PYTHON) {
    return { python: process.env.PYTHON, source: "$PYTHON" };
  }
  for (const rel of [
    join("sdk-python", ".venv", "bin", "python"),
    join("sdk-python", ".venv", "Scripts", "python.exe"),
  ]) {
    const candidate = join(repoRoot, rel);
    if (existsSync(candidate)) return { python: candidate, source: rel };
  }
  return { python: "python3", source: "PATH" };
}

/**
 * Fail with a message that names the missing module and how to install it,
 * rather than letting an import error surface as a stack trace the reader has
 * to decode — and, worse, mistake for a divergence.
 */
export function requirePythonModules(python, source, modules) {
  const missing = [];
  for (const mod of modules) {
    try {
      execFileSync(python, ["-c", `import ${mod}`], { stdio: "ignore" });
    } catch {
      missing.push(mod);
    }
  }
  if (missing.length === 0) return;

  const plural = missing.length > 1 ? "modules" : "module";
  console.error(
    [
      `✗ cannot run the cross-language check: the Python interpreter is missing ${missing.length} required ${plural}.`,
      ``,
      `  interpreter : ${python}`,
      `  resolved by : ${source}`,
      `  missing     : ${missing.join(", ")}`,
      ``,
      `  This is NOT a parity failure — nothing was compared. Install the dev`,
      `  extra into the interpreter this script found:`,
      ``,
      `      cd sdk-python && python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"`,
      ``,
      `  or point the script at an interpreter that already has them:`,
      ``,
      `      PYTHON=/path/to/python node scripts/<this-script>.mjs`,
    ].join("\n"),
  );
  process.exit(2);
}
