/**
 * The per-integration tool-policy grading tables, held against the tree.
 *
 * Two READMEs carry a table telling a reader whether a `blocked` verdict on a
 * given surface actually stopped the tool. It is the table the documentation
 * points a buyer at before they put a destructive capability behind a policy,
 * and until now NOTHING read it: `enforcement-reporting-invariant.test.ts`
 * mentions the READMEs only inside a failure message telling a maintainer to
 * regrade. So a row flipped to the wrong grade — or a surface that quietly lost
 * its gate while the row kept claiming one — was caught by nothing offline.
 *
 * WHAT THIS CHECKS, AND WHAT IT CANNOT. It grades the ROW against the SOURCE
 * PREDICATE, using the same one the invariant's coverage tests use: a file
 * ships a tool gate if it reads the deny list or delegates to the shared tool
 * governor. That is a structural claim — the gate is there, or it is not — and it is exactly the claim a row makes when it
 * says *no integration* or "no gate of their own". It cannot check the adverbs:
 * "driven live at 0.13.4", "ZERO executions", "allow control at exactly one"
 * rest on the live artifacts behind them, as they did before. What this closes
 * is the gap where the prose and the tree could disagree with nobody noticing.
 *
 * The TypeScript column only. Python's column is graded by its own predicate in
 * sdk-python/tests/test_enforcement_grading_table.py — re-implementing one
 * language's predicate in the other is the drift this file exists to prevent.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

// Jest runs with cwd = sdk-typescript/.
const ROOT = join(process.cwd(), "..");
const rootReadme = readFileSync(join(ROOT, "README.md"), "utf-8");
const tsReadme = readFileSync(join(process.cwd(), "README.md"), "utf-8");

const HEADING = "### Does a tool-policy block actually stop the tool?";

/** The rows of the first markdown table under `heading`, as cell arrays. */
function gradingTable(markdown: string, heading: string): string[][] {
  const start = markdown.indexOf(heading);
  expect(start).toBeGreaterThan(-1);
  const lines = markdown.slice(start).split("\n");
  const rows: string[][] = [];
  let inTable = false;
  for (const line of lines) {
    if (!line.startsWith("|")) {
      if (inTable) break; // the table ended
      continue;
    }
    inTable = true;
    const cells = line.split("|").slice(1, -1).map((c) => c.trim());
    if (cells.every((c) => /^-+$/.test(c))) continue; // separator
    rows.push(cells);
  }
  // Drop the header row.
  return rows.slice(1);
}

/**
 * THE SOURCE PREDICATE. Byte-identical to `shipsAToolGate` in
 * enforcement-reporting-invariant.test.ts, and deliberately so: a row and an
 * invariant grading the same surface by two different rules is how they end up
 * disagreeing.
 */
function shipsAToolGate(rel: string): boolean {
  const full = join(process.cwd(), rel);
  if (!existsSync(full)) return false;
  const source = readFileSync(full, "utf-8");
  return source.includes("deniedTools") || source.includes("obsvrGovernTool(");
}

type Grade = "enforces" | "records only" | "governed per tool" | "no integration";

/**
 * Read a cell's grade. An unrecognised shape THROWS rather than being skipped:
 * a rewritten cell that no longer parses would otherwise pass this file
 * silently, which is the same failure mode as no check at all.
 */
function gradeOf(cell: string, where: string): Grade {
  // `**enforces` rather than `**enforces**`: one row qualifies the word inside
  // the bold ("**enforces on the tools, not on the turns**"). The bold marker
  // and the word itself stay required, so a cell that merely mentions enforcing
  // somewhere in its prose is still unreadable rather than generously accepted.
  if (/^\*\*enforces\b/.test(cell)) return "enforces";
  if (/^\*\*records only\b/.test(cell)) return "records only";
  if (/^\*no integration\*/.test(cell)) return "no integration";
  if (/^via `obsvrGovernTool`/.test(cell)) return "governed per tool";
  if (/^no gate of their own; govern individual tools with `obsvrGovernTool`/.test(cell))
    return "governed per tool";
  throw new Error(
    `${where}: cell does not start with a recognised grade — ` +
      `"**enforces**", "**records only**", "*no integration*" or ` +
      `"via \`obsvrGovernTool\`". Got: ${JSON.stringify(cell.slice(0, 80))}`,
  );
}

/**
 * Surface name (column 1, verbatim) -> the TypeScript file that would carry its
 * gate, or null where the row claims TypeScript has no such integration at all.
 *
 * Hand-maintained ON PURPOSE, and every row must be in it: a new row with no
 * entry fails below rather than being waved through, so adding a surface to the
 * documentation forces someone to say which file backs it.
 */
const ROOT_TABLE_SOURCES: Record<string, string | null> = {
  "MCP": "src/integrations/mcp.ts",
  "tool governor (`obsvrGovernTool` / `govern_tool`)": "src/integrations/tools.ts",
  "LangChain": "src/integrations/langchain.ts",
  "Haystack": null,
  "AutoGen": null,
  "Pydantic-AI": null,
  "OpenAI Agents": "src/integrations/openai-agents.ts",
  "CrewAI": null,
  "LlamaIndex": "src/integrations/llamaindex.ts",
  "Vercel AI SDK": "src/integrations/vercel-ai.ts",
  "provider tool runners": "src/proxy/runner-tool-gate.ts",
};

const TS_TABLE_SOURCES: Record<string, string | null> = {
  "MCP": "src/integrations/mcp.ts",
  "`obsvrGovernTool`": "src/integrations/tools.ts",
  "LangChain (`ObsvrCallbackHandler`)": "src/integrations/langchain.ts",
  "LlamaIndex, Vercel AI SDK": "src/integrations/llamaindex.ts",
  "OpenAI Agents SDK": "src/integrations/openai-agents.ts",
  "`chat.completions.runTools`, `beta.messages.toolRunner`": "src/proxy/runner-tool-gate.ts",
};

/** What the tree must look like for each grade to be honest. */
function assertGradeMatchesSource(grade: Grade, source: string | null, where: string): void {
  if (grade === "no integration") {
    // The strongest claim in the table: there is nothing here at all.
    expect({ where, source }).toEqual({ where, source: null });
    return;
  }
  if (source === null) {
    throw new Error(`${where}: graded "${grade}" but mapped to no TypeScript source file`);
  }
  expect(existsSync(join(process.cwd(), source))).toBe(true);
  if (grade === "enforces") {
    // A row claiming a gate must have one.
    expect({ where, source, gate: shipsAToolGate(source) }).toEqual({
      where,
      source,
      gate: true,
    });
  } else {
    // "governed per tool" / "records only" claim the surface has NO gate of its
    // own. A file that grew one has to be regraded — the direction that turns a
    // conservative row into an understated one, which is still a wrong row.
    expect({ where, source, gate: shipsAToolGate(source) }).toEqual({
      where,
      source,
      gate: false,
    });
  }
}

describe("the root README grading table matches the TypeScript tree", () => {
  const rows = gradingTable(rootReadme, HEADING);

  it("has the three-column shape this file assumes", () => {
    // A two-column rewrite would silently make every row below read the Python
    // cell as TypeScript's.
    expect(rows.length).toBeGreaterThanOrEqual(10);
    for (const cells of rows) expect(cells).toHaveLength(3);
  });

  it.each(gradingTable(rootReadme, HEADING).map((r) => [r[0], r] as const))(
    "%s",
    (surface, cells) => {
      if (!(surface in ROOT_TABLE_SOURCES)) {
        throw new Error(
          `root README grading table has a row for "${surface}" with no entry in ` +
            `ROOT_TABLE_SOURCES. Name the TypeScript file that backs it, or null ` +
            `if TypeScript has no such integration.`,
        );
      }
      const where = `root README / ${surface} / TypeScript`;
      assertGradeMatchesSource(gradeOf(cells[1], where), ROOT_TABLE_SOURCES[surface], where);
    },
  );
});

describe("the TypeScript README grading table matches the tree", () => {
  const rows = gradingTable(tsReadme, HEADING);

  it("has the two-column shape this file assumes", () => {
    expect(rows.length).toBeGreaterThanOrEqual(5);
    for (const cells of rows) expect(cells).toHaveLength(2);
  });

  it.each(gradingTable(tsReadme, HEADING).map((r) => [r[0], r] as const))(
    "%s",
    (surface, cells) => {
      if (!(surface in TS_TABLE_SOURCES)) {
        throw new Error(
          `the TypeScript README grading table has a row for "${surface}" with no ` +
            `entry in TS_TABLE_SOURCES. Name the file that backs it.`,
        );
      }
      const where = `sdk-typescript README / ${surface}`;
      assertGradeMatchesSource(gradeOf(cells[1], where), TS_TABLE_SOURCES[surface], where);
    },
  );

  it("the LlamaIndex/Vercel row speaks for BOTH files it names", () => {
    // One row, two files. The map can only point at one, so the second is
    // asserted here rather than left ungraded by the row that names it.
    expect(shipsAToolGate("src/integrations/vercel-ai.ts")).toBe(false);
  });
});

// ── coverage runs both ways ──────────────────────────────────────────────────

describe("every TypeScript tool gate has a row in the root table", () => {
  // The invariant suite already asserts this against ITS table. The
  // documentation is the other place a surface can go ungraded, and it is the
  // one a reader consults.
  it("no file ships a gate without appearing in the grading table", () => {
    const candidates = [
      ...readdirSync(join(process.cwd(), "src/integrations"))
        .filter((f) => f.endsWith(".ts"))
        .map((f) => `src/integrations/${f}`),
      "src/proxy/runner-tool-gate.ts",
    ];
    const graded = new Set(Object.values(ROOT_TABLE_SOURCES).filter(Boolean));
    const ungraded = candidates.filter((f) => shipsAToolGate(f) && !graded.has(f));

    expect(ungraded).toEqual([]);
  });

  it("no row points at a file that is not in the tree", () => {
    const missing = Object.entries(ROOT_TABLE_SOURCES)
      .filter(([, f]) => f !== null && !existsSync(join(process.cwd(), f)))
      .map(([surface]) => surface);

    expect(missing).toEqual([]);
  });
});

// ── non-vacuity ──────────────────────────────────────────────────────────────

describe("the grading check can fail", () => {
  it("rejects an enforces row whose source ships no gate", () => {
    expect(() =>
      assertGradeMatchesSource("enforces", "src/integrations/vercel-ai.ts", "probe"),
    ).toThrow();
  });

  it("rejects a no-integration row for a surface that has one", () => {
    expect(() =>
      assertGradeMatchesSource("no integration", "src/integrations/mcp.ts", "probe"),
    ).toThrow();
  });

  it("rejects a governed-per-tool row whose source grew a gate of its own", () => {
    expect(() =>
      assertGradeMatchesSource("governed per tool", "src/integrations/mcp.ts", "probe"),
    ).toThrow();
  });

  it("rejects a cell whose grade it cannot read", () => {
    expect(() => gradeOf("probably fine", "probe")).toThrow(/recognised grade/);
  });
});
