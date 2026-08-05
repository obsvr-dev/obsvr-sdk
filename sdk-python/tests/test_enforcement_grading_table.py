"""The per-integration tool-policy grading table, Python column, held against
the tree.

Twin: sdk-typescript/tests/unit/enforcement-grading-table.test.ts, which grades
the same table's TypeScript column with the TypeScript predicate. Each language
grades its own column with its own source predicate deliberately — a column
graded by a re-implementation of the other language's rule is exactly the drift
this pair exists to prevent.

The root README carries the table telling a reader whether a ``blocked`` verdict
on a given surface actually stopped the tool. It is what the documentation points
a buyer at before they put a destructive capability behind a policy, and nothing
read it: ``test_enforcement_reporting_invariant.py`` mentions the READMEs only in
a failure message telling a maintainer to regrade. A row flipped to the wrong
grade, or a surface that quietly lost its gate while the row kept claiming one,
was caught by nothing offline.

WHAT THIS CHECKS, AND WHAT IT CANNOT. It grades the ROW against the SOURCE
PREDICATE — the same one ``test_the_table_covers_every_surface_that_has_a_tool_gate``
uses: a module carries a gate if it defines ``_check_tool``/``_check_tool_policy``
or BINDS ``govern_tool``. That is a structural claim, and it is exactly the claim
a row makes when it says *no integration*. It cannot check the adverbs — "driven
live at 0.9.9", "ZERO executions", "allow control at exactly one" — which rest on
the live artifacts behind them, as they did before. What this closes is the gap
where the prose and the tree could disagree with nobody noticing.
"""
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
INTEGRATIONS = pathlib.Path(__file__).resolve().parents[1] / "obsvr" / "integrations"
HEADING = "### Does a tool-policy block actually stop the tool?"

ENFORCES = "enforces"
RECORDS_ONLY = "records only"
GOVERNED_PER_TOOL = "governed per tool"
NO_INTEGRATION = "no integration"


def ships_a_tool_gate(stem: str) -> bool:
    """THE SOURCE PREDICATE, identical to the invariant suite's.

    Two ways to carry a gate, because there are two. Defining ``_check_tool`` is
    one; BINDING the shared governor is the other — llamaindex refuses nothing of
    its own and is still an enforcing surface, because it hands the framework's
    tools to ``govern_tool`` at the seam every dispatch crosses.
    """
    path = INTEGRATIONS / f"{stem}.py"
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8")
    defines_check = "def _check_tool(" in text or "def _check_tool_policy(" in text
    # A CALL, not a mention: openai_agents names govern_tool in prose to point
    # readers at it, which is not the same as binding it.
    binds_governor = bool(re.search(r"^(?!\s*#).*\bgovern_tool\(", text, re.M))
    return defines_check or (binds_governor and stem != "tools")


def grading_table(markdown: str) -> list:
    """Rows of the first markdown table under the grading heading."""
    start = markdown.index(HEADING)
    rows = []
    in_table = False
    for line in markdown[start:].split("\n"):
        if not line.startswith("|"):
            if in_table:
                break
            continue
        in_table = True
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if all(re.fullmatch(r"-+", c) for c in cells):
            continue
        rows.append(cells)
    return rows[1:]  # drop the header


def grade_of(cell: str, where: str) -> str:
    """Read a cell's grade.

    An unrecognised shape RAISES rather than being skipped: a rewritten cell
    that no longer parses would otherwise pass this file silently, which is the
    same failure mode as no check at all.
    """
    # ``**enforces`` rather than ``**enforces**``: one row qualifies the word
    # inside the bold. The bold marker and the word stay required, so a cell
    # that merely mentions enforcing in its prose is still unreadable.
    if re.match(r"^\*\*enforces\b", cell):
        return ENFORCES
    if re.match(r"^\*\*records only\b", cell):
        return RECORDS_ONLY
    if re.match(r"^\*no integration\*", cell):
        return NO_INTEGRATION
    if re.match(r"^via `obsvrGovernTool`", cell):
        return GOVERNED_PER_TOOL
    raise AssertionError(
        f"{where}: cell does not start with a recognised grade - "
        f'"**enforces**", "**records only**", "*no integration*" or '
        f'"via `obsvrGovernTool`". Got: {cell[:80]!r}'
    )


#: Surface name (column 1, verbatim) -> the Python module stem that would carry
#: its gate, or None where the row claims Python has no such integration.
#:
#: Hand-maintained ON PURPOSE, and every row must be in it: a new row with no
#: entry fails below rather than being waved through, so adding a surface to the
#: documentation forces someone to say which module backs it.
PYTHON_SOURCES = {
    "MCP": "mcp",
    "tool governor (`obsvrGovernTool` / `govern_tool`)": "tools",
    "LangChain": "langchain",
    "Haystack": "haystack",
    "AutoGen": "autogen",
    "Pydantic-AI": "pydantic_ai",
    "OpenAI Agents": "openai_agents",
    "CrewAI": "crewai",
    "LlamaIndex": "llamaindex",
    "Vercel AI SDK": None,
    "provider tool runners": None,
}

ROOT_README = (REPO / "README.md").read_text(encoding="utf-8")
ROWS = grading_table(ROOT_README)


def assert_grade_matches_source(grade: str, stem, where: str) -> None:
    """What the tree must look like for each grade to be honest."""
    if grade == NO_INTEGRATION:
        # The strongest claim in the table: there is nothing here at all.
        assert stem is None, f"{where}: graded *no integration* but maps to {stem}.py"
        return
    assert stem is not None, f"{where}: graded {grade!r} but mapped to no Python module"
    assert (INTEGRATIONS / f"{stem}.py").exists(), f"{where}: {stem}.py is not in the tree"
    if grade == ENFORCES:
        assert ships_a_tool_gate(stem), (
            f"{where}: the row claims a gate and {stem}.py carries none - "
            f"regrade the row, or restore the gate"
        )
    else:
        assert not ships_a_tool_gate(stem), (
            f"{where}: the row claims this surface has no gate of its own and "
            f"{stem}.py now carries one - regrade the row"
        )


def test_the_table_has_the_three_column_shape_this_file_assumes():
    """A two-column rewrite would silently make every row below read a
    different cell as Python's."""
    assert len(ROWS) >= 10
    for cells in ROWS:
        assert len(cells) == 3, cells


@pytest.mark.parametrize("cells", ROWS, ids=[r[0] for r in ROWS])
def test_each_row_matches_the_python_tree(cells):
    surface = cells[0]
    assert surface in PYTHON_SOURCES, (
        f'the root README grading table has a row for "{surface}" with no entry '
        f"in PYTHON_SOURCES. Name the module that backs it, or None if Python "
        f"has no such integration."
    )
    where = f"root README / {surface} / Python"
    assert_grade_matches_source(grade_of(cells[2], where), PYTHON_SOURCES[surface], where)


def test_every_python_tool_gate_has_a_row():
    """Coverage runs both ways. The invariant suite already asserts this against
    ITS table; the documentation is the other place a surface can go ungraded,
    and it is the one a reader consults."""
    graded = {s for s in PYTHON_SOURCES.values() if s}
    gated = {
        p.stem
        for p in sorted(INTEGRATIONS.glob("*.py"))
        if not p.stem.startswith("_") and ships_a_tool_gate(p.stem)
    }

    assert not (gated - graded), (
        f"these modules carry a tool gate but no row in the README grading "
        f"table: {sorted(gated - graded)}"
    )


# ── non-vacuity ──────────────────────────────────────────────────────────────


def test_an_enforces_row_whose_source_ships_no_gate_is_rejected():
    with pytest.raises(AssertionError):
        # bedrock.py is a real module with no tool gate.
        assert_grade_matches_source(ENFORCES, "bedrock", "probe")


def test_a_no_integration_row_for_a_surface_that_has_one_is_rejected():
    with pytest.raises(AssertionError):
        assert_grade_matches_source(NO_INTEGRATION, "mcp", "probe")


def test_a_governed_per_tool_row_whose_source_grew_a_gate_is_rejected():
    with pytest.raises(AssertionError):
        assert_grade_matches_source(GOVERNED_PER_TOOL, "mcp", "probe")


def test_a_cell_whose_grade_cannot_be_read_is_rejected():
    with pytest.raises(AssertionError, match="recognised grade"):
        grade_of("probably fine", "probe")
