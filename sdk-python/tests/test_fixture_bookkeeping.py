"""Conformance-corpus bookkeeping (Python side). Twin:
sdk/tests/unit/fixture-bookkeeping.test.ts - both suites validate the SAME
structural vocabulary over the SAME corpus, so a malformed entry fails CI in
either language.

Three pieces of bookkeeping, and why each is validated rather than merely
described:

1. ``sdk_support`` - per-case ``{ts, py}`` support levels, each one of
   "required" | "optional" | "skip". "skip" turns "language X hasn't done
   this yet" from a missing test into a reviewable datum: the case exists,
   the runner shows it as skipped, and flipping it to "required" is the
   port's acceptance gate. A typo'd level would silently run (or silently
   not-skip), so the vocabulary is enforced here.

2. ``claimable`` - a boolean marking a fixture (or case) that backs a claim
   made in the PUBLIC docs (README/SECURITY/BENCHMARKS), as opposed to one that merely
   exercises behavior. The assignment rule is objective: a fixture is
   claimable iff a public doc cites it. Enforced bidirectionally below so
   the marking cannot drift from the docs.

3. known-divergences.json - the drift catalog: the machine-readable
   allowlist of ACCEPTED cross-SDK divergences. Exact key set per entry,
   ``status`` restricted to "intended", ``sdk`` to a real SDK name,
   ``category`` to the catalog's own declared vocabulary. An allowlist that
   cannot be validated degrades into prose.
"""
import json
from pathlib import Path

FIXTURES_DIR = (Path(__file__).parent / "../../conformance/fixtures").resolve()
CATALOG_PATH = (Path(__file__).parent / "../../conformance/known-divergences.json").resolve()
REPO_ROOT = FIXTURES_DIR.parent.parent

SUPPORT_LEVELS = {"required", "optional", "skip"}
SDK_NAMES = {"ts", "py"}
ENTRY_KEYS = {
    "id", "sdk", "category", "status", "description",
    "parity_scope", "allowed_difference", "tracking",
}


def _all_fixtures():
    for path in sorted(FIXTURES_DIR.glob("*.json")):
        yield path.name, json.loads(path.read_text())


def _collect(value, key, out):
    """Recursively collect every value stored under ``key`` in the doc."""
    if isinstance(value, list):
        for v in value:
            _collect(v, key, out)
    elif isinstance(value, dict):
        for k, v in value.items():
            if k == key:
                out.append(v)
            _collect(v, key, out)


def test_every_sdk_support_uses_the_known_vocabulary():
    for name, data in _all_fixtures():
        found = []
        _collect(data, "sdk_support", found)
        for s in found:
            assert isinstance(s, dict) and s, (name, s)
            for sdk, level in s.items():
                assert sdk in SDK_NAMES, (name, sdk)
                assert level in SUPPORT_LEVELS, (name, level)


def test_no_case_is_skip_for_both_languages():
    # skip-everywhere is deletion wearing a bookkeeping hat.
    for name, data in _all_fixtures():
        found = []
        _collect(data, "sdk_support", found)
        for s in found:
            assert not all(v == "skip" for v in s.values()), (name, s)


def test_claimable_is_always_boolean():
    for name, data in _all_fixtures():
        found = []
        _collect(data, "claimable", found)
        for c in found:
            assert isinstance(c, bool), (name, c)


def test_fixture_is_claimable_iff_a_public_doc_cites_it():
    # The assignment rule made checkable: one of the PUBLISHED docs citing
    # ``fixtures/<name>.json`` is what "backs a public claim" MEANS here.
    # Marking without a citation or citing without a marking both fail, so the
    # two cannot drift. BENCHMARKS.md is in the set because a published number
    # is a claim like any other: a fixture cited only there must come out
    # claimable, and dropping it would silently require the opposite.
    docs = "\n".join(
        (REPO_ROOT / d).read_text()
        for d in (
            "README.md",
            "SECURITY.md",
            "BENCHMARKS.md",
            "sdk/README.md",
            "sdk-python/README.md",
        )
        if (REPO_ROOT / d).exists()
    )
    for name, data in _all_fixtures():
        cited = name in docs
        marked = data.get("claimable") is True
        assert marked == cited, (name, {"claimable": marked, "cited": cited})


def test_drift_catalog_entries_carry_exactly_the_required_keys():
    catalog = json.loads(CATALOG_PATH.read_text())
    for e in catalog["entries"]:
        assert set(e.keys()) == ENTRY_KEYS, e.get("id")
        for k in ENTRY_KEYS:
            assert isinstance(e[k], str) and e[k], (e.get("id"), k)


def test_drift_catalog_status_has_one_legal_value():
    catalog = json.loads(CATALOG_PATH.read_text())
    for e in catalog["entries"]:
        assert e["status"] == "intended", e["id"]


def test_drift_catalog_vocabularies():
    catalog = json.loads(CATALOG_PATH.read_text())
    for e in catalog["entries"]:
        assert e["sdk"] in SDK_NAMES, e["id"]
        assert e["category"] in catalog["categories"], e["id"]


def test_drift_catalog_ids_unique_and_kd_numbered():
    import re

    catalog = json.loads(CATALOG_PATH.read_text())
    ids = [e["id"] for e in catalog["entries"]]
    assert len(set(ids)) == len(ids)
    for i in ids:
        assert re.fullmatch(r"KD-\d+", i), i
