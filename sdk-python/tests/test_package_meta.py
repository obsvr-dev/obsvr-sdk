"""Package metadata + README accuracy guards.

Locks the pre-launch invariants: obsvr-sdk is Apache-2.0 everywhere
(pyproject license + classifier, LICENSE text, NOTICE, README license
section), and the README's built-in PII claim matches the real
BUILTIN_PII_PATTERNS label count so scanner changes cannot silently
leave the docs stale.
"""
from pathlib import Path

from obsvr.policy import BUILTIN_PII_PATTERNS

ROOT = Path(__file__).parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text()
LICENSE = (ROOT / "LICENSE").read_text()
NOTICE = (ROOT / "NOTICE").read_text()
README = (ROOT / "README.md").read_text()


def test_pyproject_declares_apache_2():
    assert 'license = { text = "Apache-2.0" }' in PYPROJECT
    assert "License :: OSI Approved :: Apache Software License" in PYPROJECT
    assert "License :: OSI Approved :: MIT License" not in PYPROJECT


def test_license_file_is_apache_text_with_obsvr_copyright():
    assert "Apache License" in LICENSE
    assert "Version 2.0, January 2004" in LICENSE
    assert "Copyright 2026 Obsvr" in LICENSE
    assert "MIT License" not in LICENSE


def test_notice_names_product_and_copyright():
    assert "Obsvr SDK" in NOTICE
    assert "Copyright 2026 Obsvr" in NOTICE


def test_readme_license_section_is_apache_not_mit():
    assert "Apache-2.0" in README
    assert "## License\n\nMIT" not in README


def test_readme_builtin_pii_type_count_matches_scanner():
    """README claims N built-in regex PII types; keep N honest."""
    labels = {entry["label"] for entry in BUILTIN_PII_PATTERNS}
    assert f"covers {len(labels)} PII types" in README
