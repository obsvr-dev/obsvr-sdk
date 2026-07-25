"""obsvr-verify console script: modes, exit codes, and the entry point.

Contract of record: sdk/src/cli-verify.ts. Byte-level parity with that CLI over
one shared export is asserted separately by
scripts/check-cli-verify-parity.mjs, which drives BOTH binaries; these tests
pin the Python side's own behavior and the packaging that makes it reachable
as `obsvr-verify`.

The chain under test comes from conformance/fixtures/signing_vectors.json, not
from per-language literals - a CLI that verifies a chain only its own language
produced proves nothing about a customer's export.
"""

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from obsvr.cli_verify import main, verify_structure  # noqa: E402

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
VECTORS_PATH = os.path.join(REPO_ROOT, "conformance/fixtures/signing_vectors.json")

with open(VECTORS_PATH, encoding="utf-8") as fh:
    VECTORS = json.load(fh)

API_KEY = VECTORS["api_key"]


def _chain():
    return [dict(e, sdk_session_id=VECTORS["session_id"]) for e in VECTORS["events"]]


def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def _run(args):
    """Run main() and return its exit code, translating SystemExit."""
    try:
        return main(args)
    except SystemExit as exit_:
        return exit_.code


# ── exit codes, one per documented outcome ──────────────────────────────────


def test_valid_chain_keyless_exits_0(tmp_path, capsys):
    assert _run([_write(tmp_path, "v.json", _chain())]) == 0
    assert "STRUCTURAL verification passed" in capsys.readouterr().out


def test_valid_chain_with_api_key_exits_0(tmp_path, capsys):
    assert _run([_write(tmp_path, "v.json", _chain()), "--api-key", API_KEY]) == 0
    out = capsys.readouterr().out
    assert "CONTENT + CHAIN verification passed" in out
    assert "2 signature(s) recomputed" in out


def test_tampered_content_with_api_key_exits_1(tmp_path, capsys):
    chain = _chain()
    chain[1]["prompt"] = "tampered"
    assert _run([_write(tmp_path, "t.json", chain), "--api-key", API_KEY]) == 1
    assert "✗" in capsys.readouterr().err


def test_tampered_content_is_invisible_without_the_key(tmp_path, capsys):
    """The documented limit of the keyless tier, pinned so it cannot be
    mistaken for a passing full verification."""
    chain = _chain()
    chain[1]["prompt"] = "tampered"
    assert _run([_write(tmp_path, "t.json", chain)]) == 0
    assert "signatures were not recomputed" in capsys.readouterr().out


def test_seq_gap_fails_keyless(tmp_path, capsys):
    chain = _chain()
    chain[1]["seq_no"] = 5
    assert _run([_write(tmp_path, "g.json", chain)]) == 1
    assert "seq_no gap" in capsys.readouterr().err


def test_broken_prev_sig_fails_keyless(tmp_path, capsys):
    chain = _chain()
    chain[1]["prev_sig"] = "0" * 64
    assert _run([_write(tmp_path, "p.json", chain)]) == 1
    assert "prev_sig does not link" in capsys.readouterr().err


def test_timestamp_regression_fails_keyless(tmp_path, capsys):
    chain = _chain()
    chain[1]["timestamp_sdk"] = chain[0]["timestamp_sdk"] - 1
    assert _run([_write(tmp_path, "ts.json", chain)]) == 1
    assert "timestamp regression" in capsys.readouterr().err


def test_wrong_key_exits_1(tmp_path):
    assert _run([_write(tmp_path, "v.json", _chain()), "--api-key", "wrong"]) == 1


def test_usage_error_exits_2(capsys):
    assert _run([]) == 2
    assert "Usage: obsvr-verify" in capsys.readouterr().err


def test_unrecognized_shape_exits_2(tmp_path, capsys):
    assert _run([_write(tmp_path, "w.json", {"nope": True})]) == 2
    assert "Unrecognized file shape" in capsys.readouterr().err


def test_unreadable_file_exits_2(tmp_path, capsys):
    assert _run([str(tmp_path / "absent.json")]) == 2
    assert "Cannot read" in capsys.readouterr().err


# ── the bundle shapes the TS CLI accepts, in its order ──────────────────────


@pytest.mark.parametrize("wrap", [
    lambda chain: chain,
    lambda chain: {"trace": {"steps": chain}},
    lambda chain: {"steps": chain},
    lambda chain: {"events": chain},
])
def test_accepts_every_documented_bundle_shape(tmp_path, capsys, wrap):
    assert _run([_write(tmp_path, "b.json", wrap(_chain())), "--api-key", API_KEY]) == 0
    assert "CONTENT + CHAIN verification passed" in capsys.readouterr().out


def test_flag_value_is_never_mistaken_for_the_file(tmp_path, capsys):
    path = _write(tmp_path, "v.json", _chain())
    assert _run(["--api-key", API_KEY, path]) == 0
    assert f"from {path}" in capsys.readouterr().out


# ── multi-session exports ───────────────────────────────────────────────────


def test_verifies_each_session_chain_separately(tmp_path, capsys):
    """The HMAC chain is per sdk_session_id, so an export holding two sessions
    must verify as two chains rather than one interleaved (and broken) one.

    The second chain is signed by the SDK's own signer rather than by copying
    the fixture under a new session id - the session id is part of the signed
    preimage, so a copy would not (and must not) verify.
    """
    from obsvr import sender

    sender._reset_sender()
    live = [{"request_id": "a", "prompt": "one", "response": "1"},
            {"request_id": "b", "prompt": "two", "response": "2"}]
    for event in live:
        sender.sign_event(event, API_KEY)
    sender._reset_sender()

    assert _run([_write(tmp_path, "m.json", _chain() + live), "--api-key", API_KEY]) == 0
    out = capsys.readouterr().out
    assert "across 2 session(s)" in out
    assert "4 signature(s) recomputed" in out


def test_structural_check_skips_linkage_across_sessions():
    a = _chain()
    b = [dict(e, sdk_session_id="other") for e in VECTORS["events"]]
    valid, reason = verify_structure(a + b)
    assert valid is True, reason


# ── packaging: the entry point is what makes this reachable ────────────────


def test_console_script_entry_point_is_declared():
    pyproject = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
    with open(pyproject, encoding="utf-8") as fh:
        content = fh.read()
    assert "[project.scripts]" in content
    assert 'obsvr-verify = "obsvr.cli_verify:main"' in content


def test_module_runs_as_a_script(tmp_path):
    """`python -m obsvr.cli_verify` is the same entry the console script calls,
    so a packaging mistake cannot leave the CLI importable but unrunnable."""
    path = _write(tmp_path, "v.json", _chain())
    result = subprocess.run(
        [sys.executable, "-m", "obsvr.cli_verify", path, "--api-key", API_KEY],
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "CONTENT + CHAIN verification passed" in result.stdout
