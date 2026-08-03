"""obsvr-verify console script: modes, exit codes, and the entry point.

Contract of record: sdk-typescript/src/cli-verify.ts. Byte-level parity with that CLI over
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

GAP_PATH = os.path.join(REPO_ROOT, "conformance/fixtures/audit_gap.json")

with open(GAP_PATH, encoding="utf-8") as fh:
    GAP_FIXTURE = json.load(fh)

GAP_API_KEY = GAP_FIXTURE["signing"]["api_key"]


def _gap_chain():
    """A valid chain whose middle event is a signed gap marker."""
    signing = GAP_FIXTURE["signing"]
    return [dict(e, sdk_session_id=signing["session_id"]) for e in signing["events"]]


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


def test_success_banner_states_the_preimage_boundary(tmp_path, capsys):
    """The banner must say what the format-3 preimage covers (content, order,
    the eight decision/attribution fields) and what it does not (tenant_id and
    the other fields sealed only by the server countersignature)."""
    assert _run([_write(tmp_path, "v.json", _chain()), "--api-key", API_KEY]) == 0
    out = capsys.readouterr().out
    assert "does NOT cover the decision" not in out
    for covered in ("action_taken", "rule_id", "policy_version", "user_id"):
        assert covered in out
    assert "does NOT cover tenant_id" in out
    for uncovered in ("token", "metadata", "operation", "content_provenance"):
        assert uncovered in out


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


def test_declared_gap_exits_3_not_0(tmp_path, capsys):
    """The whole point: `obsvr-verify chain.json && deploy` must NOT pass on a
    record the chain itself says is missing events. Valid is not complete."""
    code = _run([_write(tmp_path, "gap.json", _gap_chain()), "--api-key", GAP_API_KEY])
    assert code == 3
    out = capsys.readouterr().out
    assert "CONTENT + CHAIN verification passed" in out
    assert "declared LOST" in out


def test_declared_gap_exits_3_keyless_too(tmp_path, capsys):
    # Keyless reads the marker without authenticating it, and still refuses to
    # report the run as clean - the count is untrusted, its presence is not.
    assert _run([_write(tmp_path, "gap.json", _gap_chain())]) == 3


def test_allow_gaps_opts_back_into_0(tmp_path, capsys):
    code = _run(
        [_write(tmp_path, "gap.json", _gap_chain()), "--api-key", GAP_API_KEY, "--allow-gaps"]
    )
    assert code == 0
    # The status is suppressed; the disclosure is not. A team that accepts
    # bounded-queue loss still has the loss printed in its CI log.
    assert "declared LOST" in capsys.readouterr().out


def test_allow_gaps_does_not_rescue_a_broken_chain(tmp_path, capsys):
    chain = _chain()
    chain[1]["prompt"] = "tampered"
    code = _run([_write(tmp_path, "t.json", chain), "--api-key", API_KEY, "--allow-gaps"])
    assert code == 1


def test_allow_gaps_on_a_clean_chain_is_a_no_op(tmp_path, capsys):
    assert _run([_write(tmp_path, "v.json", _chain()), "--api-key", API_KEY, "--allow-gaps"]) == 0


def test_usage_error_exits_2(capsys):
    assert _run([]) == 2
    assert "Usage: obsvr-verify" in capsys.readouterr().err


def test_unrecognized_shape_exits_2(tmp_path, capsys):
    assert _run([_write(tmp_path, "w.json", {"nope": True})]) == 2
    assert "Unrecognized file shape" in capsys.readouterr().err


def test_unreadable_file_exits_2(tmp_path, capsys):
    assert _run([str(tmp_path / "absent.json")]) == 2
    assert "Cannot read" in capsys.readouterr().err


# ── every break in one run, and --json ──────────────────────────────────────


def _two_break_chain():
    """Two independent tampers: a content edit at event 0 and a forged
    signature at event 1."""
    chain = _chain()
    chain[0]["prompt"] = "tampered"
    chain[1]["sdk_sig"] = "0" * 64
    return chain


def test_every_break_is_rendered_not_just_the_first(tmp_path, capsys):
    assert _run([_write(tmp_path, "mb.json", _two_break_chain()), "--api-key", API_KEY]) == 1
    err = capsys.readouterr().err
    assert "Signature mismatch at event 0 (event index 0)" in err
    assert "Signature mismatch at event 1 (event index 1)" in err
    assert err.index("(event index 0)") < err.index("(event index 1)")


def test_json_reports_the_full_break_list(tmp_path, capsys):
    code = _run(
        [_write(tmp_path, "mb.json", _two_break_chain()), "--api-key", API_KEY, "--json"]
    )
    assert code == 1
    doc = json.loads(capsys.readouterr().out)
    assert doc["mode"] == "content+chain"
    assert doc["valid"] is False
    assert doc["exitCode"] == 1
    (session,) = doc["sessions"]
    assert [b["index"] for b in session["breaks"]] == [0, 1]
    # First-break fields stay what they always were.
    assert session["brokenAt"] == 0
    assert session["reason"] == "Signature mismatch at event 0"


def test_json_on_a_valid_keyed_chain(tmp_path, capsys):
    assert _run([_write(tmp_path, "v.json", _chain()), "--api-key", API_KEY, "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mode"] == "content+chain"
    assert doc["valid"] is True
    assert doc["eventsVerified"] == 2
    assert doc["exitCode"] == 0
    assert doc["sessions"][0]["breaks"] == []


def test_json_keyless_is_the_structural_tier(tmp_path, capsys):
    assert _run([_write(tmp_path, "v.json", _chain()), "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["mode"] == "structural"
    assert doc["valid"] is True
    assert doc["events"] == 2
    assert doc["exitCode"] == 0


def test_json_keeps_the_incomplete_status_and_allow_gaps_mapping(tmp_path, capsys):
    """Exit 3 (valid but incomplete) and the --allow-gaps 3->0 mapping are the
    exit-code contract; --json must carry them unchanged."""
    path = _write(tmp_path, "gap.json", _gap_chain())
    assert _run([path, "--api-key", GAP_API_KEY, "--json"]) == 3
    doc = json.loads(capsys.readouterr().out)
    assert doc["valid"] is True
    assert doc["exitCode"] == 3
    assert doc["eventsDeclaredLost"] == 1234

    assert _run([path, "--api-key", GAP_API_KEY, "--json", "--allow-gaps"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["valid"] is True
    assert doc["allowGaps"] is True
    assert doc["exitCode"] == 0


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


SECOND_SESSION = "22222222-2222-2222-2222-222222222222"


def test_verifies_each_session_chain_separately(tmp_path, capsys, monkeypatch):
    """The HMAC chain is per sdk_session_id, so an export holding two sessions
    must verify as two chains rather than one interleaved (and broken) one.

    The second chain is signed by the SDK's own signer rather than by copying
    the fixture under a new session id - the session id is part of the signed
    preimage, so a copy would not (and must not) verify.

    The signer's session id is pinned explicitly rather than left to the
    module default. `_reset_sender()` clears the sequence and chain head but
    NOT `_sdk_session_id`, so whichever value another test last wrote is still
    in place - and one of them writes the fixture's own session id. Inheriting
    it would put both chains in one group with two seq 1s, which is a failure
    that depends only on test order. monkeypatch restores it afterwards.
    """
    from obsvr import sender

    monkeypatch.setattr(sender, "_sdk_session_id", SECOND_SESSION)
    assert SECOND_SESSION != VECTORS["session_id"], "the two chains must not share a session"

    sender._reset_sender()
    live = [{"request_id": "a", "prompt": "one", "response": "1"},
            {"request_id": "b", "prompt": "two", "response": "2"}]
    for event in live:
        sender.sign_event(event, API_KEY)
    assert {e["sdk_session_id"] for e in live} == {SECOND_SESSION}
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
