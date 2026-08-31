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
    """The banner distinguishes fields added by formats 3, 4, and 5 from
    fields sealed only by the server countersignature."""
    assert _run([_write(tmp_path, "v.json", _chain()), "--api-key", API_KEY]) == 0
    out = capsys.readouterr().out
    assert "does NOT cover the decision" not in out
    for covered in (
        "action_taken", "rule_id", "policy_version", "user_id",
        "operation", "event_type", "source_lineage_hash",
    ):
        assert covered in out
    assert "does NOT cover tenant_id" in out
    for uncovered in ("token", "cost", "arbitrary metadata"):
        assert uncovered in out


def test_tampered_content_with_api_key_exits_1(tmp_path, capsys):
    chain = _chain()
    chain[1]["prompt"] = "tampered"
    assert _run([_write(tmp_path, "t.json", chain), "--api-key", API_KEY]) == 1
    assert "✗" in capsys.readouterr().err


def test_tampered_content_is_invisible_without_the_key(tmp_path, capsys):
    """The documented limit of the keyless tier, pinned so it cannot be
    mistaken for a passing full verification.

    The summary must name a PLAIN FIELD EDIT, not only a re-signed forgery. The
    previous wording said the tier "cannot detect a re-signed forgery (that
    needs the key)", which a reader takes to mean an edit made WITHOUT the key
    would be caught. It is not: no content or decision field is read at this
    tier at all.
    """
    chain = _chain()
    chain[1]["prompt"] = "tampered"
    assert _run([_write(tmp_path, "t.json", chain)]) == 0
    out = capsys.readouterr().out
    assert "reads NO content, decision or attribution field" in out
    assert "action_taken" in out
    assert "needs no signing key" in out


def test_a_decision_field_edit_is_named_as_uncovered_in_json(tmp_path, capsys):
    """A machine consumer of `valid: true` can see the scope of the claim.

    The exit code and `valid` are identical for a clean chain and one whose
    verdicts were rewritten, so the JSON has to carry what was not examined or
    a CI gate reads an ordering check as an integrity check.
    """
    chain = _chain()
    chain[1]["action_taken"] = "allowed"
    assert _run([_write(tmp_path, "j.json", chain), "--json"]) == 0
    doc = json.loads(capsys.readouterr().out.strip())
    assert doc["valid"] is True
    assert "action_taken" in doc["notChecked"]
    assert "sdk_sig_recomputation" in doc["notChecked"]
    assert "prev_sig_linkage" in doc["checked"]


# ── the keyless tier on a MULTI-SESSION bundle ──────────────────────────────
#
# A chain is per sdk_session_id. The tier used to sort the whole bundle by
# seq_no and skip every adjacent pair whose sessions differed — and a global
# sort of two sessions INTERLEAVES them, so every pair was cross-session and no
# check ran on anything. A fleet export is exactly this shape.


def _two_session_bundle(mutate=None):
    """Two independent chains in one file, interleaved by seq_no on sort."""
    events = []
    for session in ("session-a", "session-b"):
        previous = None
        for seq in (1, 2, 3):
            signature = f"{session}-{seq}".ljust(64, "0")
            events.append(
                {
                    "sdk_session_id": session,
                    "seq_no": seq,
                    "sdk_sig": signature,
                    "prev_sig": previous,
                    "timestamp_sdk": 1_000 + seq,
                    "chain_format": 3,
                }
            )
            previous = signature
    if mutate:
        mutate(events)
    return events


def test_well_formed_multi_session_bundle_still_passes():
    assert verify_structure(_two_session_bundle()) == (True, None)


def test_broken_linkage_in_one_session_is_caught_in_a_multi_session_bundle():
    def break_it(events):
        for event in events:
            if event["sdk_session_id"] == "session-b" and event["seq_no"] == 3:
                event["prev_sig"] = "deadbeef" * 8

    valid, reason = verify_structure(_two_session_bundle(break_it))
    assert valid is False
    assert "session-b" in reason and "prev_sig" in reason


def test_timestamp_regression_is_caught_in_a_multi_session_bundle():
    def break_it(events):
        for event in events:
            if event["sdk_session_id"] == "session-a" and event["seq_no"] == 2:
                event["timestamp_sdk"] = 0

    valid, reason = verify_structure(_two_session_bundle(break_it))
    assert valid is False and "timestamp regression" in reason


def test_seq_gap_is_caught_in_a_multi_session_bundle():
    def break_it(events):
        for event in events:
            if event["sdk_session_id"] == "session-a" and event["seq_no"] == 3:
                event["seq_no"] = 9

    valid, reason = verify_structure(_two_session_bundle(break_it))
    assert valid is False and "seq_no gap" in reason


def test_deleted_chain_prefix_is_caught():
    """Removing the head of a chain leaves every surviving pair linking."""
    chain = [e for e in _two_session_bundle() if e["sdk_session_id"] == "session-a"]
    valid, reason = verify_structure(chain[1:])
    assert valid is False and "does not start at seq_no 1" in reason


def test_chain_format_change_mid_chain_is_caught():
    def break_it(events):
        for event in events:
            if event["sdk_session_id"] == "session-a" and event["seq_no"] == 2:
                event["chain_format"] = 2

    valid, reason = verify_structure(_two_session_bundle(break_it))
    assert valid is False and "chain_format changes mid-chain" in reason


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


def test_unsigned_insertion_without_prev_sig_fails_keyless(tmp_path, capsys):
    """An appended event with a plausible seq_no, a well-formed sdk_sig and NO
    prev_sig is an insertion, and the keyless tier must refuse it: every event
    after the first has to link to its predecessor."""
    chain = _chain()
    chain.append(
        {
            "sdk_session_id": VECTORS["session_id"],
            "seq_no": chain[-1]["seq_no"] + 1,
            "timestamp_sdk": chain[-1]["timestamp_sdk"] + 1,
            "prompt": "inserted",
            "response": "",
            "sdk_sig": "a" * 64,
        }
    )
    assert _run([_write(tmp_path, "ins.json", chain)]) == 1
    assert "missing prev_sig" in capsys.readouterr().err


def test_first_event_legitimately_carries_no_prev_sig(tmp_path, capsys):
    """The chain start is the one position with no predecessor to link to, so
    an absent prev_sig there is legitimate, not an insertion."""
    chain = _chain()
    chain[0] = {k: v for k, v in chain[0].items() if k != "prev_sig"}
    assert _run([_write(tmp_path, "v.json", chain)]) == 0
    assert "STRUCTURAL verification passed" in capsys.readouterr().out


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


# ── an explicitly passed --api-key that carries no key ──────────────────────


def _tampered_chain():
    """A valid chain whose middle event's content has been altered."""
    chain = _chain()
    chain[1] = dict(chain[1], prompt="TAMPERED - not what was signed")
    return chain


def test_empty_api_key_is_a_usage_error_not_a_silent_downgrade(tmp_path, capsys):
    """`--api-key "$SECRET"` with the secret unset is the ordinary CI shape.

    The empty string is falsy, so the run used to fall through to structural
    verification and exit 0 -- on a TAMPERED chain, with the printed text
    honestly saying "STRUCTURAL". Nothing lied; the exit code, which is the
    whole interface for the CI use the README recommends, could not tell
    "verified" from "could not verify".
    """
    path = _write(tmp_path, "t.json", _tampered_chain())
    assert _run([path, "--api-key", ""]) == 2
    err = capsys.readouterr().err
    assert "--api-key was passed with no key" in err


def test_api_key_flag_with_no_value_is_a_usage_error(tmp_path, capsys):
    # Same failure, other spelling: a dropped variable can leave the flag
    # trailing with nothing after it, which also read as absent.
    path = _write(tmp_path, "t.json", _tampered_chain())
    assert _run([path, "--api-key"]) == 2
    assert "--api-key was passed with no key" in capsys.readouterr().err


def test_empty_api_key_is_refused_before_json_can_report_a_pass(tmp_path, capsys):
    path = _write(tmp_path, "t.json", _tampered_chain())
    assert _run([path, "--api-key", "", "--json"]) == 2
    captured = capsys.readouterr()
    # The refusal must not be dressed as a verification document: a consumer
    # parsing stdout must find nothing that reads as a verdict.
    assert '"valid":true' not in captured.out
    assert captured.out.strip() == ""


def test_CONTROL_the_absent_flag_still_means_structural_verification(tmp_path, capsys):
    # Without this, the three rows above would also be satisfied by a CLI that
    # had simply stopped accepting keyless runs -- which is a documented mode.
    path = _write(tmp_path, "t.json", _tampered_chain())
    assert _run([path]) == 0
    assert "STRUCTURAL verification passed" in capsys.readouterr().out


def test_CONTROL_a_real_key_still_detects_the_tamper(tmp_path):
    # And without THIS, they would be satisfied by a CLI that had stopped
    # verifying anything at all.
    path = _write(tmp_path, "t.json", _tampered_chain())
    assert _run([path, "--api-key", API_KEY]) == 1
