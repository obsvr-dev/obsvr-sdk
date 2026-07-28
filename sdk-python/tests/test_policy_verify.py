"""Python consumer of the shared signed-policy vectors.

Contract of record: conformance/fixtures/policy_signature.json - the same file
the TypeScript suite (sdk/tests/unit/policy-verify.test.ts) consumes. Both
languages must accept and refuse the same vectors for the same cause, which is
why every rejecting case also pins a substring its reason must contain.

Ed25519 has no standard-library implementation in Python, so the backend is
optional. These tests therefore assert BOTH worlds: with a backend every vector
resolves exactly as TS resolves it; without one the two crypto-dependent
vectors still fail closed and raise the policy_verification_unavailable flag
instead of silently passing.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from obsvr import config as config_mod  # noqa: E402
from obsvr import policy_verify  # noqa: E402
from obsvr import sender  # noqa: E402
from obsvr.policy_verify import (  # noqa: E402
    POLICY_VERIFICATION_UNAVAILABLE,
    INTEGRITY_FLAGS_METADATA_KEY,
    verify_policy_signature,
)

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "conformance/fixtures/policy_signature.json",
)

with open(FIXTURE_PATH, encoding="utf-8") as fh:
    FIXTURE = json.load(fh)

PINNED_KEY = FIXTURE["keys"]["pinned_public_key_b64"]
CASES = FIXTURE["cases"]
CASE_IDS = [c["id"] for c in CASES]


@pytest.fixture(autouse=True)
def _reset():
    policy_verify._reset_policy_verify()
    yield
    policy_verify._reset_policy_verify()


def _has_backend() -> bool:
    try:
        return policy_verify._resolve_backend() is not None
    finally:
        policy_verify._reset_policy_verify()


HAS_BACKEND = _has_backend()


def test_fixture_has_cases():
    assert len(CASES) >= 8, "the shared vectors must not shrink silently"


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_policy_signature_vector(case):
    """Every vector in the shared fixture resolves as the fixture pins it."""
    result = verify_policy_signature(
        case["rules"], case["approvals"], case.get("signature"), PINNED_KEY
    )
    expect = case["expect"]

    # The vectors that need real Ed25519 arithmetic are exactly the ones the
    # fixture marks sdk_support py:"optional" - Python resolves that primitive
    # through an optional backend. Everything else is refused structurally
    # (wrong key, bad hash, missing block) before any crypto runs, so those
    # verdicts hold with or without a backend. Reading the marking rather than
    # re-deriving it from the expectation shape keeps the fixture the single
    # source of truth; the test below pins the two against each other so the
    # marking cannot drift away from the property it names.
    needs_crypto = case.get("sdk_support", {}).get("py") == "optional"
    if needs_crypto and not HAS_BACKEND:
        assert result.ok is False, "no backend must never mean 'accepted'"
        assert result.unavailable is True
        assert POLICY_VERIFICATION_UNAVAILABLE  # the flag this state raises
        return

    assert result.ok is expect["ok"], f"{case['id']}: {result.reason}"
    if not expect["ok"]:
        assert expect["reason_contains"] in (result.reason or ""), (
            f"{case['id']}: reason {result.reason!r} does not contain "
            f"{expect['reason_contains']!r}"
        )
        assert result.unavailable is False


def test_optional_marking_names_exactly_the_crypto_dependent_vectors():
    """The fixture's py:"optional" marking must name exactly the vectors that
    cannot be refused structurally.

    Pinning the marking against the property it stands for is what stops the
    two from drifting: a vector added later that needs real Ed25519 but is
    left marked "required" fails HERE, with a backend installed, instead of
    only on a zero-dependency install where nobody is looking.
    """
    marked = {c["id"] for c in CASES if c.get("sdk_support", {}).get("py") == "optional"}
    needs_crypto = {
        c["id"]
        for c in CASES
        if c["expect"]["ok"] is True
        or c["expect"].get("reason_contains") == "verification failed"
    }
    assert marked == needs_crypto


@pytest.mark.skipif(not HAS_BACKEND, reason="no Ed25519 backend installed")
def test_valid_vector_accepts_with_backend():
    """Guards against a suite that passes only by refusing everything."""
    valid = next(c for c in CASES if c["id"] == "valid_signature_accepts")
    result = verify_policy_signature(
        valid["rules"], valid["approvals"], valid["signature"], PINNED_KEY
    )
    assert result.ok is True
    assert result.reason is None


def test_anti_rollback_refuses_an_older_signed_policy():
    """issued_at monotonicity is checked before any crypto, so it holds in
    both worlds. The poll-path wiring that feeds last_applied_issued_at is
    asserted separately."""
    valid = next(c for c in CASES if c["id"] == "valid_signature_accepts")
    result = verify_policy_signature(
        valid["rules"],
        valid["approvals"],
        valid["signature"],
        PINNED_KEY,
        last_applied_issued_at="2099-01-01T00:00:00.000Z",
    )
    assert result.ok is False
    assert "rollback" in (result.reason or "")


# --- degraded posture: no crypto backend -----------------------------------


def test_backend_resolution_fails_when_neither_library_imports(monkeypatch):
    """Inject the import failure both optional backends would raise."""
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def blocked_import(name, *args, **kwargs):
        if name.split(".")[0] in ("cryptography", "nacl"):
            raise ImportError(f"no module named {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", blocked_import)
    policy_verify._reset_policy_verify()
    assert policy_verify._resolve_backend() is None


def test_no_backend_does_not_silently_pass(monkeypatch):
    """The signed, valid vector must NOT be accepted without a backend."""
    monkeypatch.setattr(policy_verify, "_backend", None)
    valid = next(c for c in CASES if c["id"] == "valid_signature_accepts")
    result = verify_policy_signature(
        valid["rules"], valid["approvals"], valid["signature"], PINNED_KEY
    )
    assert result.ok is False
    assert result.unavailable is True
    assert "no Ed25519 backend" in (result.reason or "")
    assert policy_verify.is_verification_unavailable() is True


def test_no_backend_flags_every_emitted_event(monkeypatch):
    """The degraded posture rides reserved metadata on every emitted event."""
    monkeypatch.setattr(policy_verify, "_backend", None)
    valid = next(c for c in CASES if c["id"] == "valid_signature_accepts")
    verify_policy_signature(
        valid["rules"], valid["approvals"], valid["signature"], PINNED_KEY
    )

    captured = []
    monkeypatch.setattr(sender, "_ensure_worker", lambda: None)
    monkeypatch.setattr(sender, "sign_event", lambda event, api_key: captured.append(event))

    cfg = config_mod.ResolvedConfig(api_key="k", ingest_url="https://x.test")
    for _ in range(3):
        sender.send_audit_async(cfg, {"request_id": "r", "prompt": "", "response": ""})

    assert len(captured) == 3
    for event in captured:
        flags = (event.get("metadata") or {}).get(INTEGRITY_FLAGS_METADATA_KEY)
        assert flags == [POLICY_VERIFICATION_UNAVAILABLE]
    sender._reset_sender()


def test_healthy_posture_stamps_no_flag(monkeypatch):
    """No flag when nothing is degraded - the array is additive, not always-on."""
    captured = []
    monkeypatch.setattr(sender, "_ensure_worker", lambda: None)
    monkeypatch.setattr(sender, "sign_event", lambda event, api_key: captured.append(event))

    cfg = config_mod.ResolvedConfig(api_key="k", ingest_url="https://x.test")
    sender.send_audit_async(cfg, {"request_id": "r", "prompt": "", "response": ""})

    assert len(captured) == 1
    assert INTEGRITY_FLAGS_METADATA_KEY not in (captured[0].get("metadata") or {})
    sender._reset_sender()


def test_integrity_flag_key_is_preserved_by_the_metadata_trimmer():
    """A reserved evidence key that the trimmer drops is evidence lost."""
    from obsvr.events import _RESERVED_META_KEYS

    assert INTEGRITY_FLAGS_METADATA_KEY in _RESERVED_META_KEYS


# --- config surface ---------------------------------------------------------


def test_policy_public_key_is_on_the_single_config_shape():
    cfg = config_mod.ResolvedConfig(api_key="k")
    assert cfg.policy_public_key is None

    config_mod._reset()
    try:
        config_mod.init("k", ingest_url="https://x.test", policy_public_key=PINNED_KEY,
                        policy_refresh_interval_s=0)
        assert config_mod.get_config().policy_public_key == PINNED_KEY
    finally:
        config_mod._reset()
