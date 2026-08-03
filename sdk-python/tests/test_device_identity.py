"""The optional client-held device signing identity (Ed25519).

The HMAC chain is keyed from the API key, so any key holder can mint a valid
chain; the device seal is the opt-in second signature over the SAME payload,
giving non-repudiation against everyone who does not hold the device key.
These tests pin the loader's refusal behaviour (this SDK NEVER generates key
material), the derived key id, the additive stamping on signed events, and
the property the feature exists for: an API-key holder's re-minted chain
fails under the pinned device key. Twin: the TS device-identity/device
verifier suites; signature bytes are pinned cross-language in
conformance/fixtures/signing_vectors.json.
"""

import base64
import copy
import json
import time

import pytest

import obsvr
from obsvr import sender
from obsvr.config import _reset
from obsvr.device_identity import (
    DeviceIdentityError,
    derive_device_key_id,
    load_device_public_key,
    load_device_signer,
    verify_device_sig,
)
from obsvr.sender import _reset_sender, configure_device_signer, sign_event
from obsvr.verify_chain import verify_chain

#: RFC 8032 test vector 1 — publicly known, test-only key material.
SEED_A = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUB_A_B64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
KEY_ID_A = "21fe31dfa154a261"
SEED_B = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"


@pytest.fixture(autouse=True)
def _fresh():
    _reset()
    _reset_sender()
    yield
    _reset()
    _reset_sender()


def _seed_file(tmp_path, seed=SEED_A, name="device.key"):
    path = tmp_path / name
    path.write_text(seed)
    return str(path)


def _signed_chain(api_key="test-key", n=3):
    events = []
    for i in range(n):
        event = {"prompt": f"p{i}", "response": f"r{i}", "action_taken": "allowed"}
        sign_event(event, api_key)
        events.append(event)
    return events


class TestLoader:
    def test_the_loader_never_generates_a_key(self, tmp_path):
        """A missing key file is a refusal, never a fresh keypair — a
        verifier or signer that mints key material on a fresh machine is the
        known failure mode this loader exists to rule out."""
        with pytest.raises(DeviceIdentityError, match="never\\s+generates"):
            load_device_signer(str(tmp_path / "does-not-exist.key"))

    def test_hex_base64_and_pem_forms_load_to_one_identity(self, tmp_path):
        hex_signer = load_device_signer(_seed_file(tmp_path))
        b64 = base64.b64encode(bytes.fromhex(SEED_A)).decode()
        b64_signer = load_device_signer(_seed_file(tmp_path, b64, "b64.key"))
        assert hex_signer.key_id == b64_signer.key_id == KEY_ID_A
        assert hex_signer.public_key_b64 == PUB_A_B64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        pem = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_A))
            .private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            .decode()
        )
        pem_signer = load_device_signer(_seed_file(tmp_path, pem, "device.pem"))
        assert pem_signer.key_id == KEY_ID_A

    def test_garbage_key_material_is_refused(self, tmp_path):
        with pytest.raises(DeviceIdentityError, match="neither a PEM nor"):
            load_device_signer(_seed_file(tmp_path, "not a key", "bad.key"))

    def test_key_id_is_derived_from_the_public_key(self):
        raw = base64.b64decode(PUB_A_B64)
        assert derive_device_key_id(raw) == KEY_ID_A
        with pytest.raises(DeviceIdentityError, match="32 raw bytes"):
            derive_device_key_id(b"short")

    def test_public_key_loader_accepts_b64_hex_and_refuses_garbage(self):
        assert load_device_public_key(PUB_A_B64) == base64.b64decode(PUB_A_B64)
        assert (
            load_device_public_key(base64.b64decode(PUB_A_B64).hex())
            == base64.b64decode(PUB_A_B64)
        )
        with pytest.raises(DeviceIdentityError):
            load_device_public_key("???")


class TestInitWiring:
    def test_init_refuses_a_key_that_cannot_sign(self, tmp_path):
        """The operator asked for non-repudiation: a config whose key cannot
        be read must refuse at init, never ship unsigned events quietly."""
        with pytest.raises(ValueError, match="device_signing_key_file"):
            obsvr.init(
                api_key="k",
                device_signing_key_file=str(tmp_path / "missing.key"),
                policy_refresh_interval_s=0,
            )

    def test_init_installs_the_seal_and_reinit_without_clears_it(self, tmp_path):
        obsvr.init(
            api_key="test-key",
            device_signing_key_file=_seed_file(tmp_path),
            policy_refresh_interval_s=0,
        )
        sealed = {"prompt": "p", "response": "r"}
        sign_event(sealed, "test-key")
        assert sealed["device_key_id"] == KEY_ID_A
        assert len(sealed["device_sig"]) == 128

        _reset()
        obsvr.init(api_key="test-key", policy_refresh_interval_s=0)
        plain = {"prompt": "p", "response": "r"}
        sign_event(plain, "test-key")
        assert "device_sig" not in plain and "device_key_id" not in plain


class TestSealAndVerify:
    def test_the_seal_is_additive_to_the_hmac_chain(self, tmp_path, monkeypatch):
        """Byte-for-byte: the HMAC fields of a sealed chain are identical to
        an unsealed chain over the same inputs — existing chains and
        verifiers are untouched by construction.

        timestamp_sdk is part of the signature payload, so "the same inputs"
        has to include the clock: freeze it, or the sealed and plain chains
        are signed at different milliseconds and every sdk_sig — and thus
        every following prev_sig — diverges for a reason that has nothing to
        do with the seal. Without the freeze this passed only when both chains
        happened to land in one millisecond, which a tight loop does and a
        fixture-laden run does not.
        """
        monkeypatch.setattr(time, "time", lambda: 1_700_000_000.0)
        configure_device_signer(load_device_signer(_seed_file(tmp_path)))
        sealed = _signed_chain()
        _reset_sender()
        plain = _signed_chain()
        # The session id is stable in-process, and the clock is frozen, so the
        # entire HMAC — sdk_sig itself, not just its inputs — must be identical.
        # The seal only ADDS device fields; it never touches the HMAC preimage.
        for s, p in zip(sealed, plain):
            for field in ("seq_no", "prompt", "response", "prev_sig", "sdk_sig"):
                assert s.get(field) == p.get(field)
            assert "device_sig" in s and "device_sig" not in p
        # The sealed chain still verifies under the plain HMAC verifier, which
        # ignores the device fields entirely.
        result = verify_chain(sealed, "test-key")
        assert result.valid and not result.device_checked
        assert result.device_signed_events == len(sealed)

    def test_an_api_key_holder_cannot_forge_past_a_pinned_device_key(self, tmp_path):
        """The property the feature exists for: a chain re-minted with only
        the API key passes HMAC verification and fails the device tier."""
        configure_device_signer(load_device_signer(_seed_file(tmp_path)))
        genuine = _signed_chain()
        raw_pub = base64.b64decode(PUB_A_B64)
        assert verify_chain(genuine, "test-key", device_public_keys=[raw_pub]).valid

        _reset_sender()  # the "attacker": holds the API key, not the device key
        forged = _signed_chain()
        assert verify_chain(forged, "test-key").valid, "HMAC alone cannot tell"
        result = verify_chain(forged, "test-key", device_public_keys=[raw_pub])
        assert not result.valid
        assert "Device signature missing" in result.breaks[0]["reason"]

    def test_a_foreign_key_is_reported_never_trusted_on_first_use(self, tmp_path):
        configure_device_signer(load_device_signer(_seed_file(tmp_path, SEED_B, "b.key")))
        events = _signed_chain()
        raw_pub_a = base64.b64decode(PUB_A_B64)
        result = verify_chain(events, "test-key", device_public_keys=[raw_pub_a])
        assert not result.valid
        assert "Device key unknown" in result.breaks[0]["reason"]
        assert "is not among the pinned keys" in result.breaks[0]["reason"]

    def test_device_only_verification_needs_no_api_key(self, tmp_path):
        """The device seal covers the same payload the HMAC covers, so
        content, order and the decision fields verify under the public key
        alone — and a content tamper is caught without any shared secret."""
        configure_device_signer(load_device_signer(_seed_file(tmp_path)))
        events = _signed_chain()
        raw_pub = base64.b64decode(PUB_A_B64)
        assert verify_chain(events, None, device_public_keys=[raw_pub]).valid

        tampered = copy.deepcopy(events)
        tampered[1]["prompt"] = "EDITED"
        result = verify_chain(tampered, None, device_public_keys=[raw_pub])
        assert not result.valid
        assert "Device signature mismatch" in result.breaks[0]["reason"]

    def test_neither_key_supplied_is_a_usage_error(self):
        with pytest.raises(ValueError, match="api_key"):
            verify_chain([], None)

    def test_verify_reports_could_not_check_without_a_backend(
        self, tmp_path, monkeypatch
    ):
        """No backend must never fold into valid or tampered: the result says
        the tier could not run, and stays on whatever the HMAC tier said."""
        configure_device_signer(load_device_signer(_seed_file(tmp_path)))
        events = _signed_chain()
        from obsvr import policy_verify

        monkeypatch.setattr(policy_verify, "_backend", None)
        result = verify_chain(
            events, "test-key", device_public_keys=[base64.b64decode(PUB_A_B64)]
        )
        assert result.valid  # the HMAC tier passed
        assert not result.device_checked
        assert "no Ed25519 backend" in result.device_unverified_reason


class TestConformancePins:
    def test_the_pinned_signature_bytes_reproduce(self, tmp_path):
        """Consume the shared fixture: same seed, same payload, same bytes,
        in both languages (Ed25519 is deterministic per RFC 8032)."""
        from pathlib import Path

        fixture = json.loads(
            (Path(__file__).parent / "../../conformance/fixtures/signing_vectors.json")
            .resolve()
            .read_text()
        )
        section = fixture["device_signatures"]
        signer = load_device_signer(_seed_file(tmp_path, section["seed_hex"]))
        assert signer.key_id == section["key_id"]
        assert signer.public_key_b64 == section["public_key_b64"]
        for case in section["cases"]:
            assert signer.sign_payload(case["signature_payload"]) == case["device_sig"], case["name"]
            assert verify_device_sig(
                signer.raw_public_key,
                signer.key_id,
                case["signature_payload"],
                case["device_sig"],
            ) is True
