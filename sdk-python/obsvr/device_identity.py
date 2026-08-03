"""Optional client-held device signing identity (Ed25519).

The HMAC chain is keyed from the API key, so every API-key holder — the
customer, the service, anyone who has ever seen the key — can mint a complete
valid chain. That is an integrity mechanism, not non-repudiation, and
``SECURITY.md`` says so. This module is the opt-in second seal: a device
private key the operator generates and holds, whose signature over the SAME
preimage the HMAC signs gives non-repudiation against everyone who does not
hold that key. The HMAC chain is untouched — every existing chain and
verifier keeps working, unchanged, forever; device fields are additive.

What is signed: ``obsvr-device/1 \\x00 key_id \\x00 signature_payload`` —
the version label and the key id are inside the signature, so neither can be
swapped without breaking it, and the payload is byte-identical to the HMAC's
(content, order via ``prev_sig`` linkage, and the format-3 decision fields).

Key handling rules, stated because the failure modes are known:

- **This module NEVER generates a key.** Not at init, not at verify. A
  verifier that mints key material reports every genuine record as foreign
  on a fresh machine; generation is the operator's act, out of band
  (``openssl genpkey -algorithm ed25519``).
- The key id is ``sha256(raw 32-byte public key)`` hex, first 16 chars —
  derived, never configured, so a record cannot claim an identity its
  signature does not prove.
- The key id on an event is a HINT for key selection. Verification trusts
  only keys pinned out of band; an event signed by an unpinned key is
  reported as foreign, never trusted on first use.
- With a key file configured and no Ed25519 backend importable, ``init()``
  REFUSES rather than shipping unsigned events under a config that promised
  signing — a silent no-op here is the defect, not the safeguard. Python
  needs ``pip install "obsvr-sdk[crypto]"`` (or PyNaCl); TypeScript signs
  with ``node:crypto`` and needs nothing.

Twin: sdk-typescript/src/proxy/device-identity.ts. The signature bytes are
pinned cross-language in ``conformance/fixtures/signing_vectors.json``
(Ed25519 is deterministic per RFC 8032, so one literal pin covers both).
"""

import base64
import binascii
import hashlib
import os
from typing import Any, Callable, Optional

#: Leads the device preimage. A version bump here is a new label, verified
#: side by side with this one — never a silent semantic change.
DEVICE_SIG_VERSION = "obsvr-device/1"

#: Length of the derived key id (hex chars of sha256(raw public key)).
DEVICE_KEY_ID_LEN = 16


class DeviceIdentityError(ValueError):
    """A configured device identity that cannot actually sign or be read.

    Raised loudly at init / CLI-argument time: the operator asked for
    non-repudiation, so anything short of a working signer must refuse.
    """


def derive_device_key_id(raw_public_key: bytes) -> str:
    """``sha256(raw 32-byte public key)`` hex, truncated to 16 chars."""
    if len(raw_public_key) != 32:
        raise DeviceIdentityError(
            f"device public key must be 32 raw bytes, got {len(raw_public_key)}"
        )
    return hashlib.sha256(raw_public_key).hexdigest()[:DEVICE_KEY_ID_LEN]


def device_preimage(key_id: str, signature_payload: str) -> bytes:
    """The exact bytes the device key signs (see module docstring)."""
    return (
        DEVICE_SIG_VERSION.encode("utf-8")
        + b"\x00"
        + key_id.encode("utf-8")
        + b"\x00"
        + signature_payload.encode("utf-8")
    )


def _decode_key_material(text: str, *, what: str) -> Optional[bytes]:
    """32 raw bytes from a hex or base64 rendering, or None if neither."""
    stripped = "".join(text.split())
    if len(stripped) == 64:
        try:
            raw = binascii.unhexlify(stripped)
            if len(raw) == 32:
                return raw
        except (binascii.Error, ValueError):
            pass
    try:
        raw = base64.b64decode(stripped, validate=True)
        if len(raw) == 32:
            return raw
    except (binascii.Error, ValueError):
        pass
    return None


class DeviceSigner:
    """A loaded, working signing identity: ``sign()`` or it does not exist."""

    def __init__(self, sign: Callable[[bytes], bytes], raw_public_key: bytes) -> None:
        self._sign = sign
        self.raw_public_key = raw_public_key
        self.public_key_b64 = base64.b64encode(raw_public_key).decode("ascii")
        self.key_id = derive_device_key_id(raw_public_key)

    def sign_payload(self, signature_payload: str) -> str:
        """Hex Ed25519 signature over the device preimage for this payload."""
        return self._sign(device_preimage(self.key_id, signature_payload)).hex()


def _signer_from_seed(seed: bytes) -> DeviceSigner:
    """Build a signer from a raw 32-byte seed via whichever backend imports."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        key = Ed25519PrivateKey.from_private_bytes(seed)
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        raw_pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return DeviceSigner(key.sign, raw_pub)
    except ImportError:
        pass

    try:
        from nacl.signing import SigningKey

        key = SigningKey(seed)
        return DeviceSigner(
            lambda message: key.sign(message).signature,
            bytes(key.verify_key),
        )
    except ImportError:
        pass

    raise DeviceIdentityError(
        "device signing is configured but no Ed25519 backend is importable; "
        'install one: pip install "obsvr-sdk[crypto]" (or pynacl)'
    )


def _signer_from_pem(pem_text: str) -> DeviceSigner:
    """Build a signer from a PKCS8 PEM (needs ``cryptography``)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )
    except ImportError:
        raise DeviceIdentityError(
            "the device key file is PEM, which needs the cryptography backend; "
            'install it: pip install "obsvr-sdk[crypto]" — or store the key as '
            "a raw 32-byte seed (hex or base64), which PyNaCl can also read"
        ) from None

    try:
        key = load_pem_private_key(pem_text.encode("utf-8"), password=None)
    except Exception as exc:
        raise DeviceIdentityError(f"unreadable device key PEM: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise DeviceIdentityError(
            f"device key must be Ed25519, got {type(key).__name__}"
        )
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw_pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return DeviceSigner(key.sign, raw_pub)


def load_device_signer(path: str) -> DeviceSigner:
    """Load the operator-generated private key at ``path``, loudly.

    Accepted forms: a PKCS8 PEM (``BEGIN PRIVATE KEY``), or a raw 32-byte
    seed rendered as 64 hex chars or base64. Anything else — including a
    missing file — raises :class:`DeviceIdentityError`. Never generates.
    """
    if not path or not os.path.isfile(path):
        raise DeviceIdentityError(
            f"device signing key file not found: {path!r} — this SDK never "
            "generates keys; create one out of band "
            "(openssl genpkey -algorithm ed25519)"
        )
    try:
        text = open(path, "r", encoding="utf-8").read()
    except OSError as exc:
        raise DeviceIdentityError(f"unreadable device key file {path!r}: {exc}") from exc

    if "BEGIN" in text:
        return _signer_from_pem(text)
    seed = _decode_key_material(text, what="private seed")
    if seed is None:
        raise DeviceIdentityError(
            f"device key file {path!r} is neither a PEM nor a 32-byte seed "
            "(hex or base64)"
        )
    return _signer_from_seed(seed)


def load_device_public_key(value: str) -> bytes:
    """Raw 32 public-key bytes from a verifier-supplied value.

    Accepts the raw key as base64 or 64-char hex, or a path to a PEM public
    key (``BEGIN PUBLIC KEY``; needs ``cryptography``). For pinning at
    verify time — the caller derives the key id, never the export.
    """
    text = value
    if os.path.isfile(value):
        try:
            text = open(value, "r", encoding="utf-8").read()
        except OSError as exc:
            raise DeviceIdentityError(
                f"unreadable device public key file {value!r}: {exc}"
            ) from exc
    if "BEGIN" in text:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
                load_pem_public_key,
            )
        except ImportError:
            raise DeviceIdentityError(
                "a PEM public key needs the cryptography backend; install it "
                '(pip install "obsvr-sdk[crypto]") or supply the raw key as '
                "base64/hex"
            ) from None
        try:
            key = load_pem_public_key(text.encode("utf-8"))
        except Exception as exc:
            raise DeviceIdentityError(f"unreadable public key PEM: {exc}") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise DeviceIdentityError(
                f"device public key must be Ed25519, got {type(key).__name__}"
            )
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    raw = _decode_key_material(text, what="public key")
    if raw is None:
        raise DeviceIdentityError(
            "device public key must be 32 raw bytes as base64 or hex, or a "
            "PEM file"
        )
    return raw


def verify_device_sig(
    raw_public_key: bytes, key_id: str, signature_payload: str, sig_hex: Any
) -> Optional[bool]:
    """True/False under the given key, or None if no backend is importable.

    ``None`` is distinct on purpose: the caller (the verifier) must report
    "could not check" as its own outcome, never fold it into valid or
    tampered.
    """
    from .policy_verify import _resolve_backend

    backend = _resolve_backend()
    if backend is None:
        return None
    if not isinstance(sig_hex, str):
        return False
    try:
        signature = binascii.unhexlify(sig_hex)
    except (binascii.Error, ValueError):
        return False
    return backend(raw_public_key, device_preimage(key_id, signature_payload), signature)
