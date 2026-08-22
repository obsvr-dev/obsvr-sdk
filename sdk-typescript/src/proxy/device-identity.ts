/**
 * Optional client-held device signing identity (Ed25519).
 *
 * The HMAC chain is keyed from the API key, so every API-key holder can mint
 * a complete valid chain — an integrity mechanism, not non-repudiation, and
 * SECURITY.md says so. This module is the opt-in second seal: a device
 * private key the operator generates and holds, whose signature over the
 * SAME payload the HMAC signs gives non-repudiation against everyone who
 * does not hold that key. The HMAC chain is untouched — device fields are
 * additive, so every existing chain and verifier keeps working unchanged.
 *
 * What is signed: `obsvr-device/1 \0 key_id \0 signature_payload` — the
 * version label and the key id are inside the signature, so neither can be
 * swapped without breaking it.
 *
 * Key handling rules, stated because the failure modes are known:
 * - This module NEVER generates a key — not at init, not at verify. A
 *   verifier that mints key material reports every genuine record as
 *   foreign on a fresh machine. Generation is the operator's act, out of
 *   band (`openssl genpkey -algorithm ed25519`).
 * - The key id is sha256(raw 32-byte public key) hex, first 16 chars —
 *   derived, never configured.
 * - The key id on an event is a HINT for key selection; verification trusts
 *   only keys pinned out of band. An unpinned key id is reported as
 *   foreign, never trusted on first use.
 *
 * Twin: sdk-python/obsvr/device_identity.py. Signature bytes are pinned
 * cross-language in conformance/fixtures/signing_vectors.json (Ed25519 is
 * deterministic per RFC 8032, so one literal pin covers both).
 *
 * @packageDocumentation
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

/** Leads the device preimage; a bump is a new label, never a silent change. */
export const DEVICE_SIG_VERSION = "obsvr-device/1";

/** Length of the derived key id (hex chars of sha256(raw public key)). */
export const DEVICE_KEY_ID_LEN = 16;

/** A configured device identity that cannot actually sign or be read. */
export class DeviceIdentityError extends Error {}

/** PKCS8 DER framing for a raw Ed25519 seed (RFC 8410). */
const PKCS8_ED25519_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
/** SPKI DER framing for a raw Ed25519 public key (RFC 8410). */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function deriveDeviceKeyId(rawPublicKey: Buffer): string {
  if (rawPublicKey.length !== 32) {
    throw new DeviceIdentityError(
      `device public key must be 32 raw bytes, got ${rawPublicKey.length}`,
    );
  }
  return createHash("sha256")
    .update(rawPublicKey)
    .digest("hex")
    .slice(0, DEVICE_KEY_ID_LEN);
}

/** The exact bytes the device key signs. */
export function devicePreimage(keyId: string, signaturePayload: string): Buffer {
  return Buffer.concat([
    Buffer.from(DEVICE_SIG_VERSION, "utf-8"),
    Buffer.from([0]),
    Buffer.from(keyId, "utf-8"),
    Buffer.from([0]),
    Buffer.from(signaturePayload, "utf-8"),
  ]);
}

/** 32 raw bytes from a hex or base64 rendering, or null if neither. */
function decodeKeyMaterial(text: string): Buffer | null {
  const stripped = text.replace(/\s+/g, "");
  if (stripped.length === 64 && /^[0-9a-fA-F]+$/.test(stripped)) {
    const raw = Buffer.from(stripped, "hex");
    if (raw.length === 32) return raw;
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(stripped)) {
    const raw = Buffer.from(stripped, "base64");
    if (raw.length === 32) return raw;
  }
  return null;
}

export interface DeviceSigner {
  keyId: string;
  rawPublicKey: Buffer;
  publicKeyB64: string;
  /** Hex Ed25519 signature over the device preimage for this payload. */
  signPayload(signaturePayload: string): string;
  /** Hex Ed25519 signature over caller-supplied raw bytes (no legacy domain). */
  signBytes(message: Uint8Array): string;
}

function signerFromKeyObject(key: KeyObject): DeviceSigner {
  if (key.asymmetricKeyType !== "ed25519") {
    throw new DeviceIdentityError(
      `device key must be Ed25519, got ${String(key.asymmetricKeyType)}`,
    );
  }
  const spki = createPublicKey(key).export({ type: "spki", format: "der" });
  const rawPublicKey = Buffer.from(spki.subarray(spki.length - 32));
  const keyId = deriveDeviceKeyId(rawPublicKey);
  return {
    keyId,
    rawPublicKey,
    publicKeyB64: rawPublicKey.toString("base64"),
    signPayload: (signaturePayload: string) =>
      cryptoSign(null, devicePreimage(keyId, signaturePayload), key).toString(
        "hex",
      ),
    signBytes: (message: Uint8Array) =>
      cryptoSign(null, Buffer.from(message), key).toString("hex"),
  };
}

/**
 * Load the operator-generated private key at `path`, loudly. Accepted
 * forms: a PKCS8 PEM (`BEGIN PRIVATE KEY`) or a raw 32-byte seed as 64 hex
 * chars or base64. Anything else — including a missing file — throws.
 * Never generates.
 */
export function loadDeviceSigner(path: string): DeviceSigner {
  if (!path || !existsSync(path)) {
    throw new DeviceIdentityError(
      `device signing key file not found: ${JSON.stringify(path)} — this SDK ` +
        "never generates keys; create one out of band " +
        "(openssl genpkey -algorithm ed25519)",
    );
  }
  const text = readFileSync(path, "utf-8");
  try {
    if (text.includes("BEGIN")) {
      return signerFromKeyObject(createPrivateKey(text));
    }
    const seed = decodeKeyMaterial(text);
    if (seed === null) {
      throw new DeviceIdentityError(
        `device key file ${JSON.stringify(path)} is neither a PEM nor a ` +
          "32-byte seed (hex or base64)",
      );
    }
    return signerFromKeyObject(
      createPrivateKey({
        key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
        format: "der",
        type: "pkcs8",
      }),
    );
  } catch (err) {
    if (err instanceof DeviceIdentityError) throw err;
    throw new DeviceIdentityError(
      `unreadable device key file ${JSON.stringify(path)}: ${String(err)}`,
    );
  }
}

/**
 * Raw 32 public-key bytes from a verifier-supplied value: base64, 64-char
 * hex, or a path to a PEM public key. For pinning at verify time — the
 * caller derives the key id, never the export.
 */
export function loadDevicePublicKey(value: string): Buffer {
  let text = value;
  if (existsSync(value)) {
    text = readFileSync(value, "utf-8");
  }
  if (text.includes("BEGIN")) {
    try {
      const key = createPublicKey(text);
      if (key.asymmetricKeyType !== "ed25519") {
        throw new DeviceIdentityError(
          `device public key must be Ed25519, got ${String(key.asymmetricKeyType)}`,
        );
      }
      const spki = key.export({ type: "spki", format: "der" });
      return Buffer.from(spki.subarray(spki.length - 32));
    } catch (err) {
      if (err instanceof DeviceIdentityError) throw err;
      throw new DeviceIdentityError(`unreadable public key PEM: ${String(err)}`);
    }
  }
  const raw = decodeKeyMaterial(text);
  if (raw === null) {
    throw new DeviceIdentityError(
      "device public key must be 32 raw bytes as base64 or hex, or a PEM file",
    );
  }
  return raw;
}

/** True/false under the given key. Node always has an Ed25519 backend. */
export function verifyDeviceSig(
  rawPublicKey: Buffer,
  keyId: string,
  signaturePayload: string,
  sigHex: unknown,
): boolean {
  if (typeof sigHex !== "string" || !/^[0-9a-fA-F]+$/.test(sigHex)) {
    return false;
  }
  let key: KeyObject;
  try {
    key = createPublicKey({
      key: Buffer.concat([SPKI_ED25519_PREFIX, rawPublicKey]),
      format: "der",
      type: "spki",
    });
  } catch {
    return false;
  }
  return cryptoVerify(
    null,
    devicePreimage(keyId, signaturePayload),
    key,
    Buffer.from(sigHex, "hex"),
  );
}
