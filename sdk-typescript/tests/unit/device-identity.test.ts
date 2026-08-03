/**
 * The optional client-held device signing identity (Ed25519).
 *
 * The HMAC chain is keyed from the API key, so any key holder can mint a
 * valid chain; the device seal is the opt-in second signature over the SAME
 * payload, giving non-repudiation against everyone who does not hold the
 * device key. These tests pin the loader's refusal behaviour (the SDK NEVER
 * generates key material), the derived key id, the additive stamping, and
 * the property the feature exists for: an API-key holder's re-minted chain
 * fails under the pinned device key. Twin: sdk-python/tests/test_device_identity.py.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  deriveDeviceKeyId,
  DeviceIdentityError,
  loadDevicePublicKey,
  loadDeviceSigner,
  verifyDeviceSig,
} from "../../src/proxy/device-identity";
import { init, _reset, getConfig } from "../../src/proxy/config";
import {
  _resetSender,
  setDeviceSigner,
  signAndEnqueueForTest,
} from "../../src/proxy/sender/fire-and-forget";
import { verifyAuditChain } from "../../src/governance/verify-chain";
import type { AuditEvent } from "../../src/proxy/types";

// RFC 8032 test vector 1 — publicly known, test-only key material.
const SEED_A = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const PUB_A_B64 = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
const KEY_ID_A = "21fe31dfa154a261";
const SEED_B = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";

const tmp = mkdtempSync(join(tmpdir(), "obsvr-device-"));
function seedFile(seed = SEED_A, name = "device.key"): string {
  const path = join(tmp, name);
  writeFileSync(path, seed);
  return path;
}

beforeEach(() => {
  _reset();
  _resetSender();
});
afterEach(() => {
  _reset();
  _resetSender();
});

function signedChain(apiKey = "test-key", n = 3): AuditEvent[] {
  const events: AuditEvent[] = [];
  for (let i = 0; i < n; i++) {
    const event = { prompt: `p${i}`, response: `r${i}`, action_taken: "allowed" } as unknown as AuditEvent;
    signAndEnqueueForTest(getConfig(), event);
    events.push(event);
  }
  return events;
}

describe("device signer loader", () => {
  it("never generates a key — a missing file refuses", () => {
    expect(() => loadDeviceSigner(join(tmp, "does-not-exist.key"))).toThrow(
      /never\s+generates/,
    );
  });

  it("loads hex and base64 seeds to one identity", () => {
    const hexSigner = loadDeviceSigner(seedFile());
    const b64 = Buffer.from(SEED_A, "hex").toString("base64");
    const b64Signer = loadDeviceSigner(seedFile(b64, "b64.key"));
    expect(hexSigner.keyId).toBe(KEY_ID_A);
    expect(b64Signer.keyId).toBe(KEY_ID_A);
    expect(hexSigner.publicKeyB64).toBe(PUB_A_B64);
  });

  it("refuses garbage key material", () => {
    expect(() => loadDeviceSigner(seedFile("not a key", "bad.key"))).toThrow(
      DeviceIdentityError,
    );
  });

  it("derives the key id from the public key", () => {
    expect(deriveDeviceKeyId(Buffer.from(PUB_A_B64, "base64"))).toBe(KEY_ID_A);
    expect(() => deriveDeviceKeyId(Buffer.from("short"))).toThrow(/32 raw bytes/);
  });

  it("loads a public key from base64 and hex, refuses garbage", () => {
    const raw = Buffer.from(PUB_A_B64, "base64");
    expect(loadDevicePublicKey(PUB_A_B64).equals(raw)).toBe(true);
    expect(loadDevicePublicKey(raw.toString("hex")).equals(raw)).toBe(true);
    expect(() => loadDevicePublicKey("???")).toThrow(DeviceIdentityError);
  });
});

describe("init wiring", () => {
  it("refuses a key that cannot sign", () => {
    expect(() =>
      init({ api_key: "k", device_signing_key_file: join(tmp, "missing.key") } as never),
    ).toThrow(/deviceSigningKeyFile/);
  });

  it("installs the seal and a re-init without one clears it", () => {
    init({ api_key: "test-key", device_signing_key_file: seedFile() } as never);
    const sealed = { prompt: "p", response: "r" } as unknown as AuditEvent;
    signAndEnqueueForTest(getConfig(), sealed);
    expect((sealed as { device_key_id?: string }).device_key_id).toBe(KEY_ID_A);
    expect((sealed as { device_sig?: string }).device_sig).toHaveLength(128);

    _reset();
    init({ api_key: "test-key" } as never);
    const plain = { prompt: "p", response: "r" } as unknown as AuditEvent;
    signAndEnqueueForTest(getConfig(), plain);
    expect((plain as { device_sig?: string }).device_sig).toBeUndefined();
  });
});

describe("seal and verify", () => {
  it("is additive: a sealed chain still verifies under HMAC alone", () => {
    init({ api_key: "test-key" } as never);
    setDeviceSigner(loadDeviceSigner(seedFile()));
    const sealed = signedChain();
    const result = verifyAuditChain(sealed, "test-key");
    expect(result.valid).toBe(true);
    expect(result.deviceChecked).toBe(false);
    expect(result.deviceSignedEvents).toBe(sealed.length);
  });

  it("an API-key holder cannot forge past a pinned device key", () => {
    init({ api_key: "test-key" } as never);
    setDeviceSigner(loadDeviceSigner(seedFile()));
    const genuine = signedChain();
    const rawPub = Buffer.from(PUB_A_B64, "base64");
    expect(verifyAuditChain(genuine, "test-key", [rawPub]).valid).toBe(true);

    // The "attacker": holds the API key, not the device key.
    _resetSender();
    const forged = signedChain();
    expect(verifyAuditChain(forged, "test-key").valid).toBe(true); // HMAC alone cannot tell
    const result = verifyAuditChain(forged, "test-key", [rawPub]);
    expect(result.valid).toBe(false);
    expect(result.breaks[0].reason).toMatch(/Device signature missing/);
  });

  it("reports a foreign key, never trusts it on first use", () => {
    init({ api_key: "test-key" } as never);
    setDeviceSigner(loadDeviceSigner(seedFile(SEED_B, "b.key")));
    const events = signedChain();
    const result = verifyAuditChain(events, "test-key", [Buffer.from(PUB_A_B64, "base64")]);
    expect(result.valid).toBe(false);
    expect(result.breaks[0].reason).toMatch(/Device key unknown/);
  });

  it("device-only verification needs no API key and catches a content tamper", () => {
    init({ api_key: "test-key" } as never);
    setDeviceSigner(loadDeviceSigner(seedFile()));
    const events = signedChain();
    const rawPub = Buffer.from(PUB_A_B64, "base64");
    expect(verifyAuditChain(events, null, [rawPub]).valid).toBe(true);

    const tampered = events.map((e) => ({ ...e }));
    tampered[1].prompt = "EDITED";
    const result = verifyAuditChain(tampered as AuditEvent[], null, [rawPub]);
    expect(result.valid).toBe(false);
    expect(result.breaks[0].reason).toMatch(/Device signature mismatch/);
  });

  it("throws when neither key is supplied", () => {
    expect(() => verifyAuditChain([], null)).toThrow(/apiKey/);
  });
});

describe("conformance pins", () => {
  it("reproduces the pinned signature bytes", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
    const fixture = JSON.parse(
      readFileSync(join(root, "conformance", "fixtures", "signing_vectors.json"), "utf8"),
    );
    const section = fixture.device_signatures;
    const signer = loadDeviceSigner(seedFile(section.seed_hex, "pin.key"));
    expect(signer.keyId).toBe(section.key_id);
    expect(signer.publicKeyB64).toBe(section.public_key_b64);
    for (const c of section.cases) {
      expect(signer.signPayload(c.signature_payload)).toBe(c.device_sig);
      expect(
        verifyDeviceSig(signer.rawPublicKey, signer.keyId, c.signature_payload, c.device_sig),
      ).toBe(true);
    }
  });
});
