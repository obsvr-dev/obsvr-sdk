#!/usr/bin/env node
/**
 * Cross-language parity for the obsvr-verify CLI.
 *
 * The verification claim is language-unqualified: an auditor holding an export
 * must reach the same verdict whichever CLI they run. That is only true if both
 * are driven over the SAME export and compared, which is what this does - the
 * unit suites on each side can agree with themselves forever while disagreeing
 * with each other.
 *
 * The export is built from the shared signing vectors
 * (conformance/fixtures/signing_vectors.json), so the chain is the fixture's,
 * not a per-language literal. The gap-marker cases are built from
 * conformance/fixtures/audit_gap.json for the same reason: a chain that
 * declares dropped events must read the same in both CLIs, or an auditor
 * running one of them is told a lossy run was clean.
 *
 * Compared per case: exit code, stdout, and stderr, byte for byte. Exit codes
 * and verdicts are the contract; the prose is compared too because it costs
 * nothing and catches a drift the verdict alone would hide.
 *
 * Requires the TypeScript SDK to be built (sdk-typescript/dist/cli-verify.js). Run:
 *   npm --prefix sdk-typescript run build && node scripts/check-cli-verify-parity.mjs
 */
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { resolvePython } from "./python-interpreter.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const TS_CLI = join(root, "sdk-typescript", "dist", "cli-verify.js");
const PY_DIR = join(root, "sdk-python");
// Same interpreter resolution as the canonicalizer parity check, so the two
// cross-language scripts cannot disagree about which Python they are testing.
const { python } = resolvePython(root);

if (!existsSync(TS_CLI)) {
  console.error(`✗ ${TS_CLI} is missing. Build it first: npm --prefix sdk-typescript run build`);
  process.exit(2);
}

const vectors = JSON.parse(
  readFileSync(join(root, "conformance", "fixtures", "signing_vectors.json"), "utf8"),
);
const API_KEY = vectors.api_key;
/** The fixture chain, with the session id the fixture keeps alongside it. */
const chain = vectors.events.map((e) => ({ ...e, sdk_session_id: vectors.session_id }));

const gapFixture = JSON.parse(
  readFileSync(join(root, "conformance", "fixtures", "audit_gap.json"), "utf8"),
);
/** A chain whose middle event is a signed gap marker declaring 1,234 losses. */
const gapChain = gapFixture.signing.events.map((e) => ({
  ...e,
  sdk_session_id: gapFixture.signing.session_id,
}));

/** A dual-sealed chain: the fixture's format-3 events, each also carrying an
 *  Ed25519 device_sig, plus the public key the verifier pins. The device
 *  tier's cross-language parity is checked over this, keyed and device-only. */
const deviceChain = vectors.device_chain.events;
const DEVICE_PUBKEY = vectors.device_chain.public_key_b64;

const workdir = mkdtempSync(join(tmpdir(), "obsvr-cli-parity-"));
const write = (name, value) => {
  const path = join(workdir, name);
  writeFileSync(path, JSON.stringify(value));
  return path;
};

const tampered = JSON.parse(JSON.stringify(chain));
tampered[1].prompt = "tampered";
const gapped = [chain[0], { ...chain[1], seq_no: 5 }];
/** Two independent tampers: a content edit at event 0 AND a forged signature
 *  at event 1. Both CLIs must report BOTH breaks in one run, identically. */
const multiBroken = JSON.parse(JSON.stringify(chain));
multiBroken[0].prompt = "tampered";
multiBroken[1].sdk_sig = "0".repeat(64);

const CASES = [
  { name: "valid chain, keyless", args: [write("valid.json", chain)] },
  { name: "valid chain, --api-key", args: [write("valid.json", chain), "--api-key", API_KEY] },
  { name: "flags before the file", args: ["--api-key", API_KEY, write("valid.json", chain)] },
  {
    name: "trace bundle shape",
    args: [write("bundle.json", { trace: { steps: chain } }), "--api-key", API_KEY],
  },
  { name: "steps bundle shape", args: [write("steps.json", { steps: chain })] },
  { name: "events bundle shape", args: [write("events.json", { events: chain })] },
  {
    name: "tampered content, --api-key",
    args: [write("tampered.json", tampered), "--api-key", API_KEY],
  },
  { name: "tampered content, keyless (undetectable by design)", args: [write("tampered.json", tampered)] },
  { name: "seq_no gap, keyless", args: [write("gapped.json", gapped)] },
  {
    // A plausible seq_no and a well-formed sdk_sig with NO prev_sig is an
    // unsigned insertion; the keyless tier refuses it in both languages.
    name: "unsigned insertion without prev_sig, keyless",
    args: [
      write("inserted.json", [
        ...chain,
        {
          sdk_session_id: vectors.session_id,
          seq_no: chain[chain.length - 1].seq_no + 1,
          timestamp_sdk: chain[chain.length - 1].timestamp_sdk + 1,
          prompt: "inserted",
          response: "",
          sdk_sig: "a".repeat(64),
        },
      ]),
    ],
  },
  {
    // The chain start has no predecessor, so an absent prev_sig there is
    // legitimate.
    name: "first event without prev_sig, keyless",
    args: [
      write("no-first-prev.json", [
        Object.fromEntries(Object.entries(chain[0]).filter(([k]) => k !== "prev_sig")),
        ...chain.slice(1),
      ]),
    ],
  },
  // Exit 3 (valid but incomplete) is the contract these pin: a chain that
  // declares dropped events must not pass a `verify && deploy` gate, and both
  // CLIs must agree on that status, not just on the printed finding.
  {
    name: "declared audit gap, --api-key (exit 3)",
    args: [write("audit-gap.json", gapChain), "--api-key", gapFixture.signing.api_key],
  },
  { name: "declared audit gap, keyless (exit 3)", args: [write("audit-gap.json", gapChain)] },
  {
    name: "declared audit gap, --allow-gaps opts back into 0",
    args: [write("audit-gap.json", gapChain), "--api-key", gapFixture.signing.api_key, "--allow-gaps"],
  },
  {
    name: "--allow-gaps on a clean chain changes nothing",
    args: [write("valid.json", chain), "--api-key", API_KEY, "--allow-gaps"],
  },
  {
    name: "--allow-gaps does not rescue a broken chain",
    args: [write("tampered.json", tampered), "--api-key", API_KEY, "--allow-gaps"],
  },
  {
    name: "two breaks, --api-key (every break reported, not the first)",
    args: [write("multi-broken.json", multiBroken), "--api-key", API_KEY],
  },
  { name: "valid chain, --api-key --json", args: [write("valid.json", chain), "--api-key", API_KEY, "--json"] },
  { name: "valid chain, keyless --json", args: [write("valid.json", chain), "--json"] },
  {
    name: "two breaks, --api-key --json",
    args: [write("multi-broken.json", multiBroken), "--api-key", API_KEY, "--json"],
  },
  { name: "seq_no gap, keyless --json", args: [write("gapped.json", gapped), "--json"] },
  {
    name: "declared audit gap, --api-key --json (exit 3 in the document)",
    args: [write("audit-gap.json", gapChain), "--api-key", gapFixture.signing.api_key, "--json"],
  },
  {
    name: "declared audit gap, --json --allow-gaps maps the document to 0",
    args: [write("audit-gap.json", gapChain), "--api-key", gapFixture.signing.api_key, "--json", "--allow-gaps"],
  },
  {
    name: "device chain, --api-key + --device-pubkey (both seals)",
    args: [write("device.json", deviceChain), "--api-key", API_KEY, "--device-pubkey", DEVICE_PUBKEY],
  },
  {
    name: "device chain, --device-pubkey alone (no api key, no shared secret)",
    args: [write("device.json", deviceChain), "--device-pubkey", DEVICE_PUBKEY],
  },
  {
    name: "device chain, both seals --json",
    args: [write("device.json", deviceChain), "--api-key", API_KEY, "--device-pubkey", DEVICE_PUBKEY, "--json"],
  },
  {
    name: "device chain, device-only --json",
    args: [write("device.json", deviceChain), "--device-pubkey", DEVICE_PUBKEY, "--json"],
  },
  {
    name: "device seal stripped is a break (pinning asserts the expectation)",
    args: [
      write("device-stripped.json", [
        deviceChain[0],
        Object.fromEntries(
          Object.entries(deviceChain[1]).filter(([k]) => k !== "device_sig" && k !== "device_key_id"),
        ),
      ]),
      "--device-pubkey",
      DEVICE_PUBKEY,
    ],
  },
  {
    name: "unpinned device key is foreign, not trusted on first use",
    args: [write("device.json", deviceChain), "--device-pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
  },
  { name: "wrong key", args: [write("valid.json", chain), "--api-key", "not-the-key"] },
  { name: "unrecognized shape", args: [write("weird.json", { nope: true })] },
  { name: "missing file argument", args: [] },
  {
    name: "nonexistent file",
    args: [join(workdir, "absent.json")],
    // The message ends in the runtime's own OS error text ("ENOENT: no such
    // file or directory" vs "[Errno 2] No such file or directory"), which is
    // not something either SDK should paper over. Everything that IS the
    // contract - exit code, and the SDK's own wording up to the cause - is
    // still compared exactly.
    stderrPrefix: "✗ Cannot read ",
  },
];

/** Python is invoked as a module so this runs against the tree under test,
 *  installed console script or not - the entry point itself is asserted by the
 *  Python unit suite. */
const runPy = (args) =>
  spawnSync(python, ["-m", "obsvr.cli_verify", ...args], { cwd: PY_DIR, encoding: "utf8" });
const runTs = (args) => spawnSync("node", [TS_CLI, ...args], { cwd: root, encoding: "utf8" });

let failures = 0;
for (const testCase of CASES) {
  const ts = runTs(testCase.args);
  const py = runPy(testCase.args);
  const diffs = [];
  if (ts.status !== py.status) diffs.push(`exit code: ts=${ts.status} py=${py.status}`);
  if (ts.stdout !== py.stdout) diffs.push(`stdout:\n--- ts ---\n${ts.stdout}--- py ---\n${py.stdout}`);
  if (testCase.stderrPrefix) {
    for (const [lang, out] of [["ts", ts.stderr], ["py", py.stderr]]) {
      if (!out.startsWith(testCase.stderrPrefix)) {
        diffs.push(`${lang} stderr does not start with ${JSON.stringify(testCase.stderrPrefix)}: ${out}`);
      }
    }
  } else if (ts.stderr !== py.stderr) {
    diffs.push(`stderr:\n--- ts ---\n${ts.stderr}--- py ---\n${py.stderr}`);
  }
  if (diffs.length) {
    failures++;
    console.error(`✗ ${testCase.name}`);
    for (const d of diffs) console.error(`   ${d}`);
  } else {
    console.log(`✓ ${testCase.name} (exit ${ts.status})`);
  }
}

if (failures) {
  console.error(`✗ obsvr-verify CLI parity FAILED: ${failures}/${CASES.length} case(s) diverged`);
  process.exit(1);
}
console.log(`✓ obsvr-verify CLI parity: ${CASES.length} cases identical in both languages`);
