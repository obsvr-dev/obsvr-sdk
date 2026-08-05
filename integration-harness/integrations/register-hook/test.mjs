/**
 * Auto-discovery (zero-code) — production test you can read top to bottom.
 *
 * Spawns a real Node child with `--import @obsvr/sdk/register` running a fixture
 * that imports the REAL openai package UNMODIFIED (no obsvr.wrap anywhere) and
 * points it at a local stub endpoint. Proves the module interceptor governs it:
 * instanceof preserved (no monkey-patching), a client built before init() is
 * governed after, PII blocks before the provider, and audit events arrive at
 * ingest over real HTTP. No API key.
 *
 * Run it directly:
 *   node integrations/register-hook/test.mjs
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

// Zero-code auto-discovery needs no API key: it spawns a child that imports the
// real openai package (--import @obsvr/sdk/register) and points it at a local
// stub. Marked offline so the runner runs it without provider credentials.
export const meta = { offline: true };

const HERE = dirname(fileURLToPath(import.meta.url));
const HARNESS_ROOT = join(HERE, "..", "..");
const FIXTURE = join(HERE, "fixture.mjs");

function runChild(ingestUrl) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "@obsvr/sdk/register", FIXTURE], {
      cwd: HARNESS_ROOT,
      env: { ...process.env, OBSVR_TEST_INGEST_URL: ingestUrl },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

export async function run() {
  const ingest = await startMockIngest();
  const { code, stdout, stderr } = await runChild(ingest.url);

  const line = stdout.split("\n").find((l) => l.startsWith("RESULT:"));
  if (code !== 0 || !line) {
    console.log(`   child stderr: ${stderr.slice(0, 400)}`);
    await ingest.stop();
    check("child ran the register fixture (exit 0 + RESULT line)", false, `exit ${code}`);
    return done.results();
  }
  const r = JSON.parse(line.slice("RESULT:".length));
  console.log(`   fixture: reply="${r.reply}"  ssnBlocked=${r.ssnBlocked}  stubHits=${r.stubHits}`);

  // Give async delivery a beat, then look at what reached ingest.
  await new Promise((res) => setTimeout(res, 300));
  const events = ingest.getEvents();
  showEvents(events);

  check("no monkey-patching → client instanceof OpenAI preserved", r.instanceofOk === true);
  check("client built before init() is governed after (allowed call flowed)", r.reply === "stubbed reply");
  check("PII SSN blocked before reaching the provider", r.ssnBlocked === true);
  check("blocked call never hit the provider (stub saw exactly 1 hit)", r.stubHits === 1);
  check("audit events arrived at ingest over real HTTP (>=2)", events.length >= 2);
  check("a blocked_call event is on the record", events.some((e) => e.event_type === "blocked_call"));

  // Deepen: the child's events arrived over real HTTP; assert the primary
  // llm_call is fully signed and chain-verify the whole capture. The child signs
  // with ITS api key — process.env.OBSVR_API_KEY || "test-key" (fixture.mjs) —
  // so verify with that exact value (not the "obsvr-test-key" the direct suites
  // use). Base integrity only: the auto-discovery path is not one of the three
  // native core-proxy suites, so no decision-record assertion here.
  const firstLlm = events.find((e) => e.event_type === "llm_call");
  assertSignedEvent(firstLlm, "register-hook", { decisionRecord: false });
  verifyCapturedChain(events, process.env.OBSVR_API_KEY || "test-key", "register-hook");

  await ingest.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
