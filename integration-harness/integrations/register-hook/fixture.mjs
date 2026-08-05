/**
 * Child fixture for the zero-code auto-discovery test. Launched by test.mjs as:
 *   node --import @obsvr/sdk/register fixture.mjs
 *
 * Imports the REAL `openai` package with no obsvr-specific code, points it at a
 * local stub endpoint (no key, no network), and proves the module interceptor
 * governs it: allowed calls flow and are audited; an SSN prompt is blocked
 * before it reaches the provider. Emits a RESULT: JSON line.
 */
import { createServer } from "node:http";
import OpenAI from "openai";
import { obsvr } from "@obsvr/sdk";

let stubHits = 0;
const stub = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    stubHits += 1;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        id: "chatcmpl-stub",
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: "gpt-4o",
        choices: [{ index: 0, message: { role: "assistant", content: "stubbed reply" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
      }),
    );
  });
});
await new Promise((r) => stub.listen(0, "127.0.0.1", r));
const port = stub.address().port;

// Constructed BEFORE obsvr.init(): the interceptor must hand back a working
// client that picks up governance automatically after init.
const client = new OpenAI({ apiKey: "test-not-real", baseURL: `http://127.0.0.1:${port}/v1` });
const results = { instanceofOk: client instanceof OpenAI };

obsvr.init({
  apiKey: process.env.OBSVR_API_KEY || "test-key",
  ingestUrl: process.env.OBSVR_TEST_INGEST_URL,
  environment: "development",
  sampleRate: 1,
  piiPolicy: {},
  policyRefreshIntervalMs: 0,
});

const res = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "hello from the register hook" }],
});
results.reply = res.choices?.[0]?.message?.content;

try {
  await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: "My SSN is 123-45-6789" }],
  });
  results.ssnBlocked = false;
} catch {
  results.ssnBlocked = true;
}
results.stubHits = stubHits;

// Drain the fire-and-forget queue before exit (process.exit would kill
// in-flight sends), then give the parent tee a beat to capture + forward.
await obsvr.flush();
await new Promise((r) => setTimeout(r, 400));
stub.close();
console.log("RESULT:" + JSON.stringify(results));
process.exit(0);
