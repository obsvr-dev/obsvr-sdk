/**
 * Offline provider-wrapper shims — every infra wrapper exercised with ZERO keys.
 *
 * The five infra provider suites (bedrock, vertex, cloudflare, azure-openai,
 * together) each make REAL, billable cloud calls and skip without credentials.
 * This suite drives the SAME obsvr wrappers keylessly so `node run.mjs offline`
 * covers all five wrapper code paths:
 *
 *   - bedrock     wrapBedrock       -> duck-typed { send } client + a REAL
 *                                      ConverseCommand (constructor.name + .input
 *                                      shape the wrapper reads). AWS send hard-
 *                                      requires network + SigV4 creds, so the
 *                                      transport is stubbed; the wrapper path is real.
 *   - vertex      wrapVertexAI      -> duck-typed { model, generateContent } (Vertex
 *                                      generateContent hard-requires GCP ADC + network).
 *   - cloudflare  wrapWorkersAI     -> duck-typed { run } binding (that IS the env.AI
 *                                      contract; no SDK, no network offline).
 *   - azure       wrapAzureOpenAI   -> REAL openai `AzureOpenAI` client pointed at a
 *                                      local http stub (constructs offline w/ a dummy
 *                                      key + local endpoint; mirrors register-hook).
 *   - together    wrapTogether      -> REAL `together-ai` client pointed at the same
 *                                      local http stub (baseURL override + dummy key).
 *
 * Each wrapper emits a SIGNED event with the correct provider label + operation
 * string (source-verified in src/integrations/*.ts). Governance is proven offline
 * too: an SSN prompt is BLOCKED pre-call (bedrock) and an email is REDACTED
 * before send (together). Ends with a full HMAC-chain verification.
 *
 * Run: node integrations/offline-shims/test.mjs
 */
import { createServer } from "node:http";
import { obsvr } from "@obsvr/sdk";
import { wrapBedrock } from "@obsvr/sdk/bedrock";
import { wrapVertexAI } from "@obsvr/sdk/vertex";
import { wrapWorkersAI } from "@obsvr/sdk/cloudflare";
import { wrapAzureOpenAI } from "@obsvr/sdk/azure-openai";
import { wrapTogether } from "@obsvr/sdk/together";
import { ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import { AzureOpenAI } from "openai";
import Together from "together-ai";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done, showEvents } from "../../lib/check.mjs";
import { assertSignedEvent, verifyCapturedChain } from "../../lib/assert-governance.mjs";

export const meta = { offline: true };

const HELLO = "Say hello in one short sentence.";
const SSN_PROMPT = "My SSN is 123-45-6789 — remember it.";
const EMAIL_PROMPT = "Email me at user@example.com with the summary.";
const ATTR = { user_id: "user_alice", service_name: "billing-svc" };

const BEDROCK_MODEL = "anthropic.claude-3-haiku-20240307-v1:0";
const VERTEX_MODEL = "gemini-1.5-flash";
const CLOUDFLARE_MODEL = "@cf/meta/llama-3.1-8b-instruct";
const AZURE_DEPLOYMENT = "gpt-4o-test";
const TOGETHER_MODEL = "meta-llama/Llama-3.3-70B-Instruct-Turbo";

/** A local OpenAI-compatible chat-completions stub (for the real Azure/Together
 *  clients). Responds to ANY POST with a valid completion — no keys, no cloud. */
async function startOpenAIStub() {
  let hits = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      hits += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: "chatcmpl-stub",
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: "stub-model",
          choices: [
            { index: 0, message: { role: "assistant", content: "stubbed reply" }, finish_reason: "stop" },
          ],
          usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 },
        }),
      );
    });
  });
  const port = await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
  return {
    url: `http://127.0.0.1:${port}`,
    hits: () => hits,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

/** Assert a provider's primary governed llm_call event: correct provider label,
 *  operation string, model pin, subject attribution, and full signed envelope. */
function assertProvider(events, { label, provider, operation, modelIncludes }) {
  // Selected on `source`, the wrapper-declared label, which is unique per leg.
  // `provider` is DERIVED FROM THE ENDPOINT, and every leg here points a real
  // client at this suite's own localhost stub, so the SDK correctly resolves
  // provider to "unknown"/local rather than to the wrapper's brand name —
  // labelling a localhost call by vendor is the data-residency defect that
  // derivation exists to prevent. Matching on `provider` therefore found
  // nothing for two legs, and matching on the derived value instead would
  // collapse both onto the SAME first "unknown" event.
  const ev = events.find((e) => e.source === provider && e.event_type === "llm_call");
  check(`${label}: signed llm_call captured (source=${provider})`, !!ev);
  check(`${label}: operation string is "${operation}"`, ev?.operation === operation);
  check(`${label}: model pinned on the event (${modelIncludes})`, String(ev?.model || "").toLowerCase().includes(modelIncludes));
  check(`${label}: attributed to user_alice / billing-svc`, ev?.user_id === "user_alice" && ev?.service_name === "billing-svc");
  if (ev) assertSignedEvent(ev, label, { decisionRecord: true });
  return ev;
}

export async function run() {
  const apiKey = process.env.OBSVR_API_KEY || "obsvr-test-key";
  const ingest = await startMockIngest();
  const stub = await startOpenAIStub();

  obsvr.init({
    apiKey,
    ingestUrl: ingest.url,
    environment: "development",
    piiPolicy: {}, // severity-driven: ssn BLOCK, email REDACT
    policyRefreshIntervalMs: 0,
  });

  // --- 1. Bedrock: duck-typed { send } + REAL ConverseCommand ------------------
  const bedrockStub = {
    async send(_command) {
      return {
        output: { message: { role: "assistant", content: [{ text: "hello from bedrock stub" }] } },
        usage: { inputTokens: 5, outputTokens: 3, totalTokens: 8 },
        stopReason: "end_turn",
      };
    },
  };
  const bedrock = wrapBedrock(bedrockStub, ATTR);
  const converse = (text) =>
    bedrock.send(
      new ConverseCommand({
        modelId: BEDROCK_MODEL,
        messages: [{ role: "user", content: [{ text }] }],
        inferenceConfig: { maxTokens: 32 },
      }),
    );
  const bedrockReply = await converse(HELLO);
  console.log(`   Bedrock said: "${bedrockReply.output.message.content[0].text}"`);

  // --- 2. Vertex AI: duck-typed { model, generateContent } ---------------------
  const vertexStub = {
    model: VERTEX_MODEL,
    async generateContent(_request) {
      return {
        response: {
          candidates: [
            { content: { parts: [{ text: "hello from vertex stub" }], role: "model" }, finishReason: "STOP" },
          ],
          usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 3, totalTokenCount: 8 },
          modelVersion: "gemini-1.5-flash-002",
        },
      };
    },
  };
  const vertex = wrapVertexAI(vertexStub, ATTR);
  const vertexReply = await vertex.generateContent({ contents: [{ role: "user", parts: [{ text: HELLO }] }] });
  console.log(`   Vertex said: "${vertexReply.response.candidates[0].content.parts[0].text}"`);

  // --- 3. Cloudflare Workers AI: duck-typed { run } binding --------------------
  const workersBinding = {
    async run(_model, _inputs) {
      return { response: "hello from workers ai stub", usage: { prompt_tokens: 5, completion_tokens: 3, total_tokens: 8 } };
    },
  };
  const ai = wrapWorkersAI(workersBinding, ATTR);
  const cfReply = await ai.run(CLOUDFLARE_MODEL, { messages: [{ role: "user", content: HELLO }] });
  console.log(`   Workers AI said: "${cfReply.response}"`);

  // --- 4. Azure OpenAI: REAL AzureOpenAI client -> local http stub ------------
  const azureClient = new AzureOpenAI({
    apiKey: "test-not-real",
    endpoint: stub.url,
    apiVersion: "2024-06-01",
    deployment: AZURE_DEPLOYMENT,
    maxRetries: 0,
  });
  const azure = wrapAzureOpenAI(azureClient, ATTR);
  const azureReply = await azure.chat.completions.create({
    model: AZURE_DEPLOYMENT,
    max_tokens: 32,
    messages: [{ role: "user", content: HELLO }],
  });
  console.log(`   Azure said: "${azureReply.choices[0].message.content}"`);

  // --- 5. Together AI: REAL together-ai client -> local http stub -------------
  const togetherClient = new Together({ apiKey: "test-not-real", baseURL: `${stub.url}/v1`, maxRetries: 0 });
  const together = wrapTogether(togetherClient, ATTR);
  const togetherReply = await together.chat.completions.create({
    model: TOGETHER_MODEL,
    max_tokens: 32,
    messages: [{ role: "user", content: HELLO }],
  });
  console.log(`   Together said: "${togetherReply.choices[0].message.content}"`);

  // --- Governance offline: SSN BLOCK (bedrock) + email REDACT (together) -------
  let ssnBlocked = false;
  try {
    await converse(SSN_PROMPT);
  } catch (e) {
    ssnBlocked = true;
    console.log(`   SSN call blocked pre-call (bedrock): ${e.message}`);
  }

  await together.chat.completions.create({
    model: TOGETHER_MODEL,
    max_tokens: 32,
    messages: [{ role: "user", content: EMAIL_PROMPT }],
  });

  await obsvr.flush();
  const events = ingest.getEvents();
  showEvents(events);

  // --- Per-provider signed-event assertions (all source-verified) -------------
  assertProvider(events, { label: "bedrock", provider: "bedrock", operation: "bedrock.converse", modelIncludes: "claude" });
  assertProvider(events, { label: "vertex", provider: "vertex_ai", operation: "generateContent", modelIncludes: "gemini" });
  assertProvider(events, { label: "cloudflare", provider: "cloudflare", operation: "ai.run", modelIncludes: "llama" });
  assertProvider(events, { label: "azure", provider: "azure_openai", operation: "chat.completions.create", modelIncludes: "gpt-4o" });
  assertProvider(events, { label: "together", provider: "together", operation: "chat.completions.create", modelIncludes: "llama" });

  // Real clients actually reached the local stub (proves the offline round-trip).
  check("azure + together real clients hit the local stub", stub.hits() >= 3);

  // --- Governance proof (offline) ---------------------------------------------
  const bedrockBlock = events.find((e) => e.provider === "bedrock" && e.event_type === "blocked_call");
  check("bedrock: SSN prompt blocked pre-call (throws)", ssnBlocked);
  check("bedrock: block recorded as a blocked_call event (status 403)", !!bedrockBlock && bedrockBlock.status_code === 403);
  check("SSN never leaked into any recorded event", !/\d{3}-\d{2}-\d{4}/.test(JSON.stringify(events)));
  check("together: email redacted in the stored record ([REDACTED_EMAIL])", JSON.stringify(events).includes("[REDACTED_EMAIL]"));
  check("raw email never leaked into any recorded event", !JSON.stringify(events).includes("user@example.com"));

  // --- Whole capture verifies as an HMAC chain (SDK verifier + independent) ----
  verifyCapturedChain(events, apiKey, "offline-shims");

  await stub.close();
  await ingest.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
