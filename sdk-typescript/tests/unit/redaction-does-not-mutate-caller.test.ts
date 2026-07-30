/**
 * Outbound PII redaction must not rewrite the caller's own objects.
 *
 * `filterArgs` builds a fresh TOP-LEVEL request object but copies its entries
 * by reference, so `cleaned.messages` is the caller's array and
 * `cleaned.messages[i]` are the caller's message objects. Redaction then wrote
 * through them. The top-level scalars (`system`, `instructions`, a string
 * `input`) were always safe for the same reason — they land on the new object —
 * which is why this was easy to miss: the shallow copy looks like a copy.
 *
 * The consequence is not cosmetic. A conversation history is normally an array
 * the caller keeps and appends to, so one redacted turn silently rewrote the
 * caller's own history, and every later turn sent `[REDACTED_SSN]` where the
 * application still believed it held the real text.
 *
 * Twin: sdk-python/tests/test_redaction_does_not_mutate_caller.py.
 */
import { init, _reset } from "../../src/proxy/config";
import { wrap } from "../../src/proxy/wrapper";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";

const SSN = "123-45-6789";

let seenBodies: any[] = [];
let sentEvents: any[] = [];

function fakeClient() {
  return {
    chat: {
      completions: {
        create: async (body: any) => {
          seenBodies.push(JSON.parse(JSON.stringify(body)));
          return {
            id: "x",
            model: "gpt-4o",
            choices: [{ message: { role: "assistant", content: "ok" } }],
            usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
          };
        },
      },
    },
  };
}

beforeEach(() => {
  _reset();
  _resetSender();
  seenBodies = [];
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    Array.isArray(body) ? sentEvents.push(...body) : sentEvents.push(body);
    return { ok: true, status: 200 };
  };
  init({
    api_key: "test-key",
    ingest_url: "https://x",
    sample_rate: 1,
    // snake_case, to match `api_key` above. Mixing the two spellings makes
    // init() drop this whole key — the warning added for that is in
    // config-key-spelling.test.ts.
    pii_policy: { rules: { ssn: "redact" } },
  });
});

afterEach(() => {
  _reset();
  _resetSender();
});

describe("outbound redaction leaves the caller's objects alone", () => {
  it("does not rewrite a message object the caller still holds", async () => {
    const history = [
      { role: "system", content: "You are a helpful assistant." },
      { role: "user", content: `my ssn is ${SSN}` },
    ];
    const client: any = wrap(fakeClient());

    await client.chat.completions.create({ model: "gpt-4o", messages: history });

    // The provider must have received the redacted text — without this the
    // test would also pass if redaction had simply stopped working.
    const sent = JSON.stringify(seenBodies[0]);
    expect(sent).not.toContain(SSN);
    expect(sent).toContain("[REDACTED_SSN]");

    // And the caller's own array must be untouched.
    expect(history[1].content).toBe(`my ssn is ${SSN}`);
  });

  it("does not rewrite a structured content part the caller still holds", async () => {
    const part = { type: "text", text: `my ssn is ${SSN}` };
    const history = [{ role: "user", content: [part] }];
    const client: any = wrap(fakeClient());

    await client.chat.completions.create({ model: "gpt-4o", messages: history });

    const sent = JSON.stringify(seenBodies[0]);
    expect(sent).not.toContain(SSN);
    expect(sent).toContain("[REDACTED_SSN]");

    expect(part.text).toBe(`my ssn is ${SSN}`);
  });

  it("does not rewrite a Responses-API input item the caller still holds", async () => {
    const item = { role: "user", content: `my ssn is ${SSN}` };
    const client: any = wrap({
      responses: {
        create: async (body: any) => {
          seenBodies.push(JSON.parse(JSON.stringify(body)));
          return { id: "x", model: "gpt-4o", output_text: "ok" };
        },
      },
    });

    await client.responses.create({ model: "gpt-4o", input: [item] });

    const sent = JSON.stringify(seenBodies[0]);
    expect(sent).not.toContain(SSN);
    expect(item.content).toBe(`my ssn is ${SSN}`);
  });

  it("a FROZEN caller message is redacted and the call succeeds", async () => {
    // The behaviour this pins used to be the opposite: a frozen message made
    // the in-place write throw, which resolved closed and refused the call.
    const frozen = Object.freeze({ role: "user", content: `my ssn is ${SSN}` });
    const history = [frozen];
    const client: any = wrap(fakeClient());

    const res = await client.chat.completions.create({
      model: "gpt-4o",
      messages: history,
    });

    expect(res.choices[0].message.content).toBe("ok");
    const sent = JSON.stringify(seenBodies[0]);
    expect(sent).not.toContain(SSN);
    expect(sent).toContain("[REDACTED_SSN]");
    expect(frozen.content).toBe(`my ssn is ${SSN}`);
    expect(history[0]).toBe(frozen);

    // The stored copy is redacted too.
    for (let i = 0; i < 100 && sentEvents.length === 0; i++) {
      await new Promise((r) => setTimeout(r, 10));
    }
    const event = sentEvents.find((e) => e.action_taken === "redacted");
    expect(event).toBeDefined();
    expect(event.prompt).not.toContain(SSN);
  });

  it("CONTROL: with no redacting rule, the caller's object is untouched and the SSN goes out", async () => {
    // Without this row, "the caller's object is unchanged" would also be
    // satisfied by redaction never running at all.
    _reset();
    _resetSender();
    init({ api_key: "test-key", ingest_url: "https://x", sample_rate: 1 });

    const history = [{ role: "user", content: `my ssn is ${SSN}` }];
    const client: any = wrap(fakeClient());

    await client.chat.completions.create({ model: "gpt-4o", messages: history });

    expect(JSON.stringify(seenBodies[0])).toContain(SSN);
    expect(history[0].content).toBe(`my ssn is ${SSN}`);
  });
});
