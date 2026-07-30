/**
 * Mixing camelCase and snake_case config keys silently dropped half a config.
 *
 * `isObsvrConfig` is `"apiKey" in config`, so ONE key decides the naming
 * convention for the whole object. `api_key` beside `piiPolicy` takes the
 * snake_case path, `piiPolicy` is never read, the PII policy does not exist,
 * and the SSN reaches the provider — with no error, no warning, and an audit
 * event that is honest, because obsvr never saw a policy to enforce.
 *
 * The posture is WARN AND CONTINUE. Rejecting turns a typo into an outage for a
 * caller passing a harmless extra field; accepting both spellings hides the
 * mistake and keeps two conventions alive forever.
 *
 * This is the exact shape that found the defect: a probe wrote `api_key` beside
 * `piiPolicy` and the resulting unredacted SSN read as a broken fix rather than
 * a broken config.
 *
 * Twin: sdk-python/tests/test_config_key_spelling.py.
 */
import { init, _reset, getConfig } from "../../src/proxy/config";
import { wrap } from "../../src/proxy/wrapper";
import { _resetSender } from "../../src/proxy/sender/fire-and-forget";

const SSN = "123-45-6789";

let warnings: string[] = [];
const realWarn = console.warn;

beforeEach(() => {
  _reset();
  _resetSender();
  warnings = [];
  console.warn = (...args: unknown[]) => {
    warnings.push(args.map(String).join(" "));
  };
  (global as any).fetch = async () => ({ ok: true, status: 200 });
});

afterEach(() => {
  console.warn = realWarn;
  _reset();
  _resetSender();
});

const spellingWarnings = () => warnings.filter((w) => w.includes("init() read this config as"));
const unknownWarnings = () => warnings.filter((w) => w.includes("does not recognise these config keys"));

describe("config key spelling", () => {
  it("warns, names the detected style, and names every dropped key", () => {
    init({
      api_key: "k",
      ingest_url: "https://x",
      piiPolicy: { rules: { ssn: "redact" } },
      policyRules: [],
    } as never);

    expect(spellingWarnings()).toHaveLength(1);
    const w = spellingWarnings()[0];
    // The style it chose, and why it chose it.
    expect(w).toContain("snake_case");
    expect(w).toContain("`apiKey` is absent");
    // Every dropped key, by name.
    expect(w).toContain("piiPolicy");
    expect(w).toContain("policyRules");
    // And the spelling that would have been read - "unknown key" is not
    // actionable, "piiPolicy -> pii_policy" is.
    expect(w).toContain("piiPolicy -> pii_policy");
    expect(w).toContain("policyRules -> policy_rules");
  });

  it("warns the other way round too, when apiKey selects camelCase", () => {
    init({ apiKey: "k", ingestUrl: "https://x", pii_policy: { rules: { ssn: "redact" } } } as never);

    const w = spellingWarnings()[0];
    expect(w).toContain("camelCase");
    expect(w).toContain("`apiKey` is present");
    expect(w).toContain("pii_policy -> piiPolicy");
  });

  it("CONTROL: a consistently spelled config warns nothing, either style", () => {
    init({ api_key: "k", ingest_url: "https://x", pii_policy: { rules: { ssn: "redact" } } });
    expect(spellingWarnings()).toHaveLength(0);
    expect(unknownWarnings()).toHaveLength(0);

    _reset();
    warnings = [];
    init({ apiKey: "k", ingestUrl: "https://x", piiPolicy: { rules: { ssn: "redact" } } });
    expect(spellingWarnings()).toHaveLength(0);
    expect(unknownWarnings()).toHaveLength(0);
  });

  it("names a key that belongs to neither convention, without rejecting it", () => {
    init({ api_key: "k", ingest_url: "https://x", piiPolicyy: {} } as never);

    expect(unknownWarnings()).toHaveLength(1);
    expect(unknownWarnings()[0]).toContain("piiPolicyy");
    // Continues rather than throwing: a stray field must not be an outage.
    expect(getConfig().api_key).toBe("k");
  });

  it("the warning is the only thing between a mixed config and an unredacted SSN", async () => {
    // The case that matters. The PII policy is present but in the unread
    // spelling, so it does not exist, and the provider gets the raw value.
    let sentToProvider = "";
    init({
      api_key: "k",
      ingest_url: "https://x",
      piiPolicy: { rules: { ssn: "redact" } },
    } as never);

    // It was dropped...
    expect(getConfig().pii_policy).toBeUndefined();

    const client: any = wrap({
      chat: {
        completions: {
          create: async (args: unknown) => {
            sentToProvider = JSON.stringify(args);
            return { choices: [{ message: { content: "ok" } }] };
          },
        },
      },
    });
    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: `my ssn is ${SSN}` }],
    });

    // ...so the SSN really does reach the provider, unredacted.
    expect(sentToProvider).toContain(SSN);
    // And the warning is what stands between the caller and that outcome.
    expect(spellingWarnings()).toHaveLength(1);
    expect(spellingWarnings()[0]).toContain("piiPolicy -> pii_policy");
  });

  it("CONTROL: spelled correctly, the same policy redacts", async () => {
    // Without this the row above would also be satisfied by redaction being
    // broken for every config, not just the mixed one.
    let sentToProvider = "";
    init({ api_key: "k", ingest_url: "https://x", pii_policy: { rules: { ssn: "redact" } } });

    const client: any = wrap({
      chat: {
        completions: {
          create: async (args: unknown) => {
            sentToProvider = JSON.stringify(args);
            return { choices: [{ message: { content: "ok" } }] };
          },
        },
      },
    });
    await client.chat.completions.create({
      model: "gpt-4o",
      messages: [{ role: "user", content: `my ssn is ${SSN}` }],
    });

    expect(sentToProvider).not.toContain(SSN);
    expect(sentToProvider).toContain("[REDACTED_SSN]");
    expect(spellingWarnings()).toHaveLength(0);
  });
});
