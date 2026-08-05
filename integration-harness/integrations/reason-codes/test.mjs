/**
 * reason-codes — the closed reason-code registry, its rule-type mapping, and the
 * codes the engine actually emits, pinned to conformance/fixtures/reason_codes.json.
 *
 * reason_code is emitted by the ENGINE API (evaluate()/evaluateShadowRules()),
 * NOT copied onto wrap() audit events (those carry the coarse action_reason). So
 * this suite drives reason codes through evaluate() and evaluateShadowRules().
 *
 * Run: node integrations/reason-codes/test.mjs
 */
import {
  obsvr,
  ReasonCode,
  REASON_CODES,
  RULE_TYPE_TO_REASON_CODE,
  ruleTypeToReasonCode,
  evaluate,
  evaluateShadowRules,
} from "@obsvr/sdk";
import { startMockIngest } from "../../lib/mock-ingest.mjs";
import { check, done } from "../../lib/check.mjs";
import { verifyCapturedChain, assertSignedEvent } from "../../lib/assert-governance.mjs";
import { loadFixture } from "../../lib/fixtures.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";
const UNIQ = `rc-${Date.now()}`; // unique quota scope so global quota state can't contaminate

const rule = (over) => ({ id: "r", name: "r", enabled: true, action: "block", type: "keyword", conditions: {}, ...over });

export async function run() {
  const ingest = await startMockIngest();
  const fx = loadFixture("reason_codes");

  // ── 1. Registry parity: REASON_CODES == fixture.codes (both sorted) ─────────
  const codes = [...REASON_CODES].sort();
  const fxCodes = [...fx.codes].sort();
  check("REASON_CODES registry equals the shared fixture (byte-identical set)", JSON.stringify(codes) === JSON.stringify(fxCodes));

  // Every ReasonCode enum member is in the closed registry, and vice-versa.
  const enumVals = Object.values(ReasonCode).sort();
  check("every ReasonCode enum value is in the fixture registry", enumVals.every((v) => fx.codes.includes(v)));
  check("registry has no code outside the ReasonCode enum", fx.codes.every((c) => enumVals.includes(c)));

  // ── 2. Rule-type → reason-code mapping parity ───────────────────────────────
  let mapOk = true;
  let mapFn = true;
  for (const [type, expected] of Object.entries(fx.rule_type_to_reason_code)) {
    if (RULE_TYPE_TO_REASON_CODE[type] !== expected) mapOk = false;
    if (ruleTypeToReasonCode(type) !== expected) mapFn = false;
  }
  check("RULE_TYPE_TO_REASON_CODE matches the fixture mapping", mapOk);
  check("ruleTypeToReasonCode(type) matches the fixture mapping", mapFn);
  check("unknown rule type maps to UNKNOWN_BLOCKED", ruleTypeToReasonCode("no_such_type") === ReasonCode.UNKNOWN_BLOCKED);

  // ── 3. Codes the engine actually emits via evaluate() ───────────────────────
  const initFor = (rules, piiPolicy) =>
    obsvr.init({ apiKey: API_KEY, ingestUrl: ingest.url, environment: "development", policyRules: rules, piiPolicy, policyRefreshIntervalMs: 0 });

  // keyword block → KEYWORD_BLOCKED
  initFor([rule({ type: "keyword", conditions: { keywords: ["forbidden"] } })]);
  let r = await evaluate({ action_type: "test.act", payload: { text: "this is forbidden content" } });
  check("keyword block → decision BLOCKED, reason_code KEYWORD_BLOCKED", r.decision === "BLOCKED" && r.reason_code === ReasonCode.KEYWORD_BLOCKED, `${r.decision}/${r.reason_code}`);

  // regex match → REGEX_MATCHED
  initFor([rule({ type: "regex", conditions: { pattern: "\\bsecret\\b" } })]);
  r = await evaluate({ action_type: "test.act", payload: { text: "the secret is out" } });
  check("regex match → reason_code REGEX_MATCHED", r.decision === "BLOCKED" && r.reason_code === ReasonCode.REGEX_MATCHED, `${r.decision}/${r.reason_code}`);

  // PII → PII_DETECTED
  initFor([], {});
  r = await evaluate({ action_type: "test.act", payload: { note: "ssn 123-45-6789" } });
  check("PII in payload → reason_code PII_DETECTED", r.decision === "BLOCKED" && r.reason_code === ReasonCode.PII_DETECTED, `${r.decision}/${r.reason_code}`);

  // quota → QUOTA_EXCEEDED (unique user_id scope so state is isolated)
  initFor([rule({ type: "quota", conditions: { quota_limit: 1, quota_window_ms: 60_000, quota_scope: "user_id" } })]);
  await evaluate({ action_type: "test.act", payload: { text: "call 1" }, user_id: UNIQ });
  r = await evaluate({ action_type: "test.act", payload: { text: "call 2" }, user_id: UNIQ });
  check("quota exceeded → reason_code QUOTA_EXCEEDED", r.decision === "BLOCKED" && r.reason_code === ReasonCode.QUOTA_EXCEEDED, `${r.decision}/${r.reason_code}`);

  // clean → PERMITTED
  initFor([], {});
  r = await evaluate({ action_type: "test.act", payload: { text: "hello there" } });
  check("clean action → decision PERMITTED, reason_code PERMITTED, execution_token issued", r.decision === "PERMITTED" && r.reason_code === ReasonCode.PERMITTED && typeof r.execution_token === "string", `${r.decision}/${r.reason_code}`);

  // ── 4. Shadow rules → SHADOW_WOULD_BLOCK ────────────────────────────────────
  const shadow = evaluateShadowRules(
    [rule({ id: "sh", name: "sh", mode: "shadow", type: "keyword", conditions: { keywords: ["shadowword"] } })],
    "contains shadowword here",
    "prompt",
  );
  check("shadow rule match → would-have outcome recorded", !!shadow && shadow.would === "block", JSON.stringify(shadow));
  check("shadow reason_code is SHADOW_WOULD_BLOCK (regardless of rule type)", shadow?.reason_code === ReasonCode.SHADOW_WOULD_BLOCK, String(shadow?.reason_code));

  // ── 5. The emitted governance events are still a valid signed chain ─────────
  await obsvr.flush();
  const events = ingest.getEvents();
  const gov = events.find((e) => e.source === "governance-evaluate");
  if (gov) assertSignedEvent(gov, "evaluate event", { decisionRecord: true });
  verifyCapturedChain(events, API_KEY, "evaluate() chain");

  obsvr._reset();
  await ingest.stop();
  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
