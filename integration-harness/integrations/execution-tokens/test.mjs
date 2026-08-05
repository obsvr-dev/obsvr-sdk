/**
 * JWT execution tokens — offline unit E2E.
 *
 * issueExecutionToken() mints an HS256 proof-of-evaluation token; the round-trip
 * verifies, and every tamper / wrong-key / expiry / malformed path is rejected
 * with the SDK's exact error string. No network, no sleeping (expiry is forced
 * with a negative ttlMs so `exp` lands in the past immediately).
 *
 *   node integrations/execution-tokens/test.mjs
 */
import { issueExecutionToken, verifyExecutionToken } from "@obsvr/sdk";
import { check, done } from "../../lib/check.mjs";

export const meta = { offline: true };

const API_KEY = process.env.OBSVR_API_KEY || "obsvr-test-key";

/** Flip the first base64url char so a segment is guaranteed to change while
 *  staying the same length (keeps the length check from short-circuiting). */
const flip = (seg) => (seg[0] === "A" ? "B" : "A") + seg.slice(1);

export async function run() {
  // ── valid round-trip ───────────────────────────────────────────────────────
  const token = issueExecutionToken(API_KEY, { action: "wire_transfer", decision: "PERMITTED", rule_id: "r1" });
  check("issued token has exactly 3 dot-separated parts", token.split(".").length === 3);

  const ok = verifyExecutionToken(API_KEY, token);
  check("valid token verifies { valid:true }", ok.valid === true);
  check("payload round-trips action/decision/rule_id", ok.payload?.action === "wire_transfer" && ok.payload?.decision === "PERMITTED" && ok.payload?.rule_id === "r1");
  check("payload carries exp + nonce + timestamp", typeof ok.payload?.exp === "number" && typeof ok.payload?.nonce === "string" && typeof ok.payload?.timestamp === "number");

  const [h, p, s] = token.split(".");

  // ── tampered signature → Invalid signature ─────────────────────────────────
  const tSig = verifyExecutionToken(API_KEY, [h, p, flip(s)].join("."));
  check("tampered signature is rejected", tSig.valid === false);
  check("tampered signature error is exactly 'Invalid signature'", tSig.error === "Invalid signature");

  // ── tampered payload → Invalid signature (sig check precedes payload decode) ─
  const tPay = verifyExecutionToken(API_KEY, [h, flip(p), s].join("."));
  check("tampered payload rejected as 'Invalid signature'", tPay.valid === false && tPay.error === "Invalid signature");

  // ── tampered header → Invalid token header ─────────────────────────────────
  const tHdr = verifyExecutionToken(API_KEY, [flip(h), p, s].join("."));
  check("tampered header rejected as 'Invalid token header'", tHdr.valid === false && tHdr.error === "Invalid token header");

  // ── wrong apiKey → Invalid signature ───────────────────────────────────────
  const wrong = verifyExecutionToken(API_KEY + "-different", token);
  check("wrong apiKey rejected as 'Invalid signature'", wrong.valid === false && wrong.error === "Invalid signature");

  // ── expired (ttlMs negative → exp in the past, no sleep) → Token expired ────
  const expiredToken = issueExecutionToken(API_KEY, { action: "read_record", decision: "PERMITTED" }, -1000);
  const expired = verifyExecutionToken(API_KEY, expiredToken);
  check("expired token is rejected", expired.valid === false);
  check("expired token error is exactly 'Token expired'", expired.error === "Token expired");
  check("expired token still returns the decoded payload", expired.payload?.action === "read_record");

  // ── malformed (≠ 3 parts) → Invalid token format ───────────────────────────
  const tooMany = verifyExecutionToken(API_KEY, "not.a.valid.jwt.token"); // 5 parts
  check("malformed token (>3 parts) rejected", tooMany.valid === false);
  check("malformed token error is exactly 'Invalid token format: expected 3 parts'", tooMany.error === "Invalid token format: expected 3 parts");
  const tooFew = verifyExecutionToken(API_KEY, "only.two"); // 2 parts
  check("malformed token (<3 parts) rejected with the same error", tooFew.valid === false && tooFew.error === "Invalid token format: expected 3 parts");

  return done.results();
}

if (import.meta.url === `file://${process.argv[1]}`) run();
