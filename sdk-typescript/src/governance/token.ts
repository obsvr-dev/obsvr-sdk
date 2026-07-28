/**
 * JWT Execution Token issuer and verifier.
 * Issues short-lived signed JWTs as proof-of-evaluation for PERMITTED decisions.
 *
 * @packageDocumentation
 */
import { createHmac, timingSafeEqual } from 'crypto';
import { randomUUID } from 'crypto';
import type { GovernanceDecision, PolicyEvaluationToken } from './types.js';

const SIGNING_SALT = 'obsvr-sdk-signing-v1';
const DEFAULT_TTL_MS = 60_000; // 60 seconds

/** Derive HMAC signing key from API key (same derivation as fire-and-forget.ts) */
function deriveSigningKey(apiKey: string): Buffer {
  return createHmac('sha256', SIGNING_SALT).update(apiKey).digest();
}

/** Base64url encode */
function base64url(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input) : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Base64url decode */
function base64urlDecode(input: string): Buffer {
  let str = input.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

const JWT_HEADER = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));

/**
 * Issue a signed JWT execution token for a PERMITTED evaluation.
 */
export function issueExecutionToken(
  apiKey: string,
  payload: {
    action: string;
    decision: GovernanceDecision;
    rule_id?: string;
  },
  ttlMs: number = DEFAULT_TTL_MS
): string {
  const now = Date.now();
  const tokenPayload: PolicyEvaluationToken = {
    action: payload.action,
    decision: payload.decision,
    rule_id: payload.rule_id,
    timestamp: now,
    nonce: randomUUID(),
    exp: now + ttlMs,
  };

  const encodedPayload = base64url(JSON.stringify(tokenPayload));
  const signingKey = deriveSigningKey(apiKey);
  const sigInput = `${JWT_HEADER}.${encodedPayload}`;
  const signature = base64url(
    createHmac('sha256', signingKey).update(sigInput).digest()
  );

  return `${sigInput}.${signature}`;
}

/**
 * Verify a JWT execution token and return the decoded payload.
 */
export function verifyExecutionToken(
  apiKey: string,
  token: string
): { valid: boolean; payload?: PolicyEvaluationToken; error?: string } {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token format: expected 3 parts' };
    }

    const [header, encodedPayload, signature] = parts;

    // Verify header
    if (header !== JWT_HEADER) {
      return { valid: false, error: 'Invalid token header' };
    }

    // Verify signature
    const signingKey = deriveSigningKey(apiKey);
    const sigInput = `${header}.${encodedPayload}`;
    const expectedSig = base64url(
      createHmac('sha256', signingKey).update(sigInput).digest()
    );

    // Constant-time comparison. Buffer.equals short-circuits on the first
    // differing byte (memcmp) and is NOT constant-time; timingSafeEqual is.
    // Length is checked first because timingSafeEqual throws on unequal lengths.
    const sigBuf = Buffer.from(signature);
    const expectedBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
      return { valid: false, error: 'Invalid signature' };
    }

    // Decode payload
    const payload: PolicyEvaluationToken = JSON.parse(
      base64urlDecode(encodedPayload).toString('utf8')
    );

    // Expiry is mandatory: a validly-signed token with `exp` stripped or
    // non-numeric must NOT be treated as non-expiring (fail-closed on the claim).
    if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
      return { valid: false, payload, error: 'Token missing or invalid exp' };
    }
    if (payload.exp < Date.now()) {
      return { valid: false, payload, error: 'Token expired' };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: `Token verification failed: ${(err as Error).message}` };
  }
}
