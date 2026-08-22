import {
  STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
  STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
  StrictIdentityEvidenceV21ValidationError,
  buildStrictIdentityEvidenceV21,
  canonicalizeStrictIdentityEvidenceV21,
  createStrictIdentityEvidenceV21Authority,
  strictIdentityEvidenceV21Hash,
  trustedStrictIdentityEvidenceV21Document,
  type StrictIdentityEvidenceV21Input,
  type TrustedStrictIdentityEvidenceV21,
} from '../../src/governance/strict-identity-evidence-v2-1';

const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);
const D = 'd'.repeat(64);
const PINNED_HASH = 'b756d7faa47c4a2a2dda6646168ca2771aed55fe8b6c1a2503decc8005a1e234';

function delegated(): StrictIdentityEvidenceV21Input {
  return {
    schema: STRICT_IDENTITY_EVIDENCE_V2_1_SCHEMA,
    profile_version: STRICT_IDENTITY_EVIDENCE_V2_1_PROFILE,
    relationship: 'delegated',
    receipt_time_ms: 1_000,
    requester: {
      requester_ref_hash: A,
      principal_type: 'human',
      role_ids: ['legal.reviewer', 'admin', 'admin'],
      privilege_scopes: ['write', 'admin', 'read'],
    },
    initiator: {
      agent_ref_hash: C,
      key_id: `sha256:${D}`,
      role_ids: ['worker'],
      privilege_scopes: ['read'],
    },
    delegation_chain: [
      {
        hop: 0, delegation_id_hash: '1'.repeat(64), delegator_ref_hash: A,
        delegatee_ref_hash: B, granted_scopes: ['write', 'read'],
        issued_at_ms: 900, expires_at_ms: 2_000,
      },
      {
        hop: 1, delegation_id_hash: '2'.repeat(64), delegator_ref_hash: B,
        delegatee_ref_hash: C, granted_scopes: ['read'],
        issued_at_ms: 950, expires_at_ms: 1_500,
      },
    ],
  };
}

function direct(): StrictIdentityEvidenceV21Input {
  const input = delegated();
  return {
    ...input,
    relationship: 'direct',
    requester: { ...input.requester, requester_ref_hash: C },
    delegation_chain: [],
  };
}

function clone(input: StrictIdentityEvidenceV21Input): StrictIdentityEvidenceV21Input {
  return JSON.parse(JSON.stringify(input)) as StrictIdentityEvidenceV21Input;
}

describe('strict identity evidence profile 2.1', () => {
  it('pins cross-language canonical sorting and the domain-separated hash', () => {
    const document = buildStrictIdentityEvidenceV21(delegated());
    expect(document.requester.role_ids).toEqual(['admin', 'legal.reviewer']);
    expect(document.requester.privilege_scopes).toEqual(['admin', 'read', 'write']);
    expect(document.delegation_chain[0].granted_scopes).toEqual(['read', 'write']);
    expect(canonicalizeStrictIdentityEvidenceV21(delegated()))
      .toBe(canonicalizeStrictIdentityEvidenceV21(document));
    expect(strictIdentityEvidenceV21Hash(delegated())).toBe(PINNED_HASH);
  });

  it('accepts direct identity only when explicitly direct and self-initiated', () => {
    expect(buildStrictIdentityEvidenceV21(direct()).delegation_chain).toEqual([]);
    const mismatch = direct();
    mismatch.initiator.agent_ref_hash = B;
    expect(() => buildStrictIdentityEvidenceV21(mismatch))
      .toThrow('direct relationship requires requester and initiator to match');
    const hiddenDelegation = direct();
    hiddenDelegation.delegation_chain = delegated().delegation_chain;
    expect(() => buildStrictIdentityEvidenceV21(hiddenDelegation))
      .toThrow('direct relationship requires an empty delegation_chain');
  });

  it('requires a contiguous requester-to-initiator chain', () => {
    const badHop = delegated();
    badHop.delegation_chain[1].hop = 2;
    expect(() => buildStrictIdentityEvidenceV21(badHop)).toThrow('.hop must equal 1');
    const badStart = delegated();
    badStart.delegation_chain[0].delegator_ref_hash = D;
    expect(() => buildStrictIdentityEvidenceV21(badStart)).toThrow('must start at requester');
    const broken = delegated();
    broken.delegation_chain[1].delegator_ref_hash = D;
    expect(() => buildStrictIdentityEvidenceV21(broken)).toThrow('does not continue');
    const duplicate = delegated();
    duplicate.delegation_chain[1].delegation_id_hash = duplicate.delegation_chain[0].delegation_id_hash;
    expect(() => buildStrictIdentityEvidenceV21(duplicate)).toThrow('duplicate delegation_id_hash');
    const badEnd = delegated();
    badEnd.delegation_chain[1].delegatee_ref_hash = D;
    expect(() => buildStrictIdentityEvidenceV21(badEnd)).toThrow('must end at initiator');
  });

  it('enforces delegation validity at the receipt timestamp, including equality', () => {
    const future = delegated();
    future.delegation_chain[0].issued_at_ms = 1_001;
    expect(() => buildStrictIdentityEvidenceV21(future)).toThrow('not valid at receipt_time_ms');
    const exactExpiry = delegated();
    exactExpiry.delegation_chain[1].expires_at_ms = 1_000;
    expect(() => buildStrictIdentityEvidenceV21(exactExpiry)).toThrow('not valid at receipt_time_ms');
    const exactIssue = delegated();
    exactIssue.delegation_chain[0].issued_at_ms = 1_000;
    expect(() => buildStrictIdentityEvidenceV21(exactIssue)).not.toThrow();
  });

  it('prevents privilege amplification across every hop', () => {
    const first = delegated();
    first.delegation_chain[0].granted_scopes.push('root');
    expect(() => buildStrictIdentityEvidenceV21(first)).toThrow('outside requester');
    const child = delegated();
    child.delegation_chain[1].granted_scopes.push('admin');
    expect(() => buildStrictIdentityEvidenceV21(child)).toThrow('expands granted_scopes');
    const agent = delegated();
    agent.initiator.privilege_scopes.push('write');
    expect(() => buildStrictIdentityEvidenceV21(agent)).toThrow('exceed delegated scopes');
  });

  it('rejects raw identity, email-shaped values, controls, and surrogates', () => {
    for (const field of ['email', 'name', 'display_name', 'principal']) {
      const raw = delegated() as unknown as Record<string, unknown>;
      (raw.requester as Record<string, unknown>)[field] = 'raw-identity';
      expect(() => buildStrictIdentityEvidenceV21(raw as unknown as StrictIdentityEvidenceV21Input))
        .toThrow(`requester contains unsupported field: ${field}`);
    }
    const rawRef = delegated();
    rawRef.requester.requester_ref_hash = 'person@example.com';
    expect(() => buildStrictIdentityEvidenceV21(rawRef)).toThrow('must be 64 lowercase hex');
    for (const unsafe of ['person@example.com', 'role\nadmin', '\ud800']) {
      const input = delegated();
      input.requester.role_ids = [unsafe];
      expect(() => buildStrictIdentityEvidenceV21(input)).toThrow('safe ASCII identifier');
    }
  });

  it('caps safe identifiers, sets, and delegation hops', () => {
    const identifier = delegated();
    identifier.requester.role_ids = [`a${'x'.repeat(128)}`];
    expect(() => buildStrictIdentityEvidenceV21(identifier)).toThrow('1-128 byte');
    const set = delegated();
    set.requester.role_ids = Array.from({ length: 65 }, (_, index) => `r${index}`);
    expect(() => buildStrictIdentityEvidenceV21(set)).toThrow('exceeds 64 items');
    const chain = delegated();
    chain.delegation_chain = Array.from({ length: 17 }, (_, index) => ({
      hop: index, delegation_id_hash: index.toString(16).padStart(64, '0'),
      delegator_ref_hash: A, delegatee_ref_hash: C, granted_scopes: [],
      issued_at_ms: 0, expires_at_ms: 2_000,
    }));
    expect(() => buildStrictIdentityEvidenceV21(chain)).toThrow('exceeds 16 items');

    const scopes = Array.from(
      { length: 64 }, (_, index) => `s${index.toString().padStart(2, '0')}${'x'.repeat(125)}`,
    );
    const refs = Array.from({ length: 17 }, (_, index) => index.toString(16).padStart(64, '0'));
    const canonical = delegated();
    canonical.requester.requester_ref_hash = refs[0];
    canonical.requester.privilege_scopes = scopes;
    canonical.initiator.agent_ref_hash = refs[16];
    canonical.initiator.privilege_scopes = scopes;
    canonical.delegation_chain = Array.from({ length: 16 }, (_, index) => ({
      hop: index, delegation_id_hash: (index + 32).toString(16).padStart(64, '0'),
      delegator_ref_hash: refs[index], delegatee_ref_hash: refs[index + 1],
      granted_scopes: scopes, issued_at_ms: 0, expires_at_ms: 2_000,
    }));
    expect(() => buildStrictIdentityEvidenceV21(canonical))
      .toThrow('canonical identity evidence exceeds 65536 UTF-8 bytes');
  });

  it('binds tampering and keeps authority-issued evidence immutable by copy', () => {
    const roleTamper = delegated();
    roleTamper.requester.role_ids = ['viewer'];
    expect(strictIdentityEvidenceV21Hash(roleTamper)).not.toBe(PINNED_HASH);
    const chainTamper = delegated();
    chainTamper.delegation_chain[0].expires_at_ms = 1_999;
    expect(strictIdentityEvidenceV21Hash(chainTamper)).not.toBe(PINNED_HASH);
    const timeTamper = delegated();
    timeTamper.receipt_time_ms = 999;
    expect(strictIdentityEvidenceV21Hash(timeTamper)).not.toBe(PINNED_HASH);

    const authority = createStrictIdentityEvidenceV21Authority();
    const original = delegated();
    const trusted = authority.issue(original);
    original.requester.role_ids = ['tampered'];
    const first = trustedStrictIdentityEvidenceV21Document(trusted);
    expect(first.requester.role_ids).toEqual(['admin', 'legal.reviewer']);
    first.requester.role_ids.push('tampered');
    expect(trustedStrictIdentityEvidenceV21Document(trusted).requester.role_ids)
      .toEqual(['admin', 'legal.reviewer']);
    expect(() => trustedStrictIdentityEvidenceV21Document(
      clone(delegated()) as unknown as TrustedStrictIdentityEvidenceV21,
    )).toThrow('not issued by a trusted authority');
  });
});
