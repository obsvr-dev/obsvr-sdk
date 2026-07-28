/**
 * Unit tests for the inbound OPA/Cedar external policy backend (ADR-4):
 *   - SSRF guard (scheme, literal + resolved private/metadata addresses)
 *   - backend evaluation (OPA/Cedar response parsing, timeout, error, ssrf)
 *   - init-time validation
 *   - pre-call pipeline integration (deny-wins, fail-closed, shadow, provenance)
 *
 * The cross-language merge + provenance semantics are pinned separately by
 * external-backend-conformance.test.ts against conformance/fixtures/external_backend.json.
 */
import { init, _reset, getConfig } from '../../src/proxy/config';
import { applyPreCallPolicy } from '../../src/integrations/core';
import { _resetSender, enqueueAuditEvent } from '../../src/proxy/sender/fire-and-forget';
import {
  evaluateExternalBackend,
  buildBackendInput,
  type ExternalPolicyBackendConfig,
  type BackendDecisionInput,
} from '../../src/policy/external-backend';
import {
  isPrivateOrReservedIp,
  isAlwaysBlockedIp,
  assertBackendUrlStatic,
  assertBackendUrlAllowed,
  SsrfError,
} from '../../src/utils/ssrf';

beforeEach(() => {
  _reset();
  _resetSender();
});

const INPUT: BackendDecisionInput = buildBackendInput({
  operation: 'chat.completions.create',
  provider: 'openai',
  model: 'gpt-4o',
  environment: 'production',
  userId: 'u1',
  localDecision: 'allow',
  rulesHash: 'abcd',
  promptSha256: 'deadbeef',
});

// ── SSRF guard ───────────────────────────────────────────────────────────────

describe('ssrf: address classification', () => {
  it.each([
    '10.0.0.1', '127.0.0.1', '169.254.169.254', '172.16.5.5', '192.168.1.1',
    '100.64.0.1', '0.0.0.0', '::1', 'fe80::1', 'fc00::1', 'fd00:ec2::254',
    '::ffff:10.0.0.1',
  ])('flags %s as private/reserved', (ip) => {
    expect(isPrivateOrReservedIp(ip)).toBe(true);
  });

  it.each(['8.8.8.8', '1.1.1.1', '9.9.9.9', '2606:4700:4700::1111'])(
    'treats %s as public',
    (ip) => {
      expect(isPrivateOrReservedIp(ip)).toBe(false);
    },
  );

  it('always-blocks metadata + link-local regardless of allowPrivateNetwork', () => {
    expect(isAlwaysBlockedIp('169.254.169.254')).toBe(true);
    expect(isAlwaysBlockedIp('fe80::1')).toBe(true);
    expect(isAlwaysBlockedIp('fd00:ec2::254')).toBe(true);
    expect(isAlwaysBlockedIp('10.0.0.1')).toBe(false); // private but not always-blocked
  });

  it('folds IPv4-mapped IPv6: hex and dotted ::ffff: forms classify as their IPv4', () => {
    // Node's URL parser normalizes [::ffff:169.254.169.254] to the HEX form
    // ::ffff:a9fe:a9fe; before the fix the dotted-only regex missed it and the
    // metadata endpoint was reachable through the untrusted backend URL.
    expect(isAlwaysBlockedIp('::ffff:a9fe:a9fe')).toBe(true); // 169.254.169.254 (hex)
    expect(isAlwaysBlockedIp('::ffff:169.254.169.254')).toBe(true); // dotted
    expect(isPrivateOrReservedIp('::ffff:c0a8:0101')).toBe(true); // 192.168.1.1 (hex)
    expect(isPrivateOrReservedIp('::ffff:0a00:0001')).toBe(true); // 10.0.0.1 (hex)
    expect(isPrivateOrReservedIp('0:0:0:0:0:ffff:7f00:0001')).toBe(true); // 127.0.0.1 (expanded)
    // A mapped PUBLIC address is still public (no over-block).
    expect(isPrivateOrReservedIp('::ffff:0808:0808')).toBe(false); // 8.8.8.8
  });
});

describe('ssrf: static url guard', () => {
  it('rejects non-http(s) schemes', () => {
    expect(() => assertBackendUrlStatic('ftp://opa.example.com/x')).toThrow(SsrfError);
    expect(() => assertBackendUrlStatic('file:///etc/passwd')).toThrow(SsrfError);
  });
  it('rejects the cloud metadata IP even with allowPrivateNetwork', () => {
    expect(() =>
      assertBackendUrlStatic('http://169.254.169.254/latest/meta-data', { allowPrivateNetwork: true }),
    ).toThrow(SsrfError);
  });
  it('rejects the metadata IP written as an IPv4-mapped IPv6 literal', () => {
    // The actual attack: the URL parser stores the hostname as ::ffff:a9fe:a9fe.
    expect(() =>
      assertBackendUrlStatic('http://[::ffff:169.254.169.254]/latest/meta-data', {
        allowPrivateNetwork: true,
      }),
    ).toThrow(SsrfError);
  });
  it('rejects a literal private IP by default', () => {
    expect(() => assertBackendUrlStatic('http://10.0.0.5:8181/v1/data/x')).toThrow(SsrfError);
  });
  it('permits a literal private IP with allowPrivateNetwork (sidecar)', () => {
    expect(() =>
      assertBackendUrlStatic('http://127.0.0.1:8181/v1/data/x', { allowPrivateNetwork: true }),
    ).not.toThrow();
  });
  it('permits a public literal IP', () => {
    expect(() => assertBackendUrlStatic('https://8.8.8.8/v1/data/x')).not.toThrow();
  });
});

describe('ssrf: resolve-before-connect', () => {
  it('rejects a public hostname that resolves to a private address', async () => {
    const resolver = async () => ['10.1.2.3'];
    await expect(
      assertBackendUrlAllowed('https://opa.example.com/x', {}, resolver),
    ).rejects.toBeInstanceOf(SsrfError);
  });
  it('always-blocks a hostname resolving to metadata even with allowPrivateNetwork', async () => {
    const resolver = async () => ['169.254.169.254'];
    await expect(
      assertBackendUrlAllowed('https://sneaky.example.com/x', { allowPrivateNetwork: true }, resolver),
    ).rejects.toBeInstanceOf(SsrfError);
  });
  it('allows a hostname resolving to a public address', async () => {
    const resolver = async () => ['93.184.216.34'];
    await expect(
      assertBackendUrlAllowed('https://opa.example.com/x', {}, resolver),
    ).resolves.toBeUndefined();
  });
});

// ── Backend evaluation (response parsing + failure mapping) ───────────────────

function okJson(body: unknown): typeof fetch {
  return (async () => ({ ok: true, status: 200, json: async () => body })) as unknown as typeof fetch;
}

describe('evaluateExternalBackend: OPA', () => {
  const opa: ExternalPolicyBackendConfig = { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow' };

  it('parses result:true as allow', async () => {
    const r = await evaluateExternalBackend(opa, INPUT, { fetchImpl: okJson({ result: true }) });
    expect(r.outcome).toBe('allow');
  });
  it('parses result:false as deny', async () => {
    const r = await evaluateExternalBackend(opa, INPUT, { fetchImpl: okJson({ result: false }) });
    expect(r.outcome).toBe('deny');
  });
  it('parses an object result with allow + reasons', async () => {
    const r = await evaluateExternalBackend(opa, INPUT, {
      fetchImpl: okJson({ result: { allow: false, reasons: ['tenant not permitted'] } }),
    });
    expect(r.outcome).toBe('deny');
    expect(r.reasons).toEqual(['tenant not permitted']);
  });
  it('treats a missing result document as error (fail-closed)', async () => {
    const r = await evaluateExternalBackend(opa, INPUT, { fetchImpl: okJson({}) });
    expect(r.outcome).toBe('error');
  });
  it('sends the input wrapped under {input}', async () => {
    let captured: unknown;
    const spy = (async (_url: string, init2: { body: string }) => {
      captured = JSON.parse(init2.body);
      return { ok: true, status: 200, json: async () => ({ result: true }) };
    }) as unknown as typeof fetch;
    await evaluateExternalBackend(opa, INPUT, { fetchImpl: spy });
    expect(captured).toEqual({ input: INPUT });
  });
});

describe('evaluateExternalBackend: Cedar', () => {
  const cedar: ExternalPolicyBackendConfig = { type: 'cedar', url: 'https://1.1.1.1/v1/is_authorized' };
  it('parses decision Allow', async () => {
    const r = await evaluateExternalBackend(cedar, INPUT, { fetchImpl: okJson({ decision: 'Allow' }) });
    expect(r.outcome).toBe('allow');
  });
  it('parses decision Deny (case-insensitive)', async () => {
    const r = await evaluateExternalBackend(cedar, INPUT, { fetchImpl: okJson({ decision: 'DENY' }) });
    expect(r.outcome).toBe('deny');
  });
  it('sends the input document directly (not wrapped)', async () => {
    let captured: unknown;
    const spy = (async (_url: string, init2: { body: string }) => {
      captured = JSON.parse(init2.body);
      return { ok: true, status: 200, json: async () => ({ decision: 'Allow' }) };
    }) as unknown as typeof fetch;
    await evaluateExternalBackend(cedar, INPUT, { fetchImpl: spy });
    expect(captured).toEqual(INPUT);
  });
});

describe('evaluateExternalBackend: failure mapping', () => {
  const opa: ExternalPolicyBackendConfig = { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow' };
  it('maps an aborted request to timeout', async () => {
    const fetchImpl = (async () => {
      throw Object.assign(new Error('The operation was aborted'), { name: 'AbortError' });
    }) as unknown as typeof fetch;
    const r = await evaluateExternalBackend(opa, INPUT, { fetchImpl });
    expect(r.outcome).toBe('timeout');
  });
  it('maps a network error to error', async () => {
    const fetchImpl = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    const r = await evaluateExternalBackend(opa, INPUT, { fetchImpl });
    expect(r.outcome).toBe('error');
  });
  it('maps a non-2xx response to error', async () => {
    const fetchImpl = (async () => ({ ok: false, status: 503, json: async () => ({}) })) as unknown as typeof fetch;
    const r = await evaluateExternalBackend(opa, INPUT, { fetchImpl });
    expect(r.outcome).toBe('error');
  });
  it('maps an SSRF-blocked url to error without ever calling fetch', async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return { ok: true, status: 200, json: async () => ({ result: true }) };
    }) as unknown as typeof fetch;
    const blocked: ExternalPolicyBackendConfig = { type: 'opa', url: 'http://169.254.169.254/x' };
    const r = await evaluateExternalBackend(blocked, INPUT, { fetchImpl });
    expect(r.outcome).toBe('error');
    expect(r.reasons).toContain('ssrf_guard_blocked_backend_url');
    expect(called).toBe(false);
  });
});

// ── init-time validation ─────────────────────────────────────────────────────

describe('init: externalPolicyBackend validation', () => {
  it('rejects an unknown backend type', () => {
    expect(() =>
      init({ api_key: 't', external_policy_backend: { type: 'xacml' as never, url: 'https://x.example.com' } }),
    ).toThrow(/must be "opa" or "cedar"/);
  });
  it('rejects a non-http(s) scheme at init', () => {
    expect(() =>
      init({ api_key: 't', external_policy_backend: { type: 'opa', url: 'ftp://opa.example.com' } }),
    ).toThrow(SsrfError);
  });
  it('rejects a literal metadata IP at init', () => {
    expect(() =>
      init({ api_key: 't', external_policy_backend: { type: 'opa', url: 'http://169.254.169.254/x' } }),
    ).toThrow(SsrfError);
  });
  it('accepts a localhost sidecar with allowPrivateNetwork', () => {
    expect(() =>
      init({
        apiKey: 't',
        externalPolicyBackend: { type: 'opa', url: 'http://127.0.0.1:8181/v1/data/x', allowPrivateNetwork: true },
      }),
    ).not.toThrow();
    expect(getConfig().external_policy_backend?.type).toBe('opa');
  });
});

// ── pre-call pipeline integration (deny-wins / fail-closed / shadow) ──────────

function preCall() {
  return applyPreCallPolicy('hello world', {
    config: getConfig(),
    provider: 'openai',
    operation: 'chat.completions.create',
  });
}

describe('applyPreCallPolicy: external backend integration', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('blocks the call when the backend denies (deny-wins from the backend)', async () => {
    global.fetch = okJson({ result: { allow: false, reasons: ['blocked by corp policy'] } });
    init({ api_key: 't', external_policy_backend: { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow' } });
    const result = await preCall();
    expect(result.decision).toBe('block');
    expect(result.compliance.action_source).toBe('external_backend');
    expect(result.compliance.policy_reason).toBe('blocked by corp policy');
    expect(result.compliance.external_backend).toMatchObject({
      type: 'opa',
      outcome: 'deny',
      shadow: false,
      identity: 'opa:8.8.8.8',
    });
  });

  it('allows the call when the backend allows, and records provenance on the allowed event', async () => {
    global.fetch = okJson({ result: true });
    init({ api_key: 't', external_policy_backend: { type: 'cedar', url: 'https://1.1.1.1/authz' } });
    // cedar shape: decision field. Re-point fetch to a cedar response.
    global.fetch = okJson({ decision: 'Allow' });
    const result = await preCall();
    expect(result.decision).toBe('allow');
    expect(result.compliance.external_backend).toMatchObject({ type: 'cedar', outcome: 'allow' });
  });

  it('fails closed: a backend error blocks the call (enforce mode)', async () => {
    global.fetch = (async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    init({ api_key: 't', external_policy_backend: { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow' } });
    const result = await preCall();
    expect(result.decision).toBe('block');
    expect(result.compliance.action_source).toBe('external_backend');
    expect(result.compliance.external_backend).toMatchObject({ outcome: 'error', shadow: false });
  });

  it('shadow mode never blocks, but records what the backend would have done', async () => {
    global.fetch = okJson({ result: false });
    init({
      api_key: 't',
      external_policy_backend: { type: 'opa', url: 'https://8.8.8.8/v1/data/obsvr/allow', shadow: true },
    });
    const result = await preCall();
    expect(result.decision).toBe('allow');
    expect(result.compliance.action_source).not.toBe('external_backend');
    expect(result.compliance.external_backend).toMatchObject({ outcome: 'deny', shadow: true });
  });

  it('is inert when no backend is configured (zero-config default)', async () => {
    init({ api_key: 't' });
    const result = await preCall();
    expect(result.decision).toBe('allow');
    expect(result.compliance.external_backend).toBeUndefined();
  });
});

describe('wire-shape normalization at enqueue', () => {
  beforeEach(() => { _reset(); _resetSender(); });

  it('mirrors external_backend to metadata and promotes delegation to top-level', async () => {
    const sent: any[] = [];
    (global as any).fetch = async (_u: any, o: any) => {
      sent.push(JSON.parse(o.body));
      return { ok: true, status: 200, json: async () => ({}) };
    };
    init({ api_key: 'test', ingest_url: 'https://x' });

    enqueueAuditEvent(getConfig(), {
      request_id: 'r1',
      environment: 'dev',
      provider: 'unknown',
      model: 'm',
      operation: 'op',
      prompt: '',
      response: '',
      success: true,
      // top-level external_backend is stripped by ingest → must be mirrored
      external_backend: { backend: 'opa', outcome: 'deny', reasons: ['x'] },
      // delegation rides in metadata → must be promoted to the top-level columns
      metadata: { delegation_chain: ['a', 'b'], delegation_depth: 1 },
    } as any);

    for (let i = 0; i < 100 && sent.length < 1; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    const ev = sent[0];
    expect(ev.metadata.obsvr_external_backend).toEqual({ backend: 'opa', outcome: 'deny', reasons: ['x'] });
    expect(ev.delegation_chain).toEqual(['a', 'b']);
    expect(ev.delegation_depth).toBe(1);

    delete (global as any).fetch;
  });

  it('trims oversized metadata but preserves trace_id / agent_run_id', async () => {
    const sent: any[] = [];
    (global as any).fetch = async (_u: any, o: any) => {
      sent.push(JSON.parse(o.body));
      return { ok: true, status: 200, json: async () => ({}) };
    };
    init({ api_key: 'test', ingest_url: 'https://x' });

    const bigAttrs: Record<string, string> = {};
    for (let i = 0; i < 2000; i++) bigAttrs['k' + i] = 'v'.repeat(20); // well over 9 KB
    enqueueAuditEvent(getConfig(), {
      request_id: 'r',
      environment: 'dev',
      provider: 'unknown',
      model: 'm',
      operation: 'op',
      prompt: '',
      response: '',
      success: true,
      metadata: { trace_id: 'T1', agent_run_id: 'R1', obsvr_span: { span_id: 's', attributes: bigAttrs } },
    } as any);

    for (let i = 0; i < 100 && sent.length < 1; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    const ev = sent[0];
    // Metadata is under the ingest cap → not replaced wholesale by ingest...
    expect(JSON.stringify(ev.metadata).length).toBeLessThanOrEqual(9000);
    // ...and the grouping keys survived (event stays linked to its run/trace).
    expect(ev.metadata.trace_id).toBe('T1');
    expect(ev.metadata.agent_run_id).toBe('R1');
    expect(ev.metadata._obsvr_metadata_trimmed).toBe(true);

    delete (global as any).fetch;
  });
});
