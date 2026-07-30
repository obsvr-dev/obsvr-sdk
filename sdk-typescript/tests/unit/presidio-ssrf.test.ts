import { init, _reset } from '../../src/proxy/config';
import { isAlwaysBlockedIp, isPrivateOrReservedIp } from '../../src/utils/ssrf';

/**
 * SSRF guard on the presidio analyzer/anonymizer endpoints. These receive the
 * PROMPT/PII content to scan — the endpoint that sees the MOST sensitive data —
 * so a misconfigured or hijacked URL is both an SSRF primitive and an
 * exfiltration surface. Parity with the external-backend guard; twin:
 * sdk-python/tests/test_presidio_ssrf.py.
 *
 * Guard policy for presidio (localhost-sidecar norm): cloud-metadata /
 * link-local is ALWAYS refused (no opt-out — the crown jewel), but
 * private/loopback is PERMITTED (a presidio sidecar is normally on localhost).
 */

beforeEach(() => _reset());
afterEach(() => _reset());

const BASE = { api_key: 'k', ingest_url: 'https://x' };

describe('presidio endpoint SSRF guard (init)', () => {
  it('refuses a cloud-metadata analyzer URL (169.254.169.254)', () => {
    expect(() =>
      init({ ...BASE, presidio_analyzer_url: 'http://169.254.169.254/analyze' } as any),
    ).toThrow(/presidioAnalyzerUrl.*SSRF guard/i);
  });

  it('refuses a cloud-metadata anonymizer URL', () => {
    expect(() =>
      init({ ...BASE, presidio_anonymizer_url: 'http://169.254.169.254/anonymize' } as any),
    ).toThrow(/presidioAnonymizerUrl.*SSRF guard/i);
  });

  it('refuses the IPv4-mapped IPv6 metadata form (the guard folds it)', () => {
    expect(() =>
      init({ ...BASE, presidio_analyzer_url: 'http://[::ffff:169.254.169.254]/analyze' } as any),
    ).toThrow(/SSRF guard/i);
  });

  it('refuses a non-http(s) scheme', () => {
    expect(() =>
      init({ ...BASE, presidio_analyzer_url: 'file:///etc/passwd' } as any),
    ).toThrow(/SSRF guard/i);
  });

  it('PERMITS a localhost sidecar (private is allowed for presidio)', () => {
    expect(() =>
      init({ ...BASE, presidio_analyzer_url: 'http://127.0.0.1:5002', presidio_anonymizer_url: 'http://127.0.0.1:5001' } as any),
    ).not.toThrow();
  });

  it('PERMITS a private-range sidecar host (10.x)', () => {
    expect(() =>
      init({ ...BASE, presidio_analyzer_url: 'http://10.0.0.7:5002/analyze' } as any),
    ).not.toThrow();
  });

  it('PERMITS a public https endpoint and a plain hostname', () => {
    expect(() => init({ ...BASE, presidio_analyzer_url: 'https://8.8.8.8/analyze' } as any)).not.toThrow();
    _reset();
    expect(() => init({ ...BASE, presidio_analyzer_url: 'http://analyzer.local/analyze' } as any)).not.toThrow();
  });

  it('rejects an empty-string presidio URL', () => {
    expect(() =>
      init({ ...BASE, presidio_analyzer_url: '   ' } as any),
    ).toThrow(/presidioAnalyzerUrl must be a non-empty string/i);
  });
});

/**
 * Every IPv6 spelling that carries an IPv4 address. The guard folded exactly
 * ONE of the four (`::ffff:`), so `http://[::169.254.169.254]/` reached the
 * network through the external-policy backend and was accepted by `init()` as
 * a Presidio URL while the `::ffff:` spelling of the same address was refused.
 * "Always refused, no opt-out" held for one spelling of the address.
 *
 * The public-address rows are the controls: without them "everything IPv6 is
 * blocked" would pass, which is a different bug and a worse one.
 */
describe('SSRF: every IPv6 form that carries an IPv4 address', () => {
  const METADATA = [
    ['169.254.169.254', 'IPv4 literal'],
    ['::ffff:169.254.169.254', 'IPv4-mapped, dotted'],
    ['::ffff:a9fe:a9fe', 'IPv4-mapped, hex (what the URL parser produces)'],
    ['::169.254.169.254', 'IPv4-compatible, dotted'],
    ['::a9fe:a9fe', 'IPv4-compatible, hex'],
    ['64:ff9b::169.254.169.254', 'NAT64 well-known prefix'],
    ['64:ff9b::a9fe:a9fe', 'NAT64, hex'],
    ['2002:a9fe:a9fe::', '6to4'],
    ['2002:a9fe:a9fe::1', '6to4 with a host suffix'],
  ] as const;

  for (const [ip, how] of METADATA) {
    it(`always-blocks the metadata address written as ${how}`, () => {
      expect(isAlwaysBlockedIp(ip)).toBe(true);
    });
  }

  const PUBLIC = [
    ['8.8.8.8', 'IPv4 literal'],
    ['::ffff:8.8.8.8', 'IPv4-mapped public'],
    ['2002:0808:0808::', '6to4 of a public address'],
    ['2001:4860:4860::8888', 'ordinary public IPv6'],
  ] as const;

  for (const [ip, how] of PUBLIC) {
    it(`does NOT block a public address written as ${how}`, () => {
      expect(isAlwaysBlockedIp(ip)).toBe(false);
      expect(isPrivateOrReservedIp(ip)).toBe(false);
    });
  }
});
