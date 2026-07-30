/**
 * The ingest URL runs the SSRF guard, and the loopback exemption is a parsed
 * hostname rather than a substring.
 *
 * `ingest_url` receives every prompt, every response and the `X-API-Key`
 * header. It used to be validated for two things: that `new URL()` accepted it,
 * and that a `http://` prefix was paired with the literal text "localhost" or
 * "127.0.0.1" ANYWHERE in the URL. So `file:///etc/passwd` was accepted, the
 * cloud-metadata endpoint was accepted, and `http://localhost.evil.example.com`
 * was accepted as plaintext.
 *
 * The ACCEPTED table is what makes the refusals mean something: a guard that
 * refused everything would satisfy every REFUSED row and be useless.
 *
 * Twin: sdk-python/tests/test_ingest_url_ssrf.py.
 */
import { init, getConfig, isInitialized, _reset } from '../../src/proxy/config';

const initWith = (ingest_url: string): void => {
  // Polling disabled: these tests must never attempt a network poll.
  init({ api_key: 'test', ingest_url, policy_refresh_interval_s: 0 } as never);
};

/** Every scheme that is not http(s). Each of these used to be ACCEPTED. */
const NON_HTTP_SCHEMES = [
  'file:///etc/passwd',
  'gopher://127.0.0.1:11211/_stats',
  'ftp://evil.example.com/pwn',
  'data:text/plain,x',
];

/**
 * The cloud-metadata address in all four IPv6 spellings that route to it, plus
 * the IPv4 literal. ALWAYS refused — no opt-out, no loopback exemption.
 */
const METADATA_SPELLINGS = [
  'http://169.254.169.254/',
  'http://[::ffff:169.254.169.254]/', // IPv4-mapped
  'http://[::169.254.169.254]/', // IPv4-compatible (deprecated)
  'http://[64:ff9b::169.254.169.254]/', // NAT64
  'http://[2002:a9fe:a9fe::]/', // 6to4
  'https://[::169.254.169.254]/', // https does not exempt it either
];

const PRIVATE_LITERALS = [
  'https://10.0.0.5:8443/',
  'https://192.168.1.9/',
  'https://172.16.4.4/',
  'https://[fd00::1]/',
];

/** The control column. Nothing here may be refused. */
const ACCEPTED = [
  'https://audit.example.com',
  'https://audit.example.com:8443/ingest',
  'https://8.8.8.8',
  'http://localhost:8787',
  'http://127.0.0.1:9999',
  'http://[::1]:9999',
];

/**
 * The substring bypass. `includes("localhost")` treated all of these as
 * loopback, so each was accepted as a PLAINTEXT ingest URL — shipping prompts,
 * responses and the API key in the clear to a host the operator did not intend.
 */
const SUBSTRING_BYPASS = [
  'http://localhost.evil.example.com/ingest',
  'http://evil.example.com/localhost',
  'http://127.0.0.1.evil.example.com/',
  'http://evil.example.com/?next=127.0.0.1',
];

describe('ingest_url SSRF guard', () => {
  beforeEach(() => {
    _reset();
  });

  it.each(NON_HTTP_SCHEMES)('refuses the non-http(s) scheme %s', (url) => {
    expect(() => initWith(url)).toThrow('failed the SSRF guard');
  });

  it.each(METADATA_SPELLINGS)('refuses the metadata address spelled %s', (url) => {
    expect(() => initWith(url)).toThrow('failed the SSRF guard');
  });

  it.each(PRIVATE_LITERALS)('refuses the private literal %s', (url) => {
    expect(() => initWith(url)).toThrow('failed the SSRF guard');
  });

  it.each(SUBSTRING_BYPASS)('refuses %s, which the substring test called loopback', (url) => {
    expect(() => initWith(url)).toThrow('plaintext HTTP');
  });

  it.each(ACCEPTED)('accepts the legitimate ingest url %s', (url) => {
    // Non-vacuity for every refusal above: the guard distinguishes.
    initWith(url);
    expect(isInitialized()).toBe(true);
    expect(getConfig().ingest_url).toBe(url);
  });

  it('still initializes with no ingest_url configured', () => {
    // The empty default must not be dragged into the guard, which requires a host.
    init({ api_key: 'test', policy_refresh_interval_s: 0 } as never);
    expect(isInitialized()).toBe(true);
    expect(getConfig().ingest_url).toBe('');
  });

  it('strips exactly one trailing slash, as before', () => {
    initWith('https://audit.example.com/');
    expect(getConfig().ingest_url).toBe('https://audit.example.com');
  });
});
