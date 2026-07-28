/**
 * SSRF guard for outbound backend URLs (ADR-4 external policy backend).
 *
 * An external policy backend URL is treated as UNTRUSTED input: it may arrive
 * from server-pushed config or a multi-tenant dashboard, so a naive fetch would
 * be a server-side request forgery primitive — an attacker could point it at the
 * cloud metadata endpoint (169.254.169.254) or an internal service. This module
 * blocks non-http(s) schemes and private / loopback / link-local / metadata
 * addresses, RESOLVING the hostname before connecting so a public-looking name
 * that resolves to a private IP is still refused.
 *
 * Two tiers of blocking:
 *  - ALWAYS blocked (even with allowPrivateNetwork): cloud metadata + link-local.
 *    These are never a legitimate policy backend and are the crown-jewel SSRF
 *    target, so no opt-out exists.
 *  - Blocked BY DEFAULT, allowed with allowPrivateNetwork=true: loopback and
 *    RFC1918 / ULA / CGNAT private ranges. A legitimate OPA/Cedar deployment is
 *    frequently a sidecar on localhost or a private-network host, so this
 *    deliberate, documented opt-in keeps the feature usable without weakening
 *    the metadata protection.
 *
 * Kept dependency-free (Node stdlib dns only) to match the SDK's zero-runtime-dep
 * posture. Twin: sdk-python/obsvr/ssrf.py — the two must classify the same
 * private/reserved IP ranges identically.
 *
 * @packageDocumentation
 */

import { lookup } from 'node:dns/promises';

/** Raised when a backend URL fails the SSRF guard. */
export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SsrfError';
  }
}

export interface SsrfOptions {
  /** Allow loopback + RFC1918/ULA/CGNAT private ranges (never metadata/link-local). */
  allowPrivateNetwork?: boolean;
}

/** Parse an IPv4 dotted-quad into 4 octets, or null if not an IPv4 literal. */
function parseIpv4(ip: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  return octets as [number, number, number, number];
}

/**
 * If `ip` is an IPv4-mapped IPv6 address, return the embedded IPv4 dotted-quad;
 * otherwise null. Covers the dotted tail `::ffff:a.b.c.d`, the HEX form
 * `::ffff:HHHH:HHHH`, and the fully-expanded `0:0:0:0:0:ffff:...` prefix.
 *
 * This is load-bearing for the SSRF guard: Node's WHATWG URL parser normalizes
 * `[::ffff:169.254.169.254]` to the HEX form `::ffff:a9fe:a9fe`, which a
 * dotted-decimal-only check does not recognize — leaving the cloud-metadata
 * address reachable. Folding to IPv4 first closes that bypass.
 */
function mappedIpv4(ip: string): string | null {
  const norm = ip.toLowerCase().replace(/^\[|\]$/g, "");
  // Leading zero groups may be compressed (`::`) or explicit (`0:0:0:0:0:`).
  const m =
    /^(?:::|(?:0:){1,5})ffff:(?:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(
      norm,
    );
  if (!m) return null;
  if (m[1]) {
    const octets = parseIpv4(m[1]);
    return octets ? m[1] : null;
  }
  const hi = parseInt(m[2], 16);
  const lo = parseInt(m[3], 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/** True for an IPv4 or IPv6 literal (with brackets already stripped). */
export function isIpLiteral(host: string): boolean {
  if (parseIpv4(host)) return true;
  // Any colon means an IPv6 literal (possibly with a ::ffff: mapped tail).
  return host.includes(':');
}

/**
 * Cloud-metadata + link-local addresses. ALWAYS blocked — no opt-out.
 * Covers 169.254.0.0/16 (incl. 169.254.169.254), IPv6 link-local fe80::/10,
 * and the AWS IPv6 metadata address fd00:ec2::254.
 */
export function isAlwaysBlockedIp(ip: string): boolean {
  // Fold any IPv4-mapped IPv6 form to its IPv4 first (hex or dotted), so a
  // mapped metadata/link-local address cannot slip past the v4 range checks.
  const effective = mappedIpv4(ip) ?? ip;
  const v4 = parseIpv4(effective);
  if (v4) {
    return v4[0] === 169 && v4[1] === 254; // 169.254/16 link-local (metadata)
  }
  const norm = effective.toLowerCase().replace(/^\[|\]$/g, '');
  if (/^fe[89ab]/.test(norm)) return true; // fe80::/10 link-local
  if (norm === 'fd00:ec2::254') return true; // AWS IPv6 metadata
  return false;
}

/**
 * Private / loopback / reserved addresses (blocked by default; allowed with
 * allowPrivateNetwork). Includes 0/8, 10/8, 127/8, 169.254/16, 172.16/12,
 * 192.168/16, 100.64/10 (CGNAT), multicast/reserved (>=224), IPv6 ::/::1,
 * fc00::/7 (ULA), fe80::/10 (link-local), and ::ffff: mapped IPv4.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const effective = mappedIpv4(ip) ?? ip;
  const v4 = parseIpv4(effective);
  if (v4) {
    const [a, b] = v4;
    if (a === 0) return true; // 0.0.0.0/8 "this network"
    if (a === 10) return true; // 10/8
    if (a === 127) return true; // loopback
    if (a === 169 && b === 254) return true; // link-local
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
    if (a === 192 && b === 168) return true; // 192.168/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
    // Reserved documentation / benchmarking ranges (kept in lockstep with the
    // Python twin's ipaddress classification so both SDKs refuse the same set):
    if (a === 192 && b === 0 && (v4[2] === 0 || v4[2] === 2)) return true; // 192.0.0/24 + 192.0.2/24 (TEST-NET-1)
    if (a === 198 && b === 51 && v4[2] === 100) return true; // 198.51.100/24 (TEST-NET-2)
    if (a === 203 && b === 0 && v4[2] === 113) return true; // 203.0.113/24 (TEST-NET-3)
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18/15 benchmarking
    if (a >= 224) return true; // 224/4 multicast + 240/4 reserved
    return false;
  }
  const norm = effective.toLowerCase().replace(/^\[|\]$/g, '');
  if (norm === '::1' || norm === '::') return true; // loopback / unspecified
  if (/^f[cd]/.test(norm)) return true; // fc00::/7 unique-local
  if (/^fe[89ab]/.test(norm)) return true; // fe80::/10 link-local
  return false;
}

/** Assert one resolved/literal address is permitted, or throw SsrfError. */
export function assertIpAllowed(ip: string, opts: SsrfOptions = {}): void {
  if (isAlwaysBlockedIp(ip)) {
    throw new SsrfError(`backend url resolves to a blocked metadata/link-local address: ${ip}`);
  }
  if (!opts.allowPrivateNetwork && isPrivateOrReservedIp(ip)) {
    throw new SsrfError(
      `backend url resolves to a blocked private/reserved address: ${ip} ` +
        `(set allowPrivateNetwork to permit a sidecar/private-network backend)`,
    );
  }
}

/**
 * STATIC guard (no DNS): validate scheme and, for a literal-IP host, its range.
 * Called at init() so a clearly-unsafe URL fails fast. Hostnames pass this
 * stage and are checked dynamically by {@link assertBackendUrlAllowed}.
 */
export function assertBackendUrlStatic(url: string, opts: SsrfOptions = {}): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new SsrfError(`invalid backend url: ${String(url)}`);
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new SsrfError(`backend url scheme must be http(s), got "${u.protocol}"`);
  }
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isIpLiteral(host)) {
    assertIpAllowed(host, opts);
  }
  return u;
}

/** Resolve a hostname to all A/AAAA addresses. Injectable for tests. */
export type Resolver = (host: string) => Promise<string[]>;

const defaultResolver: Resolver = async (host: string): Promise<string[]> => {
  const results = await lookup(host, { all: true });
  return results.map((r) => r.address);
};

/**
 * FULL guard: static checks plus DNS resolution of a hostname host, asserting
 * EVERY resolved address is permitted (resolve-before-connect). A public name
 * that resolves to a private IP is refused. Literal-IP hosts skip DNS.
 *
 * Residual TOCTOU: the subsequent fetch re-resolves the name, so a name that
 * flips to a private IP between this check and the connect could still be hit.
 * Literal-IP backends have no such gap; for hostnames this narrows, not closes,
 * the window. Callers fail closed on any thrown SsrfError.
 */
export async function assertBackendUrlAllowed(
  url: string,
  opts: SsrfOptions = {},
  resolver: Resolver = defaultResolver,
): Promise<void> {
  const u = assertBackendUrlStatic(url, opts);
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isIpLiteral(host)) return; // already asserted in the static pass
  const addrs = await resolver(host);
  if (!addrs.length) {
    throw new SsrfError(`backend url host did not resolve: ${host}`);
  }
  for (const addr of addrs) assertIpAllowed(addr, opts);
}
