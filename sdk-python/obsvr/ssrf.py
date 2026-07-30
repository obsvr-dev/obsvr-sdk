"""SSRF guard for outbound backend URLs (ADR-4 external policy backend).

Twin of sdk-typescript/src/utils/ssrf.ts. An external policy backend URL is UNTRUSTED
input (it may arrive from server-pushed config or a multi-tenant dashboard), so
a naive request would be a server-side request forgery primitive. This module
blocks non-http(s) schemes and private / loopback / link-local / metadata
addresses, RESOLVING the hostname before connecting so a public-looking name
that resolves to a private IP is still refused.

Two tiers:
  - ALWAYS blocked (even with allow_private_network): cloud metadata + link-local.
  - Blocked BY DEFAULT, allowed with allow_private_network=True: loopback +
    RFC1918 / ULA / CGNAT private ranges (a legit OPA/Cedar sidecar is often on
    localhost or a private host).

Stdlib only (``ipaddress`` + ``socket``) to keep the core dependency-free.
"""

import ipaddress
import socket
from typing import Callable, List, Optional
from urllib.parse import urlsplit


class SsrfError(Exception):
    """Raised when a backend URL fails the SSRF guard."""


def _parse_ip(ip: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError:
        return None


def _unwrap(addr: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """Unwrap an IPv6 address that CARRIES an IPv4 address to that IPv4.

    This used to cover exactly one of the four ways an IPv6 literal can carry a
    v4 address -- ``ipaddress.ipv4_mapped``, i.e. ``::ffff:a.b.c.d``. Measured:
    with only that form folded, ``http://[::169.254.169.254]/`` reached the
    network through the external-policy backend and was ACCEPTED by ``init()``
    as a Presidio URL, while the ``::ffff:`` spelling of the SAME address was
    refused -- so "always blocked, no opt-out" over the cloud-metadata endpoint
    held for one spelling of it.

    The four forms, all of which route to the same host:
      - IPv4-MAPPED      ``::ffff:a.b.c.d``           (stdlib ``ipv4_mapped``)
      - IPv4-COMPATIBLE  ``::a.b.c.d``                deprecated, still routable
      - NAT64            ``64:ff9b::a.b.c.d``         RFC 6052 / 8215
      - 6to4             ``2002:HHHH:HHHH::``         RFC 3056 -- the v4 address
                                                      is the two groups after
                                                      the prefix

    Twin: ``mappedIpv4`` in sdk-typescript/src/utils/ssrf.ts.
    """
    if not isinstance(addr, ipaddress.IPv6Address):
        return addr
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    packed = addr.packed
    # IPv4-compatible: 96 zero bits then the v4 address. `::` and `::1` are
    # loopback/unspecified and are classified on their own merits, not folded.
    if packed[:12] == b"\x00" * 12 and packed[12:] not in (b"\x00\x00\x00\x00", b"\x00\x00\x00\x01"):
        return ipaddress.IPv4Address(packed[12:])
    # NAT64 well-known prefix 64:ff9b::/96.
    if packed[:12] == b"\x00\x64\xff\x9b" + b"\x00" * 8:
        return ipaddress.IPv4Address(packed[12:])
    # 6to4: 2002:V4V4:V4V4::/48.
    if packed[:2] == b"\x20\x02":
        return ipaddress.IPv4Address(packed[2:6])
    return addr


def is_ip_literal(host: str) -> bool:
    """True when ``host`` is an IPv4/IPv6 literal (brackets already stripped)."""
    return _parse_ip(host) is not None


def is_always_blocked_ip(ip: str) -> bool:
    """Cloud-metadata + link-local addresses. ALWAYS blocked — no opt-out.
    Covers 169.254.0.0/16 (incl. 169.254.169.254), IPv6 link-local fe80::/10,
    and the AWS IPv6 metadata address fd00:ec2::254."""
    addr = _parse_ip(ip)
    if addr is None:
        return False
    addr = _unwrap(addr)
    if addr.is_link_local:  # 169.254/16 and fe80::/10
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr == ipaddress.IPv6Address("fd00:ec2::254"):
        return True
    return False


def is_private_or_reserved_ip(ip: str) -> bool:
    """Private / loopback / reserved (blocked by default; allowed with
    allow_private_network). Uses the stdlib classifiers plus an explicit
    100.64.0.0/10 (CGNAT) check for parity with the TS twin."""
    addr = _parse_ip(ip)
    if addr is None:
        return False
    addr = _unwrap(addr)
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        return True
    # CGNAT 100.64.0.0/10 — not flagged is_private on every Python version.
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        return True
    return False


def _assert_ip_allowed(ip: str, allow_private_network: bool) -> None:
    if is_always_blocked_ip(ip):
        raise SsrfError(f"backend url resolves to a blocked metadata/link-local address: {ip}")
    if not allow_private_network and is_private_or_reserved_ip(ip):
        raise SsrfError(
            f"backend url resolves to a blocked private/reserved address: {ip} "
            "(set allow_private_network to permit a sidecar/private-network backend)"
        )


def assert_backend_url_static(url: str, allow_private_network: bool = False):
    """STATIC guard (no DNS): validate scheme and, for a literal-IP host, its
    range. Called at init() so a clearly-unsafe URL fails fast."""
    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise SsrfError(f"invalid backend url: {url!r}") from e
    if parts.scheme not in ("http", "https"):
        raise SsrfError(f'backend url scheme must be http(s), got "{parts.scheme}"')
    host = parts.hostname or ""
    if host == "":
        raise SsrfError(f"backend url has no host: {url!r}")
    if is_ip_literal(host):
        _assert_ip_allowed(host, allow_private_network)
    return parts


Resolver = Callable[[str], List[str]]


def _default_resolver(host: str) -> List[str]:
    infos = socket.getaddrinfo(host, None)
    return [info[4][0] for info in infos]


def assert_backend_url_allowed(
    url: str,
    allow_private_network: bool = False,
    resolver: Optional[Resolver] = None,
) -> None:
    """FULL guard: static checks plus DNS resolution of a hostname host,
    asserting EVERY resolved address is permitted (resolve-before-connect). A
    public name that resolves to a private IP is refused. Literal-IP hosts skip
    DNS. Residual TOCTOU on hostnames is documented in the TS twin."""
    parts = assert_backend_url_static(url, allow_private_network)
    host = parts.hostname or ""
    if is_ip_literal(host):
        return
    resolve = resolver or _default_resolver
    addrs = resolve(host)
    if not addrs:
        raise SsrfError(f"backend url host did not resolve: {host}")
    for addr in addrs:
        _assert_ip_allowed(addr, allow_private_network)
