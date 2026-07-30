"""SSRF guard on the presidio analyzer/anonymizer endpoints (init-time).
These receive the PROMPT/PII content to scan — the endpoint that sees the MOST
sensitive data — so a misconfigured/hijacked URL is both an SSRF primitive and
an exfiltration surface. Twin: sdk-typescript/tests/unit/presidio-ssrf.test.ts.

Guard policy for presidio (localhost-sidecar norm): cloud-metadata / link-local
is ALWAYS refused; private/loopback is PERMITTED (a presidio sidecar is normally
on localhost).
"""

import pytest

import obsvr
from obsvr.config import _reset

URL = "https://localhost:9"  # a valid ingest_url for the harness


def _init(**extra):
    _reset()
    obsvr.init(api_key="k", ingest_url=URL, disabled=False, **extra)


class TestPresidioSsrfGuard:
    def test_refuses_metadata_analyzer_url(self):
        with pytest.raises(ValueError, match=r"presidio_analyzer_url.*SSRF guard"):
            _init(presidio_analyzer_url="http://169.254.169.254/analyze")

    def test_refuses_metadata_anonymizer_url(self):
        with pytest.raises(ValueError, match=r"presidio_anonymizer_url.*SSRF guard"):
            _init(presidio_anonymizer_url="http://169.254.169.254/anonymize")

    def test_refuses_non_http_scheme(self):
        with pytest.raises(ValueError, match=r"SSRF guard"):
            _init(presidio_analyzer_url="file:///etc/passwd")

    def test_permits_localhost_sidecar(self):
        # No raise — a presidio sidecar on loopback is the norm.
        _init(
            presidio_analyzer_url="http://127.0.0.1:5002",
            presidio_anonymizer_url="http://127.0.0.1:5001",
        )

    def test_permits_private_range_sidecar(self):
        _init(presidio_analyzer_url="http://10.0.0.7:5002/analyze")

    def test_permits_public_and_hostname(self):
        _init(presidio_analyzer_url="https://8.8.8.8/analyze")
        _init(presidio_analyzer_url="http://analyzer.local/analyze")

    def test_rejects_empty_url(self):
        with pytest.raises(ValueError, match=r"presidio_analyzer_url must be a non-empty string"):
            _init(presidio_analyzer_url="   ")


# Every IPv6 spelling that carries an IPv4 address. The guard folded exactly ONE
# of the four (``::ffff:``, via the stdlib ``ipv4_mapped``), so
# ``http://[::169.254.169.254]/`` reached the network through the
# external-policy backend and was accepted by ``init()`` as a Presidio URL while
# the ``::ffff:`` spelling of the SAME address was refused. "Always refused, no
# opt-out" held for one spelling of the address.
#
# The public-address rows are the controls: without them "everything IPv6 is
# blocked" would pass, which is a different bug and a worse one.

_METADATA_FORMS = [
    ("169.254.169.254", "IPv4 literal"),
    ("::ffff:169.254.169.254", "IPv4-mapped, dotted"),
    ("::ffff:a9fe:a9fe", "IPv4-mapped, hex"),
    ("::169.254.169.254", "IPv4-compatible, dotted"),
    ("::a9fe:a9fe", "IPv4-compatible, hex"),
    ("64:ff9b::169.254.169.254", "NAT64 well-known prefix"),
    ("64:ff9b::a9fe:a9fe", "NAT64, hex"),
    ("2002:a9fe:a9fe::", "6to4"),
    ("2002:a9fe:a9fe::1", "6to4 with a host suffix"),
]

_PUBLIC_FORMS = [
    ("8.8.8.8", "IPv4 literal"),
    ("::ffff:8.8.8.8", "IPv4-mapped public"),
    ("2002:0808:0808::", "6to4 of a public address"),
    ("2001:4860:4860::8888", "ordinary public IPv6"),
]


@pytest.mark.parametrize("ip,how", _METADATA_FORMS, ids=[h for _, h in _METADATA_FORMS])
def test_metadata_address_is_always_blocked_in_every_ipv6_form(ip, how):
    from obsvr.ssrf import is_always_blocked_ip

    assert is_always_blocked_ip(ip) is True


@pytest.mark.parametrize("ip,how", _PUBLIC_FORMS, ids=[h for _, h in _PUBLIC_FORMS])
def test_public_address_is_not_blocked_in_any_form(ip, how):
    from obsvr.ssrf import is_always_blocked_ip, is_private_or_reserved_ip

    assert is_always_blocked_ip(ip) is False
    assert is_private_or_reserved_ip(ip) is False
