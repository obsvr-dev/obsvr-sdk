"""SSRF guard on the presidio analyzer/anonymizer endpoints (init-time).
These receive the PROMPT/PII content to scan — the endpoint that sees the MOST
sensitive data — so a misconfigured/hijacked URL is both an SSRF primitive and
an exfiltration surface. Twin: sdk/tests/unit/presidio-ssrf.test.ts.

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
