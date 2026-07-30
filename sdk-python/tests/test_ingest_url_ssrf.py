"""The ingest URL runs the SSRF guard.

``ingest_url`` receives every prompt, every response and the ``X-API-Key``
header, and it used to be validated for exactly one thing: whether a plaintext
``http`` URL pointed off-loopback. Any other scheme returned early, so
``file:///etc/passwd`` was accepted, and no address check ran at all, so the
cloud-metadata endpoint was accepted as an ingest target.

The table below is the whole contract. The ACCEPTED rows are what makes the
refusals mean something: a guard that refuses everything would satisfy every
REFUSED row and be useless.
"""
import pytest

import obsvr


def _init(url):
    # Polling disabled: these tests must never attempt a network poll.
    obsvr.init(api_key="test", policy_refresh_interval_s=0, ingest_url=url)


# Every scheme that is not http(s). Each of these used to be ACCEPTED, because
# the old check returned early for anything whose scheme was not exactly "http".
NON_HTTP_SCHEMES = [
    "file:///etc/passwd",
    "gopher://127.0.0.1:11211/_stats",
    "ftp://evil.example.com/pwn",
    "data:text/plain,x",
]

# The cloud-metadata address in all four IPv6 spellings that route to it, plus
# the IPv4 literal. ALWAYS refused - there is no opt-out and no loopback
# exemption, because none of these is ever a legitimate ingest target.
METADATA_SPELLINGS = [
    "http://169.254.169.254/",
    "http://[::ffff:169.254.169.254]/",   # IPv4-mapped
    "http://[::169.254.169.254]/",        # IPv4-compatible (deprecated)
    "http://[64:ff9b::169.254.169.254]/",  # NAT64
    "http://[2002:a9fe:a9fe::]/",         # 6to4
    "https://[::169.254.169.254]/",       # https does not exempt it either
]

PRIVATE_LITERALS = [
    "https://10.0.0.5:8443/",
    "https://192.168.1.9/",
    "https://172.16.4.4/",
    "https://[fd00::1]/",
]

# The control column. Nothing here may be refused.
ACCEPTED = [
    "https://audit.example.com",
    "https://audit.example.com:8443/ingest",
    "https://8.8.8.8",
    "http://localhost:8787",
    "http://127.0.0.1:9999",
    "http://[::1]:9999",
]


@pytest.mark.parametrize("url", NON_HTTP_SCHEMES)
def test_non_http_scheme_is_refused(url):
    with pytest.raises(ValueError, match="failed the SSRF guard"):
        _init(url)


@pytest.mark.parametrize("url", METADATA_SPELLINGS)
def test_metadata_address_is_refused_in_every_spelling(url):
    with pytest.raises(ValueError, match="failed the SSRF guard"):
        _init(url)


@pytest.mark.parametrize("url", METADATA_SPELLINGS)
def test_allow_http_does_not_rescue_the_metadata_address(url, monkeypatch):
    monkeypatch.setenv("OBSVR_ALLOW_HTTP", "1")
    with pytest.raises(ValueError, match="failed the SSRF guard"):
        _init(url)


@pytest.mark.parametrize("url", PRIVATE_LITERALS)
def test_private_literal_is_refused(url):
    with pytest.raises(ValueError, match="failed the SSRF guard"):
        _init(url)


@pytest.mark.parametrize("url", ACCEPTED)
def test_legitimate_ingest_urls_are_accepted(url):
    # Non-vacuity for every REFUSED row above: the guard distinguishes.
    _init(url)
    assert obsvr.is_initialized()
    assert obsvr.get_config().ingest_url == url


def test_unconfigured_ingest_url_still_initializes():
    # The empty default must not be dragged into the guard, which requires a host.
    obsvr.init(api_key="test", policy_refresh_interval_s=0)
    assert obsvr.is_initialized()
    assert obsvr.get_config().ingest_url == ""


def test_hostname_is_compared_parsed_not_as_a_substring():
    # The TypeScript twin gated on `url.includes("localhost")`, so a host merely
    # CONTAINING the word was treated as loopback. Python has always parsed the
    # hostname; this pins that it stays parsed in both trees.
    with pytest.raises(ValueError, match="must use https"):
        _init("http://localhost.evil.example.com/ingest")
    with pytest.raises(ValueError, match="must use https"):
        _init("http://evil.example.com/localhost")
