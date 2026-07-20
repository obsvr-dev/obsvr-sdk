"""init() HTTPS enforcement: non-localhost ingest URLs must be https.

The README claims "HTTPS enforced for non-localhost"; these tests pin that
claim. Local development (localhost / 127.0.0.1 / [::1]) stays http-friendly,
and OBSVR_ALLOW_HTTP=1 is the explicit escape hatch.
"""
import pytest

import obsvr


def _init(url=None, **extra):
    # Polling disabled: these tests must never attempt a network poll.
    kwargs = dict(api_key="test", policy_refresh_interval_s=0)
    if url is not None:
        kwargs["ingest_url"] = url
    kwargs.update(extra)
    obsvr.init(**kwargs)


def test_http_remote_url_raises():
    with pytest.raises(ValueError, match="must use https"):
        _init("http://audit.example.com")


def test_http_remote_url_with_port_and_path_raises():
    with pytest.raises(ValueError, match="must use https"):
        _init("http://10.0.0.5:3000/ingest")


def test_https_remote_url_allowed():
    _init("https://audit.example.com")
    assert obsvr.get_config().ingest_url == "https://audit.example.com"


@pytest.mark.parametrize("url", [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://[::1]:3000",
])
def test_http_localhost_allowed(url):
    _init(url)
    assert obsvr.is_initialized()


def test_default_ingest_url_allowed():
    _init()  # DEFAULT_INGEST_URL is http://localhost:3000
    assert obsvr.is_initialized()


def test_env_override_allows_http_remote(monkeypatch):
    monkeypatch.setenv("OBSVR_ALLOW_HTTP", "1")
    _init("http://audit.example.com")
    assert obsvr.get_config().ingest_url == "http://audit.example.com"


def test_env_override_falsy_value_still_raises(monkeypatch):
    monkeypatch.setenv("OBSVR_ALLOW_HTTP", "0")
    with pytest.raises(ValueError, match="must use https"):
        _init("http://audit.example.com")
