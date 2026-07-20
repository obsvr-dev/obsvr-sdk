"""SDK version single-sourcing: what goes on the wire is __version__.

obsvr/_version.py is the single source consumed by __init__ (__version__),
remote.py (SDK_VERSION → X-Obsvr-Sdk header), sender.py (signed-event
sdk_version stamp), and pyproject (dynamic version) — a stale hardcoded
copy must be impossible.
"""
import json
from unittest.mock import MagicMock

import obsvr
from obsvr import remote, sender
from obsvr.config import ResolvedConfig


def test_remote_sdk_version_matches_package_version():
    assert remote.SDK_VERSION == obsvr.__version__


def test_signed_event_carries_package_version():
    event = {"prompt": "p", "response": "r"}
    sender.sign_event(event, "test-key")
    assert event["sdk_version"] == f"python/{obsvr.__version__}"


def test_policy_poll_header_carries_package_version(monkeypatch):
    received = {}

    def fake_urlopen(req, timeout=None):
        received["headers"] = dict(req.headers)
        resp = MagicMock()
        resp.read.return_value = json.dumps({"rules": []}).encode("utf-8")
        return resp

    monkeypatch.setattr(remote, "urlopen", fake_urlopen)
    cfg = ResolvedConfig(api_key="test-key", ingest_url="http://localhost:3000")
    remote.poll_once(cfg)
    # urllib capitalizes header names: X-Obsvr-Sdk -> X-obsvr-sdk
    assert received["headers"]["X-obsvr-sdk"] == f"python/{obsvr.__version__}"


def test_pyproject_version_is_dynamic_from_version_module():
    """pyproject must not carry its own hardcoded copy of the version."""
    import re
    from pathlib import Path

    text = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert 'dynamic = ["version"]' in text
    assert re.search(r'^version\s*=\s*"', text, re.MULTILINE) is None
    assert 'attr = "obsvr._version.__version__"' in text
