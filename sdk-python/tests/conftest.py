import pytest

import obsvr
from obsvr import sender


@pytest.fixture(autouse=True)
def clean_state():
    obsvr._reset()
    sender._reset_sender()
    yield
    obsvr._reset()
    sender._reset_sender()


@pytest.fixture
def sent(monkeypatch):
    """Capture events instead of HTTP-sending them."""
    captured = []
    monkeypatch.setattr(
        sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured
