import pytest

import obsvr
from obsvr import sender


@pytest.fixture(autouse=True)
def clean_state():
    obsvr._reset()
    sender._reset_sender()
    # Signal dispositions are PROCESS state, not sender state: the enqueue path
    # installs obsvr's SIGTERM/SIGINT handler on first use, and leaving it in
    # place makes every later test's view of `getsignal` depend on which tests
    # ran before it.
    sender._reset_signal_handlers()
    yield
    obsvr._reset()
    sender._reset_sender()
    sender._reset_signal_handlers()


@pytest.fixture
def sent(monkeypatch):
    """Capture events instead of HTTP-sending them."""
    captured = []
    monkeypatch.setattr(
        sender, "send_audit_async", lambda config, event: captured.append(event)
    )
    return captured
