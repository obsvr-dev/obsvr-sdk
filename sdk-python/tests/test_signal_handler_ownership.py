"""SIGTERM/SIGINT ownership, Python half.

Twin: sdk-typescript/tests/unit/exit-handler-ownership.test.ts.

This SDK flushed only from ``atexit``, which a default-disposition ``SIGTERM``
never reaches — so every container stop dropped whatever the bounded queue still
held, and the events most likely to be lost are the ones nearest the shutdown.
The TypeScript twin is the reference for the ownership rules and they are ported
rather than reinvented: chain to any prior handler, flush within the existing
budget, and re-raise the default disposition ONLY when the prior handler was
SIG_DFL.

WHY SUBPROCESSES. A handler that restores SIG_DFL and re-delivers the signal
ends the process it runs in, so the SIG_DFL rows cannot be driven in-process
without ending the test session. Each row below is a real interpreter, sent a
real signal, graded on its exit status and on what it wrote before dying.
"""
import os
import signal
import subprocess
import sys
import textwrap
import time

import pytest

from obsvr import sender

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX signal dispositions"
)


def run_child(body: str, sig: signal.Signals, wait_for: str = "ready"):
    """Start a child running ``body``, signal it once it prints ``wait_for``."""
    src = "import os, signal, sys, time\n" + textwrap.dedent(body)
    proc = subprocess.Popen(
        [sys.executable, "-c", src],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.time() + 20
    # Every line, not only the marker: a row may assert on something the child
    # printed BEFORE it was ready, and dropping those reads as a silent absence.
    seen = []
    while time.time() < deadline:
        line = proc.stdout.readline()
        seen.append(line)
        if wait_for in line:
            break
        if proc.poll() is not None:
            break
    else:  # pragma: no cover - only on a hung child
        proc.kill()
        pytest.fail("child never reported ready")
    proc.send_signal(sig)
    out, err = proc.communicate(timeout=20)
    return proc.returncode, "".join(seen) + out, err


# ── the three ownership rows ────────────────────────────────────────────────

def test_sigterm_with_no_prior_handler_flushes_and_dies_by_the_signal():
    """SIG_DFL was the disposition, so obsvr owns the exit — and re-raises the
    DEFAULT rather than exiting with a number that stands in for it. A process
    killed by SIGTERM is what a supervisor reads.

    BOTH halves are asserted. The exit status alone proves nothing here: an
    interpreter with no obsvr handler at all dies exactly the same way, so
    without the flush line this row would pass against the defect it exists
    for."""
    body = """
    import obsvr
    from obsvr import sender

    real = sender.flush
    def spy(timeout=5.0):
        print("FLUSH", timeout, flush=True)
        return real(0.01)
    sender.flush = spy

    print("PRIOR IS DFL", signal.getsignal(signal.SIGTERM) is signal.SIG_DFL, flush=True)
    obsvr.init(api_key="k", ingest_url="https://example.invalid")
    sender._ensure_worker()
    print("OBSVR INSTALLED",
          signal.getsignal(signal.SIGTERM) is sender._handle_shutdown_signal, flush=True)
    print("ready", flush=True)
    time.sleep(30)
"""
    code, out, err = run_child(body, signal.SIGTERM)

    # This really is the SIG_DFL row, and obsvr really did take the disposition.
    assert "PRIOR IS DFL True" in out, (out, err)
    assert "OBSVR INSTALLED True" in out, (out, err)
    assert "FLUSH" in out, (out, err)
    # -SIGTERM, not 143: the process died BY the signal.
    assert code == -signal.SIGTERM, (code, out, err)


def test_sigterm_flushes_the_queue_before_it_lets_go():
    """The whole point. A flush must have run, with the shutdown budget."""
    body = """
    import obsvr
    from obsvr import sender

    seen = []
    real = sender.flush
    def spy(timeout=5.0):
        seen.append(timeout)
        print("FLUSH", timeout, flush=True)
        return real(0.01)
    sender.flush = spy

    def prior(signum, frame):
        print("HOST", flush=True)
        os._exit(0)
    signal.signal(signal.SIGTERM, prior)

    obsvr.init(api_key="k", ingest_url="https://example.invalid")
    sender._ensure_worker()
    print("OBSVR INSTALLED",
          signal.getsignal(signal.SIGTERM) is sender._handle_shutdown_signal, flush=True)
    print("ready", flush=True)
    time.sleep(30)
"""
    code, out, err = run_child(body, signal.SIGTERM)

    assert "OBSVR INSTALLED True" in out, (out, err)
    assert "FLUSH" in out, (out, err)
    # The existing shutdown budget, not a new number invented for this path.
    assert f"FLUSH {sender.SHUTDOWN_FLUSH_TIMEOUT_S}" in out, out
    # And the flush ran BEFORE the host handler, not after it.
    assert out.index("FLUSH") < out.index("HOST"), out


def test_a_prior_handler_owns_termination_and_obsvr_does_not_exit():
    """The host installed its own shutdown first. obsvr flushes beside it and
    hands the signal on; the process ends when the HOST says so, with the
    host's status — never obsvr ending it out from under a drain."""
    body = """
    import obsvr
    from obsvr import sender

    def prior(signum, frame):
        print("HOST", flush=True)
        # A real drain: obsvr must not have ended the process before this.
        time.sleep(0.3)
        print("HOST DONE", flush=True)
        os._exit(7)
    signal.signal(signal.SIGTERM, prior)

    obsvr.init(api_key="k", ingest_url="https://example.invalid")
    sender._ensure_worker()
    print("OBSVR INSTALLED",
          signal.getsignal(signal.SIGTERM) is sender._handle_shutdown_signal, flush=True)
    print("ready", flush=True)
    time.sleep(30)
"""
    code, out, err = run_child(body, signal.SIGTERM)

    assert "OBSVR INSTALLED True" in out, (out, err)
    assert "HOST DONE" in out, (out, err)
    assert code == 7, (code, out, err)


def test_a_host_handler_that_returns_leaves_the_process_running():
    """The other half of chaining, and the one an unconditional exit breaks: a
    handler that logs and returns must leave the process alive."""
    body = """
    import obsvr
    from obsvr import sender

    def prior(signum, frame):
        print("HOST SAW IT", flush=True)
    signal.signal(signal.SIGTERM, prior)

    obsvr.init(api_key="k", ingest_url="https://example.invalid")
    sender._ensure_worker()
    print("OBSVR INSTALLED",
          signal.getsignal(signal.SIGTERM) is sender._handle_shutdown_signal, flush=True)
    print("ready", flush=True)
    time.sleep(1.5)
    print("STILL ALIVE", flush=True)
    os._exit(3)
"""
    code, out, err = run_child(body, signal.SIGTERM)

    assert "OBSVR INSTALLED True" in out, (out, err)
    assert "HOST SAW IT" in out, (out, err)
    assert "STILL ALIVE" in out, (out, err)
    assert code == 3, (code, out, err)


def test_sigint_is_owned_the_same_way():
    """SIGINT's default disposition in CPython is ``default_int_handler``, a
    CALLABLE — so obsvr chains to it and KeyboardInterrupt still propagates.
    Nothing about the interactive contract changes."""
    body = """
    import obsvr
    from obsvr import sender

    obsvr.init(api_key="k", ingest_url="https://example.invalid")
    sender._ensure_worker()
    print("OBSVR INSTALLED",
          signal.getsignal(signal.SIGINT) is sender._handle_shutdown_signal, flush=True)
    print("ready", flush=True)
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        print("KEYBOARDINTERRUPT", flush=True)
        os._exit(4)
    os._exit(5)
"""
    code, out, err = run_child(body, signal.SIGINT)

    assert "OBSVR INSTALLED True" in out, (out, err)
    assert "KEYBOARDINTERRUPT" in out, (out, err)
    assert code == 4, (code, out, err)


def test_an_ignored_signal_is_left_alone():
    """SIG_IGN is a disposition the host set deliberately. A process that
    ignores SIGTERM is not going to die from it, so there is no queue tail to
    save and taking the signal over would only break the host's contract."""
    body = """
    import obsvr
    from obsvr import sender

    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    obsvr.init(api_key="k", ingest_url="https://example.invalid")
    sender._ensure_worker()
    print("DISPOSITION", signal.getsignal(signal.SIGTERM) is signal.SIG_IGN, flush=True)
    # The installer DID run in this process — it just declined this one signal.
    # Without this the row would pass equally well against no installer at all.
    print("OBSVR INSTALLED ELSEWHERE",
          signal.getsignal(signal.SIGINT) is sender._handle_shutdown_signal, flush=True)
    print("ready", flush=True)
    time.sleep(1.5)
    print("STILL ALIVE", flush=True)
    os._exit(6)
"""
    code, out, err = run_child(body, signal.SIGTERM)

    assert "DISPOSITION True" in out, (out, err)
    assert "OBSVR INSTALLED ELSEWHERE True" in out, (out, err)
    assert "STILL ALIVE" in out, (out, err)
    assert code == 6, (code, out, err)


# ── in-process rows: what can be asserted without ending the interpreter ────


def test_installation_is_recorded_and_reversible():
    # Read the host's disposition only after any leftover install is undone,
    # or this reads obsvr's own handler as "what was there before".
    sender._reset_signal_handlers()
    prior_term = signal.getsignal(signal.SIGTERM)
    try:
        sender._install_signal_handlers()

        assert sender._signal_handlers_installed
        assert signal.getsignal(signal.SIGTERM) is sender._handle_shutdown_signal
        # The disposition obsvr replaced is kept, because chaining needs it.
        assert sender._prior_dispositions[signal.SIGTERM] == prior_term
    finally:
        sender._reset_signal_handlers()

    assert signal.getsignal(signal.SIGTERM) == prior_term


def test_installation_is_skipped_off_the_main_thread():
    """Only the main thread may set a disposition, and the enqueue path runs on
    whatever thread made the governed call. That must be a quiet no-op, not a
    raise on the caller's audit path."""
    import threading

    sender._reset_signal_handlers()
    prior_term = signal.getsignal(signal.SIGTERM)
    errors = []

    def off_main():
        try:
            sender._install_signal_handlers()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    t = threading.Thread(target=off_main)
    t.start()
    t.join()

    assert errors == []
    assert not sender._signal_handlers_installed
    assert signal.getsignal(signal.SIGTERM) == prior_term


def test_the_shutdown_latch_is_released_when_the_host_owns_termination(monkeypatch):
    """``_shutdown`` is what makes the worker skip its 429 backoff. A host
    handler may RETURN rather than exit, so leaving it set would leave the
    sender hammering a rate-limited ingest for the rest of the process's life.

    ``os.kill`` is intercepted rather than trusted not to fire: this row drives
    the handler in-process, so a regression that took the re-raise branch would
    otherwise end the test session instead of failing a case."""
    sender._reset_signal_handlers()
    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(sig))
    seen = []
    prior = lambda signum, frame: seen.append(signum)  # noqa: E731
    sender._prior_dispositions[signal.SIGTERM] = prior
    try:
        sender._handle_shutdown_signal(signal.SIGTERM, None)
    finally:
        sender._reset_signal_handlers()

    assert seen == [signal.SIGTERM]
    # The host owns termination on this path — obsvr must not re-raise.
    assert killed == []
    assert not sender._shutdown.is_set()
    assert not sender._signal_flush_started
