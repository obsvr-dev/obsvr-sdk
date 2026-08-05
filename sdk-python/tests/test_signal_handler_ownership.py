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


# ── driving a child: the two protections every signalled row needs ──────────
#
# A marker read off the pipe says the child STARTED that write, not that it
# finished it and released the writer. Signalling into that window runs the
# child's handler while its own ``print`` still holds the stdout lock, and a
# ``print`` from the handler then re-enters the same buffered writer — which
# raises ``RuntimeError: reentrant call`` inside the handler, where obsvr's
# ``except Exception: pass`` absorbs it. The line the row asserts on is then
# simply never written, and nothing is written to stderr either.
#
# Both protections below are load-bearing and neither substitutes for the
# other: the settle keeps the child out of that window, ``mark`` makes landing
# in it harmless. They live here, on the one helper every signalled row goes
# through, so no row can be added without them.

#: Handler output goes through ``os.write``, which reaches the fd directly and
#: takes no lock. Every child in this file is given ``mark``; every child-side
#: signal handler in this file uses it in place of ``print``.
MARK = 'def mark(text):\n    os.write(1, text.encode() + b"\\n")\n'

#: How long to let a marker line settle before delivering the signal.
SETTLE_BEFORE_SIGNAL_S = 0.15


def _drive_child(src, steps, timeout=20):
    """Run ``src`` as a child, delivering a signal at each step.

    ``steps`` is a list of ``(marker, signal_or_None)``: wait for the child to
    print ``marker``, then deliver ``signal``. Returns
    ``(returncode, output, stderr)``.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", src],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Every line, not only the marker: a row may assert on something the child
    # printed BEFORE it was ready, and dropping those reads as a silent absence.
    seen = []
    try:
        for marker, sig in steps:
            deadline = time.time() + timeout
            while time.time() < deadline:
                line = proc.stdout.readline()
                seen.append(line)
                if marker in line or proc.poll() is not None:
                    break
            else:  # pragma: no cover - only on a hung child
                proc.kill()
                pytest.fail("child never printed %r" % marker)
            if sig is not None:
                time.sleep(SETTLE_BEFORE_SIGNAL_S)
                proc.send_signal(sig)
        out, err = proc.communicate(timeout=timeout)
    finally:
        if proc.poll() is None:  # pragma: no cover - only on a hung child
            proc.kill()
            out, err = proc.communicate(timeout=5)
    return proc.returncode, "".join(seen) + out, err


def run_child(body: str, sig: signal.Signals, wait_for: str = "ready"):
    """Start a child running ``body``, signal it once it prints ``wait_for``."""
    src = "import os, signal, sys, time\n" + MARK + textwrap.dedent(body)
    return _drive_child(src, [(wait_for, sig)])


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
        mark("FLUSH " + str(timeout))    # runs from obsvr's handler
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
        mark("FLUSH " + str(timeout))    # runs from obsvr's handler
        return real(0.01)
    sender.flush = spy

    def prior(signum, frame):
        mark("HOST")
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
        mark("HOST")
        # A real drain: obsvr must not have ended the process before this.
        time.sleep(0.3)
        mark("HOST DONE")
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
        mark("HOST SAW IT")
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
    latched = {}
    try:
        sender._handle_shutdown_signal(signal.SIGTERM, None)
        # Read both latches HERE, not after the reset. ``_reset_signal_handlers``
        # clears ``_signal_flush_started`` itself, so a read taken after it
        # answers for the reset and would hold whatever the handler did.
        latched["shutdown"] = sender._shutdown.is_set()
        latched["flush_started"] = sender._signal_flush_started
    finally:
        sender._reset_signal_handlers()

    assert seen == [signal.SIGTERM]
    # The host owns termination on this path — obsvr must not re-raise.
    assert killed == []
    assert not latched["shutdown"]
    assert not latched["flush_started"]


# ── the second flush: a signal, then a normal exit ──────────────────────────
#
# When the host handler RETURNS rather than exiting, obsvr clears both latches
# and hands the signal on. The process may then exit normally, and `atexit`
# fires a SECOND flush over the same sender. That path is correct by
# construction -- the flushes are sequential, the second finds a drained queue,
# and a genuine duplicate is absorbed as idempotent success by the 409
# `duplicate_event` rule -- and none of the nine rows above drove it.
#
# These three drive it against a REAL ingest endpoint rather than a patched
# sender: duplication is a delivery-layer property, and a spy on `flush` cannot
# see it. The child runs a recording HTTP server on loopback, writes every event
# the server durably accepted to a file, and the parent grades that file.

#: Child-side recording ingest. Records each event once per `request_id`.
#: In `duplicate` mode it records the event and STILL answers 409
#: `duplicate_event`, which is what ingest returns when a retry races a lost
#: 2xx -- the answer the sender is required to read as idempotent success.
RECORDING_INGEST = """
    import http.server, json, threading, time

    ACCEPTED = []          # every event durably recorded, in arrival order
    _SEEN = set()          # request_ids already recorded
    ALWAYS_409 = %r
    SLOW_FROM = %r          # 1-based request index from which delivery is slow
    SLOW_SECONDS = %r

    _requests = [0]

    class _Ingest(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            events = body if isinstance(body, list) else [body]
            _requests[0] += 1
            if SLOW_FROM and _requests[0] >= SLOW_FROM:
                # Record only AFTER the delay, so a process that exits without
                # waiting for its queue leaves this delivery unrecorded -- which
                # is what an undelivered queue tail looks like from ingest.
                time.sleep(SLOW_SECONDS)
            for ev in events:
                rid = ev.get("request_id")
                if rid in _SEEN:
                    continue
                _SEEN.add(rid)
                ACCEPTED.append(ev)
            if ALWAYS_409:
                payload = json.dumps({"error": "duplicate_event"}).encode()
                self.send_response(409)
            else:
                payload = b"{}"
                self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    _server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Ingest)
    INGEST_URL = "http://127.0.0.1:%%d" %% _server.server_address[1]
    threading.Thread(target=_server.serve_forever, daemon=True).start()

    def dump_accepted(path):
        with open(path, "w") as fh:
            for ev in ACCEPTED:
                fh.write(json.dumps(ev) + "\\n")
"""


def _emit(request_id):
    """Child source enqueuing one governed event with a known request_id."""
    return (
        "obsvr.sender.send_audit_async(obsvr.config.get_config(), "
        '{"request_id": %r, "environment": "test", "region": "us", '
        '"provider": "openai", "model": "m", "operation": "chat.completions.create", '
        '"source": "test", "prompt": "p", "response": "r", "success": True})' % request_id
    )


def run_recording_child(
    body, steps, always_409=False, slow_from=0, slow_seconds=0.0, timeout=25
):
    """Run a child with a recording ingest, signaling it at each step.

    Signalling itself is ``_drive_child``'s, same as every other row's; what
    this adds is the loopback ingest and the file of what it durably accepted.
    Returns `(returncode, output, stderr, accepted_events)`.
    """
    import json
    import tempfile

    fd, dump_path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    src = (
        "import os, signal, sys, time\n"
        + textwrap.dedent(RECORDING_INGEST % (always_409, slow_from, slow_seconds))
        + "\nDUMP_PATH = %r\n" % dump_path
        + MARK
        + textwrap.dedent(body)
    )
    code, out, err = _drive_child(src, steps, timeout=timeout)
    accepted = []
    with open(dump_path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                accepted.append(json.loads(line))
    os.unlink(dump_path)
    return code, out, err, accepted


def assert_one_delivery_each(accepted, expected_ids, where):
    """Exactly one durable record per event, on one unforked chain."""
    ids = [ev["request_id"] for ev in accepted]
    assert sorted(ids) == sorted(expected_ids), f"{where}: delivered {ids}"
    assert len(set(ids)) == len(ids), f"{where}: duplicate delivery {ids}"
    sessions = {ev["sdk_session_id"] for ev in accepted}
    assert len(sessions) == 1, f"{where}: {len(sessions)} sessions claimed"
    seqs = sorted(ev["seq_no"] for ev in accepted)
    assert seqs == list(range(1, len(accepted) + 1)), f"{where}: seq_no {seqs}"


def test_a_signal_then_a_normal_exit_delivers_each_event_exactly_once():
    """The path none of the nine rows above drove. The host handler returns, so
    obsvr clears its latches and does not end the process; the process then
    exits normally and `atexit` flushes a second time over the same sender."""
    body = """
    import obsvr

    def prior(signum, frame):
        mark("HOST RETURNED")
    signal.signal(signal.SIGTERM, prior)

    obsvr.init(api_key="k", ingest_url=INGEST_URL, sample_rate=1)
    import atexit
    atexit.register(lambda: dump_accepted(DUMP_PATH))
    %s
    print("ready", flush=True)

    time.sleep(1.2)                       # the signal lands in here
    %s                                    # enqueued AFTER the signal flush
    print("SECOND EVENT QUEUED", flush=True)
    sys.exit(0)                           # normal exit -> obsvr's atexit flush
""" % (_emit("before-signal"), _emit("after-signal"))

    code, out, err, accepted = run_recording_child(
        body, [("ready", signal.SIGTERM), ("SECOND EVENT QUEUED", None)]
    )

    assert "HOST RETURNED" in out, (out, err)
    assert code == 0, (code, out, err)
    assert_one_delivery_each(accepted, ["before-signal", "after-signal"], "signal+atexit")


def test_a_second_signal_still_flushes_what_arrived_after_the_first():
    """Why the latch reset is load-bearing. The host exits on the SECOND
    signal, so `atexit` never runs and obsvr's own handler is the only flush the
    later event can get -- which it performs only because the first signal
    cleared `_signal_flush_started` on its way out.

    Ingest is made SLOW for the second delivery on purpose. With a healthy
    endpoint the live worker drains the queue in milliseconds and the flush is
    never what delivers anything, so the row would pass with the latch reset
    removed -- it would be measuring the worker, not the shutdown path. A
    delivery still in flight is the only state in which "did obsvr wait for its
    queue" is answerable."""
    body = """
    import obsvr

    _n = [0]
    def prior(signum, frame):
        _n[0] += 1
        if _n[0] == 1:
            mark("HOST RETURNED")
            return
        mark("HOST EXITING")
        dump_accepted(DUMP_PATH)
        os._exit(0)                       # skips atexit entirely
    signal.signal(signal.SIGTERM, prior)

    obsvr.init(api_key="k", ingest_url=INGEST_URL, sample_rate=1)
    %s
    print("ready", flush=True)

    time.sleep(1.2)
    %s
    print("SECOND EVENT QUEUED", flush=True)
    time.sleep(8)
""" % (_emit("before-signal"), _emit("after-signal"))

    code, out, err, accepted = run_recording_child(
        body,
        [("ready", signal.SIGTERM), ("SECOND EVENT QUEUED", signal.SIGTERM)],
        slow_from=2,
        slow_seconds=1.5,
    )

    assert "HOST EXITING" in out, (out, err)
    assert_one_delivery_each(accepted, ["before-signal", "after-signal"], "two signals")


def test_a_duplicate_answer_across_the_flushes_is_absorbed_not_dropped():
    """The other half of "safe today". Ingest answers 409 `duplicate_event` for
    an event it already holds, which is what a retry racing a lost 2xx sees. It
    is idempotent success: counting it as a drop would put a fabricated coverage
    gap on evidence that exists."""
    body = """
    import obsvr
    from obsvr import sender

    def prior(signum, frame):
        mark("HOST RETURNED")
    signal.signal(signal.SIGTERM, prior)

    obsvr.init(api_key="k", ingest_url=INGEST_URL, sample_rate=1)
    import atexit
    atexit.register(lambda: dump_accepted(DUMP_PATH))
    %s
    print("ready", flush=True)

    time.sleep(1.2)
    %s
    print("SECOND EVENT QUEUED", flush=True)
    time.sleep(1.5)
    s = sender.get_sender_stats()
    print("DROPS", s["dropped_permanent"] + s["dropped_retry_exhausted"]
                   + s["dropped_overflow"], flush=True)
    print("SENT", s["sent"], flush=True)
    sys.exit(0)
""" % (_emit("before-signal"), _emit("after-signal"))

    code, out, err, accepted = run_recording_child(
        body, [("ready", signal.SIGTERM), ("SENT", None)], always_409=True
    )

    # Every delivery was answered 409 duplicate_event, and none of them counted
    # as a loss. Both events are still on the record exactly once.
    assert "DROPS 0" in out, (out, err)
    assert "SENT 2" in out, (out, err)
    assert_one_delivery_each(accepted, ["before-signal", "after-signal"], "409 duplicate")
