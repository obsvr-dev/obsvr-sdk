"""Drive the INSTALLED obsvr-sdk exactly as an external consumer does.

This file is copied out of the repository and executed from a scratch
directory inside a virtualenv where the built wheel (or sdist) is the only
thing installed. Nothing here may import from the source tree: the whole
point is that a packaging defect — a module left out of the wheel, a missing
``py.typed``, a dynamic version that does not resolve, an entry point that
never gets exported — is invisible to a suite that runs against ``sdk-python/``
on ``sys.path``.

WHAT MAKES A PASS MEAN SOMETHING. A refusal check can go green for the wrong
reason: if ``import obsvr`` fails, or the config is rejected, the governed call
also does not happen, and a naive "the payload did not run" assertion reads
that as perfect enforcement. Four things rule that out, and every one of them
is a hard failure rather than a skip:

  1. the installed package is located and proven to live in site-packages,
     never in a checkout;
  2. an ALLOWED tool runs first and must write exactly one marker line and
     return its payload to the caller — the positive control that proves the
     instrument, the config and the governor are all live;
  3. the DENIED tool must raise the SDK's own typed policy error carrying
     reason code TOOL_DENIED, not any exception that happens to stop a call;
  4. the refusal must be on the record — the blocked audit event is collected
     from a loopback ingest sink and its reason code is asserted there too.

THE INSTRUMENT IS THE TOOL'S OWN SIDE EFFECT, in the style the integration
drivers use: the tool appends a line to a marker file and returns a secret
string. Both halves are checked, because they fail differently — a swallowed
error can produce zero executions while the caller still holds the payload,
and that reads as a perfect refusal if only the line count is checked.

Exit code 0 on success; 1 with a diagnosis on any failure.
"""

import json
import os
import sys
import sysconfig
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DENIED_TOOL = "write_marker"
ALLOWED_TOOL = "write_marker_benign"
SECRET = "SECRET-PAYLOAD-42"

# Every name the READMEs teach a first-time caller to reach for. A wheel that
# imports but no longer exports these is broken for its documented usage.
REQUIRED_PUBLIC_NAMES = [
    "init",
    "wrap",
    "govern_tool",
    "govern_tools",
    "flush",
    "explain",
    "span",
    "with_span",
    "agent_run",
    "use_subject",
    "verify_chain",
    "ObsvrPolicyError",
    "ReasonCode",
    "__version__",
]

_failures = []


def check(label, ok, detail=""):
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f"  ({detail})" if detail else ""), flush=True)
    if not ok:
        _failures.append(f"{label}" + (f" — {detail}" if detail else ""))
    return ok


def fatal(message):
    print(f"\nINSTALL-PATH CHECK FAILED: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


class _Sink(BaseHTTPRequestHandler):
    """Collects whatever the SDK's sender posts. A batch arrives as a JSON
    array and a single event as a JSON object; both are flattened."""

    events = []

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = None
        if isinstance(body, list):
            _Sink.events.extend(body)
        elif isinstance(body, dict):
            _Sink.events.append(body)
        payload = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # keep the check's output readable
        pass


class MarkerTool:
    """A ``_run``-shaped tool object, the shape structured-tool conversion
    produces. Its body is the instrument: one appended line per execution."""

    def __init__(self, name, marker):
        self.name = name
        self.description = "appends one line per invocation"
        self.marker = marker

    def _run(self, note: str = "") -> str:
        with open(self.marker, "a", encoding="utf-8") as handle:
            handle.write(f"invoked: {note!r}\n")
        return SECRET


def writes(marker):
    """Execution count, read off the instrument rather than inferred."""
    if not os.path.exists(marker):
        return 0
    return len([line for line in Path(marker).read_text(encoding="utf-8").splitlines() if line])


def main():
    print("Installed-package consumer check (Python)")
    print(f"  interpreter: {sys.version.split()[0]}")
    print(f"  working dir: {os.getcwd()}")

    repo_marker = os.environ.get("OBSVR_REPO_ROOT", "")
    if repo_marker and os.getcwd().startswith(os.path.join(repo_marker, "")):
        fatal(
            "this check runs from a directory outside the repository; "
            f"cwd {os.getcwd()!r} is inside {repo_marker!r}"
        )

    # 1) Import. An ImportError here is the packaging defect, so it is reported
    # as one rather than allowed to look like a refusal further down.
    try:
        import obsvr
    except Exception as exc:  # noqa: BLE001 - any import failure is fatal here
        fatal(f"the installed package does not import: {type(exc).__name__}: {exc}")

    # 2) Provenance. The package under test has to be the INSTALLED one.
    pkg_dir = os.path.dirname(os.path.abspath(obsvr.__file__))
    purelib = os.path.abspath(sysconfig.get_paths()["purelib"])
    check(
        "obsvr resolves from site-packages, not a checkout",
        pkg_dir.startswith(purelib + os.sep),
        f"{pkg_dir}",
    )
    if repo_marker:
        check(
            "no part of the repository is on sys.path",
            not any(
                os.path.abspath(p).startswith(os.path.join(repo_marker, "")) for p in sys.path if p
            ),
        )

    # 3) The version has to resolve. It is declared dynamically from
    # obsvr/_version.py, so a build that loses that file installs a package
    # whose metadata and runtime disagree.
    from importlib.metadata import version as dist_version

    try:
        meta_version = dist_version("obsvr-sdk")
    except Exception as exc:  # noqa: BLE001
        meta_version = f"<unresolved: {exc}>"
    check(
        "distribution metadata and obsvr.__version__ agree",
        bool(obsvr.__version__) and obsvr.__version__ == meta_version,
        f"__version__={obsvr.__version__!r} metadata={meta_version!r}",
    )
    expected = os.environ.get("OBSVR_EXPECTED_VERSION", "")
    if expected:
        check(
            "installed version matches the version in the tree",
            obsvr.__version__ == expected,
            f"installed={obsvr.__version__!r} tree={expected!r}",
        )

    # 4) Package data that only the built artifact can be missing.
    check(
        "py.typed ships inside the installed package",
        os.path.exists(os.path.join(pkg_dir, "py.typed")),
    )

    # 5) The documented public surface.
    missing = [n for n in REQUIRED_PUBLIC_NAMES if not hasattr(obsvr, n)]
    check("every documented public name is importable from obsvr", not missing, f"missing={missing}")
    if missing:
        fatal("the installed package no longer exports its documented surface")

    from obsvr import ObsvrPolicyError, govern_tool
    from obsvr.reason_codes import ReasonCode

    # 6) Drive the governed calls against a loopback sink, so the refusal can
    # be asserted on the RECORD as well as on the raise.
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    scratch = tempfile.mkdtemp(prefix="obsvr-install-check-")
    denied_marker = os.path.join(scratch, "denied.marker")
    allowed_marker = os.path.join(scratch, "allowed.marker")

    obsvr.init(
        api_key="install-path-check",
        ingest_url=f"http://127.0.0.1:{port}",
        sample_rate=1,
        agent_policy={"denied_tools": [DENIED_TOOL]},
    )
    check("the SDK reports itself initialized", obsvr.is_initialized())

    # 6a) POSITIVE CONTROL. This is what makes the deny leg mean something: a
    # process where everything raises would pass the deny leg and fail here.
    allowed = govern_tool(MarkerTool(ALLOWED_TOOL, allowed_marker))
    allowed_returned = ""
    allow_error = ""
    try:
        allowed_returned = allowed._run(note="control")
    except BaseException as exc:  # noqa: BLE001 - report, never swallow
        allow_error = f"{type(exc).__name__}: {exc}"
    check(
        "an allowed governed tool executes exactly once",
        writes(allowed_marker) == 1,
        f"writes={writes(allowed_marker)} error={allow_error or 'none'}",
    )
    check(
        "and its payload reaches the caller",
        allowed_returned == SECRET,
        f"returned={allowed_returned!r}",
    )

    # 6b) THE REFUSAL.
    denied = govern_tool(MarkerTool(DENIED_TOOL, denied_marker))
    raised = None
    returned = None
    try:
        returned = denied._run(note="should never happen")
    except BaseException as exc:  # noqa: BLE001 - the type is the assertion
        raised = exc

    check(
        "a denied governed tool refuses instead of returning",
        raised is not None,
        f"returned={returned!r}",
    )
    check(
        "the refusal is the SDK's typed policy error",
        isinstance(raised, ObsvrPolicyError),
        f"raised={type(raised).__name__ if raised else 'nothing'}: {raised}",
    )
    check(
        "the refusal carries reason code TOOL_DENIED",
        getattr(raised, "reason_code", None) == ReasonCode.TOOL_DENIED.value,
        f"reason_code={getattr(raised, 'reason_code', None)!r}",
    )
    check(
        "the denied tool's body never ran",
        writes(denied_marker) == 0,
        f"writes={writes(denied_marker)}",
    )
    check(
        "and its payload never reached the caller",
        returned != SECRET and SECRET not in str(raised or ""),
        f"returned={returned!r}",
    )

    # 6c) THE RECORD. A refusal nothing recorded is a silence, not a block.
    obsvr.flush(timeout=15)
    server.shutdown()
    blocked = [
        e
        for e in _Sink.events
        if isinstance(e, dict) and e.get("operation") == "tool.policy.tool_blocked"
    ]
    check(
        "the installed sender delivered a blocked-tool record",
        bool(blocked),
        f"events={len(_Sink.events)} operations={sorted({e.get('operation') for e in _Sink.events if isinstance(e, dict)})}",
    )
    if blocked:
        record = blocked[0]
        check(
            "the record names the denied tool and grades it TOOL_DENIED",
            (record.get("metadata") or {}).get("tool_name") == DENIED_TOOL
            and record.get("reason_code") == ReasonCode.TOOL_DENIED.value
            and record.get("action_taken") == "blocked",
            f"tool_name={(record.get('metadata') or {}).get('tool_name')!r} "
            f"reason_code={record.get('reason_code')!r} action_taken={record.get('action_taken')!r}",
        )

    if _failures:
        print("", flush=True)
        for failure in _failures:
            print(f"  - {failure}", file=sys.stderr, flush=True)
        fatal(f"{len(_failures)} assertion(s) failed against the installed package")
    print("\nAll assertions passed against the installed package.", flush=True)


if __name__ == "__main__":
    main()
