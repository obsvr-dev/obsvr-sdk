"""The 'allowed implies evaluated' invariant, as a per-surface table.

    For every event where ``action_taken == "allowed"``, a policy pipeline
    actually ran, and the record carries the evidence that it did.

WHY THIS IS THE OTHER HALF OF test_enforcement_reporting_invariant.py
--------------------------------------------------------------------
That file polices "blocked implies not executed" — that a refusal is real.
Nothing policed the reverse, and the reverse is where a Severity 1 got through:
a deployment whose only policy was a customer rule set did not arm the pre-call
pipeline at the tool and MCP boundaries, so a call whose arguments matched a
block rule EXECUTED, returned its result to the caller, and recorded ``allowed``
— a verdict the rule set was never asked for.

Every "blocked implies not executed" assertion held throughout that defect,
because nothing ever claimed ``blocked``. An invariant that only grades
refusals cannot see a gate that has stopped running. This one grades permits.

WHY ``decision_input_hash`` IS THE EVIDENCE
------------------------------------------
It is the SHA-256 of the canonical decision-input document, computed at exactly
one place in this package — inside ``apply_pre_call_policy`` — over the inputs
the decision was actually made on. A surface that skipped evaluation has no
decision input, so it cannot produce one. That is what makes its absence mean
something.

The fields that look like they would serve do not, and both were measured
before this file was written:

- ``policy_version`` is derived from the CONFIGURED rules, so an unarmed
  boundary stamped a real rules hash on a call the rules never saw.
- ``action_source`` is ``"unknown"`` on a legitimate permit that matched no
  rule, so it cannot separate "evaluated, nothing matched" from "never ran".

WHAT IT DELIBERATELY DOES NOT ASSERT
------------------------------------
That an ``allowed`` record with NO policy configured carries evidence. With
nothing configured there is no policy verdict to evidence and the record claims
none. The defect class is a CONFIGURED policy that silently did not run, so
that is the condition every row below holds.

EACH ROW CONFIGURES ONE POLICY KIND ALONE
-----------------------------------------
That is not tidiness, it is the whole point. The arming gap was invisible
because any OTHER entry in the boundary's list — even an empty PII policy —
made the rule set work. A table that always configures two layers cannot see
it.
"""

import json
import threading
import http.server
import socketserver

import pytest

import obsvr
from obsvr.integrations.tools import govern_tool
from obsvr.rules import PolicyRule


BLOCK_RULE = PolicyRule(
    id="r-forbidden",
    name="r-forbidden",
    enabled=True,
    action="block",
    type="keyword",
    conditions={"keywords": ["forbidden"]},
)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(n))
            self.server.captured.extend(
                payload if isinstance(payload, list) else [payload]
            )
        except Exception:  # noqa: BLE001
            pass
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):  # noqa: A003
        pass


@pytest.fixture
def ingest():
    """A real ingest endpoint, so the assertions read the WIRE event.

    Patching the sender would grade the compliance dict the code meant to send.
    The invariant is about what an auditor receives, so this reads the JSON that
    actually left the process.
    """
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    srv.captured = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _url(srv):
    return f"http://127.0.0.1:{srv.server_address[1]}"


def _settle(srv, n=1, timeout=3.0):
    import time

    deadline = time.monotonic() + timeout
    obsvr.flush()
    while len(srv.captured) < n and time.monotonic() < deadline:
        time.sleep(0.02)
    return list(srv.captured)


def assert_allowed_is_evidenced(event, where):
    """The invariant itself, as one function every row is graded by."""
    if event.get("action_taken") != "allowed":
        return  # blocked / redacted / not_evaluated are out of scope
    assert event.get("decision_input_hash"), (
        f"{where}: recorded `allowed` with no decision_input_hash — nothing "
        f"evidences that a policy pipeline evaluated this call"
    )
    assert event.get("engine_version"), (
        f"{where}: recorded `allowed` with no engine_version — the record does "
        f"not say which engine rendered the verdict it claims"
    )


def _tool(ran):
    class T:
        name = "calc"

        @staticmethod
        def execute(**kwargs):
            ran.append(True)
            return "done"

    return govern_tool(T(), name="calc", metadata={"user_id": "alice"})


# ── Surface: govern_tool, one policy kind at a time ─────────────────────────

ONLY_ONE_POLICY = [
    ("policy_rules alone", {"policy_rules": [BLOCK_RULE]}),
    ("pii_policy alone", {"pii_policy": {"default": "detect_only"}}),
    ("policy_floor alone", {"policy_floor": [BLOCK_RULE]}),
]


@pytest.mark.parametrize("label,cfg", ONLY_ONE_POLICY, ids=[r[0] for r in ONLY_ONE_POLICY])
def test_govern_tool_permit_carries_the_evidence(ingest, label, cfg):
    obsvr._reset()
    obsvr.init(api_key="k", ingest_url=_url(ingest), environment="development", **cfg)
    ran = []
    assert _tool(ran).execute(q="perfectly fine") == "done"
    assert ran == [True]  # control: the permit really was a permit

    events = _settle(ingest)
    ev = next(e for e in events if e.get("operation") == "tool.call")
    assert ev["action_taken"] == "allowed"
    assert_allowed_is_evidenced(ev, f"govern_tool/{label}")


def test_govern_tool_refuses_the_matching_call_and_the_body_never_runs(ingest):
    """The block leg of the same arming property.

    Graded on the RECORD and on the side effect, not on the raise: a gate that
    threw after the tool returned would satisfy an exception-only assertion.
    """
    obsvr._reset()
    obsvr.init(
        api_key="k",
        ingest_url=_url(ingest),
        environment="development",
        policy_rules=[BLOCK_RULE],
    )
    ran = []
    with pytest.raises(Exception):
        _tool(ran).execute(q="this is forbidden")
    assert ran == []

    events = _settle(ingest)
    blocked = [e for e in events if e.get("action_taken") == "blocked"]
    assert blocked, "a matching rule produced no blocked record"
    assert not [
        e for e in events if e.get("operation") == "tool.call" and e.get("action_taken") == "allowed"
    ]


def test_govern_tool_with_no_policy_claims_no_deciding_layer(ingest):
    """Nothing configured means nothing was skipped — and nothing is claimed."""
    obsvr._reset()
    obsvr.init(api_key="k", ingest_url=_url(ingest), environment="development")
    ran = []
    _tool(ran).execute(q="hello")

    events = _settle(ingest)
    ev = next(e for e in events if e.get("operation") == "tool.call")
    assert ev["action_taken"] == "allowed"
    # Not "policy_rules": crediting the rules engine for a permit it never
    # issued is the false attribution this invariant exists to keep out.
    assert ev["action_source"] == "unknown"


# ── Surface: the shared pre-call pipeline itself ────────────────────────────


@pytest.mark.parametrize("label,cfg", ONLY_ONE_POLICY, ids=[r[0] for r in ONLY_ONE_POLICY])
def test_pre_call_pipeline_permit_carries_the_evidence(label, cfg):
    from obsvr.config import get_config
    from obsvr.policy import apply_pre_call_policy

    obsvr._reset()
    obsvr.init(api_key="k", ingest_url="https://x", environment="development", **cfg)
    result = apply_pre_call_policy(
        "perfectly fine",
        get_config(),
        provider="unknown",
        operation="tool.call",
        metadata={"user_id": "alice"},
    )
    assert result["decision"] == "allow"
    assert result["compliance"]["action_taken"] == "allowed"
    assert result["compliance"]["decision_input_hash"], f"{label}: permit not evidenced"
    assert result["compliance"]["engine_version"], f"{label}: no engine named"


def test_pre_call_pipeline_refuses_on_a_rule_set_alone():
    from obsvr.config import get_config
    from obsvr.policy import apply_pre_call_policy

    obsvr._reset()
    obsvr.init(
        api_key="k", ingest_url="https://x", environment="development", policy_rules=[BLOCK_RULE]
    )
    result = apply_pre_call_policy(
        "this is forbidden",
        get_config(),
        provider="unknown",
        operation="tool.call",
        metadata={"user_id": "alice"},
    )
    assert result["decision"] == "block"
    assert result["compliance"]["action_taken"] == "blocked"


# ── The sweep ───────────────────────────────────────────────────────────────


def test_no_event_from_a_mixed_workload_claims_an_unevidenced_permit(ingest):
    obsvr._reset()
    obsvr.init(
        api_key="k",
        ingest_url=_url(ingest),
        environment="development",
        policy_rules=[BLOCK_RULE],
        pii_policy={"default": "detect_only"},
    )
    ran = []
    _tool(ran).execute(q="hello")
    _tool(ran).execute(q="also fine")

    events = _settle(ingest, n=2)
    assert len(events) >= 2
    for ev in events:
        assert_allowed_is_evidenced(ev, f"{ev.get('operation')}/{ev.get('source')}")
