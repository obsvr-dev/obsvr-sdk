"""The signed-policy verifier, wired to the poll that actually fetches policy.

`test_policy_verify.py` pins the verifier's VERDICTS against the shared
fixture. It passed for the whole time the verifier had zero production call
sites: `verify_policy_signature` was defined, correct, fully tested, and never
invoked, while the poll assigned `config.policy_rules` straight from the
response and the pinned `policy_public_key` was consumed by nothing.

That is the gap this file closes, and it is a different question from the one
the other file answers. A unit test of a verifier proves the verifier works. It
cannot prove anything reaches it.

So every case here drives `poll_once` against a fake `/policies` endpoint and
asserts on what the SDK is RUNNING afterwards — the rules in force — rather
than on a returned verdict object.

Twin: `sdk-typescript/src/proxy/config.ts` verifies at the same point and fails
closed the same way; the shared vectors are
`conformance/fixtures/policy_signature.json`.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import obsvr  # noqa: E402
from obsvr import remote  # noqa: E402
from obsvr import sender  # noqa: E402
from obsvr.config import _reset, get_config  # noqa: E402
from obsvr.rules import PolicyRule  # noqa: E402

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "conformance/fixtures/policy_signature.json"
)
with open(FIXTURE_PATH, encoding="utf-8") as fh:
    FIXTURE = json.load(fh)

PINNED_KEY = FIXTURE["keys"]["pinned_public_key_b64"]
CASES = {c["id"]: c for c in FIXTURE["cases"]}

# The rule the server tries to push. Its id is what tells "applied" from
# "refused" without reading any status field.
PUSHED_RULE_ID = CASES["valid_signature_accepts"]["rules"][0]["id"]

# The last-good policy already in force before each poll. A refused push must
# leave exactly this in place — "the policy was not applied" and "the SDK is
# running nothing" are different outcomes and only one of them is correct.
LOCAL_RULE = PolicyRule(
    id="local-floor",
    name="local floor",
    enabled=True,
    action="block",
    type="keyword",
    conditions={"keywords": ["zzz-local"]},
)


class _PolicyServer:
    """A /policies endpoint that answers with one fixture case."""

    def __init__(self, body):
        payload = json.dumps(body).encode("utf-8")

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


@pytest.fixture(autouse=True)
def _clean():
    _reset()
    sender._reset_sender()
    remote._reset_remote()
    yield
    _reset()
    sender._reset_sender()
    remote._reset_remote()


def _config(server_url, pin_key):
    kwargs = dict(
        api_key="k",
        ingest_url=server_url,
        policy_rules=[LOCAL_RULE],
        policy_refresh_interval_s=0,  # no background thread; poll_once is driven directly
    )
    if pin_key:
        kwargs["policy_public_key"] = PINNED_KEY
    obsvr.init(**kwargs)
    return get_config()


def _poll_case(case_id, pin_key=True):
    case = CASES[case_id]
    body = {"rules": case["rules"], "approvals": case.get("approvals", [])}
    if case.get("signature") is not None:
        body["signature"] = case["signature"]
    server = _PolicyServer(body)
    try:
        config = _config(server.url, pin_key)
        remote.poll_once(config)
        return config, [r.id for r in (config.policy_rules or [])]
    finally:
        server.close()


ACCEPTING = ["valid_signature_accepts"]
REFUSING = [cid for cid in CASES if cid not in ACCEPTING]


@pytest.mark.parametrize("case_id", ACCEPTING)
def test_a_valid_signature_is_applied(case_id):
    """The positive control. Without it, every refusal below could be explained
    by the poll never applying anything at all."""
    _config_, rule_ids = _poll_case(case_id)
    assert PUSHED_RULE_ID in rule_ids
    assert "local-floor" not in rule_ids  # a valid push does replace


@pytest.mark.parametrize("case_id", REFUSING)
def test_an_unverifiable_policy_is_not_applied(case_id):
    """Tampered, forged, wrong-key, key-id-mismatched, unsigned, and
    unsupported-alg pushes are all refused, and the last-good policy survives.

    Before the verifier was wired, EVERY one of these applied: the server's
    rules replaced the local ones with no check of any kind."""
    _config_, rule_ids = _poll_case(case_id)
    assert PUSHED_RULE_ID not in rule_ids, f"{case_id} was applied"
    assert rule_ids == ["local-floor"], f"{case_id} lost the last-good policy"
    assert remote._sync["policy_signature_valid"] is False
    assert remote._sync["last_policy_signature_failure"]


@pytest.mark.parametrize("case_id", REFUSING)
def test_the_same_pushes_apply_when_no_key_is_pinned(case_id):
    """The negative control, and the one that makes the test above mean
    something. With no pinned key there is nothing to verify against, so these
    same payloads are applied — which is exactly the pre-fix behaviour of a
    PINNED deployment. It proves the refusals come from the pin rather than
    from the fixture being malformed in some way the poll would reject anyway."""
    _config_, rule_ids = _poll_case(case_id, pin_key=False)
    assert PUSHED_RULE_ID in rule_ids


def test_a_refused_policy_is_reported_once_per_distinct_reason(monkeypatch):
    """A refusal is not a quiet event: the deployment believes it pinned a key
    and is in fact running the last-good policy. Emitted once per reason rather
    than per poll, so a permanently-broken publisher does not flood the log."""
    emitted = []
    monkeypatch.setattr(
        remote, "_signal_policy_signature_invalid",
        lambda cfg, reason: emitted.append(reason),
    )
    _poll_case("tampered_rules_reject")
    assert len(emitted) == 1
    assert "rules" in emitted[0].lower()


def test_rollback_is_refused_after_a_newer_policy_was_applied():
    """Anti-rollback needs state that survives between polls, which is the part
    a verifier unit test cannot exercise: the same signed payload is valid on
    the first poll and a rollback on the second."""
    case = CASES["valid_signature_accepts"]
    body = {
        "rules": case["rules"],
        "approvals": case.get("approvals", []),
        "signature": case["signature"],
    }
    server = _PolicyServer(body)
    try:
        config = _config(server.url, True)
        remote.poll_once(config)
        assert PUSHED_RULE_ID in [r.id for r in config.policy_rules]
        # Pretend a strictly newer policy was applied since.
        remote._sync["last_applied_policy_issued_at"] = "2099-01-01T00:00:00.000Z"
        config.policy_rules = []
        remote.poll_once(config)
        assert [r.id for r in (config.policy_rules or [])] == []
        assert remote._sync["policy_signature_valid"] is False
        assert "rollback" in remote._sync["last_policy_signature_failure"]
    finally:
        server.close()
