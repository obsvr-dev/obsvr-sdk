"""Config lifecycle: what a re-init reaches, and what a poll is allowed to delete.

Two halves with one root cause. ``init()`` REPLACES the resolved config while a
``/policies`` poll MUTATES it in place, so anything holding the object it was
handed at wrap time saw every poll and no re-init.

The first half — a client wrapped before a re-init being stranded on the old
policy — **does not reproduce here**. Python's wrapper reads the config through
rather than capturing it, and measured both directions the old client picked up
the new policy. That is pinned below anyway: it is the side that is correct, the
divergence is invisible until someone changes it, and an unpinned correct
behaviour is one refactor away from matching the side that was wrong.

The second half reproduced in BOTH languages: a 200 carrying ``{"rules": []}``
replaced locally declared rules and stamped the sync successful, so
``fail_mode="closed"`` never tripped — a deployment disarmed by a response
nobody ever sees. ``policy_floor`` already survived a poll; local rules were the
one tier a network response could delete.

Twin: ``sdk-typescript/tests/unit/config-lifecycle.test.ts``.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import obsvr  # noqa: E402
from obsvr.config import _reset, apply_policy_rules, get_config  # noqa: E402
from obsvr.rules import PolicyRule  # noqa: E402


def rule(rule_id, keyword, enabled=True):
    return PolicyRule(
        id=rule_id, name=rule_id, enabled=enabled, action="block",
        type="keyword", conditions={"keywords": [keyword]},
    )


def _init(rules):
    obsvr.init(api_key="k", ingest_url="http://127.0.0.1:9",
               policy_rules=rules, policy_refresh_interval_s=0)


@pytest.fixture(autouse=True)
def _clean():
    _reset()
    yield
    _reset()


def _ids():
    return [r.id for r in (get_config().policy_rules or [])]


class TestReInitReachesWrappedClients:
    """The half that does NOT reproduce on this side. Pinned so it stays that way."""

    def _client(self):
        seen = []

        class Completions:
            def create(self, **kw):
                seen.append(kw)
                return {"choices": [{"message": {"content": "ok"}}], "model": "m"}

        class Chat:
            completions = Completions()

        class Client:
            chat = Chat()

        return Client(), seen

    def test_rule_added_by_a_later_init_applies_to_an_already_wrapped_client(self):
        _init([])
        raw, seen = self._client()
        wrapped = obsvr.wrap(raw)

        _init([rule("added", "zzz-secret")])

        with pytest.raises(Exception):
            wrapped.chat.completions.create(
                model="m", messages=[{"role": "user", "content": "leak zzz-secret"}]
            )
        assert seen == []  # stopped before the provider, not after

    def test_rule_removed_by_a_later_init_stops_applying(self):
        _init([rule("removed", "zzz-secret")])
        raw, seen = self._client()
        wrapped = obsvr.wrap(raw)

        _init([])

        wrapped.chat.completions.create(
            model="m", messages=[{"role": "user", "content": "leak zzz-secret"}]
        )
        assert len(seen) == 1


class TestPollOwnsTheServerSetOnly:
    def test_empty_server_ruleset_leaves_locally_declared_rules(self):
        _init([rule("local", "zzz-local")])
        apply_policy_rules(get_config(), [])
        assert _ids() == ["local"]

    def test_empty_server_ruleset_does_clear_what_the_server_pushed(self):
        _init([rule("local", "zzz-local")])
        apply_policy_rules(get_config(), [rule("server", "zzz-server")])
        assert _ids() == ["local", "server"]

        # An empty ruleset is a VALID server state — the server's own rules go.
        apply_policy_rules(get_config(), [])
        assert _ids() == ["local"]

    def test_a_server_rule_cannot_take_over_a_locally_declared_id(self):
        _init([rule("shared", "zzz-local")])
        apply_policy_rules(get_config(), [rule("shared", "zzz-local", enabled=False)])

        rules = get_config().policy_rules or []
        assert [r.id for r in rules] == ["shared"]
        # Disabling a rule by re-sending its id is the same disarming edit
        # wearing a matching id, and it is the shape a deployment with no pinned
        # policy key has no other defence against.
        assert rules[0].enabled is True

    def test_a_later_init_does_replace_the_local_set(self):
        _init([rule("first", "zzz-a")])
        apply_policy_rules(get_config(), [rule("server", "zzz-server")])
        _init([rule("second", "zzz-b")])
        assert _ids() == ["second"]


class TestTheRealPollReachesIt:
    """Driving the helper is not driving the poll.

    The cases above call ``apply_policy_rules`` directly, which pins what the
    function does and proves nothing about whether the poll uses it — the exact
    gap that let ``verify_policy_signature`` sit fully tested and never invoked
    (see test_policy_signature_wiring.py). Caught here the same way: reverting
    the CALL SITE in remote.py left every case above green.

    So this one drives ``poll_once`` against a real endpoint answering
    ``{"rules": []}``.
    """

    def test_a_200_with_an_empty_ruleset_does_not_erase_local_rules(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        from obsvr import remote

        polls = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                polls.append(1)
                body = b'{"rules": [], "approvals": []}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            obsvr.init(
                api_key="k",
                ingest_url="http://127.0.0.1:%d" % httpd.server_address[1],
                policy_rules=[rule("local", "zzz-local")],
                policy_refresh_interval_s=0,
            )
            remote.poll_once(get_config())
            assert polls, "the endpoint was never called — this proves nothing"
            assert _ids() == ["local"]
            # The poll SUCCEEDED, which is the other half: it is a valid state,
            # not an error, and the staleness clock is right to advance.
            assert remote._sync["last_success"] is not None
        finally:
            httpd.shutdown()
