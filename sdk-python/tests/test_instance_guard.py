"""Duplicate-SDK-instance guard (Python side).

Twin: sdk/tests/unit/instance-guard.test.ts. Both drive the claim sequences in
conformance/fixtures/instance_guard.json and must reach the same outcome,
because "one governing instance per process" has to mean the same thing in a
mixed-language shop.
"""
import json
import logging
import sys
from pathlib import Path

import pytest

import obsvr
from obsvr.config import _MODULE_INSTANCE_ID, _reset, get_config
from obsvr.instance_guard import (
    _reset_instance_guard,
    claim_governing_instance,
    duplicate_instance_message,
    governing_instance,
    is_governing_instance,
)
from obsvr.wrap import wrap

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/instance_guard.json")
    .resolve()
    .read_text()
)


@pytest.fixture(autouse=True)
def _clean_slot():
    _reset_instance_guard()
    _reset()
    yield
    _reset_instance_guard()
    _reset()


@pytest.mark.parametrize(
    "case", FIXTURE["cases"], ids=[c["id"] for c in FIXTURE["cases"]]
)
def test_instance_guard_case(case):
    # Each copy logs at most once, which is what the fixture's cumulative
    # `logs` count tracks.
    logged = set()
    log_count = 0

    for claim, expected in zip(case["claims"], case["expect"]):
        result = claim_governing_instance(claim["version"], claim["instance_id"])
        if not result["governing"] and claim["instance_id"] not in logged:
            logged.add(claim["instance_id"])
            log_count += 1

        assert result["governing"] is expected["governing"], case["id"]
        assert log_count == expected["logs"], case["id"]

        if "incumbent_version" in expected:
            assert result["incumbent"]["version"] == expected["incumbent_version"]
        if "incumbent_is_older" in expected:
            assert result.get("incumbent_is_older", False) is expected["incumbent_is_older"]
        if "message_contains" in expected:
            assert expected["message_contains"] in duplicate_instance_message(result)


class TestTheSlotItself:
    def test_lives_in_sys_modules_so_every_copy_of_the_package_sees_it(self):
        """A module-level variable would not survive the duplication this
        guards against: two copies of the package are two module objects with
        two variables. sys.modules is shared by all of them."""
        claim_governing_instance("0.10.0", "copy-a")
        holder = sys.modules.get("_obsvr_governing_instance")
        assert holder is not None
        assert holder.instance == {"version": "0.10.0", "instance_id": "copy-a"}

    def test_reports_who_governs_and_who_does_not(self):
        claim_governing_instance("0.10.0", "copy-a")
        assert governing_instance()["instance_id"] == "copy-a"
        assert is_governing_instance("copy-a") is True
        assert is_governing_instance("copy-b") is False

    def test_message_says_what_happened_and_what_to_do(self):
        claim_governing_instance("0.10.0", "copy-a")
        message = duplicate_instance_message(
            claim_governing_instance("0.10.0", "copy-b")
        )
        assert "NOT governed" in message
        assert "Deduplicate" in message


class TestEndToEndThroughInitAndWrap:
    def test_governs_and_wraps_when_this_copy_holds_the_slot(self):
        obsvr.init(api_key="test", policy_refresh_interval_s=0)

        class FakeClient:
            class chat:
                class completions:
                    @staticmethod
                    def create(**_kwargs):
                        return {}

        client = FakeClient()
        assert wrap(client) is not client
        assert get_config().api_key == "test"

    def test_passes_clients_through_when_another_copy_already_governs(self, caplog):
        # Simulate the other copy having initialized first.
        claim_governing_instance("0.10.0", "some-other-copy")

        with caplog.at_level(logging.WARNING, logger="obsvr"):
            obsvr.init(api_key="test", policy_refresh_interval_s=0)

        class FakeClient:
            class chat:
                class completions:
                    @staticmethod
                    def create(**_kwargs):
                        return {}

        client = FakeClient()
        assert wrap(client) is client
        assert (
            len([r for r in caplog.records if "already" in r.getMessage()]) == 1
        )

    def test_yielded_copy_still_resolves_config(self, caplog):
        claim_governing_instance("0.10.0", "some-other-copy")
        with caplog.at_level(logging.WARNING, logger="obsvr"):
            obsvr.init(api_key="test", policy_refresh_interval_s=0)
        # Yielding is not disabling: config is resolved and readable, the copy
        # simply does not govern.
        assert get_config().api_key == "test"

    def test_same_copy_reinitializing_does_not_warn(self, caplog):
        with caplog.at_level(logging.WARNING, logger="obsvr"):
            obsvr.init(api_key="test", policy_refresh_interval_s=0)
            obsvr.init(api_key="test-2", policy_refresh_interval_s=0)
        assert [r for r in caplog.records if "already governing" in r.getMessage()] == []
        assert is_governing_instance(_MODULE_INSTANCE_ID) is True
