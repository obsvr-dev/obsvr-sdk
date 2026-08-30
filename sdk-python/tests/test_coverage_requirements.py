import asyncio

import pytest

from obsvr.coverage_attestation import (
    CoverageRequirementsError,
    assert_coverage_requirements,
    coverage_requirement_failures,
)
from obsvr.enforcement_smoke import (
    assert_enforcement_boundary,
    assert_enforcement_boundary_async,
)


SNAPSHOT = {
    "langchain": {
        "model": {"bound": True, "enforcement_depth": "enforce"},
        "tracing": {"bound": True, "enforcement_depth": "observe"},
    }
}


def test_exact_symbols_and_enforcement_depth_are_required():
    assert_coverage_requirements(
        [{"integration": "langchain", "minimum_depth": "enforce", "symbols": ["model"]}],
        SNAPSHOT,
    )
    failures = coverage_requirement_failures(
        [
            {
                "integration": "langchain",
                "minimum_depth": "enforce",
                "symbols": ["tracing", "tools"],
            }
        ],
        SNAPSHOT,
    )
    assert {(failure["symbol"], failure["reason"]) for failure in failures} == {
        ("tools", "missing"),
        ("tracing", "insufficient_depth"),
    }
    with pytest.raises(CoverageRequirementsError):
        assert_coverage_requirements(
            [
                {
                    "integration": "langchain",
                    "minimum_depth": "enforce",
                    "symbols": ["tracing"],
                }
            ],
            SNAPSHOT,
        )


def test_factory_smoke_proves_zero_downstream_calls():
    transport = {"calls": 0}

    def blocked():
        raise RuntimeError("blocked by policy")

    assert assert_enforcement_boundary(
        "spotdraft-ai-factory", blocked, lambda: transport["calls"]
    ) == {"name": "spotdraft-ai-factory", "blocked": True, "transport_calls": 0}


def test_async_factory_smoke_fails_if_transport_was_reached():
    transport = {"calls": 0}

    async def too_late():
        transport["calls"] += 1
        raise RuntimeError("blocked after transport")

    with pytest.raises(RuntimeError, match="reached downstream transport"):
        asyncio.run(
            assert_enforcement_boundary_async(
                "bypassed-factory", too_late, lambda: transport["calls"]
            )
        )
