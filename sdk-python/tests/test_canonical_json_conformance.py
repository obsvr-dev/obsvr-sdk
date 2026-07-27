"""The frozen rules-hash canonicalizer, from both directions.

Twin of sdk/tests/unit/canonical-json-conformance.test.ts.

``_canonical_json`` feeds policy_version and rules_hash, so it has to agree
with the TypeScript ``stableStringify`` byte for byte or the same policy
stamps two different versions depending on which SDK polled it.

Two instruments, because they catch different things: the shared fixture pins
the specific shapes the two SDKs used to disagree on and fails here without
needing a Node toolchain; hypothesis generates fresh documents and checks the
properties the format must satisfy universally, which is what finds the NEXT
class. The cross-language half is scripts/check-canonical-json-parity.mjs,
which runs this generator against fast-check in the conformance CI job.
"""

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from obsvr.rules import _canonical_json

FIXTURE = json.loads(
    (Path(__file__).parent / "../../conformance/fixtures/canonical_json.json")
    .resolve()
    .read_text(encoding="utf-8")
)


@pytest.mark.parametrize(
    "case",
    FIXTURE["cases"],
    ids=["%s#%d" % (c["group"], i) for i, c in enumerate(FIXTURE["cases"])],
)
def test_canonical_json_fixture(case):
    assert _canonical_json(json.loads(case["input"])) == case["expect"]


def test_fixture_covers_every_divergence_class():
    assert sorted({c["group"] for c in FIXTURE["cases"]}) == [
        "agreeing_baseline",
        "astral_key_order",
        "exponent_padding",
        "exponent_threshold",
        "int_past_2_53",
        "negative_zero",
        "unpaired_surrogate",
        "whole_valued_floats",
    ]


# ── Properties ──────────────────────────────────────────────────────────────
# Stated as properties of the FORMAT, not of the implementation: each one is
# something the TypeScript twin must satisfy too, so a property that fails
# here would have failed there.

_text = st.text(
    st.characters(codec=None, min_codepoint=0, max_codepoint=0x10FFFF), max_size=8
)
_json_value = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
    | st.floats(allow_nan=False, allow_infinity=False)
    | _text,
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(_text, inner, max_size=4),
    max_leaves=8,
)

_SETTINGS = settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])


@given(_json_value)
@_SETTINGS
def test_is_a_fixed_point(value):
    once = _canonical_json(value)
    assert _canonical_json(json.loads(once)) == once


@given(st.dictionaries(_text, _json_value, max_size=6))
@_SETTINGS
def test_does_not_depend_on_key_insertion_order(obj):
    reversed_obj = {k: obj[k] for k in reversed(list(obj))}
    assert _canonical_json(reversed_obj) == _canonical_json(obj)


@given(_json_value)
@_SETTINGS
def test_output_is_utf8_encodable(value):
    # This is where the old json.dumps twin failed: an unpaired surrogate went
    # out raw and .encode("utf-8") raised instead of returning a hash. Both
    # SDKs hash the UTF-8 bytes, so a canonical form with no encoding is not a
    # canonical form.
    s = _canonical_json(value)
    assert s.encode("utf-8").decode("utf-8") == s


@given(_json_value)
@_SETTINGS
def test_never_emits_a_bare_newline(value):
    s = _canonical_json(value)
    assert "\n" not in s and "\r" not in s


def _numbers_as_float(v):
    """Numbers compared as float64, the only type JS has. Without this the
    property fails on its own terms: a float like 2.216318071178795e16 is
    canonicalized to the plain decimal JS writes, which Python then re-parses
    as an INT, and int != float once the two differ below the shortest
    round-tripping decimal."""
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, list):
        return [_numbers_as_float(x) for x in v]
    if isinstance(v, dict):
        return {k: _numbers_as_float(x) for k, x in v.items()}
    return v


@given(_json_value)
@_SETTINGS
def test_round_trips_to_an_equal_value(value):
    # Canonicalizing is not allowed to change what the document MEANS, only
    # how it is written. -0.0 -> 0 is the one deliberate exception, and it is
    # invisible here because float(-0.0) == float(0).
    assert _numbers_as_float(json.loads(_canonical_json(value))) == _numbers_as_float(value)
