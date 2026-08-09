"""The syntax probe inside ``validate_regex_pattern`` writes nothing to stderr.

Validating a customer rule is a question with a boolean answer, and it ran a
bare ``re.compile`` to ask it. CPython's ``re`` parser emits a ``FutureWarning``
for a character class that looks like another dialect's set operation --
``[\\w--[0-9]]`` is one, and it is in the conformance corpus -- so a policy poll
carrying such a rule printed into the host application's logs from a call the
host never asked to be noisy, about a pattern the SDK had already decided to
refuse.

BOTH halves are pinned on every row: the probe emits nothing, AND it returns the
same verdict it returned before. A suppression that also changed an answer would
be a worse defect than the noise it removed.

``re.purge()`` before each probe is load-bearing. ``re.compile`` caches, and a
cached pattern skips the parser entirely and emits no warning -- so without the
purge every row here would pass against an unsuppressed probe.
"""
import re
import warnings

import pytest

from obsvr.safe_regex import (
    _SET_OPERATION_WARNING,
    compile_safe_regex,
    validate_regex_pattern,
)

#: Every class shape CPython's parser warns about, with the verdict this
#: validator reaches for it. One compiles on Python but has different meaning
#: under JavaScript's Unicode regex mode, so portability validation rejects it
#: after the deliberately quiet Python syntax probe.
WARNING_TRIGGERS = [
    pytest.param("[\\w--[0-9]]", False, id="set difference (in the conformance corpus)"),
    pytest.param("[[a]]", False, id="nested set with non-portable leading close bracket"),
    pytest.param("[a&&b]", True, id="set intersection"),
    pytest.param("[a~~b]", True, id="set symmetric difference"),
    pytest.param("[a||b]", True, id="set union"),
]


def probe(pattern):
    """Run the validator with the parser cache cold, capturing any warning."""
    re.purge()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        verdict = validate_regex_pattern(pattern)
    return verdict, [f"{w.category.__name__}: {w.message}" for w in caught]


@pytest.mark.parametrize("pattern,expected_ok", WARNING_TRIGGERS)
def test_the_probe_emits_nothing(pattern, expected_ok):
    (ok, _reason), caught = probe(pattern)

    assert caught == [], f"{pattern!r} leaked into the host's stderr: {caught}"
    assert ok is expected_ok, f"{pattern!r} changed verdict while being quieted"


def test_the_bare_engine_still_warns():
    """Non-vacuity. Without this the rows above would pass on a CPython that
    stopped warning at all, and would keep passing if the suppression were
    removed on such a build."""
    re.purge()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            re.compile("[\\w--[0-9]]")
        except re.error:
            pass

    assert [w.category.__name__ for w in caught] == ["FutureWarning"]
    assert "Possible set difference" in str(caught[0].message)


def test_the_verdicts_are_the_ones_recorded_before_the_suppression():
    """The exact reasons, not just the booleans. A suppression that shifted a
    pattern from one refusal to another would still be a behavior change."""
    assert validate_regex_pattern("[\\w--[0-9]]") == (False, "invalid_syntax")
    assert validate_regex_pattern("[[a]]") == (
        False,
        "not_portable_across_sdks: unescaped_close_bracket",
    )


def test_the_suppression_does_not_outlive_the_probe():
    """Not global, and not sticky. ``catch_warnings`` swaps process-global
    filter state, so a leaked filter would silence the host's own warnings for
    the rest of the process."""
    before = list(warnings.filters)
    validate_regex_pattern("[\\w--[0-9]]")

    assert list(warnings.filters) == before

    # And the warning the probe suppresses still reaches a caller who asks for
    # it immediately afterwards.
    re.purge()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        re.compile("[[a]]")

    assert [w.category.__name__ for w in caught] == ["FutureWarning"]


def test_a_nonportable_pattern_never_reaches_the_operative_compile():
    """The Python engine accepts ``[[a]]`` with a warning, but JavaScript's
    Unicode-mode engine interprets it differently. Cross-SDK portability must
    reject it before an operative regex object can be constructed."""
    re.purge()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        compiled = compile_safe_regex("[[a]]")

    assert compiled is None
    assert not [str(w.message) for w in caught if w.category is FutureWarning]


def test_an_unrelated_warning_raised_inside_the_window_still_reaches_the_caller(
    monkeypatch,
):
    """The narrowing, driven through the real probe rather than asserted about
    the filter constant. ``re.compile`` is made to raise an unrelated
    ``FutureWarning`` so one is guaranteed to land inside the suppression
    window -- which is what a warning raised on another thread would do."""
    real_compile = re.compile

    def noisy_compile(pattern, flags=0):
        warnings.warn("an unrelated future change", FutureWarning, stacklevel=1)
        return real_compile(pattern, flags)

    monkeypatch.setattr(re, "compile", noisy_compile)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        verdict = validate_regex_pattern("[[a]]")

    assert verdict == (
        False,
        "not_portable_across_sdks: unescaped_close_bracket",
    )
    assert "an unrelated future change" in [str(w.message) for w in caught]


def test_the_filter_is_narrowed_to_the_parsers_own_messages():
    """The filter names a MESSAGE family, not just a category, because the
    block briefly holds process-global filter state and a warning raised on
    another thread can land inside that window. Asserted against the filter
    itself: an unrelated ``FutureWarning`` raised while it is installed must
    still reach the caller, and every parser message must not."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        warnings.filterwarnings(
            "ignore", category=FutureWarning, message=_SET_OPERATION_WARNING
        )
        warnings.warn("an unrelated future change", FutureWarning, stacklevel=1)
        for suppressed in (
            "Possible nested set at position 1",
            "Possible set difference at position 3",
            "Possible set intersection at position 2",
            "Possible set symmetric difference at position 2",
            "Possible set union at position 2",
        ):
            warnings.warn(suppressed, FutureWarning, stacklevel=1)

    assert [str(w.message) for w in caught] == ["an unrelated future change"]
