"""The token normaliser: what it reads, and what it refuses to invent.

Parity target: sdk-typescript/tests/unit/token-usage.test.ts. The two languages
must accept the same shapes and refuse in the same cases, because an event's
token fields are part of the cross-language contract.

The defect this replaced was not a crash. Sites defaulted a missing field to
zero, so an upstream rename produced ``input_tokens: 0`` — a measurement that
never happened, sitting in a signed audit record, indistinguishable from a call
that genuinely consumed nothing. So most of the assertions below are negative.
"""

from obsvr.token_usage import (
    SHAPE_ABSENT,
    SHAPE_RECOGNIZED,
    SHAPE_UNRECOGNIZED,
    normalize_token_usage,
    read_token_usage,
)


class _Usage:
    """Attribute-shaped usage, as the provider SDKs actually hand it back."""

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class TestShapesItAccepts:
    def test_snake_case_wire_openai_chat(self):
        usage, shape = normalize_token_usage(
            {"prompt_tokens": 9, "completion_tokens": 3, "total_tokens": 12}
        )
        assert shape == SHAPE_RECOGNIZED
        assert usage == {"input_tokens": 9, "output_tokens": 3, "total_tokens": 12}

    def test_snake_case_wire_anthropic_derives_the_total(self):
        usage, _ = normalize_token_usage({"input_tokens": 11, "output_tokens": 2})
        assert usage == {"input_tokens": 11, "output_tokens": 2, "total_tokens": 13}

    def test_gemini_naming_in_both_spellings(self):
        snake, _ = normalize_token_usage(
            {"prompt_token_count": 5, "candidates_token_count": 7, "total_token_count": 12}
        )
        camel, _ = normalize_token_usage(
            {"promptTokenCount": 5, "candidatesTokenCount": 7, "totalTokenCount": 12}
        )
        assert snake == camel == {
            "input_tokens": 5,
            "output_tokens": 7,
            "total_tokens": 12,
        }

    def test_flat_camel_case(self):
        usage, _ = normalize_token_usage(
            {"inputTokens": 9, "outputTokens": 3, "totalTokens": 12}
        )
        assert usage == {"input_tokens": 9, "output_tokens": 3, "total_tokens": 12}

    def test_legacy_camel_case(self):
        usage, _ = normalize_token_usage(
            {"promptTokens": 9, "completionTokens": 3, "totalTokens": 12}
        )
        assert usage == {"input_tokens": 9, "output_tokens": 3, "total_tokens": 12}

    def test_nested_shape_and_the_total_the_spec_deleted(self):
        # The shape that broke a live integration: the field names survived and
        # their TYPE changed, so every "is this a number?" guard answered no.
        usage, _ = normalize_token_usage(
            {
                "inputTokens": {"total": 9, "noCache": 9, "cacheRead": 0, "cacheWrite": 0},
                "outputTokens": {"total": 3, "text": 3, "reasoning": 0},
            }
        )
        assert usage == {"input_tokens": 9, "output_tokens": 3, "total_tokens": 12}

    def test_attribute_shaped_container(self):
        usage, _ = normalize_token_usage(_Usage(input_tokens=11, output_tokens=2))
        assert usage == {"input_tokens": 11, "output_tokens": 2, "total_tokens": 13}

    def test_bedrock_titan_input_count(self):
        usage, _ = normalize_token_usage({"inputTextTokenCount": 14})
        assert usage == {"input_tokens": 14}


class TestItNeverFabricates:
    def test_absent_container_reports_absent(self):
        for container in (None, "", 0, False, 3.5):
            assert normalize_token_usage(container) == (None, SHAPE_ABSENT)

    def test_empty_container_is_absent_not_a_parse_failure(self):
        # A provider that sent `usage: {}` reported nothing, which is the same
        # fact as sending no usage at all.
        assert normalize_token_usage({}) == (None, SHAPE_ABSENT)

    def test_unrecognised_payload_says_so_instead_of_counting_zero(self):
        usage, shape = normalize_token_usage({"tokens_consumed": 42, "billing_units": 3})
        assert usage is None
        assert shape == SHAPE_UNRECOGNIZED

    def test_half_known_stays_half_known(self):
        usage, shape = normalize_token_usage({"output_tokens": 3})
        assert shape == SHAPE_RECOGNIZED
        # No fabricated input, and therefore no total derived from one.
        assert usage == {"output_tokens": 3}

    def test_non_numeric_counts_are_never_coerced(self):
        usage, shape = normalize_token_usage({"input_tokens": "nine", "output_tokens": None})
        assert usage is None
        assert shape == SHAPE_UNRECOGNIZED

    def test_a_bool_is_not_a_token_count(self):
        # bool is an int subclass in Python; True is not 1 token.
        usage, _ = normalize_token_usage({"input_tokens": True})
        assert usage is None

    def test_a_genuine_zero_survives(self):
        # The point of refusing to fabricate is that a real 0 keeps meaning
        # something: a fully cached prompt really can bill zero new tokens.
        usage, _ = normalize_token_usage({"input_tokens": 0, "output_tokens": 5})
        assert usage == {"input_tokens": 0, "output_tokens": 5, "total_tokens": 5}

    def test_a_genuine_zero_does_not_fall_through_to_the_next_alias(self):
        # Truthiness-chained alias lookup used to skip a real 0 and land on a
        # later alias. Presence, not truthiness, decides.
        usage, _ = normalize_token_usage({"input_tokens": 0, "prompt_tokens": 99})
        assert usage == {"input_tokens": 0}

    def test_an_object_where_a_number_belongs_never_reaches_the_event(self):
        usage, shape = normalize_token_usage({"inputTokens": {"noCache": 9}})
        assert usage is None
        assert shape == SHAPE_UNRECOGNIZED

    def test_a_property_that_raises_does_not_escape(self):
        # A token read must never turn into a failed governed call.
        class Hostile:
            @property
            def input_tokens(self):
                raise ValueError("boom")

        usage, _ = normalize_token_usage(Hostile())
        assert usage is None


class TestReadTokenUsageDictForm:
    def test_returns_all_three_keys_with_none_for_unread(self):
        assert read_token_usage({"output_tokens": 3}) == {
            "input_tokens": None,
            "output_tokens": 3,
            "total_tokens": None,
        }

    def test_absent_yields_all_none(self):
        assert read_token_usage(None) == {
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
        }
