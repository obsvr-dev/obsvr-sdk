#!/usr/bin/env python3
"""Python half of the canonicalizer parity harness.

Driven by scripts/check-canonical-json-parity.mjs. Two modes:

  generate <count> <out.jsonl> <seed>
      Emit `count` random JSON DOCUMENTS (one per line) using hypothesis.

  canonicalize <in.jsonl> <out.jsonl>
      Parse each document with the stdlib JSON parser and write the canonical
      form `obsvr.rules._canonical_json` produces for it, one per line.

The unit under test is the pair (parse, canonicalize), not canonicalize alone.
Policy rules reach both SDKs as JSON text off the /policies poll, so the
question that matters is whether the same BYTES hash the same in both
languages -- and some of the divergences live in the parse (Python keeps
12345678901234567890 exactly; JS rounds it at parse time), not in the
serializer. Feeding both sides one corpus of text reproduces that faithfully.

Results are written ASCII-escaped (json.dumps default) so a canonical form
containing astral characters, or an unpaired surrogate that has no UTF-8
encoding at all, survives the trip to the comparing process intact.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sdk-python"))

from obsvr.rules import _canonical_json  # noqa: E402


# -- Generation --------------------------------------------------------------
# The generator emits TEXT, not values, so it can aim at the number literals
# where the two languages are known or suspected to part company: whole-valued
# decimals, exponent forms either side of each language's switch-to-exponent
# threshold, negative zero, and integers past 2^53 where JS loses the value.

def _strategies():
    from hypothesis import strategies as st

    exponent_forms = st.builds(
        lambda m, e, sign: "%se%s%d" % (m, sign, e),
        st.sampled_from(["1", "3", "1.5", "9.99", "2.5"]),
        st.integers(min_value=0, max_value=320),
        st.sampled_from(["+", "-", ""]),
    )
    number_text = st.one_of(
        st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1).map(str),
        st.integers(min_value=2**53, max_value=2**70).map(str),
        st.integers(min_value=-(2**70), max_value=-(2**53)).map(str),
        st.sampled_from(["-0", "-0.0", "0.0", "1.0", "100.0", "1e16", "1e21",
                         "1e-4", "1e-6", "1e-7", "3e-5", "0.00003"]),
        st.floats(allow_nan=False, allow_infinity=False).map(repr),
        st.builds(lambda i: "%d.0" % i, st.integers(min_value=-10**6, max_value=10**6)),
        exponent_forms,
    )

    # Characters chosen for where the two string/key handlers can disagree:
    # the BMP ceiling next to an astral character (UTF-16 code-unit order vs
    # code-point order when keys are sorted), the line separators JS treats
    # specially, and a control character.
    # Written as escapes, never as literals: several of these are
    # invisible in a diff, and a reviewer cannot check a character they
    # cannot see. Mirrors CHARS in check-canonical-json-parity.mjs.
    chars = st.sampled_from(
        list("abzAZ09_-. ")
        + [
            "\u00e9",  # non-ASCII, emitted raw by both languages
            "\u2028",  # LINE SEPARATOR - JSON.stringify leaves this raw
            "\u2029",  # PARAGRAPH SEPARATOR - likewise
            "\ud7ff",  # last code point below the surrogate block
            "\uffff",  # top of the BMP: sorts before an astral key in JS
            "\U0001f600",
            "\U00010000",
            "\t",
            "\n",
            '"',
            "\\",
        ]
    )
    text = st.lists(chars, max_size=6).map("".join)
    string_text = text.map(lambda s: json.dumps(s))

    scalar = st.one_of(
        st.sampled_from(["null", "true", "false"]), number_text, string_text
    )

    def container(inner):
        array = st.lists(inner, max_size=4).map(lambda xs: "[" + ",".join(xs) + "]")
        obj = st.lists(st.tuples(text, inner), max_size=4).map(
            lambda kvs: "{"
            + ",".join(
                "%s:%s" % (json.dumps(k), v)
                for k, v in {k: v for k, v in kvs}.items()
            )
            + "}"
        )
        return st.one_of(array, obj)

    return st.recursive(scalar, container, max_leaves=8)


def generate(count: int, out_path: str, seed: int) -> None:
    from hypothesis import strategies as st  # noqa: F401
    from hypothesis.errors import NonInteractiveExampleWarning
    import warnings
    import random

    random.seed(seed)
    strategy = _strategies()
    lines = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", NonInteractiveExampleWarning)
        while len(lines) < count:
            doc = strategy.example()
            # One document per line; the generator never emits a raw newline
            # outside a JSON string escape, but re-serialize defensively.
            if "\n" in doc or "\r" in doc:
                continue
            lines.append(doc)
    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


# -- Canonicalization --------------------------------------------------------

def canonicalize(in_path: str, out_path: str) -> None:
    results = []
    # split("\n"), never splitlines(): str.splitlines() also breaks on U+2028 /
    # U+2029 / U+0085, and JSON.stringify emits those raw inside a string, so a
    # document containing one would silently become two records here.
    for line in Path(in_path).read_text(encoding="utf-8").split("\n"):
        if not line:
            continue
        try:
            value = json.loads(line)
        except Exception as exc:  # a generator bug, not a divergence
            results.append("!!PARSE_ERROR:%s" % type(exc).__name__)
            continue
        try:
            canonical = _canonical_json(value)
        except Exception as exc:
            results.append("!!CANONICALIZE_ERROR:%s" % type(exc).__name__)
            continue
        try:
            # A canonical form that cannot be encoded is not a canonical form:
            # both SDKs hash the UTF-8 bytes, so an unencodable string is a
            # real failure of the contract, recorded rather than hidden.
            canonical.encode("utf-8")
        except UnicodeEncodeError:
            results.append("!!ENCODE_ERROR:UnicodeEncodeError")
            continue
        results.append(canonical)
    # ensure_ascii=True (the default) so unpaired surrogates survive the file.
    Path(out_path).write_text(
        "\n".join(json.dumps(r) for r in results) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "generate":
        generate(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif mode == "canonicalize":
        canonicalize(sys.argv[2], sys.argv[3])
    else:
        raise SystemExit("unknown mode: %s" % mode)
