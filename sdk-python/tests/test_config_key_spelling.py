"""Python is structurally immune to the config-spelling defect. Pin that.

The TypeScript SDK takes a config OBJECT and picked its naming convention from
one key, so `api_key` beside `piiPolicy` silently dropped the PII policy and the
SSN reached the provider. It now warns.

This SDK cannot reach that state: ``init()`` declares explicit keyword-only
parameters, so a wrong-style or misspelled key is a ``TypeError`` at the call —
louder than a warning, and CPython even names the key that was meant.

That immunity is a property of the signature, not a decision anyone recorded, so
it is asserted here. Adding ``**kwargs`` to ``init()`` would silently turn every
misspelling into a silent no-op and reintroduce the defect on this side; these
tests fail if that happens.

Twin: sdk-typescript/tests/unit/config-key-spelling.test.ts.
"""

import pytest

import obsvr
from obsvr.config import _reset, get_config
from obsvr.wrap import wrap

SSN = "123-45-6789"


class TestConfigKeySpelling:
    def test_a_camelcase_key_is_rejected_not_ignored(self):
        _reset()
        with pytest.raises(TypeError) as exc:
            obsvr.init(
                api_key="k",
                ingest_url="https://x",
                piiPolicy={"rules": {"ssn": "redact"}},
            )
        # The key that was refused, and the one that was meant.
        assert "piiPolicy" in str(exc.value)
        assert "pii_policy" in str(exc.value)

    def test_a_typo_is_rejected_not_ignored(self):
        _reset()
        with pytest.raises(TypeError) as exc:
            obsvr.init(api_key="k", ingest_url="https://x", pii_polcy={})
        assert "pii_polcy" in str(exc.value)

    def test_init_takes_no_kwargs_catch_all(self):
        """The structural guarantee behind the two rows above.

        A ``**kwargs`` parameter would make every unrecognised key a silent
        no-op, which is exactly the shape that let the other SDK drop a PII
        policy without saying so.
        """
        import inspect

        params = inspect.signature(obsvr.init).parameters
        var_keyword = [p for p in params.values() if p.kind is inspect.Parameter.VAR_KEYWORD]
        assert var_keyword == [], (
            "obsvr.init() grew a **kwargs catch-all; an unknown or misspelled "
            "config key is now silently ignored instead of raising"
        )

    def test_control_the_correct_spelling_applies_and_redacts(self):
        """Without this, the rows above would also pass if init() rejected
        everything, or if redaction had simply stopped working."""
        _reset()
        obsvr.init(api_key="k", ingest_url="https://x", pii_policy={"rules": {"ssn": "redact"}})
        assert get_config().pii_policy == {"rules": {"ssn": "redact"}}

        seen = {}

        class _Completions:
            def create(self, **kw):
                seen.update(kw)
                return {"choices": [{"message": {"content": "ok"}}]}

        class _Chat:
            def __init__(self):
                self.completions = _Completions()

        class _Client:
            def __init__(self):
                self.chat = _Chat()

        wrap(_Client()).chat.completions.create(
            model="gpt-4", messages=[{"role": "user", "content": f"my ssn is {SSN}"}]
        )
        assert SSN not in str(seen)
        assert "[REDACTED_SSN]" in str(seen)
        _reset()
