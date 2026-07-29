"""_model_of() reads a config object, not only a dict.

llm_config was a plain dict in early releases and is an LLMConfig OBJECT on
every modern one. The old implementation tested `isinstance(llm_config, dict)`
and fell through to "unknown" for everything else, so events on the newest
supported releases recorded no model at all — on an agent whose own config
names it. Confirmed live across the version matrix: the first ag2 release
records the model, and both later releases record "unknown".

Governance was never affected. Only the evidence was, which is why nothing
surfaced it: the audit trail looked populated and one field was quietly empty.

The fakes below are deliberately NOT the framework's classes — the read is
duck-typed, and importing the real type to test it would make a soft dependency
hard.
"""

from obsvr.integrations.autogen import _model_of


class _Agent:
    def __init__(self, llm_config):
        self.llm_config = llm_config


class FakeLLMConfig:
    """The modern shape: attributes, not keys."""

    def __init__(self, model=None, config_list=None):
        if model is not None:
            self.model = model
        if config_list is not None:
            self.config_list = config_list


class FakeEntry:
    def __init__(self, model):
        self.model = model


def test_object_config_with_a_model_attribute():
    assert _model_of(_Agent(FakeLLMConfig(model="gpt-4o-mini"))) == "gpt-4o-mini"


def test_object_config_with_an_object_config_list():
    cfg = FakeLLMConfig(config_list=[FakeEntry("gpt-4o-mini")])
    assert _model_of(_Agent(cfg)) == "gpt-4o-mini"


def test_object_config_with_a_dict_config_list():
    """The mixed shape: object outside, dicts inside."""
    cfg = FakeLLMConfig(config_list=[{"model": "gpt-4o-mini"}])
    assert _model_of(_Agent(cfg)) == "gpt-4o-mini"


def test_dict_config_still_works():
    """The old shape must not regress — early releases really do pass a dict."""
    assert _model_of(_Agent({"model": "gpt-4o-mini"})) == "gpt-4o-mini"
    assert _model_of(_Agent({"config_list": [{"model": "gpt-4o-mini"}]})) == "gpt-4o-mini"


def test_unknown_stays_unknown_when_there_is_nothing_to_read():
    """`unknown` must still mean "no model found", not "we stopped looking"."""
    assert _model_of(_Agent(None)) == "unknown"
    assert _model_of(_Agent(FakeLLMConfig())) == "unknown"
    assert _model_of(_Agent({"config_list": []})) == "unknown"
    assert _model_of(_Agent(object())) == "unknown"


def test_a_config_whose_attribute_access_explodes_is_not_fatal():
    """Reading evidence must never break the call it is describing."""

    class Hostile:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    assert _model_of(_Agent(Hostile())) == "unknown"
