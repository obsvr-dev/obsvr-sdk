"""``wrap()`` says what it governed.

Twin of sdk-typescript/tests/unit/wrap-coverage-signal.test.ts.

A client whose shape carries no auditable method used to come back as an
ordinary governance proxy: every call forwarded through, no policy, no event,
and nothing said. ``init()`` already refuses to accept a config key it will not
read without saying so — a configuration that is ACCEPTED is a configuration
that is IN FORCE — and this is the same acceptance one layer over.

The proxy is still returned, so nothing that worked stops working; the change is
that the coverage gap is now stated. Both halves are asserted here: the warning
fires when nothing is governed, and it does NOT fire when something is — a
signal that fires on every wrap is worth no more than one that never does.
"""
import importlib
import logging

import pytest

import obsvr

# `obsvr.wrap` is the re-exported FUNCTION, so the module has to be asked for
# by name — the internals under test (the reported-clients set) live on it.
wrap_mod = importlib.import_module("obsvr.wrap")


@pytest.fixture(autouse=True)
def _forget_reported_clients():
    wrap_mod._ungoverned_reported = type(wrap_mod._ungoverned_reported)()


def boot(**extra):
    obsvr.init(api_key="k", ingest_url="https://example.test", **extra)


class Ungoverned:
    """A client shaped like nothing obsvr intercepts."""

    def invoke(self, *_a, **_k):
        return "hi"


class _Completions:
    def create(self, *_a, **_k):
        return {"choices": []}


class _Chat:
    completions = _Completions()


class Governed:
    """The minimum shape that IS governed: one auditable path, callable."""

    chat = _Chat()


def _gap_lines(caplog):
    return [r.getMessage() for r in caplog.records if "matched no governed method" in r.getMessage()]


def test_warns_naming_the_gap_and_the_paths_obsvr_intercepts(caplog):
    boot()
    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(Ungoverned())

    text = "\n".join(_gap_lines(caplog))
    assert "matched no governed method" in text
    assert "NOT covered" in text
    # The message has to be actionable: it names what obsvr looks for.
    assert "chat.completions.create" in text
    assert "require_governed_surface" in text


def test_still_returns_a_working_passthrough(caplog):
    boot()
    with caplog.at_level(logging.WARNING, logger="obsvr"):
        client = wrap_mod.wrap(Ungoverned())

    assert client.invoke() == "hi"


def test_warns_once_per_client_not_once_per_wrap(caplog):
    boot()
    client = Ungoverned()
    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(client)
        wrap_mod.wrap(client)
        wrap_mod.wrap(client)

    assert len(_gap_lines(caplog)) == 1


def test_warns_again_for_a_different_client(caplog):
    boot()
    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(Ungoverned())
        wrap_mod.wrap(Ungoverned())

    assert len(_gap_lines(caplog)) == 2


def test_a_governed_client_is_not_reported(caplog):
    """The non-vacuity control. Without it the warning could be unconditional
    and every case above would still pass."""
    boot()
    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(Governed())

    assert _gap_lines(caplog) == []


@pytest.mark.parametrize("method_name", ["generate_content", "generate_content_async"])
def test_a_gemini_shaped_client_is_not_reported(caplog, method_name):
    """Gemini generation methods sit directly on the model object, not under a
    namespace — the governed paths with no dots in them."""
    boot()

    class Model:
        def generation(self, *_a, **_k):
            return {}

    setattr(Model, method_name, Model.generation)

    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(Model())

    assert _gap_lines(caplog) == []


def test_require_governed_surface_raises_instead_of_warning():
    boot(require_governed_surface=True)

    with pytest.raises(RuntimeError, match="matched no governed method"):
        wrap_mod.wrap(Ungoverned())


def test_require_governed_surface_does_not_raise_for_a_governed_client():
    boot(require_governed_surface=True)

    assert wrap_mod.wrap(Governed()) is not None


def test_require_governed_surface_must_be_a_boolean():
    with pytest.raises(ValueError, match="require_governed_surface must be a boolean"):
        obsvr.init(
            api_key="k", ingest_url="https://example.test", require_governed_surface="yes"
        )


def test_default_posture_is_a_warning_not_a_raise(caplog):
    boot()
    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(Ungoverned())  # must not raise

    assert _gap_lines(caplog)


def test_the_probe_survives_a_property_that_raises_on_read(caplog):
    """Provider SDKs build sub-resources in lazy properties. ``beta`` is the one
    the probe reads and ``_detect_provider`` does not, so a raise here reaches
    the probe and nothing else."""
    boot()

    class Hostile:
        messages = _Chat()  # not the governed shape; see below

        @property
        def beta(self):
            raise RuntimeError("lazy resource blew up")

    class Messages:
        def create(self, *_a, **_k):
            return {}

    Hostile.messages = Messages()

    with caplog.at_level(logging.WARNING, logger="obsvr"):
        # `messages.create` resolves, so this client IS governed — a verdict
        # only reachable if the raising `beta` property did not abort the probe.
        wrap_mod.wrap(Hostile())

    assert _gap_lines(caplog) == []


def test_a_non_callable_at_the_method_path_is_no_surface(caplog):
    """`create` present but not callable: the proxy would never intercept it,
    so reporting it as covered would be the false direction."""
    boot()

    class NotAFunction:
        create = "not a function"

    class Chat:
        completions = NotAFunction()

    class Client:
        chat = Chat()

    with caplog.at_level(logging.WARNING, logger="obsvr"):
        wrap_mod.wrap(Client())

    assert _gap_lines(caplog)
