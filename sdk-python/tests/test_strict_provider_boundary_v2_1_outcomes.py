"""Terminal outcome checks for the strict direct-provider boundary."""

import pytest
import obsvr

from obsvr.strict_provider_boundary_v2_1 import ObsvrStrictProviderBoundaryV21Error
from tests.test_strict_provider_boundary_v2_1 import FakeOpenAI, capability, init


def test_ambiguous_provider_transport_failure_is_signed_as_uncertain():
    init()
    raw = FakeOpenAI()
    failure = TimeoutError("timed out after send")
    failure.code = "ETIMEDOUT"
    raw.chat.completions.failure = failure
    strict = capability()
    client = obsvr.wrap(raw, strict_receipt_v2_1=strict.value)
    with pytest.raises(ObsvrStrictProviderBoundaryV21Error) as caught:
        client.chat.completions.create(model="m", messages=[])
    assert caught.value.code == "admission_not_confirmed"
    terminal = strict.checkpoints[-1]
    assert terminal["terminal_status"] == "invocation_uncertain"
    assert terminal["execution_outcome"]["body"]["status"] == "uncertain"
    assert terminal["execution_outcome"]["body"]["error_code"] == (
        "provider_transport_ambiguous"
    )
