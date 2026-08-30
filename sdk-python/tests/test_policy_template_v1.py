import copy

import pytest

from obsvr.device_identity import load_device_signer
from obsvr.policy_template_v1 import policy_template_v1_hash, render_policy_template_v1, sign_rendered_policy_v1, verify_rendered_policy_v1

TEMPLATE = {"template_id": "external-send", "version": "1", "parameters": [{"name": "max_actions", "type": "integer"}, {"name": "review", "type": "enum", "enum_values": ["human", "manager"]}], "artifact": {"rules": [{"id": "send-limit", "limit": {"$obsvr_param": "max_actions"}, "approval": {"$obsvr_param": "review"}}]}}


def test_renders_typed_whole_value_parameters_with_full_provenance():
    rendered = render_policy_template_v1(TEMPLATE, {"max_actions": 5, "review": "manager"}, "a" * 64, "b" * 64)
    assert rendered["rendered_artifact"] == {"rules": [{"id": "send-limit", "limit": 5, "approval": "manager"}]}
    assert rendered["template_hash"] == policy_template_v1_hash(TEMPLATE)
    assert rendered["template_hash"] == "3cb8e4d81dea15ec1d070bae3de8bdd3c90ba73242e91368b7bf0f1c200443e8"


def test_signs_exact_rendered_provenance_and_detects_tampering(tmp_path):
    rendered = render_policy_template_v1(TEMPLATE, {"max_actions": 5, "review": "manager"}, "a" * 64, "b" * 64)
    key = tmp_path / "key"
    key.write_text("22" * 32)
    signer = load_device_signer(str(key))
    envelope = sign_rendered_policy_v1(rendered, signer)
    assert verify_rendered_policy_v1(envelope, signer.raw_public_key)
    tampered = copy.deepcopy(envelope)
    tampered["body"]["rendered_artifact"] = {"changed": True}
    assert not verify_rendered_policy_v1(tampered, signer.raw_public_key)


def test_rejects_missing_extra_and_mistyped_parameters():
    with pytest.raises(ValueError, match="missing parameter"):
        render_policy_template_v1(TEMPLATE, {"max_actions": 5}, "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="undeclared"):
        render_policy_template_v1(TEMPLATE, {"max_actions": 5, "review": "human", "raw": True}, "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="does not match"):
        render_policy_template_v1(TEMPLATE, {"max_actions": "five", "review": "human"}, "a" * 64, "b" * 64)
