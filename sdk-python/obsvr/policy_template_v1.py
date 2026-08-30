"""Typed, signed policy templates with exact rendered provenance."""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from .device_identity import DeviceSigner, derive_device_key_id, verify_device_sig
from .strict_canonical import code_point_key
from .tool_pinning import _canonical_json_for_hash

POLICY_TEMPLATE_V1_SCHEMA = "obsvr-policy-template-v1"
RENDERED_POLICY_V1_SCHEMA = "obsvr-rendered-policy-v1"
RENDERED_POLICY_ENVELOPE_V1_SCHEMA = "obsvr-rendered-policy-envelope-v1"
_HEX = frozenset("0123456789abcdef")


class PolicyTemplateV1ValidationError(ValueError):
    pass


def _fail(message: str) -> None:
    raise PolicyTemplateV1ValidationError(message)


def _text(value: Any, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip().encode()) > maximum:
        _fail(f"{field} must be nonblank and at most {maximum} UTF-8 bytes")
    return value.strip()


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        _fail(f"{field} must be a lowercase SHA-256 hash")
    return value


def _digest(domain: str, value: Any) -> str:
    return hashlib.sha256(f"{domain}\0{_canonical_json_for_hash(value)}".encode()).hexdigest()


def _validate_json(value: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    counter = counter or [0]
    counter[0] += 1
    if counter[0] > 4096 or depth > 16:
        _fail("template artifact exceeds structural bounds")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        _text(value, "template string")
        return
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 9_007_199_254_740_991:
        return
    if isinstance(value, list):
        if len(value) > 256:
            _fail("template array exceeds 256 items")
        for item in value:
            _validate_json(item, depth + 1, counter)
        return
    if isinstance(value, dict):
        if len(value) > 256:
            _fail("template object exceeds 256 fields")
        for key, item in value.items():
            _text(key, "template key", 256)
            _validate_json(item, depth + 1, counter)
        return
    _fail("template contains unsupported JSON value")


def build_policy_template_v1(input_value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(input_value, dict):
        _fail("template must be an object")
    unknown = sorted(set(input_value) - {"schema", "template_id", "version", "parameters", "artifact"}, key=code_point_key)
    if unknown:
        _fail(f"template contains unsupported field: {unknown[0]}")
    if "schema" in input_value and input_value["schema"] != POLICY_TEMPLATE_V1_SCHEMA:
        _fail("template schema is invalid")
    raw_parameters = input_value.get("parameters")
    if not isinstance(raw_parameters, list) or len(raw_parameters) > 128:
        _fail("parameters must contain at most 128 items")
    parameters = []
    for index, item in enumerate(raw_parameters):
        if not isinstance(item, dict):
            _fail(f"parameters[{index}] must be an object")
        extra = set(item) - {"name", "type", "enum_values"}
        if extra:
            _fail(f"parameters[{index}] contains unsupported field: {sorted(extra)[0]}")
        if item.get("type") not in {"string", "integer", "boolean", "enum"}:
            _fail(f"parameters[{index}].type is invalid")
        result = {"name": _text(item.get("name"), f"parameters[{index}].name", 256), "type": item["type"]}
        if result["type"] == "enum":
            values = item.get("enum_values")
            if not isinstance(values, list) or not 1 <= len(values) <= 128:
                _fail(f"parameters[{index}].enum_values is required")
            result["enum_values"] = sorted({_text(v, "enum value", 256) for v in values}, key=code_point_key)
        elif "enum_values" in item:
            _fail(f"parameters[{index}].enum_values is only valid for enum")
        parameters.append(result)
    parameters.sort(key=lambda item: code_point_key(item["name"]))
    if len({item["name"] for item in parameters}) != len(parameters):
        _fail("parameter names must be unique")
    _validate_json(input_value.get("artifact"))
    return {"schema": POLICY_TEMPLATE_V1_SCHEMA, "template_id": _text(input_value.get("template_id"), "template_id", 256), "version": _text(input_value.get("version"), "version", 256), "parameters": parameters, "artifact": input_value["artifact"]}


def policy_template_v1_hash(input_value: Dict[str, Any]) -> str:
    return _digest("obsvr-policy-template/1", build_policy_template_v1(input_value))


def _param(parameter: Dict[str, Any], value: Any) -> Any:
    if parameter["type"] == "string" and isinstance(value, str):
        return _text(value, parameter["name"])
    if parameter["type"] == "integer" and isinstance(value, int) and not isinstance(value, bool) and abs(value) <= 9_007_199_254_740_991:
        return value
    if parameter["type"] == "boolean" and isinstance(value, bool):
        return value
    if parameter["type"] == "enum" and isinstance(value, str) and value in parameter["enum_values"]:
        return value
    _fail(f"parameter {parameter['name']} does not match type {parameter['type']}")


def _render(value: Any, params: Dict[str, Any]) -> Any:
    if isinstance(value, list):
        return [_render(item, params) for item in value]
    if isinstance(value, dict):
        if set(value) == {"$obsvr_param"}:
            name = value["$obsvr_param"]
            if not isinstance(name, str) or name not in params:
                _fail("template references an undeclared parameter")
            return params[name]
        return {key: _render(item, params) for key, item in value.items()}
    return value


def render_policy_template_v1(template_input: Dict[str, Any], supplied: Dict[str, Any], approval_hash: str, activation_hash: str) -> Dict[str, Any]:
    template = build_policy_template_v1(template_input)
    if not isinstance(supplied, dict):
        _fail("supplied parameters must be an object")
    expected = {item["name"] for item in template["parameters"]}
    extras = sorted(set(supplied) - expected, key=code_point_key)
    if extras:
        _fail(f"undeclared parameter supplied: {extras[0]}")
    params = {}
    for parameter in template["parameters"]:
        name = parameter["name"]
        if name not in supplied:
            _fail(f"missing parameter: {name}")
        params[name] = _param(parameter, supplied[name])
    params = dict(sorted(params.items(), key=lambda item: code_point_key(item[0])))
    rendered = _render(template["artifact"], params)
    _validate_json(rendered)
    return {"schema": RENDERED_POLICY_V1_SCHEMA, "template_id": template["template_id"], "template_version": template["version"], "template_hash": policy_template_v1_hash(template), "parameters": params, "parameters_hash": _digest("obsvr-policy-template-parameters/1", params), "rendered_artifact": rendered, "artifact_hash": _digest("obsvr-rendered-policy-artifact/1", rendered), "approval_hash": _hash(approval_hash, "approval_hash"), "activation_hash": _hash(activation_hash, "activation_hash")}


def sign_rendered_policy_v1(rendered: Dict[str, Any], signer: DeviceSigner) -> Dict[str, Any]:
    body_hash = _digest("obsvr-rendered-policy/1", rendered)
    payload = f"obsvr-rendered-policy-signature/1\0{body_hash}"
    return {"schema": RENDERED_POLICY_ENVELOPE_V1_SCHEMA, "body": rendered, "body_hash": body_hash, "key_id": signer.key_id, "signature": signer.sign_payload(payload)}


def verify_rendered_policy_v1(envelope: Dict[str, Any], raw_public_key: bytes) -> bool:
    try:
        body_hash = _digest("obsvr-rendered-policy/1", envelope["body"])
        return envelope.get("schema") == RENDERED_POLICY_ENVELOPE_V1_SCHEMA and envelope.get("body_hash") == body_hash and envelope.get("key_id") == derive_device_key_id(raw_public_key) and verify_device_sig(raw_public_key, envelope["key_id"], f"obsvr-rendered-policy-signature/1\0{body_hash}", envelope.get("signature")) is True
    except (KeyError, TypeError, ValueError):
        return False
