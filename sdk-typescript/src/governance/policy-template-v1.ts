import { createHash } from 'node:crypto';
import { canonicalJsonForHash } from '../policy/tool-pinning.js';
import { deriveDeviceKeyId, verifyDeviceSig, type DeviceSigner } from '../proxy/device-identity.js';
import { compareCodePoints } from './strict-canonical.js';

export const POLICY_TEMPLATE_V1_SCHEMA = 'obsvr-policy-template-v1' as const;
export const RENDERED_POLICY_V1_SCHEMA = 'obsvr-rendered-policy-v1' as const;
export const RENDERED_POLICY_ENVELOPE_V1_SCHEMA = 'obsvr-rendered-policy-envelope-v1' as const;
const HASH_RE = /^[0-9a-f]{64}$/;
type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface TemplateParameterV1 { name: string; type: 'string' | 'integer' | 'boolean' | 'enum'; enum_values?: string[]; }
export interface PolicyTemplateV1Input { template_id: string; version: string; parameters: TemplateParameterV1[]; artifact: Json; }

export class PolicyTemplateV1ValidationError extends Error { constructor(message: string) { super(message); this.name = 'PolicyTemplateV1ValidationError'; } }
function fail(message: string): never { throw new PolicyTemplateV1ValidationError(message); }
function text(value: unknown, field: string, max = 2048): string { if (typeof value !== 'string' || !value.trim() || Buffer.byteLength(value.trim(), 'utf8') > max) fail(`${field} must be nonblank and at most ${max} UTF-8 bytes`); return value.trim(); }
function hash(value: unknown, field: string): string { if (typeof value !== 'string' || !HASH_RE.test(value)) fail(`${field} must be a lowercase SHA-256 hash`); return value; }
function digest(domain: string, value: unknown): string { return createHash('sha256').update(`${domain}\0${canonicalJsonForHash(value)}`, 'utf8').digest('hex'); }
function validateJson(value: unknown, depth = 0, count = { value: 0 }): asserts value is Json {
  count.value += 1; if (count.value > 4096 || depth > 16) fail('template artifact exceeds structural bounds');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') { if (typeof value === 'string') text(value, 'template string'); return; }
  if (typeof value === 'number') { if (!Number.isSafeInteger(value)) fail('template numbers must be safe integers'); return; }
  if (Array.isArray(value)) { if (value.length > 256) fail('template array exceeds 256 items'); value.forEach((item) => validateJson(item, depth + 1, count)); return; }
  if (!value || typeof value !== 'object') fail('template contains unsupported JSON value');
  const record = value as Record<string, unknown>; if (Object.keys(record).length > 256) fail('template object exceeds 256 fields');
  for (const [key, item] of Object.entries(record)) { text(key, 'template key', 256); validateJson(item, depth + 1, count); }
}

export function buildPolicyTemplateV1(input: PolicyTemplateV1Input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('template must be an object');
  const raw = input as unknown as Record<string, unknown>; const unknown = Object.keys(raw).filter((key) => !['schema', 'template_id', 'version', 'parameters', 'artifact'].includes(key)).sort(compareCodePoints); if (unknown.length) fail(`template contains unsupported field: ${unknown[0]}`);
  if (raw.schema !== undefined && raw.schema !== POLICY_TEMPLATE_V1_SCHEMA) fail('template schema is invalid');
  if (!Array.isArray(raw.parameters) || raw.parameters.length > 128) fail('parameters must contain at most 128 items');
  const parameters = raw.parameters.map((candidate, index) => {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) fail(`parameters[${index}] must be an object`);
    const p = candidate as Record<string, unknown>; const extra = Object.keys(p).filter((key) => !['name', 'type', 'enum_values'].includes(key)); if (extra.length) fail(`parameters[${index}] contains unsupported field: ${extra[0]}`);
    if (!['string', 'integer', 'boolean', 'enum'].includes(String(p.type))) fail(`parameters[${index}].type is invalid`);
    const result: TemplateParameterV1 = { name: text(p.name, `parameters[${index}].name`, 256), type: p.type as TemplateParameterV1['type'] };
    if (result.type === 'enum') { if (!Array.isArray(p.enum_values) || p.enum_values.length === 0 || p.enum_values.length > 128) fail(`parameters[${index}].enum_values is required`); result.enum_values = [...new Set(p.enum_values.map((v, i) => text(v, `enum_values[${i}]`, 256)))].sort(compareCodePoints); }
    else if (p.enum_values !== undefined) fail(`parameters[${index}].enum_values is only valid for enum`);
    return result;
  }).sort((a, b) => compareCodePoints(a.name, b.name));
  if (new Set(parameters.map((item) => item.name)).size !== parameters.length) fail('parameter names must be unique');
  validateJson(raw.artifact);
  return { schema: POLICY_TEMPLATE_V1_SCHEMA, template_id: text(raw.template_id, 'template_id', 256), version: text(raw.version, 'version', 256), parameters, artifact: raw.artifact as Json };
}

export function policyTemplateV1Hash(input: PolicyTemplateV1Input): string { return digest('obsvr-policy-template/1', buildPolicyTemplateV1(input)); }

function validateParam(parameter: TemplateParameterV1, value: unknown): Json {
  if (parameter.type === 'string' && typeof value === 'string') return text(value, parameter.name);
  if (parameter.type === 'integer' && typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (parameter.type === 'boolean' && typeof value === 'boolean') return value;
  if (parameter.type === 'enum' && typeof value === 'string' && parameter.enum_values?.includes(value)) return value;
  return fail(`parameter ${parameter.name} does not match type ${parameter.type}`);
}
function renderNode(value: Json, params: Record<string, Json>): Json {
  if (Array.isArray(value)) return value.map((item) => renderNode(item, params));
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === '$obsvr_param') { const name = (value as Record<string, Json>).$obsvr_param; if (typeof name !== 'string' || !(name in params)) fail('template references an undeclared parameter'); return params[name]; }
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, renderNode(item, params)]));
  }
  return value;
}

export function renderPolicyTemplateV1(templateInput: PolicyTemplateV1Input, supplied: Record<string, unknown>, approvalHash: string, activationHash: string) {
  const template = buildPolicyTemplateV1(templateInput); if (!supplied || typeof supplied !== 'object' || Array.isArray(supplied)) fail('supplied parameters must be an object');
  const expected = new Set(template.parameters.map((item) => item.name)); const extras = Object.keys(supplied).filter((key) => !expected.has(key)); if (extras.length) fail(`undeclared parameter supplied: ${extras.sort(compareCodePoints)[0]}`);
  const params: Record<string, Json> = {}; for (const parameter of template.parameters) { if (!(parameter.name in supplied)) fail(`missing parameter: ${parameter.name}`); params[parameter.name] = validateParam(parameter, supplied[parameter.name]); }
  const rendered = renderNode(template.artifact, params); validateJson(rendered);
  return { schema: RENDERED_POLICY_V1_SCHEMA, template_id: template.template_id, template_version: template.version, template_hash: policyTemplateV1Hash(template), parameters: Object.fromEntries(Object.entries(params).sort(([a], [b]) => compareCodePoints(a, b))), parameters_hash: digest('obsvr-policy-template-parameters/1', params), rendered_artifact: rendered, artifact_hash: digest('obsvr-rendered-policy-artifact/1', rendered), approval_hash: hash(approvalHash, 'approval_hash'), activation_hash: hash(activationHash, 'activation_hash') };
}

export function signRenderedPolicyV1(rendered: ReturnType<typeof renderPolicyTemplateV1>, signer: DeviceSigner) { const bodyHash = digest('obsvr-rendered-policy/1', rendered); const payload = `obsvr-rendered-policy-signature/1\0${bodyHash}`; return { schema: RENDERED_POLICY_ENVELOPE_V1_SCHEMA, body: rendered, body_hash: bodyHash, key_id: signer.keyId, signature: signer.signPayload(payload) }; }
export function verifyRenderedPolicyV1(envelope: ReturnType<typeof signRenderedPolicyV1>, rawPublicKey: Buffer): boolean { try { const bodyHash = digest('obsvr-rendered-policy/1', envelope.body); return envelope.schema === RENDERED_POLICY_ENVELOPE_V1_SCHEMA && envelope.body_hash === bodyHash && envelope.key_id === deriveDeviceKeyId(rawPublicKey) && verifyDeviceSig(rawPublicKey, envelope.key_id, `obsvr-rendered-policy-signature/1\0${bodyHash}`, envelope.signature); } catch { return false; } }
