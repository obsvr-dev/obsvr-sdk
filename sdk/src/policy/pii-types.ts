/**
 * Shared PII type constants -- single source of truth for both SDK policy
 * layer and ingest layer. Keep in sync with the ingest-layer PII type list.
 * @packageDocumentation
 */

export const PII_TYPES = [
  'email',
  'phone',
  'ssn',
  'credit_card',
  'ip_address',
  'api_key',
  'aws_access_key',
  'jwt',
  'uuid',
  'name',
  'address',
  'person',
  'location',
  'medical',
  'national_id',
  'private_key',
  'github_token',
  'slack_webhook',
  'prompt_injection',
] as const;

export type PiiType = (typeof PII_TYPES)[number];

export type PiiPolicyAction = 'block' | 'redact' | 'detect_only';

/**
 * Built-in severity defaults.
 * - block: ssn, credit_card, api_key, jwt
 * - redact: email, phone, ip_address
 * - detect_only: uuid, name, address (low-sensitivity identifiers)
 */
export const BUILTIN_SEVERITY: Record<string, PiiPolicyAction> = {
  ssn:              'block',
  credit_card:      'block',
  api_key:          'block',
  aws_access_key:   'block',
  jwt:              'block',
  // redact (not block). The regex matches ANY dotted quad — public IPs,
  // 127.0.0.1, version-like strings — so blocking on it hard-fails calls that
  // merely mention an IP. Redaction masks the value without the availability hit.
  ip_address:       'redact',
  private_key:      'block',
  github_token:     'block',
  slack_webhook:    'block',
  prompt_injection: 'block',
  email:            'redact',
  phone:            'redact',
  // uuid, name, address -> implicit detect_only
};
