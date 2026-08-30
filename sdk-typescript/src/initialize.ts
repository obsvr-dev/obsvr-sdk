/**
 * One-step production preload.
 *
 * Usage:
 *   NODE_OPTIONS="--import @obsvr/sdk/initialize" node app.js
 *
 * The preload runs before application imports, arms ESM and CommonJS provider
 * construction interception, and initializes obsvr from environment variables.
 */

import './register.js';
import { obsvr } from './index.js';
import type { ObsvrConfig } from './proxy/types.js';

const PROVIDERS = new Set(['openai', 'anthropic', 'google']);

function parseProviders(raw: string | undefined): ObsvrConfig['providers'] {
  if (!raw?.trim()) return undefined;
  const providers = raw.split(',').map((value) => value.trim()).filter(Boolean);
  const invalid = providers.filter((provider) => !PROVIDERS.has(provider));
  if (invalid.length > 0) {
    throw new Error(
      `[obsvr] OBSVR_PROVIDERS contains unsupported values: ${invalid.join(', ')}`,
    );
  }
  return providers as ObsvrConfig['providers'];
}

function parsePiiPolicy(raw: string | undefined): ObsvrConfig['piiPolicy'] {
  if (!raw?.trim()) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `[obsvr] OBSVR_PII_POLICY must be valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('[obsvr] OBSVR_PII_POLICY must be a JSON object');
  }
  return parsed as ObsvrConfig['piiPolicy'];
}

function environmentConfig(): ObsvrConfig {
  const apiKey = process.env.OBSVR_API_KEY?.trim();
  if (!apiKey) {
    throw new Error(
      '[obsvr] OBSVR_API_KEY is required by @obsvr/sdk/initialize. ' +
        'Set it or use @obsvr/sdk/register with an explicit obsvr.init() call.',
    );
  }
  const environment = process.env.OBSVR_ENVIRONMENT?.trim();
  if (
    environment &&
    environment !== 'development' &&
    environment !== 'staging' &&
    environment !== 'production'
  ) {
    throw new Error(
      `[obsvr] OBSVR_ENVIRONMENT must be development, staging, or production; got ${environment}`,
    );
  }
  return {
    apiKey,
    ingestUrl: process.env.OBSVR_INGEST_URL?.trim() || undefined,
    environment: environment as ObsvrConfig['environment'],
    providers: parseProviders(process.env.OBSVR_PROVIDERS),
    piiPolicy: parsePiiPolicy(process.env.OBSVR_PII_POLICY),
  };
}

obsvr.init(environmentConfig());
