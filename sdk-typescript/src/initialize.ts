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
import { assertRequiredBindings, recordBinding } from './binding-report.js';

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

function parseJsonObject(name: string, raw: string | undefined): Record<string, unknown> | undefined {
  if (!raw?.trim()) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(
      `[obsvr] ${name} must be valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`[obsvr] ${name} must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
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
    piiPolicy: parseJsonObject('OBSVR_PII_POLICY', process.env.OBSVR_PII_POLICY) as ObsvrConfig['piiPolicy'],
    agentPolicy: parseJsonObject('OBSVR_AGENT_POLICY', process.env.OBSVR_AGENT_POLICY) as ObsvrConfig['agentPolicy'],
    mcpToolPolicy: parseJsonObject('OBSVR_MCP_TOOL_POLICY', process.env.OBSVR_MCP_TOOL_POLICY) as ObsvrConfig['mcpToolPolicy'],
  };
}

obsvr.init(environmentConfig());

function requiredBindings(raw: string | undefined): string[] {
  if (!raw?.trim()) return [];
  return [...new Set(raw.split(',').map((value) => value.trim()).filter(Boolean))];
}

async function bindRequiredIntegration(name: string): Promise<void> {
  // Keep optional peers optional at build time. The runtime string still goes
  // through the registered loader hook, which is the binding being verified.
  const load = (specifier: string): Promise<unknown> => import(specifier);
  try {
    if (name === 'openai.client') {
      await load('openai');
      return;
    }
    if (name === 'anthropic.client') {
      await load('@anthropic-ai/sdk');
      return;
    }
    if (name === 'google.client') {
      try {
        await load('@google/genai');
      } catch {
        await load('@google/generative-ai');
      }
      return;
    }
    if (name === 'mcp.client') {
      await load('@modelcontextprotocol/sdk/client/index.js');
      return;
    }
    if (name === 'openai_agents.tools' || name === 'openai_agents.model') {
      await load('@openai/agents');
      return;
    }
  } catch (error) {
    recordBinding(name, `${name}.startup-export`, error);
  }
}

const required = requiredBindings(process.env.OBSVR_REQUIRED_BINDINGS);
for (const name of required) {
  await bindRequiredIntegration(name);
}
assertRequiredBindings(required);
