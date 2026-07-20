/**
 * obsvr SDK - Manual Tracking Client
 *
 * Provides explicit tracking of LLM completions.
 * For automatic proxy-based tracking, use obsvr.wrap() instead.
 *
 * @example
 * ```typescript
 * import { ObsvrClient, trackCompletion } from '@obsvr/sdk';
 *
 * // Option 1: Use the convenience function
 * const result = await trackCompletion({
 *   apiKey: 'your-api-key',
 *   prompt: 'Hello, world!',
 *   response: 'Hi there!',
 *   model: 'gpt-4',
 *   region: 'us-east-1'
 * });
 *
 * // Option 2: Use the client for multiple calls
 * const client = new ObsvrClient({ apiKey: 'your-api-key' });
 * await client.trackCompletion({
 *   prompt: 'Hello!',
 *   response: 'Hi!',
 *   model: 'gpt-4',
 *   region: 'us-east-1'
 * });
 * ```
 *
 * @packageDocumentation
 */

import type {
  ObsvrClientConfig,
  LLMAuditClientConfig,
  TrackCompletionParams,
  TrackBatchParams,
  TrackResult,
  TrackBatchResult,
  RawEvent,
} from "./types.js";
import {
  DEFAULT_INGEST_URL,
  INGEST_PATH,
  INGEST_BATCH_PATH,
  API_KEY_HEADER,
  CLIENT_TIMEOUT_MS,
  LOG_PREFIX,
} from "./constants.js";

// Re-export types
export type {
  ObsvrClientConfig,
  LLMAuditClientConfig,
  TrackCompletionParams,
  TrackBatchParams,
  TrackResult,
  TrackBatchResult,
  TrackResponse,
  TrackBatchResponse,
  TrackErrorResponse,
} from "./types.js";
import { randomUUID } from "node:crypto";

/**
 * Generate a UUID v4 via node:crypto — works on all supported Node versions
 * (the global Web Crypto `crypto` is not present on every Node 18 build).
 */
export function generateUUID(): string {
  return randomUUID();
}

/**
 * LLM Audit Client - Manual Tracking (No Compliance Controls)
 *
 * **WARNING**: This client bypasses all SDK compliance controls including
 * PII scanning, policy rule evaluation, HMAC chain signing, and the
 * fire-and-forget event queue. Events sent via `trackCompletion()` and
 * `trackBatch()` have no integrity guarantees and cannot be
 * distinguished from forged events by the ingest server.
 *
 * For production use with compliance requirements, use `obsvr.wrap()`
 * instead, which provides automatic PII detection, policy enforcement,
 * HMAC-signed tamper-evident audit trails, and structured event delivery.
 *
 * Reusable client for tracking LLM completions.
 * Create one instance and reuse it across your application.
 */
export class ObsvrClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly defaultSource: string;
  private readonly debug: boolean;

  constructor(config: ObsvrClientConfig) {
    if (!config.apiKey) {
      throw new Error("ObsvrClient: apiKey is required");
    }

    this.apiKey = config.apiKey;
    const resolvedBaseUrl = (config.baseUrl || DEFAULT_INGEST_URL).replace(/\/$/, "");
    if (!resolvedBaseUrl) {
      throw new Error(
        "ObsvrClient: baseUrl is required - set baseUrl in the constructor options " +
        "(e.g., { apiKey: '...', baseUrl: 'https://ingest.example.com' })",
      );
    }
    this.baseUrl = resolvedBaseUrl;
    this.timeout = config.timeout ?? CLIENT_TIMEOUT_MS;
    this.defaultSource = config.defaultSource ?? "sdk";
    this.debug = config.debug ?? false;
  }

  /**
   * Log debug message if debug mode is enabled
   */
  private log(message: string, data?: unknown): void {
    if (this.debug) {
      console.log(`${LOG_PREFIX} ${message}`, data ?? "");
    }
  }

  /**
   * Build a RawEvent from TrackCompletionParams.
   *
   * H-2: Stamps `compliance_bypass: true` so the ingest server can
   * distinguish manually-sent events from proxy-wrapped events.
   */
  private buildRawEvent(params: TrackCompletionParams): RawEvent {
    return {
      request_id: params.requestId || generateUUID(),
      model: params.model,
      region: params.region,
      prompt: params.prompt,
      response: params.response,
      source: params.source || this.defaultSource,
      metadata: params.metadata,
      compliance_bypass: true,
    };
  }

  /**
   * Make an HTTP request to the ingest API
   */
  private async request<T>(endpoint: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    this.log(`POST ${url}`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [API_KEY_HEADER]: this.apiKey,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      const data = await response.json();

      this.log(`Response ${response.status}:`, data);

      return data as T;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return {
          ok: false,
          error: "timeout",
          message: `Request timed out after ${this.timeout}ms`,
        } as T;
      }

      return {
        ok: false,
        error: "network_error",
        message: error instanceof Error ? error.message : String(error),
      } as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Track a single LLM completion
   *
   * **Note**: This method bypasses PII scanning, policy rules, and HMAC
   * signing. For compliance-grade auditing, use `obsvr.wrap()` instead.
   *
   * @param params - Completion parameters
   * @returns Result with event_id on success, or error details on failure
   *
   * @example
   * ```typescript
   * const result = await client.trackCompletion({
   *   prompt: 'What is 2+2?',
   *   response: '4',
   *   model: 'gpt-4',
   *   region: 'us-east-1'
   * });
   *
   * if (result.ok) {
   *   console.log('Tracked event:', result.eventId);
   * } else {
   *   console.error('Failed:', result.error);
   * }
   * ```
   */
  async trackCompletion(params: TrackCompletionParams): Promise<TrackResult> {
    const rawEvent = this.buildRawEvent(params);

    const response = await this.request<{
      ok: boolean;
      event_id?: string;
      error?: string;
      message?: string;
      details?: unknown;
    }>(INGEST_PATH, rawEvent);

    if (response.ok && response.event_id) {
      return {
        ok: true,
        eventId: response.event_id,
      };
    }

    return {
      ok: false,
      error: response.error || "unknown_error",
      message: response.message,
      details: response.details,
    };
  }

  /**
   * Track multiple LLM completions in a single batch
   *
   * More efficient than multiple individual calls.
   * Maximum 1000 events per batch.
   *
   * @param params - Batch parameters with events array
   * @returns Result with event_ids on success, or error details on failure
   *
   * @example
   * ```typescript
   * const result = await client.trackBatch({
   *   events: [
   *     { prompt: 'Q1', response: 'A1', model: 'gpt-4', region: 'us-east-1' },
   *     { prompt: 'Q2', response: 'A2', model: 'gpt-4', region: 'us-east-1' },
   *   ]
   * });
   *
   * if (result.ok) {
   *   console.log(`Tracked ${result.count} events`);
   * }
   * ```
   */
  async trackBatch(params: TrackBatchParams): Promise<TrackBatchResult> {
    if (params.events.length === 0) {
      return {
        ok: false,
        error: "validation_error",
        message: "events array cannot be empty",
      };
    }

    if (params.events.length > 1000) {
      return {
        ok: false,
        error: "batch_too_large",
        message: "Maximum 1000 events per batch",
      };
    }

    const rawEvents = params.events.map((e) => this.buildRawEvent(e));

    const response = await this.request<{
      ok: boolean;
      count?: number;
      event_ids?: string[];
      error?: string;
      message?: string;
      details?: unknown;
    }>(INGEST_BATCH_PATH, rawEvents);

    if (response.ok && response.event_ids) {
      return {
        ok: true,
        count: response.count || response.event_ids.length,
        eventIds: response.event_ids,
      };
    }

    return {
      ok: false,
      error: response.error || "unknown_error",
      message: response.message,
      details: response.details,
    };
  }
}

/**
 * Convenience function for one-off tracking
 *
 * Creates a temporary client and tracks a single completion.
 * For multiple calls, use ObsvrClient instead.
 *
 * @param params - Completion parameters including apiKey
 * @returns Result with event_id on success
 *
 * @example
 * ```typescript
 * import { trackCompletion } from '@obsvr/sdk';
 *
 * const result = await trackCompletion({
 *   apiKey: 'your-api-key',
 *   prompt: 'Hello!',
 *   response: 'Hi there!',
 *   model: 'gpt-4',
 *   region: 'us-east-1'
 * });
 * ```
 */
export async function trackCompletion(
  params: TrackCompletionParams & {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
  },
): Promise<TrackResult> {
  const { apiKey, baseUrl, timeout, ...trackParams } = params;

  const client = new ObsvrClient({ apiKey, baseUrl, timeout });
  return client.trackCompletion(trackParams);
}

/**
 * Convenience function for one-off batch tracking
 *
 * @param params - Batch parameters including apiKey
 * @returns Result with event_ids on success
 */
export async function trackBatch(
  params: TrackBatchParams & {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
  },
): Promise<TrackBatchResult> {
  const { apiKey, baseUrl, timeout, ...batchParams } = params;

  const client = new ObsvrClient({ apiKey, baseUrl, timeout });
  return client.trackBatch(batchParams);
}

/**
 * @deprecated Use {@link ObsvrClient} instead. Kept as an alias for
 * backward compatibility; will be removed in a future major version.
 */
export const LLMAuditClient = ObsvrClient;
// eslint-disable-next-line @typescript-eslint/no-redeclare
export type LLMAuditClient = ObsvrClient;

// Default export for convenience
export default ObsvrClient;
