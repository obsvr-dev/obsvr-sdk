/**
 * obsvr SDK Types
 *
 * @packageDocumentation
 */

/**
 * Configuration for the ObsvrClient manual-tracking client
 */
export interface ObsvrClientConfig {
  /**
   * API key for authentication
   * Obtain from your LLM Audit dashboard
   */
  apiKey: string;

  /**
   * Base URL of the ingest service
   * @default DEFAULT_INGEST_URL
   */
  baseUrl?: string;

  /**
   * Request timeout in milliseconds
   * @default 30000
   */
  timeout?: number;

  /**
   * Default source identifier for events
   * @default "sdk"
   */
  defaultSource?: string;

  /**
   * Enable debug logging to console
   * @default false
   */
  debug?: boolean;
}

/**
 * @deprecated Use {@link ObsvrClientConfig} instead. Alias kept for
 * backward compatibility; will be removed in a future major version.
 */
export type LLMAuditClientConfig = ObsvrClientConfig;

/**
 * Parameters for tracking an LLM completion
 */
export interface TrackCompletionParams {
  /**
   * The prompt sent to the LLM
   */
  prompt: string;

  /**
   * The response received from the LLM
   */
  response: string;

  /**
   * The model used (e.g., "gpt-4", "claude-3-opus")
   */
  model: string;

  /**
   * The deployment region (e.g., "us-east-1", "eu-west-1")
   */
  region: string;

  /**
   * Source identifier for this event
   * Overrides the client's defaultSource
   */
  source?: string;

  /**
   * Optional custom request ID
   * If not provided, a UUID will be generated
   */
  requestId?: string;

  /**
   * Optional metadata to attach to the event
   */
  metadata?: Record<string, unknown>;
}

/**
 * Parameters for batch tracking
 */
export interface TrackBatchParams {
  /**
   * Array of completion events to track
   */
  events: TrackCompletionParams[];
}

/**
 * Response from a successful track operation
 */
export interface TrackResponse {
  ok: true;
  eventId: string;
}

/**
 * Response from a successful batch track operation
 */
export interface TrackBatchResponse {
  ok: true;
  count: number;
  eventIds: string[];
}

/**
 * Error response from the API
 */
export interface TrackErrorResponse {
  ok: false;
  error: string;
  message?: string;
  details?: unknown;
}

/**
 * Union type for all possible responses
 */
export type TrackResult = TrackResponse | TrackErrorResponse;
export type TrackBatchResult = TrackBatchResponse | TrackErrorResponse;

/**
 * Raw event structure sent to the ingest API
 * @internal
 */
export interface RawEvent {
  request_id: string;
  model: string;
  region: string;
  prompt: string;
  response: string;
  source: string;
  metadata?: Record<string, unknown>;
  /** H-2: Flags events that bypassed the compliance pipeline (PII scan, policy rules, HMAC signing) */
  compliance_bypass?: boolean;
}
