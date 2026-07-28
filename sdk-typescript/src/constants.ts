/**
 * SDK Constants
 *
 * All internal magic strings and numbers live here.
 * Import from this file rather than hard-coding values.
 *
 * @packageDocumentation
 */

/** Reported on the /policies poll (fleet status). Bump with package.json. */
export const SDK_VERSION         = '0.10.0';

export const DEFAULT_INGEST_URL  = '';
export const INGEST_PATH         = '/ingest';
export const INGEST_BATCH_PATH   = '/ingest/batch';
export const API_KEY_HEADER      = 'X-API-Key';
export const CLIENT_TIMEOUT_MS   = 30_000;
export const PROXY_TIMEOUT_MS    =  5_000;
export const MAX_QUEUE_SIZE      = 1_000;
export const SEND_BATCH_SIZE     = 25;
/** Serialized-bytes budget per batch request: ingest's body limit is 1MB,
 * so cap well under it and split rather than fail whole batches. */
export const MAX_BATCH_BYTES     = 750_000;
export const MAX_SEND_RETRIES    = 2;
export const INITIAL_BACKOFF_MS  = 1_000;
export const MAX_BACKOFF_MS      = 60_000;
export const LOG_PREFIX          = '[obsvr]';
export const TRUNCATION_MARKER   = ' [TRUNCATED]';
