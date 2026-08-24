import * as http from 'node:http';
import * as https from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import type { AllowedBackendTarget } from './ssrf.js';

export interface PinnedHttpResponse {
  readonly status: number;
  readonly body: Uint8Array | undefined;
}

export function pinnedRequestOptions(
  target: AllowedBackendTarget,
  headers: Readonly<Record<string, string>>,
  bodyLength: number,
  signal: AbortSignal,
): https.RequestOptions {
  const hostname = target.url.hostname.replace(/^\[|\]$/g, '');
  const requestHeaders = Object.fromEntries(
    Object.entries(headers).filter(([key]) => !['host', 'connection', 'content-length']
      .includes(key.toLowerCase())),
  );
  Object.assign(requestHeaders, {
    host: target.url.host,
    connection: 'close',
    'content-length': String(bodyLength),
  });
  return {
    method: 'POST', headers: requestHeaders,
    lookup: createPinnedLookup(target), agent: false, signal,
    ...(target.url.protocol === 'https:' && isIP(hostname) === 0
      ? { servername: hostname }
      : {}),
  };
}

/** A lookup function backed exclusively by one immutable approved snapshot. */
export function createPinnedLookup(target: AllowedBackendTarget): LookupFunction {
  return (_hostname, options, callback): void => {
    const requestedFamily = options.family === 4 || options.family === 6 ? options.family : 0;
    const candidates = requestedFamily === 0
      ? target.addresses
      : target.addresses.filter((entry) => entry.family === requestedFamily);
    if (candidates.length === 0) {
      const error = Object.assign(new Error('No approved address for requested family'), {
        code: 'EAI_ADDRFAMILY',
      }) as NodeJS.ErrnoException;
      callback(error, '', requestedFamily || undefined);
      return;
    }
    if (options.all) {
      callback(null, candidates.map(({ address, family }) => ({ address, family })));
      return;
    }
    callback(null, candidates[0].address, candidates[0].family);
  };
}

/**
 * Send one bounded POST through a fresh socket pinned to the approved address
 * snapshot. Host routing and TLS verification remain bound to the original
 * hostname; DNS is never consulted by this transport.
 */
export async function postPinnedBytes(
  target: AllowedBackendTarget,
  body: string | Uint8Array,
  headers: Readonly<Record<string, string>>,
  signal: AbortSignal,
  maxResponseBytes: number,
): Promise<PinnedHttpResponse> {
  const transport = target.url.protocol === 'https:' ? https : http;
  const bodyBytes = typeof body === 'string' ? Buffer.from(body) : Buffer.from(body);
  const requestOptions = pinnedRequestOptions(
    target, headers, bodyBytes.byteLength, signal,
  );

  return new Promise<PinnedHttpResponse>((resolve, reject) => {
    let settled = false;
    const finish = (value: PinnedHttpResponse): void => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const fail = (error: Error): void => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    const req = transport.request(
      target.url,
      requestOptions,
      (response) => {
        const status = response.statusCode ?? 0;
        const declared = response.headers['content-length'];
        if (declared !== undefined
          && (!/^[0-9]+$/.test(declared) || Number(declared) > maxResponseBytes)) {
          response.destroy();
          finish({ status, body: undefined });
          return;
        }
        const chunks: Buffer[] = [];
        let total = 0;
        response.on('data', (chunk: Buffer | string) => {
          if (settled) return;
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          total += bytes.byteLength;
          if (total > maxResponseBytes) {
            response.destroy();
            finish({ status, body: undefined });
            return;
          }
          chunks.push(bytes);
        });
        response.on('error', fail);
        response.on('end', () => finish({ status, body: Buffer.concat(chunks) }));
      },
    );
    req.on('error', fail);
    req.end(bodyBytes);
  });
}
