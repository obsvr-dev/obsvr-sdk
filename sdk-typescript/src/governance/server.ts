/**
 * Standalone HTTP governance server.
 * Deploy as a service: POST /v2/evaluate returns PERMITTED/BLOCKED decisions.
 */
import { createServer, type IncomingMessage, type ServerResponse, type Server } from 'http';
import { timingSafeEqual } from 'crypto';
import { evaluate } from './evaluate.js';
import { verifyAuditChain } from './verify-chain.js';
import { getQuotaStatus } from './quota.js';
import type { GovernanceServerConfig, EvaluateRequest } from './types.js';
import { init, isInitialized } from '../proxy/config.js';
import type { ObsvrConfig } from '../proxy/types.js';
import { SDK_VERSION } from '../constants.js';

const MAX_BODY_SIZE = 1_048_576; // 1 MB
const startTime = Date.now();

type CorsConfig = boolean | { origins: string[] };

function jsonResponse(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

/** A host is loopback-only (safe to bind without auth). */
function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === '127.0.0.1' || h === '::1' || h === 'localhost' || h.startsWith('127.');
}

let corsWildcardWarned = false;

function setCorsHeaders(req: IncomingMessage, res: ServerResponse, cors: CorsConfig): void {
  if (!cors) return;
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (cors === true) {
    // Legacy wildcard — insecure (any web origin can call the PDP). Warn once.
    if (!corsWildcardWarned) {
      console.warn(
        '[obsvr] governance server CORS is "*" (any origin). Prefer an { origins: [...] } allowlist.',
      );
      corsWildcardWarned = true;
    }
    res.setHeader('Access-Control-Allow-Origin', '*');
    return;
  }
  // Allowlist: echo the request Origin only when it matches.
  const origin = req.headers.origin;
  res.setHeader('Vary', 'Origin');
  if (origin && cors.origins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
}

/**
 * When an authToken is configured, require `Authorization: Bearer <token>`
 * (constant-time compared). Returns true when the request is authorized or no
 * token is configured (loopback-only deployments may run open).
 */
function isAuthorized(req: IncomingMessage, authToken?: string): boolean {
  if (!authToken) return true;
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const presented = Buffer.from(header.slice('Bearer '.length));
  const expected = Buffer.from(authToken);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function parseUrl(url: string | undefined): { pathname: string; params: Record<string, string> } {
  const u = new URL(url ?? '/', 'http://localhost');
  const params: Record<string, string> = {};
  u.searchParams.forEach((v, k) => { params[k] = v; });
  return { pathname: u.pathname, params };
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: { cors: CorsConfig; authToken?: string },
): Promise<void> {
  setCorsHeaders(req, res, opts.cors);

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const { pathname } = parseUrl(req.url);

  // GET /health — unauthenticated liveness probe only.
  if (req.method === 'GET' && pathname === '/health') {
    jsonResponse(res, 200, {
      status: 'ok',
      version: SDK_VERSION,
      uptime: Math.floor((Date.now() - startTime) / 1000),
    });
    return;
  }

  // Auth gate for every governance endpoint: token issuance (/v2/evaluate),
  // quota probing, and chain verification are all sensitive. When an authToken
  // is configured it is required here; a non-loopback bind mandates one (start()).
  if (pathname.startsWith('/v2/') && !isAuthorized(req, opts.authToken)) {
    jsonResponse(res, 401, { error: 'Unauthorized' });
    return;
  }

  // POST /v2/evaluate
  if (req.method === 'POST' && pathname === '/v2/evaluate') {
    try {
      const body = await readBody(req);
      const request: EvaluateRequest = JSON.parse(body);

      if (!request.action_type || !request.payload) {
        jsonResponse(res, 400, {
          error: 'Bad Request',
          message: 'action_type and payload are required',
        });
        return;
      }

      const result = await evaluate(request);
      const status = result.decision === 'BLOCKED' ? 403 : 200;
      jsonResponse(res, status, result);
    } catch (err: any) {
      if (err.message === 'Request body too large') {
        jsonResponse(res, 413, { error: 'Payload Too Large' });
      } else if (err instanceof SyntaxError) {
        jsonResponse(res, 400, { error: 'Invalid JSON' });
      } else {
        jsonResponse(res, 500, { error: 'Internal Server Error' });
      }
    }
    return;
  }

  // GET /v2/quota/:scope/:value
  const quotaMatch = pathname.match(/^\/v2\/quota\/([^/]+)\/([^/]+)$/);
  if (req.method === 'GET' && quotaMatch) {
    const [, scope, value] = quotaMatch;
    const { params } = parseUrl(req.url);
    const limit = parseInt(params.limit ?? '100', 10);
    const windowMs = parseInt(params.window_ms ?? '60000', 10);
    const status = getQuotaStatus(scope, decodeURIComponent(value), limit, windowMs);
    jsonResponse(res, 200, status);
    return;
  }

  // POST /v2/verify-chain
  if (req.method === 'POST' && pathname === '/v2/verify-chain') {
    try {
      const body = await readBody(req);
      const { events, apiKey } = JSON.parse(body);

      if (!Array.isArray(events) || !apiKey) {
        jsonResponse(res, 400, {
          error: 'Bad Request',
          message: 'events (array) and apiKey (string) are required',
        });
        return;
      }

      const result = verifyAuditChain(events, apiKey);
      jsonResponse(res, 200, result);
    } catch (err: any) {
      if (err.message === 'Request body too large') {
        jsonResponse(res, 413, { error: 'Payload Too Large' });
      } else if (err instanceof SyntaxError) {
        jsonResponse(res, 400, { error: 'Invalid JSON' });
      } else {
        jsonResponse(res, 500, { error: 'Internal Server Error' });
      }
    }
    return;
  }

  // 404
  jsonResponse(res, 404, { error: 'Not Found' });
}

/**
 * Create a standalone HTTP governance server.
 */
export function createGovernanceServer(config: GovernanceServerConfig): {
  server: Server;
  start: (port?: number) => Promise<void>;
  stop: () => Promise<void>;
} {
  const port = config.port ?? 3100;
  const cors = config.cors ?? false;
  // Default to loopback: this server issues signed execution tokens and lets
  // callers probe policy, so it must not be reachable off-host by default.
  const host = config.host ?? '127.0.0.1';

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, { cors, authToken: config.authToken }).catch((err) => {
      console.error('Unhandled request error:', err);
      if (!res.headersSent) {
        jsonResponse(res, 500, { error: 'Internal Server Error' });
      }
    });
  });

  return {
    server: httpServer,
    async start(listenPort?: number): Promise<void> {
      // Fail closed: never expose the PDP to the network without authentication.
      if (!isLoopbackHost(host) && !config.authToken) {
        throw new Error(
          `[obsvr] refusing to bind governance server to non-loopback host "${host}" ` +
            'without authToken — set config.authToken (bearer) to expose it, or bind 127.0.0.1.',
        );
      }
      // Initialize the governance config if not already done
      if (!isInitialized()) {
        const obsvrConfig: ObsvrConfig = {
          apiKey: config.apiKey,
          ingestUrl: config.ingestUrl,
          environment: config.environment,
          policyRules: config.policyRules,
          piiPolicy: config.piiPolicy,
          onPreCall: config.onPreCall,
          agentPolicy: config.agentPolicy,
        };
        init(obsvrConfig);
      }

      const p = listenPort ?? port;
      return new Promise((resolve, reject) => {
        httpServer.on('error', reject);
        httpServer.listen(p, host, () => {
          console.log(`Governance server listening on ${host}:${p}`);
          resolve();
        });
      });
    },
    async stop(): Promise<void> {
      return new Promise((resolve) => {
        httpServer.close(() => resolve());
      });
    },
  };
}
