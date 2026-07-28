import { createGovernanceServer } from '../../src/governance/server';
import { _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { _resetAllQuotas } from '../../src/governance/quota';
import http from 'http';
import type { AddressInfo } from 'net';

function request(
  port: number,
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
): Promise<{ status: number; body: any; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          ...(payload
            ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
            : {}),
          ...(extraHeaders ?? {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          try {
            resolve({ status: res.statusCode!, body: JSON.parse(text), headers: res.headers });
          } catch {
            resolve({ status: res.statusCode!, body: text, headers: res.headers });
          }
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

let serverHandle: ReturnType<typeof createGovernanceServer>;
let port: number;

beforeAll(async () => {
  _reset();
  _resetSender();
  _resetAllQuotas();
  serverHandle = createGovernanceServer({
    apiKey: 'test-server-key',
    port: 0, // let OS assign port
    cors: true,
    policyRules: [
      {
        id: 'r1', name: 'block-secret', enabled: true, action: 'block',
        type: 'keyword', conditions: { keywords: ['secret'] },
      },
    ],
    environment: 'development',
    ingestUrl: 'https://localhost:19999/ingest',
  });
  await serverHandle.start(0);
  port = (serverHandle.server.address() as AddressInfo).port;
});

afterAll(async () => {
  await serverHandle.stop();
  _reset();
  _resetSender();
});

describe('Governance HTTP Server', () => {
  it('GET /health returns ok', async () => {
    const res = await request(port, 'GET', '/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.version).toBeTruthy();
    expect(typeof res.body.uptime).toBe('number');
  });

  it('POST /v2/evaluate returns PERMITTED for clean payload', async () => {
    const res = await request(port, 'POST', '/v2/evaluate', {
      action_type: 'chat',
      payload: { message: 'hello world' },
    });
    expect(res.status).toBe(200);
    expect(res.body.decision).toBe('PERMITTED');
    expect(res.body.reason_code).toBe('PERMITTED');
    expect(res.body.execution_token).toBeTruthy();
  });

  it('POST /v2/evaluate returns BLOCKED for policy violation', async () => {
    const res = await request(port, 'POST', '/v2/evaluate', {
      action_type: 'chat',
      payload: { message: 'this is secret data' },
    });
    expect(res.status).toBe(403);
    expect(res.body.decision).toBe('BLOCKED');
    expect(res.body.reason_code).toBe('KEYWORD_BLOCKED');
    expect(res.body.rule_id).toBe('r1');
  });

  it('POST /v2/evaluate returns 400 for missing fields', async () => {
    const res = await request(port, 'POST', '/v2/evaluate', {
      payload: { message: 'hi' },
    });
    expect(res.status).toBe(400);
  });

  it('POST /v2/evaluate returns 400 for invalid JSON', async () => {
    const res = await new Promise<{ status: number; body: any }>((resolve, reject) => {
      const req = http.request(
        {
          hostname: '127.0.0.1', port, path: '/v2/evaluate', method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': '5' },
        },
        (r) => {
          const chunks: Buffer[] = [];
          r.on('data', (c: Buffer) => chunks.push(c));
          r.on('end', () => {
            resolve({ status: r.statusCode!, body: JSON.parse(Buffer.concat(chunks).toString()) });
          });
        },
      );
      req.on('error', reject);
      req.write('{bad}');
      req.end();
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Invalid JSON');
  });

  it('GET /v2/quota/:scope/:value returns status', async () => {
    const res = await request(port, 'GET', '/v2/quota/user_id/testuser?limit=100&window_ms=60000');
    expect(res.status).toBe(200);
    expect(typeof res.body.used).toBe('number');
    expect(typeof res.body.remaining).toBe('number');
  });

  it('returns 404 for unknown routes', async () => {
    const res = await request(port, 'GET', '/nonexistent');
    expect(res.status).toBe(404);
  });

  it('handles CORS preflight', async () => {
    const res = await request(port, 'OPTIONS', '/v2/evaluate');
    expect(res.status).toBe(204);
    expect(res.headers['access-control-allow-origin']).toBe('*');
  });
});

describe('Governance server hardening', () => {
  it('refuses to bind a non-loopback host without authToken', async () => {
    const h = createGovernanceServer({ apiKey: 'k', host: '0.0.0.0', port: 0 });
    await expect(h.start(0)).rejects.toThrow(/refusing to bind/i);
  });

  it('requires a bearer token on /v2/* when authToken is set; /health stays open', async () => {
    const h = createGovernanceServer({ apiKey: 'k', port: 0, authToken: 'sekret-token' });
    await h.start(0);
    const p = (h.server.address() as AddressInfo).port;
    try {
      // /health is an unauthenticated liveness probe.
      expect((await request(p, 'GET', '/health')).status).toBe(200);
      // No / wrong bearer on a /v2 endpoint → 401.
      const body = { action_type: 'chat', payload: { message: 'hi' } };
      expect((await request(p, 'POST', '/v2/evaluate', body)).status).toBe(401);
      expect(
        (await request(p, 'POST', '/v2/evaluate', body, { Authorization: 'Bearer wrong' })).status,
      ).toBe(401);
      // Correct bearer → processed.
      const ok = await request(p, 'POST', '/v2/evaluate', body, {
        Authorization: 'Bearer sekret-token',
      });
      expect(ok.status).toBe(200);
      expect(ok.body.decision).toBe('PERMITTED');
    } finally {
      await h.stop();
    }
  });

  it('CORS allowlist echoes only matching origins, never *', async () => {
    const h = createGovernanceServer({
      apiKey: 'k',
      port: 0,
      cors: { origins: ['https://ok.example'] },
    });
    await h.start(0);
    const p = (h.server.address() as AddressInfo).port;
    try {
      const good = await request(p, 'OPTIONS', '/v2/evaluate', undefined, {
        Origin: 'https://ok.example',
      });
      expect(good.headers['access-control-allow-origin']).toBe('https://ok.example');
      const bad = await request(p, 'OPTIONS', '/v2/evaluate', undefined, {
        Origin: 'https://evil.example',
      });
      expect(bad.headers['access-control-allow-origin']).toBeUndefined();
    } finally {
      await h.stop();
    }
  });
});
