/**
 * In-process ingest capture server, with optional pass-through to your REAL
 * ingest.
 *
 * Captures every signed event the SDK POSTs so tests can assert on the wire
 * payload. If OBSVR_INGEST_URL is set (e.g. http://localhost:8787), each event
 * is ALSO forwarded there — byte-identical body + headers — so your real
 * pipeline (auth, Firestore, evidence) receives the exact same signed events
 * while the test still verifies them locally.
 *
 * Mirrors the production endpoints:
 *   POST /ingest        -> single event  (body = event object)
 *   POST /ingest/batch  -> batch         (body = array of events)
 *   GET  /policies      -> policy set the SDK's polling loop consumes
 *
 * The /policies handler is CONFIGURABLE (default: a valid empty rule set
 * `{ rules: [] }`). Suites that drive fleet-quota escrow or degraded-mode
 * (kill switch / stale sync) pass a `policies` handler or call setPolicies():
 *   - object  -> served as 200 JSON (e.g. { rules: [...], quota_escrow: {...} })
 *   - function(req) -> returns a body object (200) OR { status, body } to serve
 *                      an error status (e.g. 403 kill switch, 500 stale sync).
 * The poll shape the SDK requires is `{ rules: [...] }` (proxy/config.ts
 * pollPoliciesOnce); anything without a `rules` array is a poll failure.
 */
import "./loadenv.mjs";
import { createServer } from "node:http";

const FORWARD_TO = process.env.OBSVR_INGEST_URL?.replace(/\/$/, "");

// Tee coupling mode. "isolate" (default): ACK the SDK immediately (202) and
// forward to the real ingest fire-and-forget — the real backend's status and
// latency can NEVER perturb capture semantics or timing-sensitive suites.
// "relay": pass the real backend's status/latency through to the SDK, so it
// experiences authentic backpressure (retries, backoff) — deliberate
// pipeline-behavior testing only.
const TEE_MODE = (process.env.OBSVR_INGEST_TEE_MODE || "isolate").toLowerCase();

// Forward the raw body + headers to the real ingest, unchanged, so the HMAC
// signature stays valid. Returns the real backend's [status, bodyText].
async function forward(path, headers, rawBody) {
  const fwdHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    const lk = k.toLowerCase();
    if (["host", "content-length", "connection", "accept-encoding"].includes(lk)) continue;
    fwdHeaders[k] = v;
  }
  const res = await fetch(`${FORWARD_TO}${path}`, { method: "POST", headers: fwdHeaders, body: rawBody });
  const text = await res.text().catch(() => "");
  return [res.status, text];
}

/**
 * @param {object} [opts]
 * @param {object|function} [opts.policies] initial /policies handler (see file header)
 * @param {number} [opts.slowMs] delay (ms) before ACKing each POST — used by the
 *        sender-semantics suite to keep the queue full so overflow drops happen.
 */
export async function startMockIngest(opts = {}) {
  const events = [];
  /** POSTs to /approvals/request — the human-in-the-loop request channel. */
  const approvalRequests = [];
  let policies = opts.policies ?? { rules: [] };
  let slowMs = opts.slowMs ?? 0;
  let policiesRequests = 0;
  let ingestRequests = 0;

  function resolvePolicies(req) {
    const p = typeof policies === "function" ? policies(req) : policies;
    if (p && typeof p === "object" && ("status" in p || "body" in p) && !("rules" in p)) {
      return { status: p.status ?? 200, body: p.body ?? {} };
    }
    return { status: 200, body: p ?? {} };
  }

  const server = createServer((req, res) => {
    if (req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        // Human-in-the-loop approval REQUESTS are not audit events and must not
        // land in `events`: they carry no signature, and mixing them in breaks
        // every chain verification that walks the capture.
        if (req.url?.startsWith("/approvals/request")) {
          try {
            approvalRequests.push(JSON.parse(body));
          } catch {
            /* ignore malformed */
          }
          res.writeHead(202, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
          return;
        }
        ingestRequests += 1;
        try {
          const parsed = JSON.parse(body);
          if (Array.isArray(parsed)) events.push(...parsed);
          else if (Array.isArray(parsed?.events)) events.push(...parsed.events);
          else events.push(parsed);
        } catch {
          /* ignore malformed */
        }

        const ack = async () => {
          // Pass-through to the real ingest when configured.
          if (FORWARD_TO && TEE_MODE === "relay") {
            // relay: SDK sees the real backend's status + latency (authentic
            // backpressure — 5xx will trigger SDK retries and duplicate
            // captures; use only when that is the thing under test).
            try {
              const [status, text] = await forward(req.url, req.headers, body);
              if (status >= 300) {
                console.log(`   \x1b[33m[tee] real ingest ${FORWARD_TO} returned ${status}: ${String(text).slice(0, 160)}\x1b[0m`);
              }
              res.writeHead(status, { "Content-Type": "application/json" });
              res.end(text || JSON.stringify({ ok: status < 300 }));
              return;
            } catch (e) {
              console.log(`   \x1b[33m[tee] forward to ${FORWARD_TO} failed: ${e.message}\x1b[0m`);
            }
          } else if (FORWARD_TO) {
            // isolate (default): fire-and-forget tee. Failures are logged and
            // visible, never able to poison capture or suite timing.
            forward(req.url, req.headers, body)
              .then(([status, text]) => {
                if (status >= 300) {
                  console.log(`   \x1b[33m[tee] real ingest ${FORWARD_TO} returned ${status}: ${String(text).slice(0, 160)}\x1b[0m`);
                }
              })
              .catch((e) => {
                console.log(`   \x1b[33m[tee] forward to ${FORWARD_TO} failed: ${e.message}\x1b[0m`);
              });
          }
          res.writeHead(202, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true, event_id: "mock" }));
        };

        if (slowMs > 0) {
          const t = setTimeout(ack, slowMs);
          if (typeof t === "object" && t.unref) t.unref();
        } else {
          await ack();
        }
      });
      return;
    }
    if (req.method === "GET" && req.url?.startsWith("/policies")) {
      policiesRequests += 1;
      const { status, body } = resolvePolicies(req);
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  const port = await new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
    server.once("error", reject);
  });

  console.log(
    FORWARD_TO
      ? `   \x1b[36m→ MODE: forwarding signed events to your real ingest ${FORWARD_TO} (tee: ${TEE_MODE})\x1b[0m`
      : `   \x1b[2m→ MODE: local mock only (set OBSVR_INGEST_URL to forward to your real ingest)\x1b[0m`,
  );

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    getEvents: () => [...events],
    /** Approval requests the SDK filed, in arrival order. */
    approvalRequests: () => [...approvalRequests],
    /** Events of a given event_type, in arrival order. */
    ofType: (t) => events.filter((e) => e.event_type === t),
    /** Events matching a given `operation`, in arrival order. */
    ofOperation: (op) => events.filter((e) => e.operation === op),
    /** The single most recent event (throws if none). */
    last: () => {
      if (events.length === 0) throw new Error("no events captured");
      return events[events.length - 1];
    },
    /** Number of POSTs (single or batch requests) received. */
    ingestRequestCount: () => ingestRequests,
    /** Number of GET /policies polls received. */
    policiesPollCount: () => policiesRequests,
    /** Swap the /policies handler at runtime (e.g. epoch bump, flip kill switch). */
    setPolicies: (next) => {
      policies = next;
    },
    /** Set/clear the per-POST ACK delay at runtime. */
    setSlow: (ms) => {
      slowMs = ms;
    },
    /** Resolve once at least `min` /policies polls have been observed. */
    waitForPoll: (min = 1, timeoutMs = 3000) =>
      new Promise((resolve) => {
        const start = Date.now();
        const tick = () => {
          if (policiesRequests >= min || Date.now() - start > timeoutMs) return resolve(policiesRequests);
          const t = setTimeout(tick, 15);
          if (typeof t === "object" && t.unref) t.unref();
        };
        tick();
      }),
    reset: () => {
      events.length = 0;
    },
    stop: () =>
      new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}
