import { createHash } from 'node:crypto';
import { init, _reset } from '../../src/proxy/config';
import { _resetSender } from '../../src/proxy/sender/fire-and-forget';
import { ObsvrCallbackHandler } from '../../src/integrations/langchain';
import { SPAN_ATTR } from '../../src/proxy/span-attributes';

/**
 * Retriever callbacks -> SIGNED execution spans (gap-analysis "retrieval
 * auto-spans"). The handler must emit through the M3B span pipeline
 * (event_class execution_span, span envelope in metadata, trace_id linkage
 * to the enclosing agent run) with hash+count only, never retrieval text.
 * Twin: sdk-python/tests/test_langchain_retrieval_spans.py.
 */

let sentEvents: any[] = [];

beforeEach(() => {
  _reset();
  _resetSender();
  sentEvents = [];
  (global as any).fetch = async (_url: any, opts: any) => {
    const body = JSON.parse(opts.body);
    sentEvents.push(...(Array.isArray(body) ? body : [body]));
    return { ok: true, status: 200, json: async () => ({ count: 1 }) };
  };
});

async function waitForEvents(n = 1): Promise<void> {
  for (let i = 0; i < 100 && sentEvents.length < n; i++) {
    await new Promise((r) => setTimeout(r, 5));
  }
}

const RETRIEVER = { id: ['langchain', 'retrievers', 'VectorStoreRetriever'] };

describe('LangChain retriever auto-spans', () => {
  it('start -> end emits a signed retrieval execution span with hash + count', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();
    expect(handler.ignoreRetriever).toBe(false);

    await handler.handleRetrieverStart(RETRIEVER, 'what is our PHI policy?', 'ret-1');
    await handler.handleRetrieverEnd([{ pageContent: 'a' }, { pageContent: 'b' }], 'ret-1');

    await waitForEvents(1);
    const span = sentEvents.find((e) => e.event_class === 'execution_span');
    expect(span).toBeDefined();
    expect(span.operation).toBe('VectorStoreRetriever');
    const envelope = span.metadata.obsvr_span;
    expect(envelope.span_kind).toBe('retrieval');
    expect(envelope.attributes[SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT]).toBe(2);
    expect(envelope.attributes[SPAN_ATTR.RETRIEVAL_SOURCE]).toBe('VectorStoreRetriever');
    // Query travels as a hash, never as text.
    const expectedHash = createHash('sha256')
      .update('what is our PHI policy?', 'utf8')
      .digest('hex');
    expect(envelope.attributes[SPAN_ATTR.RETRIEVAL_QUERY_HASH]).toBe(expectedHash);
    expect(JSON.stringify(span)).not.toContain('what is our PHI policy?');
    // Signed like any event.
    expect(typeof span.sdk_sig).toBe('string');
    expect(span.sdk_sig.length).toBe(64);
  });

  it('links the span to the enclosing agent run via metadata.trace_id', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();

    await handler.handleChainStart(
      { id: ['langchain', 'agents', 'AgentExecutor'] },
      { input: 'q' },
      'chain-1',
    );
    await waitForEvents(1); // agent.run.start event
    const startEvent = sentEvents.find((e) => e.operation === 'langchain.agent.run.start');
    const agentRunId = startEvent.metadata.agent_run_id;
    expect(agentRunId).toBeTruthy();

    await handler.handleRetrieverStart(RETRIEVER, 'q2', 'ret-2', 'chain-1');
    await handler.handleRetrieverEnd([], 'ret-2');
    await waitForEvents(2);

    const span = sentEvents.find((e) => e.event_class === 'execution_span');
    expect(span.metadata.trace_id).toBe(agentRunId);
    expect(span.metadata.obsvr_span.attributes[SPAN_ATTR.RETRIEVAL_DOCUMENT_COUNT]).toBe(0);
  });

  it('error path emits ok=false and cleans up state', async () => {
    init({ api_key: 'test', sample_rate: 1 });
    const handler = new ObsvrCallbackHandler();

    await handler.handleRetrieverStart(RETRIEVER, 'q3', 'ret-3');
    await handler.handleRetrieverError(new Error('index down'), 'ret-3');
    await waitForEvents(1);

    const span = sentEvents.find((e) => e.event_class === 'execution_span');
    expect(span.success).toBe(false);
    expect(span.status_code).toBe(500);

    // A second end for the same runId must be a no-op (state consumed).
    const before = sentEvents.length;
    await handler.handleRetrieverEnd([], 'ret-3');
    await new Promise((r) => setTimeout(r, 30));
    expect(sentEvents.length).toBe(before);
  });

  it('is a safe no-op when the SDK is not initialized', async () => {
    const handler = new ObsvrCallbackHandler();
    await handler.handleRetrieverStart(RETRIEVER, 'q', 'ret-4');
    await handler.handleRetrieverEnd([], 'ret-4');
    await new Promise((r) => setTimeout(r, 30));
    expect(sentEvents.length).toBe(0);
  });
});
