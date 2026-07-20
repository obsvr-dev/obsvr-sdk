"""Retriever callbacks -> SIGNED execution spans (Python twin of
sdk/tests/unit/langchain-retrieval-spans.test.ts). The handler must emit
through the M3B span pipeline with query hash + document count only, linked
to the enclosing agent run's trace when resolvable."""

import hashlib

import obsvr
from obsvr.integrations.langchain import ObsvrCallbackHandler
from obsvr.span_attributes import SPAN_ATTR

RETRIEVER = {"id": ["langchain", "retrievers", "VectorStoreRetriever"]}


def _spans(sent):
    return [
        e for e in sent
        if e.get("metadata", {}).get("obsvr_span", {}).get("event_class") == "execution_span"
    ]


def test_retriever_end_emits_retrieval_span_with_hash_and_count(sent):
    obsvr.init(api_key="test")
    h = ObsvrCallbackHandler()
    h.on_retriever_start(RETRIEVER, "what is our PHI policy?", run_id="ret-1")
    h.on_retriever_end([{"page_content": "a"}, {"page_content": "b"}], run_id="ret-1")

    spans = _spans(sent)
    assert len(spans) == 1
    env = spans[0]["metadata"]["obsvr_span"]
    assert env["span_kind"] == "retrieval"
    assert env["attributes"][SPAN_ATTR["RETRIEVAL_DOCUMENT_COUNT"]] == 2
    assert env["attributes"][SPAN_ATTR["RETRIEVAL_SOURCE"]] == "VectorStoreRetriever"
    expected = hashlib.sha256(b"what is our PHI policy?").hexdigest()
    assert env["attributes"][SPAN_ATTR["RETRIEVAL_QUERY_HASH"]] == expected
    # Query text never leaves as content.
    assert "what is our PHI policy?" not in str(spans[0])


def test_retriever_span_links_to_enclosing_agent_run(sent):
    obsvr.init(api_key="test")
    h = ObsvrCallbackHandler()
    h.on_chain_start({"id": ["langchain", "agents", "AgentExecutor"]}, {"input": "q"},
                     run_id="chain-1")
    start = next(e for e in sent if e.get("operation") == "langchain.agent.run.start")
    agent_run_id = start["metadata"]["agent_run_id"]

    h.on_retriever_start(RETRIEVER, "q2", run_id="ret-2", parent_run_id="chain-1")
    h.on_retriever_end([], run_id="ret-2")

    span = _spans(sent)[0]
    assert span["metadata"]["trace_id"] == agent_run_id
    assert span["metadata"]["obsvr_span"]["attributes"][SPAN_ATTR["RETRIEVAL_DOCUMENT_COUNT"]] == 0


def test_retriever_error_emits_failed_span_and_consumes_state(sent):
    obsvr.init(api_key="test")
    h = ObsvrCallbackHandler()
    h.on_retriever_start(RETRIEVER, "q3", run_id="ret-3")
    h.on_retriever_error(RuntimeError("index down"), run_id="ret-3")

    spans = _spans(sent)
    assert len(spans) == 1
    assert spans[0]["success"] is False

    before = len(sent)
    h.on_retriever_end([], run_id="ret-3")  # state consumed -> no-op
    assert len(sent) == before


def test_retriever_callbacks_are_noop_when_uninitialized(sent):
    h = ObsvrCallbackHandler()
    h.on_retriever_start(RETRIEVER, "q", run_id="ret-4")
    h.on_retriever_end([], run_id="ret-4")
    assert sent == []
