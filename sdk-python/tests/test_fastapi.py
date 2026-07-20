"""WS2C — FastAPI/ASGI middleware emits a signed obsvr execution span per HTTP
request, attributed with method/path/status. Pure-ASGI: driven directly with a
mock app, no Starlette/FastAPI needed."""

import asyncio
import json

import obsvr
from obsvr.integrations.fastapi import ObsvrASGIMiddleware


def _drive(mw, scope):
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    sent_messages = []

    async def send(msg):
        sent_messages.append(msg)

    asyncio.run(mw(scope, receive, send))
    return sent_messages


def test_http_request_emits_signed_span(sent):
    obsvr.init(api_key="test", auto=False)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 201, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = ObsvrASGIMiddleware(app)
    out = _drive(mw, {"type": "http", "method": "GET", "path": "/hello"})

    # The app's response passed through unchanged.
    assert any(m["type"] == "http.response.start" and m["status"] == 201 for m in out)

    # A span event was emitted for the request with the http attributes.
    spans = [e for e in sent if e.get("operation") == "http.request"]
    assert len(spans) == 1
    blob = json.dumps(spans[0])
    assert '"http.method": "GET"' in blob
    assert '"http.target": "/hello"' in blob
    assert '"http.status_code": 201' in blob


def test_non_http_scope_passes_through(sent):
    obsvr.init(api_key="test", auto=False)
    seen = {"called": False}

    async def app(scope, receive, send):
        seen["called"] = True

    mw = ObsvrASGIMiddleware(app)
    _drive(mw, {"type": "lifespan"})
    assert seen["called"] is True
    # No HTTP span for a non-http scope.
    assert not [e for e in sent if e.get("operation") == "http.request"]


def test_failed_request_records_span(sent):
    obsvr.init(api_key="test", auto=False)

    async def app(scope, receive, send):
        raise RuntimeError("boom")

    mw = ObsvrASGIMiddleware(app)
    try:
        _drive(mw, {"type": "http", "method": "POST", "path": "/x"})
    except RuntimeError:
        pass
    spans = [e for e in sent if e.get("operation") == "http.request"]
    assert len(spans) == 1
    assert spans[0].get("success") is False
