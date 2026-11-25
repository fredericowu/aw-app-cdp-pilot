"""The ``aw-cdp-pilot`` MCP server over Streamable HTTP (``POST /mcp``)."""
from __future__ import annotations

import logging

from fastapi.concurrency import run_in_threadpool

from . import remote_host, tools

log = logging.getLogger("aw_apps.cdp-pilot")

SERVER_NAME = "aw-cdp-pilot"
SERVER_VERSION = "1.0.0"


def _result(req_id, text: str, is_error: bool) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": is_error}}


async def handle_request(request: dict) -> dict | None:
    method = request.get("method", "")
    req_id = request.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools.TOOLS}}
    if method != "tools/call":
        return {"jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Unknown method: {method}"}}
    params = request.get("params") or {}
    name = params.get("name", "")
    handler = tools.HANDLERS.get(name)
    if not handler:
        return _result(req_id, f"Unknown tool: {name}", True)
    try:
        # Handlers block on urllib against aw-backend; keep the event loop free.
        text = await run_in_threadpool(handler, params.get("arguments") or {})
    except (remote_host.NotConfigured, tools.Refused) as exc:
        return _result(req_id, str(exc), True)
    except Exception as exc:  # noqa: BLE001 - must not 500 the route
        # Only the exception class is logged: messages can echo host output.
        log.warning("cdp-pilot tool %s failed: %s", name, exc.__class__.__name__)
        return _result(req_id, f"{name} failed: {exc}", True)
    return _result(req_id, text, False)
