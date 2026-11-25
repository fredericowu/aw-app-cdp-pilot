"""Entry describing this app's own ``/mcp`` endpoint for aw-mcp-gateway's
app-scan (reads ``<app dir>/mcp.json``). Same shape as aw-app-windows-pilot.
"""
from __future__ import annotations

import os
import socket

MCP_SERVER_NAME = "aw-cdp-pilot"
ROUTE_PATH = "/api/apps/cdp-pilot/mcp"


def build_self_entry(port: int | None = None) -> dict:
    host = socket.gethostname()
    port = port or int(os.environ.get("AW_PORT") or 9030)
    entry: dict = {"type": "http", "url": f"http://{host}:{port}{ROUTE_PATH}", "enabled": True}
    api_key = os.environ.get("AW_WORKSPACE_API_KEY")
    if api_key:
        entry["headers"] = {"X-Api-Key": api_key}
    return entry
