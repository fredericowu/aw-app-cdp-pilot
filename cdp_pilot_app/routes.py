"""Backend sub-app mounted at ``/api/apps/cdp-pilot`` behind IdentityGuard:
a status readout and the MCP endpoint auto-discovered by aw-mcp-gateway."""
from __future__ import annotations

from fastapi import Body, FastAPI
from fastapi.responses import JSONResponse, Response

from . import mcp_config
from .mcp import host_agent, remote_host, tools


def build_routes(ctx) -> FastAPI:
    app = FastAPI(title="cdp-pilot")

    @app.get("/status")
    async def status() -> dict:
        config = tools.current_config()
        return {
            "remote_hosts_configured": remote_host.configured(),
            "targets": [t.get("name") for t in config.get("targets") or [] if isinstance(t, dict)],
            "agent_version": host_agent.agent_version(),
            "tool_count": len(tools.TOOLS),
            "mcp_server": mcp_config.SERVER_NAME,
        }

    @app.get("/mcp.json")
    async def mcp_json() -> dict:
        return {"mcpServers": mcp_config.build_mcp_servers()}

    @app.post("/mcp")
    async def mcp_post(data: dict | list = Body(...)):
        from .mcp.http_handler import handle_request

        messages = data if isinstance(data, list) else [data]
        responses = []
        for message in messages:
            reply = await handle_request(message)
            if reply is not None:
                responses.append(reply)
        if not responses:
            return Response(status_code=202)
        return JSONResponse(responses if isinstance(data, list) else responses[0])

    @app.get("/mcp")
    async def mcp_get():
        return Response(status_code=405)

    return app
