"""Entrypoint referenced by aw-app.json's ``runtime.entrypoint``
("cdp_pilot_app.plugin:CdpPilotPlugin"). Tier-1: every tool is an exec on a
linked host, served in-process; nothing to spawn."""
from __future__ import annotations

import logging
import os

from . import mcp_config, routes as routes_mod
from .mcp import host_agent, remote_host, tools

log = logging.getLogger("aw_apps.cdp-pilot")


class CdpPilotPlugin:
    async def activate(self, ctx) -> None:
        self.ctx = ctx

        def _resolve_config() -> dict:
            # Tier-1 activation hands the plugin the raw stored config with no
            # schema-default merge, so defaults are re-declared in tools.py.
            config = getattr(ctx, "config", {}) or {}
            return {
                "targets": config.get("targets") or [],
                "session_ttl_s": config.get("session_ttl_s") or tools.DEFAULT_TTL_S,
                "screenshot_dir": config.get("screenshot_dir") or tools.DEFAULT_SCREENSHOT_DIR,
            }

        tools.set_config_resolver(_resolve_config)
        ctx.routes.register(routes_mod.build_routes(ctx))
        port = int(os.environ.get("AW_PORT") or 9030)
        doc = mcp_config.write_mcp_json(ctx.package_dir, port)
        log.info("aw-app-cdp-pilot activated: server=%s tools=%d agent=%s remote-hosts=%s "
                 "targets=%d", sorted(doc["mcpServers"]), len(tools.TOOLS),
                 host_agent.agent_version(),
                 "configured" if remote_host.configured() else "NOT SET",
                 len(_resolve_config()["targets"]))

    async def deactivate(self) -> None:
        log.info("aw-app-cdp-pilot deactivated")
