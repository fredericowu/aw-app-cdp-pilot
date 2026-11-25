"""Builds this app's root ``mcp.json`` (gitignored, written 0600: it embeds the
workspace API key). ``contributes.mcp.provides`` alone registers nothing."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .mcp import self_register

SERVER_NAME = self_register.MCP_SERVER_NAME


def build_mcp_servers(port: int | None = None) -> dict:
    return {SERVER_NAME: self_register.build_self_entry(port)}


def write_mcp_json(package_dir: str, port: int | None = None) -> dict:
    """Regenerate ``<package_dir>/mcp.json``, skipping an unchanged write
    (the gateway reloads on mtime; an unconditional rewrite is a reload loop)."""
    doc = {"mcpServers": build_mcp_servers(port or int(os.environ.get("AW_PORT") or 9030))}
    body = json.dumps(doc, indent=2) + "\n"
    path = Path(package_dir) / "mcp.json"
    try:
        if path.read_text(encoding="utf-8") == body:
            return doc
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, 0o600)
    return doc
