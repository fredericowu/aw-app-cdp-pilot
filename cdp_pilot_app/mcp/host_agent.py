"""Bridge between an MCP tool call and ``aw_cdp_pilot.py`` on the host.

One tool call is one exec of the single-file host agent. The agent is
*uploaded*, not installed: :func:`ensure_agent` re-uploads whenever the host's
copy reports a different ``agent_version``, so updating the app updates the host.

Arguments travel base64-encoded (no shell metacharacters), and the reply is
fenced by a marker so unrelated stdout noise cannot break JSON parsing.
"""
from __future__ import annotations

import base64
import json
import re
import shlex
from pathlib import Path

from . import remote_host

MARKER = "<<<AW_CDP_PILOT_JSON>>>"
AGENT_FILENAME = "aw_cdp_pilot.py"
REMOTE_DIR = ".aw-cdp-pilot/agent"
PYTHON = "/usr/bin/python3"

_ENSURED: dict[str, str] = {}
_HOME: dict[str, str] = {}


class HostError(RuntimeError):
    """The host agent reported a refusal or failure."""


def local_agent_path() -> Path:
    return Path(__file__).resolve().parent.parent / "host_agent" / AGENT_FILENAME


def agent_version() -> str:
    text = local_agent_path().read_text(encoding="utf-8")
    match = re.search(r'^VERSION\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else "0"


def _home(host_id: str) -> str:
    if host_id not in _HOME:
        out, err, code = remote_host.exec(host_id, 'printf %s "$HOME"', timeout=30)
        home = out.strip()
        if code != 0 or not home.startswith("/"):
            raise RuntimeError(f"could not resolve $HOME on the host (exit {code})")
        _HOME[host_id] = home
    return _HOME[host_id]


def remote_agent_path(host_id: str) -> str:
    return f"{_home(host_id)}/{REMOTE_DIR}/{AGENT_FILENAME}"


def _parse(stdout: str, stderr: str, code: int, verb: str) -> dict:
    index = stdout.rfind(MARKER)
    if index == -1:
        raise HostError(f"{verb}: the host agent produced no result (exit {code}); "
                        "is /usr/bin/python3 present on the host?")
    payload = json.loads(stdout[index + len(MARKER):].strip())
    if not payload.get("ok"):
        raise HostError(f"{verb}: {payload.get('error') or 'failed on the host'}")
    return payload.get("result") or {}


def call(host_id: str, verb: str, args: dict | None = None, *, timeout: int = 90,
         ensure: bool = True) -> dict:
    if ensure:
        ensure_agent(host_id)
    encoded = base64.b64encode(json.dumps(args or {}).encode("utf-8")).decode()
    command = (f"{PYTHON} {shlex.quote(remote_agent_path(host_id))} "
               f"{shlex.quote(verb)} --args-b64 {encoded}")
    stdout, stderr, code = remote_host.exec(host_id, command, timeout=timeout)
    return _parse(stdout, stderr, code, verb)


def ensure_agent(host_id: str, force: bool = False) -> dict:
    version = agent_version()
    if not force and _ENSURED.get(host_id) == version:
        return {"agent_version": version, "uploaded": False}
    status = None
    if not force:
        try:
            status = call(host_id, "status", timeout=45, ensure=False)
        except Exception:  # noqa: BLE001 - an absent/stale agent is the norm here
            status = None
    if status and status.get("agent_version") == version:
        _ENSURED[host_id] = version
        return {"agent_version": version, "uploaded": False}
    remote_host.upload(host_id, str(local_agent_path()), remote_agent_path(host_id))
    status = call(host_id, "status", timeout=45, ensure=False)
    if status.get("agent_version") != version:
        raise RuntimeError("uploaded the host agent but the host reports a different version")
    _ENSURED[host_id] = version
    return {"agent_version": version, "uploaded": True}
