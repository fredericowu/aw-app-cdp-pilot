"""aw-remote-hosts transport (exec / upload / download) for the cdp-pilot app.

Credentials come from this process's own environment (AW_BACKEND_URL,
AW_WORKSPACE, AW_WORKSPACE_HOST_TOKEN — the aw-remote-host /link handshake),
falling back to ``<AW_WORKSPACE_HOME>/.env``. Nothing is stored in app config,
so the app needs no ``secrets:own`` permission.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BACKEND_URL = "http://127.0.0.1:9025"


class NotConfigured(RuntimeError):
    """The aw-remote-host /link handshake credentials are not all present."""


def _env_file() -> str:
    home = os.environ.get("AW_WORKSPACE_HOME") or os.path.join(
        os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace"), ".aw-workspace")
    return os.environ.get("AW_WORKSPACE_ENV_FILE") or os.path.join(home, ".env")


def _resolve(key: str, default: str = "") -> str:
    if os.environ.get(key):
        return os.environ[key]
    prefix = f"{key}="
    try:
        with open(_env_file(), encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith(prefix):
                    return line[len(prefix):].strip().strip("'\"") or default
    except OSError:
        pass
    return default


def _cfg() -> tuple[str, str, str]:
    base = _resolve("AW_BACKEND_URL", DEFAULT_BACKEND_URL).rstrip("/")
    workspace = _resolve("AW_WORKSPACE")
    token = _resolve("AW_WORKSPACE_HOST_TOKEN")
    if not (base and workspace and token):
        raise NotConfigured(
            "AW_BACKEND_URL, AW_WORKSPACE and AW_WORKSPACE_HOST_TOKEN are not all available "
            "in this workspace; the aw-remote-host /link handshake may not have completed.")
    return base, workspace, token


def configured() -> bool:
    try:
        _cfg()
        return True
    except NotConfigured:
        return False


def _url(host_id: str, path: str, params: dict | None = None) -> str:
    base, workspace, _ = _cfg()
    url = f"{base}/api/workspaces/{workspace}/remote-hosts/{urllib.parse.quote(host_id)}{path}"
    return url + ("?" + urllib.parse.urlencode(params) if params else "")


def _call(host_id: str, method: str, path: str, *, body: dict | None = None,
          timeout: float = 60.0) -> dict:
    token = _cfg()[2]
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(_url(host_id, path), data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        # Status only: the body can echo the command line (typed text, selectors).
        raise RuntimeError(f"remote-host {method} {path.split('/')[1] or path} -> HTTP {exc.code}") from exc
    return json.loads(raw) if raw.strip() else {}


def exec(host_id: str, command: str, timeout: int = 60) -> tuple[str, str, int]:  # noqa: A001
    started = _call(host_id, "POST", "/exec", body={"command": command, "timeout_s": timeout})
    job_id = started.get("job_id")
    if not job_id:
        raise RuntimeError("remote-host exec did not return a job_id")
    result = _call(host_id, "POST", f"/exec/{job_id}/wait", body={"timeout_s": timeout},
                   timeout=timeout + 30.0)
    return (result.get("stdout") or "", result.get("stderr") or "",
            int(result.get("exit_code") or 0))


def upload(host_id: str, local_path: str, remote_path: str, timeout: float = 120.0) -> dict:
    token = _cfg()[2]
    with open(local_path, "rb") as handle:
        payload = handle.read()
    req = urllib.request.Request(
        _url(host_id, "/fs/upload", {"path": remote_path}), data=payload, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream",
                 "Content-Length": str(len(payload))})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"upload failed (HTTP {exc.code})") from exc
    return json.loads(raw) if raw.strip() else {}


def download(host_id: str, remote_path: str, local_path: str, timeout: float = 120.0) -> int:
    """Pull a file via the fs route (exec stdout is capped at 1 MiB)."""
    token = _cfg()[2]
    req = urllib.request.Request(_url(host_id, "/fs/download", {"path": remote_path}),
                                 headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"download failed (HTTP {exc.code})") from exc
    os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
    tmp = local_path + ".part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    os.replace(tmp, local_path)
    return len(payload)
