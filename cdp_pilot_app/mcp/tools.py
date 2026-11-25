"""The ``aw-cdp-pilot`` tool surface: 8 tools, schemas + handlers.

Tools take a configured target NAME (launch) or an opaque session id (the
rest). No tool accepts a host id, path, port, pid, URL or script, so those are
unreachable by construction rather than by validation. The target allowlist
lives in the app config and defaults to EMPTY (fail closed).

Typed text and selectors cross the exec command line base64-encoded and are
retained wherever job commands are retained, so use synthetic data only. App
logs record the verb, session id and text LENGTH, never the text.
"""
from __future__ import annotations

import contextlib
import datetime
import fcntl
import hashlib
import json
import logging
import os
import re
import threading
import time
from typing import Callable

from . import host_agent, remote_host

log = logging.getLogger("aw_apps.cdp-pilot")

SID_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_TTL_S = 1800
DEFAULT_TTL_S = 600
DEFAULT_SCREENSHOT_DIR = ".tmp/cdp-pilot/"
REGISTRY_RETENTION_S = 24 * 3600


class Refused(RuntimeError):
    """The request was rejected before anything ran on a host."""


_config_resolver: Callable[[], dict] = lambda: {}


def set_config_resolver(resolver: Callable[[], dict]) -> None:
    global _config_resolver
    _config_resolver = resolver


def current_config() -> dict:
    try:
        return _config_resolver() or {}
    except Exception:  # noqa: BLE001
        return {}


# -- session registry (session id -> host), persisted so a workspace restart
#    does not strand a live session -------------------------------------------

def _data_dir() -> str:
    home = os.environ.get("AW_WORKSPACE_HOME") or os.path.join(
        os.environ.get("AW_WORKSPACE_CONTAINER_DIR", "/opt/aw-workspace"), ".aw-workspace")
    path = os.path.join(home, "data", "cdp-pilot")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _registry_path() -> str:
    return os.path.join(_data_dir(), "sessions.json")


def _load_registry() -> dict:
    try:
        with open(_registry_path(), encoding="utf-8") as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        return {}
    now = time.time()
    return {k: v for k, v in doc.items()
            if now < float(v.get("expires_at", 0)) + REGISTRY_RETENTION_S}


def _save_registry(doc: dict) -> None:
    path = _registry_path()
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"  # unique per writer
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(doc, handle)
    os.replace(tmp, path)


_registry_lock = threading.Lock()


@contextlib.contextmanager
def _registry_txn():
    """Serialize a registry read-modify-write across threads AND worker processes."""
    with _registry_lock:
        fd = os.open(os.path.join(_data_dir(), "sessions.lock"), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing releases the flock


def _host_for(session_id: str) -> str:
    if not isinstance(session_id, str) or not SID_RE.match(session_id):
        raise Refused("unknown session")
    entry = _load_registry().get(session_id)
    if not entry:
        raise Refused("unknown session")
    return entry["host_id"]


# -- helpers -------------------------------------------------------------------

def _text(payload: dict | list) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def _iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


def _str_arg(args: dict, key: str, *, required: bool = False, max_len: int = 500) -> str:
    value = args.get(key)
    if value is None or value == "":
        if required:
            raise Refused(f"{key} is required")
        return ""
    if not isinstance(value, str) or len(value) > max_len:
        raise Refused(f"{key} must be a string of at most {max_len} characters")
    return value


def _page_id(args: dict) -> str:
    value = _str_arg(args, "page_id", max_len=64)
    if value and not re.fullmatch(r"[A-Za-z0-9]+", value):
        raise Refused("page_id is malformed")
    return value


def _find_target(name: str) -> dict:
    targets = current_config().get("targets") or []
    if not targets:
        raise Refused("no targets are configured; add one in the cdp-pilot app settings")
    for target in targets:
        if isinstance(target, dict) and target.get("name") == name:
            for key in ("host_id", "app_path", "bundle_id"):
                if not target.get(key):
                    raise Refused(f"target '{name}' is misconfigured: {key} is missing")
            return target
    raise Refused("unknown target")


def _ttl() -> int:
    try:
        ttl = int(current_config().get("session_ttl_s") or DEFAULT_TTL_S)
    except (TypeError, ValueError):
        ttl = DEFAULT_TTL_S
    return max(10, min(ttl, MAX_TTL_S))


def _session_call(verb: str, args: dict, body: dict, timeout: int = 90) -> dict:
    session_id = args.get("session_id")
    host_id = _host_for(session_id)
    log.info("cdp-pilot %s session=%s", verb, session_id)
    return host_agent.call(host_id, verb, {"session_id": session_id, **body}, timeout=timeout)


# -- handlers --------------------------------------------------------------------

def cdp_launch(args: dict) -> str:
    name = _str_arg(args, "target", required=True, max_len=100)
    target = _find_target(name)
    spec = {"name": name, "app_path": target["app_path"], "bundle_id": target["bundle_id"],
            "team_id": target.get("team_id") or "",
            "allow_unpinned_team": target.get("allow_unpinned_team") is True}
    host_id = target["host_id"]
    log.info("cdp-pilot launch target=%s", name)
    result = host_agent.call(host_id, "launch", {"target": spec, "ttl_s": _ttl()}, timeout=120)
    with _registry_txn():
        registry = _load_registry()
        registry[result["session_id"]] = {"host_id": host_id, "target": name,
                                          "expires_at": result["expires_at"]}
        _save_registry(registry)
    return _text({"session_id": result["session_id"], "target": name,
                  "expires_at": _iso(result["expires_at"]), "listener": result["listener"]})


def cdp_list_pages(args: dict) -> str:
    return _text(_session_call("list_pages", args, {}))


def cdp_inspect(args: dict) -> str:
    try:
        max_nodes = int(args.get("max_nodes") or 25)
    except (TypeError, ValueError):
        raise Refused("max_nodes must be an integer")
    return _text(_session_call("inspect", args, {
        "page_id": _page_id(args), "selector": _str_arg(args, "selector"),
        "max_nodes": max(1, min(max_nodes, 100))}))


def cdp_click(args: dict) -> str:
    nth = args.get("nth")
    if nth is not None and (not isinstance(nth, int) or isinstance(nth, bool) or nth < 0):
        raise Refused("nth must be a non-negative integer")
    return _text(_session_call("click", args, {
        "page_id": _page_id(args), "selector": _str_arg(args, "selector", required=True),
        "nth": nth}))


def cdp_type(args: dict) -> str:
    text = _str_arg(args, "text", required=True, max_len=2000)
    log.info("cdp-pilot type chars=%d", len(text))
    return _text(_session_call("type", args, {
        "page_id": _page_id(args), "text": text, "selector": _str_arg(args, "selector"),
        "clear": bool(args.get("clear"))}))


def cdp_key(args: dict) -> str:
    modifiers = args.get("modifiers") or []
    if not isinstance(modifiers, list) or not all(isinstance(m, str) for m in modifiers):
        raise Refused("modifiers must be a list of strings")
    return _text(_session_call("key", args, {
        "page_id": _page_id(args), "key": _str_arg(args, "key", required=True, max_len=20),
        "modifiers": modifiers}))


def screenshot_dir() -> str:
    base = current_config().get("screenshot_dir") or DEFAULT_SCREENSHOT_DIR
    root = base if os.path.isabs(base) else os.path.join(
        os.environ.get("AW_WORKSPACE_CONTAINER_DIR") or "/opt/aw-workspace", base)
    os.makedirs(root, exist_ok=True)
    return root


def cdp_screenshot(args: dict) -> str:
    session_id = args.get("session_id")
    host_id = _host_for(session_id)
    shot = _session_call("screenshot", args, {"page_id": _page_id(args)})
    local = os.path.join(screenshot_dir(), f"cdp-{session_id[:8]}-{int(time.time() * 1000)}.png")
    size = remote_host.download(host_id, shot["path"], local)
    with open(local, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if digest != shot.get("sha256"):
        os.remove(local)
        raise RuntimeError("screenshot failed verification: transferred bytes differ from the host's")
    return _text({"local_path": local, "bytes": size, "sha256": digest})


def cdp_close(args: dict) -> str:
    return _text(_session_call("close", args, {}, timeout=60))


# -- schemas ---------------------------------------------------------------------

def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"name": name, "description": description,
            "inputSchema": {"type": "object", "properties": properties, "required": required}}


_SID = {"session_id": {"type": "string", "description": "Opaque id returned by cdp_launch."}}
_PAGE = {"page_id": {"type": "string",
                     "description": "Optional page id from cdp_list_pages; defaults to the first page."}}
_SEL = {"type": "string", "description": "CSS selector (never JavaScript)."}

TOOLS = [
    _schema("cdp_launch",
            "Launch a configured, signature-verified app on its configured host with a "
            "disposable profile and a loopback-only ephemeral debug port. Returns an opaque "
            "session_id and expiry. One session per host. The app and profile are removed on "
            "cdp_close or expiry. Use synthetic test data only.",
            {"target": {"type": "string", "description": "Name of a configured target."}},
            ["target"]),
    _schema("cdp_list_pages", "List the session app's pages (title and origin+path only).",
            {**_SID}, ["session_id"]),
    _schema("cdp_inspect",
            "Structured DOM inspection: tag, role, text, visibility, enabled, box and a fixed "
            "attribute subset for elements matching a CSS selector. Never returns input values.",
            {**_SID, **_PAGE, "selector": _SEL,
             "max_nodes": {"type": "integer", "description": "1-100, default 25."}},
            ["session_id"]),
    _schema("cdp_click",
            "Click exactly one visible element matching the selector (use nth to pick among "
            "several visible matches) with real mouse events.",
            {**_SID, **_PAGE, "selector": _SEL, "nth": {"type": "integer"}},
            ["session_id", "selector"]),
    _schema("cdp_type",
            "Insert text into the focused element, or into the one visible element matching "
            "selector. Synthetic data only: the text is retained wherever exec job commands are.",
            {**_SID, **_PAGE, "text": {"type": "string"}, "selector": _SEL,
             "clear": {"type": "boolean", "description": "Select existing content first."}},
            ["session_id", "text"]),
    _schema("cdp_key",
            "Press one key from a fixed table (Enter, Tab, Escape, Backspace, Delete, arrows, "
            "Home/End, PageUp/PageDown, Space, a-z, 0-9) with optional modifiers "
            "(Alt, Control, Meta, Shift).",
            {**_SID, **_PAGE, "key": {"type": "string"},
             "modifiers": {"type": "array", "items": {"type": "string"}}},
            ["session_id", "key"]),
    _schema("cdp_screenshot",
            "Capture a PNG of a page. Returns a local file path in this workspace and its sha256.",
            {**_SID, **_PAGE}, ["session_id"]),
    _schema("cdp_close",
            "Close the session: kill the app's process group, remove the disposable profile and "
            "listener, and return the cleanup evidence. On an already-expired session it returns "
            "the expiry tombstone with the same evidence.",
            {**_SID}, ["session_id"]),
]

HANDLERS: dict[str, Callable[[dict], str]] = {
    "cdp_launch": cdp_launch, "cdp_list_pages": cdp_list_pages, "cdp_inspect": cdp_inspect,
    "cdp_click": cdp_click, "cdp_type": cdp_type, "cdp_key": cdp_key,
    "cdp_screenshot": cdp_screenshot, "cdp_close": cdp_close,
}
