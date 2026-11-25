#!/usr/bin/env python3
"""aw_cdp_pilot — host-side agent for the cdp-pilot app.

Single file, stdlib only, Python >= 3.9 (runs on macOS' /usr/bin/python3).
Uploaded to the linked host by the workspace and invoked once per MCP tool
call as ``aw_cdp_pilot.py <verb> --args-b64 <base64 json>``; it prints one
``MARKER{json}`` line and exits.

Security model (the part that must hold):

* The launched app is owned by a detached *supervisor* (own session, stdio to
  a file) that is the single owner of TTL + cleanup, so expiry works even when
  the workspace is down. Any later verb also sweeps sessions whose supervisor
  is dead (host reboot, supervisor crash).
* The debug listener is requested with port 0 on the default loopback bind;
  no remote-debugging-address flag is ever passed, and the launch fails (with
  full cleanup) if the listener is not loopback-only.
* Verbs address a session ONLY by its opaque 128-bit id; the recorded pid must
  still own the recorded port. There is no host/path/port/pid parameter, so an
  unrelated debuggable app on the machine is unreachable.
* No arbitrary JavaScript: inspection and interaction use the fixed page
  functions below, with the selector passed as a JSON argument.
* Never returns input values, cookies or storage; typed text is never logged.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import http.client
import json
import os
import plistlib
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from urllib.parse import urlsplit

VERSION = "0.1.1"
MARKER = "<<<AW_CDP_PILOT_JSON>>>"
MAX_TTL_S = 1800
DEFAULT_TTL_S = 600
TOMBSTONE_TTL_S = 24 * 3600
LAUNCH_WAIT_S = 30
SID_RE = re.compile(r"^[0-9a-f]{32}$")
PAGE_TYPES = ("page", "webview")


class AgentError(Exception):
    """A refusal or failure reported to the caller as {"ok": false}."""


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

def root_dir():
    return os.environ.get("AW_CDP_PILOT_HOME") or os.path.join(
        os.path.expanduser("~"), ".aw-cdp-pilot")


def sessions_dir():
    return os.path.join(root_dir(), "sessions")


def tombstones_dir():
    return os.path.join(root_dir(), "tombstones")


def session_path(sid):
    return os.path.join(sessions_dir(), sid)


def _mkdir_private(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _write_json(path, doc):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(doc, handle)
    os.replace(tmp, path)


def _read_json(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Platform seams (monkeypatched in tests; the macOS checks live here)
# --------------------------------------------------------------------------

def _run(argv, timeout=15):
    out = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=timeout, universal_newlines=True)
    return out.returncode, out.stdout, out.stderr


def verify_target(target):
    """Raise AgentError unless the configured target is exactly what is on disk.

    Returns the executable path inside the bundle.
    """
    if sys.platform != "darwin":
        raise AgentError("host platform is not darwin; this build only supports macOS targets")
    app_path = target.get("app_path") or ""
    if not app_path or not os.path.isabs(app_path):
        raise AgentError("target.app_path must be an absolute path")
    if os.path.realpath(app_path) != app_path.rstrip("/"):
        raise AgentError("target.app_path is not its own realpath (symlink or non-canonical)")
    plist = os.path.join(app_path, "Contents", "Info.plist")
    try:
        with open(plist, "rb") as handle:
            info = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException):
        raise AgentError("cannot read the target bundle's Info.plist")
    if info.get("CFBundleIdentifier") != target.get("bundle_id"):
        raise AgentError("bundle identifier on the host does not match the configured bundle_id")
    # Integrity first: `-dv` only DISPLAYS the (possibly stale) signature, so a
    # bundle whose sealed resources were modified would still show its team id.
    code, _out, _err = _run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app_path],
                            timeout=60)
    if code != 0:
        raise AgentError("code signature verification failed for the target bundle")
    team = target.get("team_id") or ""
    if team:
        code, _out, err = _run(["/usr/bin/codesign", "-dv", "--verbose=2", app_path])
        match = re.search(r"^TeamIdentifier=(.+)$", err, re.MULTILINE)
        if code != 0 or not match or match.group(1).strip() != team:
            raise AgentError("code signature TeamIdentifier does not match the configured team_id")
    exe = info.get("CFBundleExecutable")
    if not exe or "/" in exe:
        raise AgentError("target bundle has no usable CFBundleExecutable")
    path = os.path.join(app_path, "Contents", "MacOS", exe)
    if not os.access(path, os.X_OK):
        raise AgentError("target executable is not runnable")
    return path


def listeners_for(pid):
    """TCP LISTEN sockets owned by ``pid`` as [(address, port)]."""
    code, out, _err = _run(["/usr/sbin/lsof", "-nP", "-a", "-p", str(pid),
                            "-iTCP", "-sTCP:LISTEN", "-Fn"])
    found = []
    for line in out.splitlines():
        if not line.startswith("n"):
            continue
        host, _sep, port = line[1:].rpartition(":")
        if port.isdigit():
            found.append((host.strip("[]"), int(port)))
    return found


def group_members(pgid):
    code, out, _err = _run(["/bin/ps", "-axo", "pid=,pgid=,stat="])
    members = []
    for line in out.splitlines():
        parts = line.split()
        # A zombie (stat Z) is already dead, just not yet reaped by its parent.
        if len(parts) == 3 and parts[1] == str(pgid) and not parts[2].startswith("Z"):
            members.append(int(parts[0]))
    return members


def proc_start(pid):
    """Opaque start-time token for ``pid`` ("" when it does not exist)."""
    code, out, _err = _run(["/bin/ps", "-o", "lstart=", "-p", str(pid)])
    return out.strip() if code == 0 else ""


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def same_process(pid, start):
    return bool(pid) and pid_alive(pid) and bool(start) and proc_start(pid) == start


# --------------------------------------------------------------------------
# Session lifecycle
# --------------------------------------------------------------------------

def _loopback(addr):
    return addr in ("127.0.0.1", "::1", "localhost")


def cleanup_session(sid, reason, state="closed", proc=None):
    """Kill the app's process group, verify, remove the session, leave a tombstone.

    Idempotent and safe to call from the supervisor, ``close`` and the sweep.
    """
    sdir = session_path(sid)
    doc = _read_json(os.path.join(sdir, "session.json")) or {}
    pid = doc.get("pid")
    pgid = doc.get("pgid")
    port = doc.get("port")
    killed = False
    # A dead leader with surviving members still owns its pgid (the kernel will
    # not reuse the id while the group exists); a live leader must match the
    # recorded start time so a recycled pid is never signalled.
    if pgid and pgid > 1 and pid == pgid and (
            same_process(pid, doc.get("pid_start"))
            or (not pid_alive(pid) and group_members(pgid))):
        killed = True
        for sig, wait_s in ((signal.SIGTERM, 6), (signal.SIGKILL, 6)):
            try:
                os.killpg(pgid, sig)
            except (ProcessLookupError, PermissionError):  # pragma: no cover
                pass
            deadline = time.time() + wait_s
            while time.time() < deadline and group_members(pgid):
                time.sleep(0.2)  # pragma: no cover
            if not group_members(pgid):
                break
    if proc is not None:
        proc.poll()  # reap the app leader so it does not linger as a zombie
    members = group_members(pgid) if pgid else []
    listening = []
    if port:
        for _addr, p in (listeners_for(pid) if pid and pid_alive(pid) else []):
            if p == port:
                listening.append(p)
    shutil.rmtree(sdir, ignore_errors=True)
    checks = {
        "process_group_gone": not members,
        "listener_gone": not listening,
        "profile_dir_removed": not os.path.exists(sdir),
    }
    tomb = {
        "session_id": sid,
        "state": state,
        "reason": reason,
        "started_at": doc.get("started_at"),
        "ended_at": int(time.time()),
        "signalled": killed,
        "checks": checks,
    }
    _mkdir_private(tombstones_dir())
    _write_json(os.path.join(tombstones_dir(), sid + ".json"), tomb)
    return tomb


def _prune_tombstones():
    try:
        names = os.listdir(tombstones_dir())
    except OSError:
        return
    for name in names:
        path = os.path.join(tombstones_dir(), name)
        try:
            if time.time() - os.path.getmtime(path) > TOMBSTONE_TTL_S:
                os.remove(path)
        except OSError:  # pragma: no cover
            pass


def sweep():
    """Clean up sessions whose supervisor is gone or whose TTL has passed."""
    _prune_tombstones()
    try:
        names = os.listdir(sessions_dir())
    except OSError:
        return
    for sid in names:
        if not SID_RE.match(sid):
            continue
        doc = _read_json(os.path.join(session_path(sid), "session.json"))
        if doc is None:
            # Half-created (launch crashed before writing the record).
            if time.time() - os.path.getmtime(session_path(sid)) > 60:
                cleanup_session(sid, "orphaned_dir", state="expired")
            continue
        if not doc.get("supervisor_pid") and time.time() - doc.get("started_at", 0) < 60:
            continue  # supervisor still booting
        supervisor_ok = same_process(doc.get("supervisor_pid"), doc.get("supervisor_start"))
        if not supervisor_ok:
            cleanup_session(sid, "supervisor_lost", state="expired")
        elif time.time() > doc.get("expires_at", 0) + 30:
            cleanup_session(sid, "ttl_overdue", state="expired")


def _active_session():
    try:
        names = os.listdir(sessions_dir())
    except OSError:
        return None
    for sid in names:
        if SID_RE.match(sid):
            return sid
    return None


def supervise(sid):
    """Detached supervisor: spawn the app, publish its port, enforce the TTL."""
    sdir = session_path(sid)
    spath = os.path.join(sdir, "session.json")
    doc = _read_json(spath)
    if not doc:
        return
    doc.update(supervisor_pid=os.getpid(), supervisor_start=proc_start(os.getpid()))
    _write_json(spath, doc)
    env = {k: os.environ[k] for k in ("HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "PATH")
           if k in os.environ}
    stderr_path = os.path.join(sdir, "app.stderr")
    err = open(stderr_path, "wb")
    try:
        proc = subprocess.Popen(
            [doc["exe"], "--remote-debugging-port=0", "--user-data-dir=" + doc["profile"]],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
            env=env, start_new_session=True, close_fds=True)
    except OSError as exc:
        doc.update(state="failed", error="spawn failed: %s" % exc.__class__.__name__)
        _write_json(spath, doc)
        return
    doc.update(pid=proc.pid, pgid=proc.pid, pid_start=proc_start(proc.pid), state="starting")
    _write_json(spath, doc)

    port = None
    deadline = time.time() + LAUNCH_WAIT_S
    while time.time() < deadline and proc.poll() is None:
        port = discover_port(sdir, stderr_path)
        if port:
            break
        time.sleep(0.25)
    if not port:
        reason = "app_exited_before_port" if proc.poll() is not None else "no_port_in_time"
        cleanup_session(sid, reason, state="failed", proc=proc)
        return
    doc.update(port=port, state="running")
    _write_json(spath, doc)

    while True:
        if proc.poll() is not None:
            cleanup_session(sid, "app_exited", state="closed", proc=proc)
            return
        if os.path.exists(os.path.join(sdir, "close.req")):
            cleanup_session(sid, "explicit_close", state="closed", proc=proc)
            return
        if time.time() >= doc["expires_at"]:
            cleanup_session(sid, "ttl_expired", state="expired", proc=proc)
            return
        time.sleep(0.5)


def discover_port(sdir, stderr_path):
    try:
        with open(stderr_path, "rb") as handle:
            text = handle.read().decode("utf-8", "replace")
        match = re.search(r"DevTools listening on ws://127\.0\.0\.1:(\d+)/", text)
        if match:
            return int(match.group(1))
    except OSError:
        pass
    try:
        with open(os.path.join(sdir, "profile", "DevToolsActivePort")) as handle:
            first = handle.readline().strip()
        if first.isdigit() and int(first) > 0:
            return int(first)
    except OSError:
        pass
    return None


# --------------------------------------------------------------------------
# Minimal loopback WebSocket + CDP client
# --------------------------------------------------------------------------

class WS:
    def __init__(self, port, path, timeout=20.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (path, port, key)).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise AgentError("websocket handshake closed")
            head += chunk
            if len(head) > 65536:
                raise AgentError("websocket handshake too large")
        header, _sep, rest = head.partition(b"\r\n\r\n")
        if b" 101 " not in header.split(b"\r\n")[0]:
            raise AgentError("websocket upgrade refused")
        self.buf = rest

    def _read(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AgentError("websocket closed")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def send_text(self, text):
        payload = text.encode("utf-8")
        head = bytearray([0x81])
        n = len(payload)
        if n < 126:
            head.append(0x80 | n)
        elif n < 65536:
            head.append(0x80 | 126)
            head += struct.pack(">H", n)
        else:
            head.append(0x80 | 127)
            head += struct.pack(">Q", n)
        mask = os.urandom(4)
        head += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload)) if n < 4096 else \
            _mask_big(payload, mask)
        self.sock.sendall(bytes(head) + masked)

    def recv_text(self):
        message = b""
        while True:
            b0, b1 = self._read(2)
            opcode = b0 & 0x0F
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read(8))[0]
            if b1 & 0x80:
                mask = self._read(4)
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read(length)))
            else:
                payload = self._read(length)
            if opcode == 0x8:
                raise AgentError("websocket closed by the app")
            if opcode == 0x9:
                self._pong(payload)
                continue
            if opcode == 0xA:
                continue
            message += payload
            if b0 & 0x80:
                return message.decode("utf-8", "replace")

    def _pong(self, payload):
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload[:125]))
        self.sock.sendall(bytes([0x8A, 0x80 | len(masked)]) + mask + masked)

    def close(self):
        try:
            self.sock.close()
        except OSError:  # pragma: no cover
            pass


def _mask_big(payload, mask):
    # XOR via int arithmetic: orders of magnitude faster than a Python loop on MBs.
    n = len(payload)
    key = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


class CDP:
    def __init__(self, port, ws_path, timeout=20.0):
        self.ws = WS(port, ws_path, timeout)
        self.next_id = 0
        self.timeout = timeout

    def call(self, method, params=None):
        self.next_id += 1
        mid = self.next_id
        self.ws.send_text(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv_text())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise AgentError("CDP %s failed: %s" % (
                        method, str(msg["error"].get("message", "error"))[:200]))
                return msg.get("result") or {}
        raise AgentError("CDP %s timed out" % method)

    def close(self):
        self.ws.close()


def http_json(port, path):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return json.loads(resp.read().decode("utf-8", "replace"))
    finally:
        conn.close()


def list_targets(port):
    out = []
    for item in http_json(port, "/json/list"):
        if item.get("type") not in PAGE_TYPES:
            continue
        url = urlsplit(item.get("url") or "")
        safe = "%s://%s%s" % (url.scheme, url.netloc, url.path) if url.scheme else ""
        out.append({"page_id": item.get("id"), "type": item.get("type"),
                    "title": (item.get("title") or "")[:200], "url": safe})
    return out


def connect_page(port, page_id):
    """Open a CDP socket to a page chosen from the app's own target list."""
    raw = [t for t in http_json(port, "/json/list") if t.get("type") in PAGE_TYPES]
    if not raw:
        raise AgentError("the app has no page targets")
    if page_id:
        chosen = [t for t in raw if t.get("id") == page_id]
        if not chosen:
            raise AgentError("unknown page_id")
    else:
        chosen = raw
    ws_url = urlsplit(chosen[0].get("webSocketDebuggerUrl") or "")
    if ws_url.hostname not in ("127.0.0.1", "localhost") or ws_url.port != port:
        raise AgentError("refusing a debugger URL that is not the session's loopback port")
    return CDP(port, ws_url.path)


# --------------------------------------------------------------------------
# Fixed page functions (repo-owned; the selector is a JSON argument)
# --------------------------------------------------------------------------

_JS_COMMON = """
function visible(el) {
  const r = el.getBoundingClientRect();
  const s = getComputedStyle(el);
  return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
}
"""

JS_INSPECT = "function(selector, maxNodes) {" + _JS_COMMON + """
  let nodes;
  try { nodes = Array.from(document.querySelectorAll(selector)); }
  catch (e) { return {error: 'invalid selector'}; }
  const attrs = ['id', 'class', 'data-testid', 'type', 'placeholder', 'name', 'href'];
  const out = nodes.slice(0, maxNodes).map(el => {
    const r = el.getBoundingClientRect();
    const a = {};
    for (const k of attrs) { if (el.hasAttribute(k)) a[k] = String(el.getAttribute(k)).slice(0, 120); }
    for (const at of el.attributes) { if (at.name.startsWith('aria-')) a[at.name] = String(at.value).slice(0, 120); }
    const isInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName);
    return {tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || '',
            text: isInput ? '' : (el.innerText || el.textContent || '').trim().slice(0, 200),
            visible: visible(el), enabled: !el.disabled,
            box: {x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height)},
            attributes: a};
  });
  return {count: nodes.length, returned: out.length, nodes: out, title: document.title};
}"""

JS_RESOLVE = "function(selector, nth) {" + _JS_COMMON + """
  let nodes;
  try { nodes = Array.from(document.querySelectorAll(selector)); }
  catch (e) { return {error: 'invalid selector'}; }
  const vis = nodes.filter(visible);
  if (vis.length === 0) return {error: 'no visible match', matches: nodes.length};
  if (nth === null && vis.length !== 1) return {error: 'selector is ambiguous', matches: vis.length};
  const el = vis[nth === null ? 0 : nth];
  if (!el) return {error: 'nth out of range', matches: vis.length};
  el.scrollIntoView({block: 'center', inline: 'center'});
  const r = el.getBoundingClientRect();
  const x = r.x + r.width / 2, y = r.y + r.height / 2;
  const hit = document.elementFromPoint(x, y);
  if (!hit || !(hit === el || el.contains(hit) || hit.contains(el)))
    return {error: 'target is covered by another element'};
  if (el.disabled) return {error: 'target is disabled'};
  return {x: x, y: y};
}"""

JS_FOCUS = "function(selector, clear) {" + """
  const el = document.querySelector(selector);
  if (!el) return {error: 'no match'};
  el.focus();
  if (clear && typeof el.select === 'function') el.select();
  return {ok: true};
}"""

KEYS = {
    "Enter": ("Enter", "Enter", 13, "\r"), "Tab": ("Tab", "Tab", 9, ""),
    "Escape": ("Escape", "Escape", 27, ""), "Backspace": ("Backspace", "Backspace", 8, ""),
    "Delete": ("Delete", "Delete", 46, ""), "ArrowUp": ("ArrowUp", "ArrowUp", 38, ""),
    "ArrowDown": ("ArrowDown", "ArrowDown", 40, ""), "ArrowLeft": ("ArrowLeft", "ArrowLeft", 37, ""),
    "ArrowRight": ("ArrowRight", "ArrowRight", 39, ""), "Home": ("Home", "Home", 36, ""),
    "End": ("End", "End", 35, ""), "PageUp": ("PageUp", "PageUp", 33, ""),
    "PageDown": ("PageDown", "PageDown", 34, ""), "Space": (" ", "Space", 32, " "),
}
MODIFIERS = {"Alt": 1, "Control": 2, "Meta": 4, "Shift": 8}


def key_spec(name):
    if name in KEYS:
        return KEYS[name]
    if len(name) == 1 and name.isalnum() and name.isascii():
        code = ("Key" + name.upper()) if name.isalpha() else ("Digit" + name)
        return (name, code, ord(name.upper()), name)
    raise AgentError("unsupported key")


def _call_fn(cdp, fn, args):
    glob = cdp.call("Runtime.evaluate", {"expression": "globalThis"})
    oid = glob.get("result", {}).get("objectId")
    if not oid:
        raise AgentError("could not reach the page's global object")
    res = cdp.call("Runtime.callFunctionOn", {
        "objectId": oid, "functionDeclaration": fn,
        "arguments": [{"value": a} for a in args], "returnByValue": True,
        "awaitPromise": False})
    if res.get("exceptionDetails"):
        raise AgentError("page function failed")
    value = res.get("result", {}).get("value")
    return value if isinstance(value, dict) else {}


# --------------------------------------------------------------------------
# Verbs
# --------------------------------------------------------------------------

def load_session(sid):
    """Return the live session record, or raise a precise AgentError."""
    if not isinstance(sid, str) or not SID_RE.match(sid):
        raise AgentError("unknown session")
    doc = _read_json(os.path.join(session_path(sid), "session.json"))
    if doc is None:
        tomb = _read_json(os.path.join(tombstones_dir(), sid + ".json"))
        if tomb:
            raise AgentError("session is %s (%s)" % (tomb.get("state"), tomb.get("reason")))
        raise AgentError("unknown session")
    if doc.get("state") != "running" or not doc.get("port"):
        raise AgentError("session is not running")
    if not same_process(doc.get("pid"), doc.get("pid_start")):
        raise AgentError("session process is gone")
    ok = any(_loopback(a) and p == doc["port"] for a, p in listeners_for(doc["pid"]))
    if not ok:
        raise AgentError("session process no longer owns its recorded loopback port")
    return doc


def verb_status(_args):
    return {"agent_version": VERSION, "platform": sys.platform,
            "python": "%d.%d.%d" % sys.version_info[:3]}


def verb_launch(args):
    sweep()
    target = args.get("target") or {}
    ttl = int(args.get("ttl_s") or DEFAULT_TTL_S)
    ttl = max(10, min(ttl, MAX_TTL_S))
    exe = verify_target(target)
    sid = secrets.token_hex(16)
    sdir = session_path(sid)
    _mkdir_private(sessions_dir())
    # The one-session-per-host check and the slot reservation (creating the
    # session dir) must be atomic across concurrent launch processes.
    _mkdir_private(root_dir())
    lock_fd = os.open(os.path.join(root_dir(), "launch.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if _active_session():
            raise AgentError("a session is already active on this host")
        _mkdir_private(sdir)
    finally:
        os.close(lock_fd)  # closing releases the flock
    profile = os.path.join(sdir, "profile")
    _mkdir_private(profile)
    now = int(time.time())
    me = os.path.abspath(__file__)
    log = open(os.path.join(sdir, "supervisor.log"), "wb")
    _write_json(os.path.join(sdir, "session.json"), {
        "session_id": sid, "state": "starting", "exe": exe, "profile": profile,
        "target": target.get("name"), "started_at": now, "expires_at": now + ttl})
    sup = subprocess.Popen([sys.executable, me, "supervise", "--session", sid],
                           stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                           start_new_session=True, close_fds=True)
    del sup  # the supervisor records its own pid/start in session.json

    deadline = time.time() + LAUNCH_WAIT_S + 10
    while time.time() < deadline:
        doc = _read_json(os.path.join(sdir, "session.json"))
        if doc is None:
            tomb = _read_json(os.path.join(tombstones_dir(), sid + ".json")) or {}
            raise AgentError("launch failed: %s" % tomb.get("reason", "session vanished"))
        if doc.get("state") == "failed":
            cleanup_session(sid, "launch_failed", state="failed")
            raise AgentError("launch failed: %s" % doc.get("error", "unknown"))
        if doc.get("state") == "running" and doc.get("port"):
            break
        time.sleep(0.25)
    else:
        cleanup_session(sid, "launch_timeout", state="failed")
        raise AgentError("launch failed: the app never opened a debug port")

    listening = [(a, p) for a, p in listeners_for(doc["pid"]) if p == doc["port"]]
    if not listening or not all(_loopback(a) for a, _p in listening):
        cleanup_session(sid, "listener_not_loopback", state="failed")
        raise AgentError("launch failed: debug listener is not loopback-only")
    return {"session_id": sid, "expires_at": doc["expires_at"],
            "listener": {"addresses": sorted({a for a, _p in listening}), "loopback_only": True,
                         "ephemeral_port": doc["port"] >= 1024}}


def verb_list_pages(args):
    doc = load_session(args.get("session_id"))
    return {"pages": list_targets(doc["port"])}


def verb_inspect(args):
    doc = load_session(args.get("session_id"))
    selector = args.get("selector") or ("button, a, input, textarea, select, [role], "
                                        "[data-testid], h1, h2, h3, label")
    cdp = connect_page(doc["port"], args.get("page_id"))
    try:
        res = _call_fn(cdp, JS_INSPECT, [selector, max(1, min(int(args.get("max_nodes") or 25), 100))])
    finally:
        cdp.close()
    if res.get("error"):
        raise AgentError(res["error"])
    return res


def _mouse(cdp, x, y):
    cdp.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
    for kind in ("mousePressed", "mouseReleased"):
        cdp.call("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y,
                                              "button": "left", "clickCount": 1})


def _resolve(cdp, selector, nth):
    res = _call_fn(cdp, JS_RESOLVE, [selector, nth])
    if res.get("error"):
        detail = res["error"] + (" (%s)" % res["matches"] if "matches" in res else "")
        raise AgentError(detail)
    return res


def verb_click(args):
    doc = load_session(args.get("session_id"))
    cdp = connect_page(doc["port"], args.get("page_id"))
    try:
        pt = _resolve(cdp, args.get("selector") or "", args.get("nth"))
        _mouse(cdp, pt["x"], pt["y"])
    finally:
        cdp.close()
    return {"clicked": True}


def verb_type(args):
    doc = load_session(args.get("session_id"))
    text = args.get("text")
    if not isinstance(text, str) or not text:
        raise AgentError("text is required")
    cdp = connect_page(doc["port"], args.get("page_id"))
    try:
        if args.get("selector"):
            pt = _resolve(cdp, args["selector"], None)
            _mouse(cdp, pt["x"], pt["y"])
            res = _call_fn(cdp, JS_FOCUS, [args["selector"], bool(args.get("clear"))])
            if res.get("error"):
                raise AgentError(res["error"])
        cdp.call("Input.insertText", {"text": text})
    finally:
        cdp.close()
    return {"typed_chars": len(text)}


def verb_key(args):
    doc = load_session(args.get("session_id"))
    key, code, vk, text = key_spec(args.get("key") or "")
    mods = 0
    for name in args.get("modifiers") or []:
        if name not in MODIFIERS:
            raise AgentError("unsupported modifier")
        mods |= MODIFIERS[name]
    cdp = connect_page(doc["port"], args.get("page_id"))
    try:
        down = {"type": "keyDown" if text and not mods & 6 else "rawKeyDown", "key": key,
                "code": code, "windowsVirtualKeyCode": vk, "modifiers": mods}
        if text and not mods & 6:
            down["text"] = text
        cdp.call("Input.dispatchKeyEvent", down)
        cdp.call("Input.dispatchKeyEvent", {"type": "keyUp", "key": key, "code": code,
                                            "windowsVirtualKeyCode": vk, "modifiers": mods})
    finally:
        cdp.close()
    return {"pressed": True}


def verb_screenshot(args):
    doc = load_session(args.get("session_id"))
    cdp = connect_page(doc["port"], args.get("page_id"))
    try:
        shot = cdp.call("Page.captureScreenshot", {"format": "png"})
    finally:
        cdp.close()
    raw = base64.b64decode(shot.get("data") or "")
    if not raw.startswith(b"\x89PNG"):
        raise AgentError("the app returned no PNG")  # pragma: no cover
    sdir = session_path(doc["session_id"])
    _mkdir_private(os.path.join(sdir, "shots"))
    path = os.path.join(sdir, "shots", "%d.png" % int(time.time() * 1000))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
    return {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def verb_close(args):
    sid = args.get("session_id")
    if not isinstance(sid, str) or not SID_RE.match(sid):
        raise AgentError("unknown session")
    tomb_path = os.path.join(tombstones_dir(), sid + ".json")
    doc = _read_json(os.path.join(session_path(sid), "session.json"))
    if doc is None:
        tomb = _read_json(tomb_path)
        if tomb:
            return tomb
        raise AgentError("unknown session")
    try:
        open(os.path.join(session_path(sid), "close.req"), "w").close()
    except OSError:  # pragma: no cover
        pass
    deadline = time.time() + 20
    while time.time() < deadline:
        tomb = _read_json(tomb_path)
        if tomb:
            return tomb
        time.sleep(0.25)
    return cleanup_session(sid, "explicit_close_fallback", state="closed")


VERBS = {
    "status": verb_status, "launch": verb_launch, "list_pages": verb_list_pages,
    "inspect": verb_inspect, "click": verb_click, "type": verb_type, "key": verb_key,
    "screenshot": verb_screenshot, "close": verb_close,
}


def main(argv):
    if len(argv) >= 4 and argv[1] == "supervise" and argv[2] == "--session":
        if SID_RE.match(argv[3]):
            supervise(argv[3])
        return 0
    verb = argv[1] if len(argv) > 1 else ""
    try:
        if verb not in VERBS:
            raise AgentError("unknown verb")
        args = {}
        if "--args-b64" in argv:
            args = json.loads(base64.b64decode(argv[argv.index("--args-b64") + 1]).decode("utf-8"))
        if verb not in ("status", "launch"):
            sweep()
        out = {"ok": True, "result": VERBS[verb](args)}
    except AgentError as exc:
        out = {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - last resort, never a traceback with data
        out = {"ok": False, "error": "internal error: %s" % exc.__class__.__name__}
    sys.stdout.write(MARKER + json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
