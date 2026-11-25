import asyncio
import base64
import hashlib
import io
import json
import os
import urllib.error

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cdp_pilot_app import mcp_config, plugin, routes
from cdp_pilot_app.mcp import host_agent, http_handler, remote_host, self_register, tools

SID = "a" * 32
TARGET = {"name": "mini", "host_id": "H1", "app_path": "/Applications/AW Desktop.app",
          "bundle_id": "com.x.app", "team_id": "TEAM123456"}


@pytest.fixture
def cfg():
    state = {"targets": [TARGET], "session_ttl_s": 600, "screenshot_dir": ""}
    tools.set_config_resolver(lambda: state)
    yield state
    tools.set_config_resolver(lambda: {})


@pytest.fixture
def calls(monkeypatch):
    log = []

    def fake_call(host_id, verb, args=None, **kw):
        log.append((host_id, verb, args, kw))
        return {"session_id": SID, "expires_at": 4102444800, "listener": {"loopback_only": True}} \
            if verb == "launch" else {"ok": True}

    monkeypatch.setattr(host_agent, "call", fake_call)
    return log


def test_empty_targets_refuse_every_launch(cfg, calls):
    cfg["targets"] = []
    with pytest.raises(tools.Refused, match="no targets"):
        tools.cdp_launch({"target": "mini"})
    assert calls == []


def test_unknown_target_and_misconfigured(cfg, calls):
    with pytest.raises(tools.Refused, match="unknown target"):
        tools.cdp_launch({"target": "other"})
    with pytest.raises(tools.Refused, match="target must"):
        tools.cdp_launch({"target": 5})
    with pytest.raises(tools.Refused, match="target is required"):
        tools.cdp_launch({})
    cfg["targets"] = ["junk", {"name": "bad", "host_id": "H"}]
    with pytest.raises(tools.Refused, match="misconfigured"):
        tools.cdp_launch({"target": "bad"})
    assert calls == []


def test_launch_registers_session_and_clamps_ttl(cfg, calls):
    cfg["session_ttl_s"] = 99999
    out = json.loads(tools.cdp_launch({"target": "mini"}))
    assert out["session_id"] == SID and out["target"] == "mini"
    host, verb, args, _ = calls[0]
    assert (host, verb) == ("H1", "launch") and args["ttl_s"] == tools.MAX_TTL_S
    assert args["target"]["bundle_id"] == "com.x.app" and "host_id" not in args["target"]
    assert args["target"]["allow_unpinned_team"] is False
    cfg["targets"] = [{**TARGET, "allow_unpinned_team": True}]
    tools.cdp_launch({"target": "mini"})
    assert calls[-1][2]["target"]["allow_unpinned_team"] is True
    cfg["targets"] = [{**TARGET, "allow_unpinned_team": "yes"}]  # only a real boolean opts in
    tools.cdp_launch({"target": "mini"})
    assert calls[-1][2]["target"]["allow_unpinned_team"] is False
    cfg["targets"] = [TARGET]
    cfg["session_ttl_s"] = "junk"
    tools.cdp_launch({"target": "mini"})
    assert calls[-1][2]["ttl_s"] == tools.DEFAULT_TTL_S


def test_session_tools_route_by_registry_and_validate(cfg, calls):
    tools.cdp_launch({"target": "mini"})
    calls.clear()
    tools.cdp_list_pages({"session_id": SID})
    tools.cdp_inspect({"session_id": SID, "selector": "button", "max_nodes": 9999})
    tools.cdp_click({"session_id": SID, "selector": "button", "nth": 1})
    tools.cdp_type({"session_id": SID, "text": "synthetic"})
    tools.cdp_key({"session_id": SID, "key": "Enter", "modifiers": ["Shift"]})
    tools.cdp_close({"session_id": SID})
    assert [c[1] for c in calls] == ["list_pages", "inspect", "click", "type", "key", "close"]
    assert {c[0] for c in calls} == {"H1"}
    assert calls[1][2]["max_nodes"] == 100
    for bad in (None, "", "short", "g" * 32, "../" * 11, "b" * 32):
        with pytest.raises(tools.Refused, match="unknown session"):
            tools.cdp_close({"session_id": bad})


@pytest.mark.parametrize("fn,args,msg", [
    (tools.cdp_inspect, {"max_nodes": "x"}, "max_nodes"),
    (tools.cdp_inspect, {"selector": "a" * 501}, "selector"),
    (tools.cdp_inspect, {"page_id": "../x"}, "page_id"),
    (tools.cdp_click, {"selector": "b", "nth": -1}, "nth"),
    (tools.cdp_click, {"selector": "b", "nth": True}, "nth"),
    (tools.cdp_click, {}, "selector is required"),
    (tools.cdp_type, {}, "text is required"),
    (tools.cdp_type, {"text": "x" * 2001}, "text"),
    (tools.cdp_key, {"key": "a", "modifiers": "Shift"}, "modifiers"),
    (tools.cdp_key, {"key": "a", "modifiers": [1]}, "modifiers"),
])
def test_input_validation(cfg, calls, fn, args, msg):
    tools.cdp_launch({"target": "mini"})
    calls.clear()
    with pytest.raises(tools.Refused, match=msg):
        fn({"session_id": SID, **args})
    assert calls == []


def test_typed_text_never_logged(cfg, calls, caplog):
    tools.cdp_launch({"target": "mini"})
    with caplog.at_level("INFO", logger="aw_apps.cdp-pilot"):
        tools.cdp_type({"session_id": SID, "text": "TOPSECRETTEXT"})
    assert "TOPSECRETTEXT" not in caplog.text and "chars=13" in caplog.text


def test_screenshot_downloads_and_verifies(cfg, calls, monkeypatch, tmp_path):
    png = b"\x89PNG" + b"1" * 100
    sha = hashlib.sha256(png).hexdigest()
    cfg["screenshot_dir"] = str(tmp_path / "shots")
    tools.cdp_launch({"target": "mini"})
    state = {"sha": sha}
    monkeypatch.setattr(host_agent, "call", lambda *a, **k: {"path": "/h/p.png", "sha256": state["sha"]})

    def dl(host, remote, local):
        open(local, "wb").write(png)
        return len(png)

    monkeypatch.setattr(remote_host, "download", dl)
    out = json.loads(tools.cdp_screenshot({"session_id": SID}))
    assert out["sha256"] == sha and os.path.exists(out["local_path"])
    state["sha"] = "0" * 64
    with pytest.raises(RuntimeError, match="verification"):
        tools.cdp_screenshot({"session_id": SID})
    cfg["screenshot_dir"] = ""
    monkeypatch.setenv("AW_WORKSPACE_CONTAINER_DIR", str(tmp_path / "root"))
    assert tools.screenshot_dir().startswith(str(tmp_path / "root"))


def test_concurrent_launches_do_not_lose_sessions(cfg, monkeypatch):
    import threading
    import time as _t

    def fake_call(host_id, verb, args=None, **kw):
        _t.sleep(0.01)
        return {"session_id": os.urandom(16).hex(), "expires_at": 4102444800, "listener": {}}

    monkeypatch.setattr(host_agent, "call", fake_call)
    ids = []

    def one():
        ids.append(json.loads(tools.cdp_launch({"target": "mini"}))["session_id"])

    threads = [threading.Thread(target=one) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(ids) == set(tools._load_registry())


def test_registry_survives_and_expires(cfg, calls, tmp_path):
    tools.cdp_launch({"target": "mini"})
    reg = tools._load_registry()
    assert reg[SID]["host_id"] == "H1"
    reg[SID]["expires_at"] = 1
    tools._save_registry(reg)
    assert tools._load_registry() == {}
    open(tools._registry_path(), "w").write("not json")
    assert tools._load_registry() == {}
    tools.set_config_resolver(lambda: 1 / 0)
    assert tools.current_config() == {}


# -- host_agent bridge -------------------------------------------------------

def test_bridge_uploads_when_stale_and_parses(monkeypatch):
    host_agent._ENSURED.clear()
    host_agent._HOME.clear()
    execs, uploads = [], []
    state = {"version": "old"}

    def fake_exec(host, command, timeout=60):
        execs.append(command)
        if command.startswith("printf"):
            return "/Users/aw", "", 0
        if " status " in command:
            return "noise\n<<<AW_CDP_PILOT_JSON>>>" + json.dumps(
                {"ok": True, "result": {"agent_version": state["version"]}}), "", 0
        return "<<<AW_CDP_PILOT_JSON>>>" + json.dumps({"ok": True, "result": {"x": 1}}), "", 0

    def fake_upload(host, local, remote):
        uploads.append(remote)
        state["version"] = host_agent.agent_version()

    monkeypatch.setattr(remote_host, "exec", fake_exec)
    monkeypatch.setattr(remote_host, "upload", fake_upload)
    assert host_agent.call("H1", "click", {"selector": "it's \"quoted\""}) == {"x": 1}
    assert uploads == ["/Users/aw/.aw-cdp-pilot/agent/aw_cdp_pilot.py"]
    last = execs[-1]
    assert last.startswith("/usr/bin/python3 ") and "it's" not in last  # args are base64
    assert json.loads(base64.b64decode(last.split("--args-b64 ")[1]))["selector"] == "it's \"quoted\""
    n = len(execs)
    host_agent.call("H1", "click")
    assert len(execs) == n + 1  # cached: one exec, no re-probe
    assert host_agent.ensure_agent("H1")["uploaded"] is False
    host_agent._ENSURED.clear()
    assert host_agent.ensure_agent("H1")["uploaded"] is False  # host already current


def test_bridge_status_failure_triggers_upload(monkeypatch):
    host_agent._ENSURED.clear()
    host_agent._HOME["H1"] = "/h"
    replies = iter([RuntimeError("absent"), None])

    def fake_call(host, verb, args=None, **kw):
        nxt = next(replies)
        if nxt:
            raise nxt
        return {"agent_version": host_agent.agent_version()}

    monkeypatch.setattr(host_agent, "call", fake_call)
    uploads = []
    monkeypatch.setattr(remote_host, "upload", lambda *a: uploads.append(a))
    assert host_agent.ensure_agent("H1")["uploaded"] is True and uploads


def test_bridge_errors(monkeypatch):
    host_agent._ENSURED.clear()
    host_agent._HOME.clear()
    monkeypatch.setattr(remote_host, "exec", lambda *a, **k: ("", "", 1))
    with pytest.raises(RuntimeError, match="HOME"):
        host_agent.remote_agent_path("H1")
    with pytest.raises(host_agent.HostError, match="no result"):
        host_agent._parse("junk", "", 127, "launch")
    refused = "<<<AW_CDP_PILOT_JSON>>>" + json.dumps({"ok": False, "error": "nope"})
    with pytest.raises(host_agent.HostError, match="nope"):
        host_agent._parse(refused, "", 0, "launch")
    with pytest.raises(host_agent.HostError, match="failed on the host"):
        host_agent._parse("<<<AW_CDP_PILOT_JSON>>>" + json.dumps({"ok": False}), "", 0, "x")
    host_agent._HOME["H1"] = "/h"
    monkeypatch.setattr(remote_host, "exec", lambda *a, **k: (
        "<<<AW_CDP_PILOT_JSON>>>" + json.dumps({"ok": True, "result": {"agent_version": "9"}}), "", 0))
    monkeypatch.setattr(remote_host, "upload", lambda *a, **k: None)
    with pytest.raises(RuntimeError, match="different version"):
        host_agent.ensure_agent("H1", force=True)


# -- remote_host transport ---------------------------------------------------------

class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def test_remote_host_not_configured_and_env_file(tmp_path, monkeypatch):
    assert remote_host.configured() is False
    with pytest.raises(remote_host.NotConfigured):
        remote_host.exec("H", "x")
    env = tmp_path / "wshome" / ".env"
    env.write_text("AW_BACKEND_URL='http://b'\nAW_WORKSPACE=ws\nAW_WORKSPACE_HOST_TOKEN=tok\nJUNK\n")
    assert remote_host.configured() is True
    assert remote_host._cfg() == ("http://b", "ws", "tok")
    monkeypatch.setenv("AW_WORKSPACE", "fromenv")
    assert remote_host._cfg()[1] == "fromenv"


def test_remote_host_exec_upload_download(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_BACKEND_URL", "http://b/")
    monkeypatch.setenv("AW_WORKSPACE", "ws")
    monkeypatch.setenv("AW_WORKSPACE_HOST_TOKEN", "tok")
    seen = []

    def urlopen(req, timeout=0):
        seen.append((req.get_method(), req.full_url, dict(req.headers)))
        if req.full_url.endswith("/exec"):
            return Resp(b'{"job_id":"J"}')
        if "/wait" in req.full_url:
            return Resp(b'{"stdout":"o","stderr":"e","exit_code":2}')
        if "/fs/download" in req.full_url:
            return Resp(b"PNGDATA")
        return Resp(b"")

    monkeypatch.setattr(remote_host.urllib.request, "urlopen", urlopen)
    assert remote_host.exec("H 1", "ls") == ("o", "e", 2)
    assert "remote-hosts/H%201/exec" in seen[0][1]
    src = tmp_path / "f.py"
    src.write_text("x")
    assert remote_host.upload("H", str(src), "/r/f.py") == {}
    dest = tmp_path / "d" / "o.png"
    assert remote_host.download("H", "/r/o.png", str(dest)) == 7
    assert dest.read_bytes() == b"PNGDATA" and oct(dest.stat().st_mode & 0o777) == "0o600"

    def no_job(req, timeout=0):
        return Resp(b"{}")

    monkeypatch.setattr(remote_host.urllib.request, "urlopen", no_job)
    with pytest.raises(RuntimeError, match="job_id"):
        remote_host.exec("H", "x")

    def http_err(req, timeout=0):
        raise urllib.error.HTTPError(req.full_url, 502, "bad", {}, io.BytesIO(b"SECRET-BODY"))

    monkeypatch.setattr(remote_host.urllib.request, "urlopen", http_err)
    for call in (lambda: remote_host.exec("H", "x"),
                 lambda: remote_host.upload("H", str(src), "/r"),
                 lambda: remote_host.download("H", "/r", str(dest))):
        with pytest.raises(RuntimeError, match="HTTP 502") as exc:
            call()
        assert "SECRET-BODY" not in str(exc.value)


# -- MCP handler, routes, plugin ----------------------------------------------------------

def rpc(method, params=None, rid=1):
    return asyncio.run(http_handler.handle_request(
        {"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}))


def test_mcp_handler(cfg, calls, monkeypatch):
    assert rpc("initialize")["result"]["serverInfo"]["name"] == "aw-cdp-pilot"
    assert rpc("notifications/initialized") is None
    names = [t["name"] for t in rpc("tools/list")["result"]["tools"]]
    assert names == ["cdp_launch", "cdp_list_pages", "cdp_inspect", "cdp_click", "cdp_type",
                     "cdp_key", "cdp_screenshot", "cdp_close"]
    assert rpc("nope")["error"]["code"] == -32601
    assert rpc("tools/call", {"name": "zzz"})["result"]["isError"] is True
    ok = rpc("tools/call", {"name": "cdp_launch", "arguments": {"target": "mini"}})
    assert ok["result"]["isError"] is False and SID in ok["result"]["content"][0]["text"]
    refused = rpc("tools/call", {"name": "cdp_launch", "arguments": {"target": "zz"}})
    assert refused["result"]["isError"] is True
    monkeypatch.setitem(tools.HANDLERS, "cdp_close",
                        lambda a: (_ for _ in ()).throw(remote_host.NotConfigured("nc")))
    assert "nc" in rpc("tools/call", {"name": "cdp_close"})["result"]["content"][0]["text"]
    monkeypatch.setitem(tools.HANDLERS, "cdp_close", lambda a: 1 / 0)
    boom = rpc("tools/call", {"name": "cdp_close"})
    assert boom["result"]["isError"] is True


def test_no_tool_accepts_host_path_port_or_script():
    forbidden = {"host", "host_id", "path", "port", "pid", "url", "script", "expression",
                 "eval", "profile", "app_path"}
    for tool in tools.TOOLS:
        assert not forbidden & set(tool["inputSchema"]["properties"]), tool["name"]


def test_routes_and_mcp_endpoint(cfg, calls):
    class Ctx:
        pass

    client = TestClient(routes.build_routes(Ctx()))
    status = client.get("/status").json()
    assert status["targets"] == ["mini"] and status["tool_count"] == 8
    assert client.get("/mcp.json").status_code == 404  # never serve the workspace key over HTTP
    assert client.get("/mcp").status_code == 405
    one = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert len(one.json()["result"]["tools"]) == 8
    batch = client.post("/mcp", json=[{"jsonrpc": "2.0", "id": 1, "method": "initialize"}])
    assert isinstance(batch.json(), list)
    assert client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}
                       ).status_code == 202


def test_mcp_json_written_private_and_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_WORKSPACE_API_KEY", "k")
    monkeypatch.setenv("AW_PORT", "9111")
    doc = mcp_config.write_mcp_json(str(tmp_path))
    path = tmp_path / "mcp.json"
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert doc["mcpServers"]["aw-cdp-pilot"]["headers"] == {"X-Api-Key": "k"}
    mtime = path.stat().st_mtime_ns
    mcp_config.write_mcp_json(str(tmp_path))
    assert path.stat().st_mtime_ns == mtime  # unchanged write skipped
    monkeypatch.delenv("AW_WORKSPACE_API_KEY")
    assert "headers" not in self_register.build_self_entry()


def test_plugin_activate(tmp_path, monkeypatch):
    mounted = []

    class Routes:
        def register(self, app):
            mounted.append(app)

    class Ctx:
        config = {"targets": [TARGET]}
        package_dir = str(tmp_path)
        routes = Routes()

    p = plugin.CdpPilotPlugin()
    asyncio.run(p.activate(Ctx()))
    assert isinstance(mounted[0], FastAPI) and (tmp_path / "mcp.json").exists()
    cfg = tools.current_config()
    assert cfg["targets"] == [TARGET] and cfg["session_ttl_s"] == tools.DEFAULT_TTL_S
    Ctx.config = {}
    asyncio.run(p.activate(Ctx()))
    assert tools.current_config()["targets"] == []  # default EMPTY: fail closed
    asyncio.run(p.deactivate())
    tools.set_config_resolver(lambda: {})


def test_remote_host_exec_waits_through_running_snapshots(monkeypatch):
    """A wait snapshot with no exit_code means still running, never exit 0."""
    monkeypatch.setenv("AW_BACKEND_URL", "http://b")
    monkeypatch.setenv("AW_WORKSPACE", "ws")
    monkeypatch.setenv("AW_WORKSPACE_HOST_TOKEN", "tok")
    waits = []

    def urlopen(req, timeout=0):
        if req.full_url.endswith("/exec"):
            return Resp(b'{"job_id":"J"}')
        waits.append(1)
        if len(waits) < 3:
            return Resp(b'{"status":"running","stdout":"partial"}')
        return Resp(b'{"stdout":"done","stderr":"","exit_code":0}')

    monkeypatch.setattr(remote_host.urllib.request, "urlopen", urlopen)
    assert remote_host.exec("H", "x", timeout=30) == ("done", "", 0)
    assert len(waits) == 3

    # Never finishing within the budget is an error, not a success.
    clock = iter([0, 0, 5, 5, 40, 40, 80, 80])
    monkeypatch.setattr(remote_host.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(remote_host.urllib.request, "urlopen", lambda req, timeout=0: (
        Resp(b'{"job_id":"J"}') if req.full_url.endswith("/exec") else Resp(b'{"status":"running"}')))
    with pytest.raises(RuntimeError, match="time budget"):
        remote_host.exec("H", "x", timeout=30)
