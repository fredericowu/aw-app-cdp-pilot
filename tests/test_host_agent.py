import base64
import json
import os
import sys
import time
from pathlib import Path

import pytest


def b64(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode()


def launch(agent, make_exe, mode="ok", ttl=120):
    return agent.verb_launch({"target": {"name": "t", "_exe": make_exe(mode)}, "ttl_s": ttl})


def test_full_session_lifecycle_and_cleanup(agent, make_exe):
    res = launch(agent, make_exe)
    sid = res["session_id"]
    assert len(sid) == 32 and res["listener"]["loopback_only"] is True
    pages = agent.verb_list_pages({"session_id": sid})["pages"]
    assert [p["page_id"] for p in pages] == ["PAGE1"]  # service worker excluded
    assert pages[0]["url"] == "file:///x/index.html"  # query + fragment dropped
    assert "SECRET" not in json.dumps(pages)
    ins = agent.verb_inspect({"session_id": sid, "selector": "button", "max_nodes": 5})
    assert ins["nodes"][0]["text"] == "Log in"
    assert agent.verb_inspect({"session_id": sid})["count"] == 1  # default selector
    assert agent.verb_click({"session_id": sid, "selector": "button"}) == {"clicked": True}
    assert agent.verb_type({"session_id": sid, "text": "abc"}) == {"typed_chars": 3}
    assert agent.verb_type({"session_id": sid, "text": "xy", "selector": "input",
                            "clear": True}) == {"typed_chars": 2}
    assert agent.verb_key({"session_id": sid, "key": "Enter"}) == {"pressed": True}
    assert agent.verb_key({"session_id": sid, "key": "a", "modifiers": ["Shift", "Control"]})
    shot = agent.verb_screenshot({"session_id": sid})
    assert os.path.getsize(shot["path"]) == shot["bytes"] > 65536  # 64-bit frame path
    sdir = Path(agent.session_path(sid))
    assert oct(sdir.stat().st_mode & 0o777) == "0o700"
    # A second launch is refused and does not reveal the existing id.
    with pytest.raises(agent.AgentError) as exc:
        launch(agent, make_exe)
    assert sid not in str(exc.value)
    tomb = agent.verb_close({"session_id": sid})
    assert tomb["state"] == "closed" and tomb["reason"] == "explicit_close"
    assert all(tomb["checks"].values())
    assert not sdir.exists()
    # Closing again returns the same tombstone; other verbs name the final state.
    assert agent.verb_close({"session_id": sid})["session_id"] == sid
    with pytest.raises(agent.AgentError, match="closed"):
        agent.verb_list_pages({"session_id": sid})


def test_ttl_expiry_cleans_up(agent, make_exe):
    sid = "a" * 32
    sdir = Path(agent.session_path(sid))
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(str(sdir))
    agent._mkdir_private(str(sdir / "profile"))
    agent._write_json(str(sdir / "session.json"), {
        "session_id": sid, "exe": make_exe(), "profile": str(sdir / "profile"),
        "started_at": int(time.time()), "expires_at": time.time() + 1.5})
    agent.supervise(sid)
    tomb = json.loads((Path(agent.tombstones_dir()) / f"{sid}.json").read_text())
    assert tomb["state"] == "expired" and tomb["reason"] == "ttl_expired"
    assert all(tomb["checks"].values()) and not sdir.exists()
    assert agent.verb_close({"session_id": sid})["state"] == "expired"


@pytest.mark.parametrize("mode,reason", [("exit_now", "app_exited_before_port"),
                                         ("hang", "no_port_in_time")])
def test_supervisor_fails_closed_without_a_port(agent, make_exe, monkeypatch, mode, reason):
    monkeypatch.setattr(agent, "LAUNCH_WAIT_S", 2)
    sid = "b" * 32
    sdir = Path(agent.session_path(sid))
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(str(sdir))
    agent._write_json(str(sdir / "session.json"), {
        "session_id": sid, "exe": make_exe(mode), "profile": str(sdir / "profile"),
        "started_at": int(time.time()), "expires_at": time.time() + 60})
    agent.supervise(sid)
    tomb = json.loads((Path(agent.tombstones_dir()) / f"{sid}.json").read_text())
    assert tomb["state"] == "failed" and tomb["reason"] == reason
    assert tomb["checks"]["process_group_gone"] and not sdir.exists()


def test_supervisor_notices_app_exit(agent, make_exe):
    sid = "c" * 32
    sdir = Path(agent.session_path(sid))
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(str(sdir))
    agent._write_json(str(sdir / "session.json"), {
        "session_id": sid, "exe": make_exe("exit_soon"), "profile": str(sdir / "profile"),
        "started_at": int(time.time()), "expires_at": time.time() + 60})
    agent.supervise(sid)
    tomb = json.loads((Path(agent.tombstones_dir()) / f"{sid}.json").read_text())
    assert tomb["reason"] == "app_exited" and all(tomb["checks"].values())


def test_supervise_edge_cases(agent, tmp_path):
    agent.supervise("d" * 32)  # no session record: no-op
    sid = "e" * 32
    sdir = Path(agent.session_path(sid))
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(str(sdir))
    agent._write_json(str(sdir / "session.json"), {
        "exe": str(tmp_path / "missing"), "profile": "p", "expires_at": time.time() + 5})
    agent.supervise(sid)
    assert agent._read_json(str(sdir / "session.json"))["state"] == "failed"


def test_launch_failure_paths(agent, make_exe, monkeypatch):
    monkeypatch.setattr(agent, "LAUNCH_WAIT_S", 1)
    with pytest.raises(agent.AgentError, match="launch failed"):
        launch(agent, make_exe, "exit_now")
    assert agent._active_session() is None
    agent._state["bind"] = "0.0.0.0"
    with pytest.raises(agent.AgentError, match="loopback-only"):
        launch(agent, make_exe)
    assert agent._active_session() is None and not list(Path(agent.sessions_dir()).glob("*"))
    monkeypatch.setattr(agent, "LAUNCH_WAIT_S", 0)  # supervisor gives up at once
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    # Force the launcher's own wait loop to time out against a never-running record.
    monkeypatch.setattr(agent.subprocess, "Popen", lambda *a, **k: None)
    monkeypatch.setattr(agent, "LAUNCH_WAIT_S", -9)
    with pytest.raises(agent.AgentError, match="never opened"):
        launch(agent, make_exe)


def test_launch_reports_failed_record(agent, make_exe, monkeypatch):
    real_popen = agent.subprocess.Popen

    def fake_popen(argv, **kw):
        sid = argv[-1]
        p = agent.session_path(sid) + "/session.json"
        doc = agent._read_json(p)
        doc.update(state="failed", error="spawn failed: OSError")
        agent._write_json(p, doc)
        return None

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    with pytest.raises(agent.AgentError, match="spawn failed"):
        launch(agent, make_exe)
    del real_popen


def test_launch_vanished_session(agent, make_exe, monkeypatch):
    def fake_popen(argv, **kw):
        agent.cleanup_session(argv[-1], "gone", state="failed")

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    with pytest.raises(agent.AgentError, match="gone"):
        launch(agent, make_exe)


def test_ttl_is_clamped(agent, make_exe):
    sid = launch(agent, make_exe, ttl=999999)["session_id"]
    doc = agent._read_json(os.path.join(agent.session_path(sid), "session.json"))
    assert doc["expires_at"] - doc["started_at"] == agent.MAX_TTL_S
    agent.verb_close({"session_id": sid})


def test_load_session_refusals(agent, make_exe):
    for bad in (None, 5, "short", "z" * 32, "../" * 11):
        with pytest.raises(agent.AgentError, match="unknown session"):
            agent.load_session(bad)
    with pytest.raises(agent.AgentError, match="unknown session"):
        agent.load_session("f" * 32)
    with pytest.raises(agent.AgentError, match="unknown session"):
        agent.verb_close({"session_id": "f" * 32})
    with pytest.raises(agent.AgentError, match="unknown session"):
        agent.verb_close({"session_id": "bad"})
    sid = launch(agent, make_exe)["session_id"]
    p = os.path.join(agent.session_path(sid), "session.json")
    good = agent._read_json(p)
    agent._write_json(p, {**good, "state": "starting"})
    with pytest.raises(agent.AgentError, match="not running"):
        agent.load_session(sid)
    agent._write_json(p, {**good, "pid_start": "Thu Jan  1 00:00:00 1970"})
    with pytest.raises(agent.AgentError, match="process is gone"):
        agent.load_session(sid)
    agent._write_json(p, {**good, "port": good["port"] + 1})
    with pytest.raises(agent.AgentError, match="no longer owns"):
        agent.load_session(sid)
    agent._write_json(p, good)
    agent._state["bind"] = "0.0.0.0"
    with pytest.raises(agent.AgentError, match="no longer owns"):
        agent.load_session(sid)
    agent._state["bind"] = "127.0.0.1"
    agent.verb_close({"session_id": sid})


def test_sweep_cleans_orphans_and_prunes(agent, make_exe):
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(agent.tombstones_dir())
    # supervisor lost
    lost = "1" * 32
    d = Path(agent.session_path(lost))
    agent._mkdir_private(str(d))
    agent._write_json(str(d / "session.json"), {
        "session_id": lost, "supervisor_pid": 999999, "supervisor_start": "x",
        "started_at": int(time.time()), "expires_at": time.time() + 99, "pid": 999998,
        "pgid": 999998, "port": 1})
    # supervisor booting (no pid yet, fresh): left alone
    boot = "2" * 32
    b = Path(agent.session_path(boot))
    agent._mkdir_private(str(b))
    agent._write_json(str(b / "session.json"), {"started_at": int(time.time()),
                                                "expires_at": time.time() + 99})
    # overdue though the supervisor looks alive (this very test process)
    over = "3" * 32
    o = Path(agent.session_path(over))
    agent._mkdir_private(str(o))
    agent._write_json(str(o / "session.json"), {
        "supervisor_pid": os.getpid(), "supervisor_start": agent.proc_start(os.getpid()),
        "started_at": 1, "expires_at": 1})
    # half-created, old; and a non-session entry
    half = "4" * 32
    h = Path(agent.session_path(half))
    agent._mkdir_private(str(h))
    os.utime(h, (1, 1))
    (Path(agent.sessions_dir()) / "not-a-session").mkdir()
    old = Path(agent.tombstones_dir()) / "old.json"
    old.write_text("{}")
    os.utime(old, (1, 1))
    agent.sweep()
    left = {p.name for p in Path(agent.sessions_dir()).iterdir()}
    assert left == {boot, "not-a-session"}
    reasons = {s: agent._read_json(f"{agent.tombstones_dir()}/{s}.json")["reason"]
               for s in (lost, over, half)}
    assert reasons == {lost: "supervisor_lost", over: "ttl_overdue", half: "orphaned_dir"}
    assert not old.exists()
    agent._prune_tombstones()


def test_sweep_and_prune_without_dirs(agent):
    agent.sweep()  # nothing exists yet: must not raise
    agent._prune_tombstones()
    assert agent._active_session() is None


def test_cleanup_kills_a_surviving_group(agent, make_exe):
    sid = launch(agent, make_exe)["session_id"]
    p = os.path.join(agent.session_path(sid), "session.json")
    doc = agent._read_json(p)
    os.kill(doc["supervisor_pid"], 9)  # supervisor dies; the app is orphaned
    time.sleep(0.3)
    assert agent.group_members(doc["pgid"])
    agent.sweep()
    tomb = agent._read_json(f"{agent.tombstones_dir()}/{sid}.json")
    assert tomb["reason"] == "supervisor_lost" and tomb["signalled"] is True
    assert all(tomb["checks"].values())
    assert not agent.group_members(doc["pgid"])


def test_cleanup_never_signals_a_recycled_pid(agent):
    import subprocess
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                              start_new_session=True)  # its own group leader
    try:
        sid = "9" * 32
        d = Path(agent.session_path(sid))
        agent._mkdir_private(str(d))
        # the recorded leader exists but its start time differs: a recycled pid
        agent._write_json(str(d / "session.json"), {
            "pid": victim.pid, "pgid": victim.pid, "pid_start": "not-the-start", "port": 1})
        tomb = agent.cleanup_session(sid, "test")
        assert tomb["signalled"] is False and victim.poll() is None
    finally:
        victim.kill()
        victim.wait()


def test_verify_target(agent, tmp_path, monkeypatch):
    real = sys.modules["aw_cdp_pilot"]
    monkeypatch.setattr(real, "verify_target", real._real_verify)
    with pytest.raises(real.AgentError, match="not darwin"):
        real.verify_target({})
    monkeypatch.setattr(real.sys, "platform", "darwin")
    with pytest.raises(real.AgentError, match="absolute"):
        real.verify_target({"app_path": "rel.app"})
    app = tmp_path / "X.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    target = {"app_path": str(app), "bundle_id": "com.x", "team_id": ""}
    with pytest.raises(real.AgentError, match="Info.plist"):
        real.verify_target(target)
    import plistlib
    plist = app / "Contents" / "Info.plist"
    plist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.other", "CFBundleExecutable": "X"}))
    with pytest.raises(real.AgentError, match="bundle identifier"):
        real.verify_target(target)
    plist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.x", "CFBundleExecutable": "../X"}))
    with pytest.raises(real.AgentError, match="CFBundleExecutable"):
        real.verify_target(target)
    plist.write_bytes(plistlib.dumps({"CFBundleIdentifier": "com.x", "CFBundleExecutable": "X"}))
    with pytest.raises(real.AgentError, match="not runnable"):
        real.verify_target(target)
    exe = app / "Contents" / "MacOS" / "X"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert real.verify_target(target) == str(exe)
    # codesign team check
    monkeypatch.setattr(real, "_run", lambda argv, timeout=15: (0, "", "TeamIdentifier=ABC123\n"))
    assert real.verify_target({**target, "team_id": "ABC123"}) == str(exe)
    with pytest.raises(real.AgentError, match="TeamIdentifier"):
        real.verify_target({**target, "team_id": "OTHER"})
    monkeypatch.setattr(real, "_run", lambda argv, timeout=15: (1, "", ""))
    with pytest.raises(real.AgentError, match="TeamIdentifier"):
        real.verify_target({**target, "team_id": "ABC123"})
    # a symlinked app path is refused
    link = tmp_path / "Link.app"
    link.symlink_to(app)
    with pytest.raises(real.AgentError, match="realpath"):
        real.verify_target({**target, "app_path": str(link)})


def test_process_probes_parse_tool_output(agent, monkeypatch):
    monkeypatch.setattr(agent, "_run", lambda argv, timeout=15: (
        0, "p1\nn127.0.0.1:5000\nn[::1]:5001\nn*:bad\n", ""))
    assert agent._real_listeners(1) == [("127.0.0.1", 5000), ("::1", 5001)]
    monkeypatch.setattr(agent, "_run", lambda argv, timeout=15: (
        0, "  10 77 Ss\n  11 77 Z\n  12 88 S\nbroken\n", ""))
    assert agent.group_members(77) == [10]
    monkeypatch.setattr(agent, "_run", lambda argv, timeout=15: (1, "", ""))
    assert agent.proc_start(1) == ""
    assert agent.same_process(None, "x") is False
    assert agent.pid_alive(999999) is False and agent.pid_alive(os.getpid()) is True
    monkeypatch.setattr(agent.os, "kill", lambda pid, sig: (_ for _ in ()).throw(PermissionError()))
    assert agent.pid_alive(1) is True


def test_real_run_helper(agent):
    code, out, _err = agent._run([sys.executable, "-c", "print('hi')"])
    assert code == 0 and out.strip() == "hi"


def test_port_discovery_fallback(agent, tmp_path):
    sdir = tmp_path / "s"
    (sdir / "profile").mkdir(parents=True)
    assert agent.discover_port(str(sdir), str(sdir / "none")) is None
    (sdir / "profile" / "DevToolsActivePort").write_text("4321\n/devtools/browser/x\n")
    assert agent.discover_port(str(sdir), str(sdir / "none")) == 4321
    (sdir / "profile" / "DevToolsActivePort").write_text("junk\n")
    assert agent.discover_port(str(sdir), str(sdir / "none")) is None


def test_connect_page_guards(agent, make_exe):
    sid = launch(agent, make_exe)["session_id"]
    port = agent._read_json(os.path.join(agent.session_path(sid), "session.json"))["port"]
    with pytest.raises(agent.AgentError, match="unknown page_id"):
        agent.connect_page(port, "NOPE")
    agent.connect_page(port, "PAGE1").close()
    with pytest.raises(agent.AgentError, match="no visible match"):
        agent.verb_click({"session_id": sid, "selector": "no-such"})
    with pytest.raises(agent.AgentError, match="page function failed"):
        agent.verb_inspect({"session_id": sid, "selector": "boom"})
    with pytest.raises(agent.AgentError, match="no visible match"):
        agent.verb_type({"session_id": sid, "text": "t", "selector": "no-such"})
    with pytest.raises(agent.AgentError, match="no match"):
        agent.verb_type({"session_id": sid, "text": "t", "selector": "focus-miss"})
    cdp = agent.connect_page(port, "PAGE1")
    with pytest.raises(agent.AgentError, match="nope"):
        cdp.call("Input.fail")
    cdp.close()
    agent.verb_close({"session_id": sid})


@pytest.mark.parametrize("mode,msg", [("evil_ws", "loopback port"), ("no_pages", "no page targets")])
def test_connect_page_rejects_bad_targets(agent, make_exe, mode, msg):
    sid = launch(agent, make_exe, mode)["session_id"]
    with pytest.raises(agent.AgentError, match=msg):
        agent.verb_click({"session_id": sid, "selector": "button"})
    agent.verb_close({"session_id": sid})


def test_key_validation(agent):
    assert agent.key_spec("Enter")[3] == "\r"
    assert agent.key_spec("7")[1] == "Digit7" and agent.key_spec("q")[1] == "KeyQ"
    for bad in ("", "F13", "é", "ab"):
        with pytest.raises(agent.AgentError, match="unsupported key"):
            agent.key_spec(bad)


def test_verbs_validate_inputs(agent, make_exe):
    sid = launch(agent, make_exe)["session_id"]
    with pytest.raises(agent.AgentError, match="text is required"):
        agent.verb_type({"session_id": sid, "text": ""})
    with pytest.raises(agent.AgentError, match="unsupported modifier"):
        agent.verb_key({"session_id": sid, "key": "a", "modifiers": ["Hyper"]})
    agent.verb_close({"session_id": sid})


def test_ws_edge_cases(agent):
    import socket
    import threading

    def serve(handler):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        threading.Thread(target=lambda: handler(srv.accept()[0]), daemon=True).start()
        return srv.getsockname()[1]

    port = serve(lambda c: (c.recv(4096), c.sendall(b"HTTP/1.1 200 OK\r\n\r\n"), c.close()))
    with pytest.raises(agent.AgentError, match="upgrade refused"):
        agent.WS(port, "/x")
    port = serve(lambda c: (c.recv(4096), c.close()))
    with pytest.raises(agent.AgentError, match="handshake closed"):
        agent.WS(port, "/x")
    port = serve(lambda c: (c.recv(4096), c.sendall(b"HTTP/1.1 101 x\r\n" + b"a" * 70000)))
    with pytest.raises(agent.AgentError, match="too large"):
        agent.WS(port, "/x")

    def close_frame(c):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 101 x\r\n\r\n" + bytes([0x88, 0]))
    port = serve(close_frame)
    ws = agent.WS(port, "/x")
    with pytest.raises(agent.AgentError, match="closed by the app"):
        ws.recv_text()
    ws.close()

    def drop(c):
        c.recv(4096)
        c.sendall(b"HTTP/1.1 101 x\r\n\r\n")
        c.close()
    port = serve(drop)
    ws = agent.WS(port, "/x")
    with pytest.raises(agent.AgentError, match="websocket closed"):
        ws.recv_text()
    # masked server frame + small/medium send paths
    keep = []
    port = serve(lambda c: (keep.append(c), c.recv(4096), c.sendall(
        b"HTTP/1.1 101 x\r\n\r\n" + bytes([0x81, 0x82]) + b"\x01\x02\x03\x04"
        + bytes([ord("h") ^ 1, ord("i") ^ 2])), time.sleep(2)))
    ws = agent.WS(port, "/x")
    assert ws.recv_text() == "hi"
    ws.send_text("x" * 200)
    ws.send_text("y" * 70000)
    ws.close()
    ws.close()


def test_cdp_call_timeout(agent, monkeypatch):
    class Fake:
        def send_text(self, t):
            pass

        def recv_text(self):
            return json.dumps({"id": 999, "result": {}})

        def close(self):
            pass

    cdp = agent.CDP.__new__(agent.CDP)
    cdp.ws, cdp.next_id, cdp.timeout = Fake(), 0, 0.2
    with pytest.raises(agent.AgentError, match="timed out"):
        cdp.call("X.y")


def test_main_entrypoints(agent, make_exe, capsys, monkeypatch):
    def run(*argv):
        capsys.readouterr()
        agent.main(["x", *argv])
        out = capsys.readouterr().out
        return json.loads(out[out.rfind(agent.MARKER) + len(agent.MARKER):])

    assert run("status")["result"]["agent_version"] == agent.VERSION
    assert run("nope") == {"ok": False, "error": "unknown verb"}
    assert run("list_pages", "--args-b64", b64({"session_id": "x"}))["ok"] is False
    monkeypatch.setitem(agent.VERBS, "status", lambda a: 1 / 0)
    assert run("status") == {"ok": False, "error": "internal error: ZeroDivisionError"}
    assert agent.main(["x", "supervise", "--session", "not-hex"]) == 0
    assert agent.main(["x", "supervise", "--session", "a" * 32]) == 0


def _recv_server(frames):
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    keep = []

    def run():
        c = srv.accept()[0]
        keep.append(c)
        c.recv(4096)
        c.sendall(b"HTTP/1.1 101 x\r\n\r\n" + frames)
        time.sleep(1)

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


def test_ws_medium_frames_and_stray_pong(agent):
    body = b"m" * 300
    import struct
    port = _recv_server(bytes([0x8A, 0]) + bytes([0x81, 126]) + struct.pack(">H", 300) + body)
    ws = agent.WS(port, "/x")
    assert ws.recv_text() == body.decode()
    ws.close()


def test_page_function_errors(agent, make_exe):
    sid = launch(agent, make_exe)["session_id"]
    with pytest.raises(agent.AgentError, match="no visible match"):
        agent.verb_inspect({"session_id": sid, "selector": "no-such"})

    class NoGlobal:
        def call(self, method, params=None):
            return {"result": {}}

    with pytest.raises(agent.AgentError, match="global object"):
        agent._call_fn(NoGlobal(), "function(){}", [])
    agent.verb_close({"session_id": sid})


def test_close_request_is_honoured_by_supervisor(agent, make_exe):
    sid = "7" * 32
    sdir = Path(agent.session_path(sid))
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(str(sdir))
    agent._write_json(str(sdir / "session.json"), {
        "session_id": sid, "exe": make_exe(), "profile": str(sdir / "profile"),
        "started_at": int(time.time()), "expires_at": time.time() + 120})
    (sdir / "close.req").write_text("")
    agent.supervise(sid)
    assert agent._read_json(f"{agent.tombstones_dir()}/{sid}.json")["reason"] == "explicit_close"


def test_close_falls_back_when_supervisor_never_answers(agent, monkeypatch):
    sid = "8" * 32
    sdir = Path(agent.session_path(sid))
    agent._mkdir_private(agent.sessions_dir())
    agent._mkdir_private(str(sdir))
    agent._write_json(str(sdir / "session.json"), {"session_id": sid, "started_at": 1})
    clock = iter(range(0, 10**6, 10))
    monkeypatch.setattr(agent.time, "time", lambda: next(clock))
    monkeypatch.setattr(agent.time, "sleep", lambda s: None)
    tomb = agent.verb_close({"session_id": sid})
    assert tomb["reason"] == "explicit_close_fallback" and tomb["state"] == "closed"
