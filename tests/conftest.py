import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FAKE = Path(__file__).resolve().parent / "fake_app.py"


def _load_agent():
    spec = importlib.util.spec_from_file_location(
        "aw_cdp_pilot", ROOT / "cdp_pilot_app" / "host_agent" / "aw_cdp_pilot.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aw_cdp_pilot"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_CDP_PILOT_HOME", str(tmp_path / "pilot"))
    mod = _load_agent()
    mod._real_verify, mod._real_listeners = mod.verify_target, mod.listeners_for
    # The real macOS probes are patched at their seams; tests run on Linux.
    monkeypatch.setattr(mod, "verify_target", lambda target: target["_exe"])
    state = {"bind": "127.0.0.1"}

    def fake_listeners(pid):
        import json
        for sdir in Path(mod.sessions_dir()).glob("*"):
            doc = json.loads((sdir / "session.json").read_text()) if (sdir / "session.json").exists() else {}
            real = mod.discover_port(str(sdir), str(sdir / "app.stderr"))
            if doc.get("pid") == pid and real and mod.pid_alive(pid):
                return [(state["bind"], real)]
        return []

    monkeypatch.setattr(mod, "listeners_for", fake_listeners)
    mod._state = state
    return mod


@pytest.fixture
def make_exe(tmp_path):
    def make(mode="ok"):
        path = tmp_path / f"app-{mode}"
        path.write_text(f"#!/bin/sh\nFAKE_APP_MODE={mode} exec {sys.executable} {FAKE}\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return str(path)
    return make


@pytest.fixture(autouse=True)
def _isolated_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("AW_WORKSPACE_HOME", str(tmp_path / "wshome"))
    monkeypatch.setenv("AW_WORKSPACE_CONTAINER_DIR", str(tmp_path / "ws"))
    for key in ("AW_BACKEND_URL", "AW_WORKSPACE", "AW_WORKSPACE_HOST_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    os.makedirs(tmp_path / "wshome", exist_ok=True)
