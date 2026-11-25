# cdp-pilot architecture

Tier-1 in-process app exposing 8 MCP tools. Each call is one exec of a single-file,
stdlib-only Python host agent (`cdp_pilot_app/host_agent/aw_cdp_pilot.py`, uploaded when
the host's `agent_version` differs) over aw-remote-hosts.

- **Launch**: the agent verifies the target (realpath, bundle id, `codesign --verify --deep --strict` plus the Team ID as a designated requirement; a target with no `team_id` is refused unless `allow_unpinned_team` is true), then starts
  a detached supervisor (own session, stdio to a file). The supervisor spawns the app in its
  own process group with `--remote-debugging-port=0 --user-data-dir=<session>/profile`
  (no address flag), learns the port from the "DevTools listening" line (fallback
  `DevToolsActivePort`), and the agent confirms via `lsof` the listener is loopback-only.
- **Cleanup owner**: the supervisor (TTL, explicit close request file, app exit). Every verb also
  sweeps sessions whose supervisor is dead. Cleanup SIGTERM/SIGKILLs the app's process group,
  verifies no members/listener remain, removes the session dir and writes a 24h tombstone.
  The app leader is its own group (not the supervisor's) so the supervisor survives to write
  the tombstone.
- **Addressing**: a 128-bit opaque session id only; the recorded pid must still own the
  recorded loopback port. Unknown ids are refused.
- **Inspection**: fixed page functions with the selector as a JSON argument; no eval.
- **Screenshots**: staged in the session dir, pulled via fs/download (exec stdout caps at 1 MiB),
  sha256-verified.
- **Credentials**: AW_BACKEND_URL / AW_WORKSPACE / AW_WORKSPACE_HOST_TOKEN from the process env.

Not supported: profile copies, signed-in sessions, arbitrary JS, raw CDP, non-macOS hosts.
