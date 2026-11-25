---
name: aw-cdp-pilot
description: Drive a configured Electron app (AW Desktop) on a linked remote host for QA over the Chrome DevTools Protocol - launch with a disposable profile, inspect the DOM, click, type, press keys, screenshot, close - with no macOS Screen Recording or Accessibility permission. Use when asked to exercise, inspect or screenshot AW Desktop on the Mac mini, or to verify the cdp-pilot cleanup guarantees.
---

# aw-cdp-pilot

MCP server `aw-cdp-pilot`, 8 tools: `cdp_launch`, `cdp_list_pages`, `cdp_inspect`,
`cdp_click`, `cdp_type`, `cdp_key`, `cdp_screenshot`, `cdp_close`.

## Flow

1. `cdp_launch(target)` with a configured target NAME. Returns an opaque
   `session_id`, `expires_at` and `listener` evidence (loopback-only, ephemeral port).
2. `cdp_list_pages`, then `cdp_inspect(selector)` for structured DOM facts
   (tag, role, text, visible, enabled, box, id/class/data-testid/aria-*/type/placeholder).
3. `cdp_click(selector)` needs exactly one visible match (else use `nth`);
   `cdp_type(text, selector?)`; `cdp_key(key, modifiers?)`.
4. `cdp_screenshot` returns a local PNG path + sha256 (pulled over fs/download).
5. `cdp_close` returns cleanup evidence. After a TTL expiry the same call returns
   the tombstone (`state: expired`, same `checks`), which is how expiry is verified.

## Rules that hold by construction

- Targets come only from the app config (`targets`, **default empty = every launch refused**).
  The host re-verifies realpath, `CFBundleIdentifier` and codesign `TeamIdentifier`.
- One session per host; a second launch is refused without revealing the existing id.
- No tool takes a host, path, port, pid, URL or script. No arbitrary JS, no raw CDP,
  no profile copy, never input values/cookies/storage. An unrelated debuggable app
  on the host (e.g. a QA instance on port 9333) is unreachable.
- A detached host-side supervisor owns TTL (default 600s, cap 1800s) and cleanup, so
  expiry works even if the workspace is down.

## Data handling

Typed text and selectors cross the exec command line base64-encoded and are retained
wherever job commands are retained. **Use synthetic test data only**; never type credentials.
App logs record verb, session id and text length only.

## Configuring a target (example, Mac mini)

```json
{"targets": [{"name": "aw-desktop-mini", "host_id": "9753b05c9dbd57ed",
  "app_path": "/Applications/AW Desktop.app",
  "bundle_id": "com.fredericowu.awdesktop", "team_id": "WX89ETH2Z3"}]}
```

`team_id` is mandatory in practice: it is enforced as a codesign designated requirement.
Omitting it refuses the launch unless the target sets `"allow_unpinned_team": true`
(integrity is still verified).

## Verifying cleanup independently

After close or expiry check on the host (remote-hosts exec): no process whose command
contains `.aw-cdp-pilot/sessions/<id>`, `~/.aw-cdp-pilot/sessions/` has no `<id>` dir,
and nothing listens on the recorded port.

## Limits

macOS-only host checks; each call reconnects (no stable element refs); no navigation tool;
signed-in sessions are not supported.
