# aw-app-cdp-pilot

QA pilot (app id `cdp-pilot`) that drives a **configured** Electron app, today AW Desktop on a
linked Mac, over the Chrome DevTools Protocol, so it needs no macOS Screen Recording or
Accessibility permission.

Eight MCP tools: `cdp_launch`, `cdp_list_pages`, `cdp_inspect`, `cdp_click`, `cdp_type`,
`cdp_key`, `cdp_screenshot`, `cdp_close`. Launches use a disposable profile and a loopback-only
ephemeral debug port, are killed and removed on close or TTL expiry, and are limited to a named
target allowlist in the app config (default empty, so every launch is refused until configured).

Out of scope: profile copies / signed-in sessions, arbitrary JavaScript or raw CDP, arbitrary host
execution, the Node inspector, mobile, non-Chromium apps.

Docs: `docs/architecture.md`, skill `skills/aw-cdp-pilot/SKILL.md`.

Tests: `pytest --cov=cdp_pilot_app tests/ -q` (100% coverage gate). Releases go through
`.github/workflows/release.yml` (shared aw-marketplace workflow); never hand-bump the version.
