# Changelog

## v1.0.1 — 2026-11-02

- Added **two independent export buttons** to the WebUI: combined plaintext or separate files in a ZIP.
- Added a `format` option to `POST /api/decrypt`: `combined`, `split`, or `auto`.
- Preserved backward-compatible `auto` behaviour for existing API clients.
- Combined exports preserve individual guide contents and join guides with one `0x00` delimiter.
- Switching export format does not require another upload; the page reuses its in-memory payload and re-requests the chosen format.
- Added unit/API coverage for both export modes and a live browser UI interaction test.
- Updated release version and GHCR Compose examples for `Zeragonii/RXPTool`.

## v1.0.0 — 2026-11-02

- First self-hosted Docker WebUI.
- GitHub Actions CI, multi-arch GHCR publishing and Portainer stack.
