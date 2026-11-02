# Changelog

## v1.0.3 — 2026-11-02

- Switched the page to versioned JS and CSS asset URLs so browser/proxy caches cannot pair old JavaScript with new markup.
- Added visible error information for incompatible frontend DOM rather than throwing an unhelpful null `addEventListener` exception.
- Preserved the strict `script-src 'self'` CSP, without allowing inline scripts.
- Added API tests for asset consistency, strict CSP, and no inline first-party scripts.


## v1.0.2 — 2026-11-02

- Reused the original top-left RXP Decoder icon as the browser favicon (same SVG path data and colours).
- The header now displays the same SVG asset used by the favicon, keeping both identical.
- Added a multi-resolution `favicon.ico` fallback, 32px PNG favicon, and 180px Apple touch icon.
- Whitelisted the static favicon endpoints without opening arbitrary file-serving routes.
- Added API tests for all favicon assets and updated the release version.

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
