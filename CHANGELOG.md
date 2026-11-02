# Changelog

## v1.1.1 — 2026-11-02

- **Fix Encrypt/Decrypt interoperability:** Encrypt now generates the same account-derived XOR/zlib/Adler-32 Base64 chunk format the main Decrypt page accepts, instead of producing incompatible `.rxptool` AES packages.
- Allow NUL-separated plaintext TXT files or ZIP archives of individual TXT guides, preserving the guide bytes and normalising guide separators.
- Verify each new output via the **actual main decoder** before enabling download.
- Keep the old `.rxptool` decryption as optional **Legacy recovery** for existing v1.1.0 packages.
- Update frontend wording, counts and versioned asset URLs without relaxing CSP or changing Docker configuration.
- Add encrypt → main decrypt and split ZIP integration tests; validate all 191 entries from the user's sample locally.

## v1.1.0 — Independent encrypted-package workspace

- Add a separate **Encrypt** page at `/encrypt`, with a matching header navigation tab.
- Upload original/authorised plaintext TXT or ZIP, provide an ID, and download an authenticated `.rxptool` package.
- Add **Open an RXPTool package** to recover the exact original file and filename using the same ID.
- New API routes `/api/encrypt` and `/api/open-package` with clear authentication/tamper errors.
- AES-256-GCM with fresh salt and nonce, PBKDF2-HMAC-SHA256 ID derivation, zlib compression and verified byte-exact round-trip.
- Shared optional browser-side ID remembrance; strict CSP, no inline JavaScript, no server-side files or database.
- Warn explicitly that `.rxptool` is **not RestedXP import compatible** and a public Battle.net ID alone is not a strong confidentiality secret.
- Increment frontend cache-busting URLs to v1.1.0, add comprehensive API/browser tests, and install `cryptography` in the Docker image.


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
