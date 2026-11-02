# Changelog

## v1.1.3 — 2026-11-02

- Add a separate **Manifest JSON** download button on the Decrypt page, alongside existing combined, split and bundle downloads.
- Record **every NUL separator at exact zero-based byte positions** in the original decompressed chunk data (including repeats), with chunk-local and cumulative raw offsets; separately record the normalised combined TXT offsets.
- Expose the original **literal header and footer** in the JSON (and decoded guide count/addon version when present). Preserve inter-chunk text, encoded source offsets, chunk prefixes and terminators.
- Include the expanded JSON in the existing lossless metadata bundle while retaining compatibility with v1.1.2 archives; validate recorded offsets and framing during original-file restoration.
- Continue to accept standalone encrypted chunks without inventing an outer header/footer, and keep all decryption and other export modes unchanged.


## v1.1.2 — 2026-11-02

- Add **Download with metadata** on Decrypt: a lossless `rxptool_import_bundle.zip` with `manifest.json`, `original_payload.txt`, `decrypted_guides.txt`, and the exact uncompressed bytes of each original chunk.
- Preserve original import framing, leading/trailing text, checksums, chunk ordering, source guide count, version footer, and even unexpected whitespace by saving the unmodified imported string.
- Upload that archive on Encrypt with the **original matching ID** to restore `restored_original_payload.txt` byte-for-byte without generating a new encrypted string.
- Verify SHA-256 of plaintext, original import and each chunk, ID-derived key fingerprint and the existing decoder output; reject altered or wrongly keyed archives.
- Keep the existing Encrypt TXT/ZIP behaviour, combined TXT and split ZIP downloads, legacy AES recovery, strict CSP and GHCR workflow unchanged.
- Add four integration tests plus Chromium UI test covering Decrypt → lossless bundle → Encrypt restoration.


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
