## v2.1.0

- Add isolated private publication dashboard and public allowlisted, account-keyed downloads.
- Preserve both original editor pages and their API routes.
- Use the existing encrypted native import encoder with full roundtrip verification before publishing and downloading.
- Add persistent guide and allowlist storage, rollback history, request limits, and separate role-based Portainer services.

# Changelog

## v2.0.3 — 2026-11-04

- Preserve the original title (everything before the first `!` in the uploaded filename) when downloading editable guide TXT, rather than always `editable_guides.txt`.
- Include optional `#!source_name` metadata in new editable files, so the original title survives rename/edit/upload while older editable documents remain compatible.
- Name rebuilt encrypted imports `<source>!<output Battle.net ID>_YYYY-MM-DD_HH-mm.txt`, with a browser-local timestamp that is Windows-safe (`:` is not used).
- Add Windows filename sanitisation, Content-Disposition filename handling (including Unicode), and fallback naming for pasted payloads/older files. The native encrypted content is unchanged.
- Bump UI, API, assets, tests, version file and release instructions to v2.0.3. Account-key fingerprint remains informational only.


## v2.0.2 — 2026-11-02

- Fix the stale `test_wrong_account_rejected` assertion after restoring the intentional non-enforcement of legacy account-key fingerprints. A different output encryption ID is accepted and the generated payload decrypts under that ID.
- Add regression coverage showing that editing the legacy `#!account_key_fingerprint` metadata does not block encryption.
- Align `VERSION`, API version, HTML footer, cache-busting static asset URLs, and version-sensitive tests at `2.0.2`.
- Retain the v2.0.1 behaviour and all v2.0.0 UI cleanup unchanged; the fingerprint is informational only.

## v2.0.0 — 2026-11-02

- Consolidate the WebUI into **Decrypt → editable_guides.txt → Encrypt → rebuilt_import.txt**.
- Remove the Combined plaintext, Separate guides, Layout JSON, metadata bundle and legacy recovery controls, JavaScript logic, API endpoints and obsolete Python modules.
- Remove legacy combined/ZIP encryption, full-manifest rebuilding and AES `.rxptool` recovery. Retain strict raw-chunk verification.
- Make the top headline configurable with `RXP_HEADLINE` (defaults to **Guides, unlocked into plaintext.**), safely escaped on both pages and propagated through all stack examples.
- Harmonise navigation, branding, result presentation, asset URLs, static styles and footer versions. Set `VERSION=2.0.0` for GHCR release tagging.
- Update the optional CLI to export the same editable document rather than separate per-guide files.
- Drop the unused `cryptography` dependency, refresh tests and rewrite deployment/documentation for the focused workflow.

---

## v2.0.0 correction — no account-fingerprint enforcement

- Restore the original uploaded project behaviour: read legacy account fingerprint metadata, but do not compare it to the ID used for output encryption.
- Update Encrypt page messaging and tests. No other authentication, decryption, format or integrity checks are changed.

## Historical releases (prior to v2.0.0)


## v1.1.6 — 2026-11-02

- Add **Editable guide TXT** as the recommended Decrypt export, a self-contained human-readable
  document with literal header/footer, account-key fingerprint, `#!chunk`, `#!guide`,
  `#!empty`, `#!between` and `#!endguide` markers.
- Reconstruct NUL separators from **guide slots**, not stored byte positions. Editing steps
  shifts guide boundaries automatically. Add/remove guide blocks and update guide count from
  the actual content.
- Encrypt the edited TXT directly via the existing Encrypt page: no separate manifest, no
  browser session metadata, and no reuse of archived ciphertext. Checksum and encrypted bytes
  are calculated from the freshly reconstructed guide chunks.
- Strictly validate control lines, bound file sizes and counts, require the original account
  key fingerprint, and independently verify every rebuilt raw chunk via the original decoder.
- Retain legacy combined/split TXT, JSON layouts, archive restoration and package recovery.
- Add automated tests for exact raw-byte round trips, multiple chunks, leading/repeated/
  trailing NULs, edited guide length, guide count changes, CRLF and malformed documents,
  plus a real 191-guide import test when a local sample is available.
- **Native WoW acceptance remains unverified**; this version isolates whether fixed NUL
  offsets were responsible for the previous parser error.

## v1.1.5 — Simple edit/rebuild workflow

- Decrypt now creates a lean `layout.json` without encrypted payload bytes, source SHA hashes, guide-content SHA hashes, or per-chunk content SHA hashes.
- The browser tab remembers the lightweight layout following a successful Decrypt operation. Encrypt uses it automatically with a combined `.txt`, so no manual layout upload is needed in the normal same-tab workflow.
- An explicit layout upload is retained as a fallback for later sessions, while legacy archival manifests and metadata ZIP restoration remain supported.
- One original-account key fingerprint is retained to prevent re-binding third-party imports to another account.
- No changes to the Lua parsing engine or the native cipher/checksum algorithm. Native WoW parsing failure is **not** claimed resolved.

## v1.1.4 — 2026-11-02

- Add **Rebuild from manifest** to Encrypt: combined edited TXT + standalone v1.1.3 `manifest.json` + the original matching Battle.net ID.
- Generate **new** encrypted chunks; never restore or reuse ciphertext from the source export. Preserve original header/footer, between-chunk text, guide order, chunk-level empty NUL slot patterns, and guide count.
- Recompute zlib streams, Adler-32 checksums and Base64 after modifying plaintext; use the same key derivation/cipher as the existing decoder.
- Match the import's recorded original key fingerprint; reject attempts to change the account identifier through this route.
- Verify reconstruction with the unmodified RXPTool decoder before download. **Does not claim in-game addon acceptance**, which requires testing inside WoW.
- Keep normal TXT/ZIP encrypt/decrypt, exact metadata-bundle restore and legacy `.rxptool` recovery unchanged.
- Add API and unit coverage for changed guide text, multichunk source framing, repeated/leading/trailing NULs and mismatched identifiers.


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
