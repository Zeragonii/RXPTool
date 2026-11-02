# RXPTool — Self-hosted Guide Encrypt / Decrypt

A small, stateless, self-hosted browser UI for the included account-keyed guide payload decoder. Upload or paste an encrypted guide string, supply its matching identifier, and download decrypted plaintext. After decryption, choose a combined plaintext file, separate guide files, or a lossless import-and-metadata archive for exact restoration. Both export formats are available without uploading the payload again. Optionally remember the identifier in your browser's `localStorage` (not on the server).

> **Use only with data you have the right to access.** The software requires the matching account ID and does not attempt to recover unknown keys or bypass account-mismatch checks. The precise ID expected by the addon depends on its build; a displayed BattleTag may not always be that ID. This project is not affiliated with RestedXP.

## Features

- Clean responsive WebUI: file drop zone, file chooser, and pasted input.
- **v1.0.3:** Versioned frontend asset URLs to prevent stale JavaScript from being paired with new HTML behind reverse proxies; descriptive error if an incompatible page is served. The strict CSP remains unchanged.
- **v1.0.2:** Header icon doubles as the browser favicon, with SVG, ICO, PNG and Apple touch icon assets.
- Optional browser-only ID remembrance; no accounts database or persistent payload storage.
- Existing Python decoder (`rxp_decrypt.py`) used directly by the FastAPI backend.
- Matching **Encrypt** workspace: convert combined plaintext TXT or split ZIP guides into Base64-encoded payload text that the main **Decrypt** page accepts with the same ID. Legacy AES `.rxptool` recovery is retained for v1.1.0 files.
- **v1.1.3: Inspect original byte offsets:** a standalone `manifest.json` download records exact NUL separator offsets in each original chunk, plus literal outer header and footer text and the count/version fields when present. The lossless archive includes the same expanded manifest.
- **v1.1.2: Preserve import metadata:** download a lossless archive, then restore the original encrypted payload with its original matching ID.
- **v1.0.1: Choose your export:** download a combined NUL-delimited `decrypted_guides.txt` or a ZIP of individually named `.txt` guide files. Download any or all formats; alternatives are generated on demand without re-uploading.
- The API accepts an optional `format` parameter: `combined`, `split`, `manifest`, `bundle`, or `auto` (the backward-compatible default). `auto` keeps the v1.0.0 behaviour: single guide → `.txt`, multiple guides → ZIP.
- Input validation, integrity checks, request caps, concurrent-operation limit, and error feedback.
- Optional HTTP Basic authentication (`RXP_USERNAME` and `RXP_PASSWORD` must be supplied together).
- Health endpoint `/health`, nonroot Docker user, read-only filesystem and minimal container privileges.

## v1.1.4 — Edit plaintext, rebuild full framed import (original account only)

RXPTool now has a third Encrypt workflow that **creates fresh encrypted bytes**, rather than returning previously archived ciphertext. Use it to study/edit plaintext guides for the *same account key as the original import*:

1. On **Decrypt**, upload a complete original import string and your original account ID. Download **Combined plaintext** and **Manifest JSON** separately. The standalone JSON includes a source-key fingerprint, not your ID.
2. Edit the combined `decrypted_guides.txt`, preserving guide count and guide order. Do not insert or remove NUL separators. Individual guide byte lengths may change.
3. On **Encrypt**, upload the edited combined plaintext TXT, supply `manifest.json` using the new optional file picker, and enter the **original matching** account ID.
4. Download `rebuilt_import.txt`, a freshly generated full import string that preserves the original literal header, footer and between-chunk text. It preserves the original layout of empty NUL slots across chunks, while updating all content-dependent checksums after edits.
5. The backend independently decrypts the generated import using the existing decoder and rejects mismatched output before returning a file.

A bare `checksum:base64%` input is **not sufficient** for this mode; the original import needs full `guideCount|...|addonVersion` framing. This mode rejects a new/alternative Battle.net ID (account key fingerprint must match). It cannot add or remove guide entries; original guide ordering and per-chunk allocation are preserved. The separate *Download with metadata* archive remains available for byte-exact restoration of an **unmodified original**.

Endpoint: `POST /api/rebuild` with JSON `{"battle_id":"original ID","content_base64":"base64 combined TXT","manifest_base64":"base64 manifest JSON"}`. Returns `rebuilt_import.txt`.

**Verification boundary:** This generates an import with syntactically correct outer framing, checksum-prefixed chunks and a valid decode round-trip. **Native RestedXP addon acceptance is unverified**: UI parsing, game version, entitlement and other addon checks may also apply. Test with original/authorised guide content before relying on it.

## v1.1.3 — Inspectable header/footer and NUL separator manifest

After a successful decryption, click **Manifest JSON** to download a *separate* `manifest.json`, without downloading the archive. The same expanded manifest is inside **Download with metadata**. It contains:

- `source.framing.header.raw`: literal text before the first encrypted chunk (for example `"\n3|"`).
- `source.framing.footer.raw`: literal text after the final encrypted chunk (for example `"|40000\n"`).
- `source.framing.header.declared_guide_count` and `.footer.addon_version` when detectable; `null` if you uploaded only a standalone chunk or Base64 instead of a full import.
- `chunks[].nul_byte_offsets_0_based`: **all** NUL positions in the exact decompressed bytes of the corresponding chunk, including consecutive or trailing NULs.
- `chunks[].raw_stream_start_byte_0_based` / `raw_stream_end_byte_exclusive`: chunk boundaries within the conceptual concatenation of original decompressed chunks.
- `offsets.raw_chunks_concatenated_nul_byte_offsets_0_based`: original NUL positions across the concatenated raw decompressed chunks.
- `offsets.normalized_combined_nul_byte_offsets_0_based`: NUL positions in the ordinary `decrypted_guides.txt` download (this differs if original chunks had extra leading, consecutive or trailing NUL bytes).

All offsets are **zero-based byte positions**, not character indices. The file also contains original checksums, chunk order, hashes and source character spans. No cleartext Battle.net ID is stored. If the supplied input has no outer header or footer, these fields are reported as `null` rather than invented. This is an inspectable record; it does not independently prove entitlement or licence validation by another addon.

## v1.1.2 — Exact import preservation using metadata bundles

The **Decrypt** page now has a third download choice: **Download with metadata**. The resulting `rxptool_import_bundle.zip` contains:

- `manifest.json`: guide and chunk counts, original declared guide count and addon version (when present), chunk checksums, byte lengths, SHA-256 hashes, and an account-key fingerprint (**not** the cleartext Battle.net ID).
- `original_payload.txt`: the entire original submitted import string, including headers, version footer, all encrypted chunks and original whitespace, unchanged.
- `decrypted_guides.txt`: the regular combined NUL-separated plaintext guides.
- `chunks/chunk_###.bin`: exact uncompressed byte data per original encrypted chunk, preserving boundaries and any extra NUL separators lost in the regular combined TXT export.

To restore: open **Encrypt**, enter the **same original ID**, upload `rxptool_import_bundle.zip`, and click **Encrypt guides**. RXPTool detects the bundle and verifies that all archived data agrees with the original encrypted import under that ID. It returns `restored_original_payload.txt`, **byte-for-byte identical to the original submitted string**. In this mode RXPTool restores the stored original; it does **not re-encrypt with a different ID**, alter account binding, or change/check third-party entitlements. If you edit any part of the archive, exact restoration is rejected. Use the existing TXT/ZIP encryption path for original/authorised content whose guide text has been edited; these newly generated chunks may not reproduce a previous full import or pass the third-party addon's external validation.

The archive includes plaintext guide content: **keep it private**. Files and IDs are still processed in memory, and the ID is only stored in the browser when the user opts in. The archive itself does not include the cleartext ID.

API: `POST /api/decrypt` with `format: "bundle"` returns the archive. `POST /api/encrypt` with that ZIP as the upload returns the original import and includes `X-Payload-Restored: exact`. The original `combined`, `split`, and `auto` modes continue to work unchanged.

## v1.1.1 — Encrypt ↔ Decrypt compatibility

**Encrypt** (`/encrypt`) now reverses the same algorithm that runs on the main **Decrypt** (`/`) page. Unlike v1.1.0, **new exports are not AES `.rxptool` packages**. They are checksum-prefixed Base64 text chunks (`<decimal Adler32>:<base64>%`), containing zlib-compressed plaintext encrypted with the same derived ID keystream as the decoder.

1. Open **Encrypt**, enter the ID you intend to use on Decrypt.
2. Upload either a combined `.txt` of NUL-separated guides, or a `.zip` containing individual `.txt` guides.
3. Click **Encrypt guides** and download `encrypted_guides.txt`.
4. Open **Decrypt**, upload `encrypted_guides.txt`, enter the **same ID**, then choose a combined plaintext download or separate `.txt` guides in a ZIP.

Before returning an encrypted download, the backend runs the payload through the **same** `decode_payload()` function used by `/api/decrypt` and checks that the guide bytes match. A wrong ID fails the decoder's zlib/Adler-32 integrity checks.

- For combined plaintext input, consecutive and trailing NUL bytes are normalised to one separator between nonempty guides. **Guide contents remain byte-for-byte unchanged.**
- For ZIP input, individual `.txt` files are combined in ZIP entry order using a single NUL byte between guides. The original ZIP's container metadata is **not** reproduced by decryption; only its guides are recovered.
- Files are limited to 16 MiB before encoding; ZIP output is limited to 1000 guides and 16 MiB of uncompressed guide contents.
- The older v1.1.0 AES `.rxptool` format can still be opened via **Legacy recovery** at the bottom of the Encrypt page. New encrypted exports use `encrypted_guides.txt` and the **main Decrypt** page.

**Compatibility scope:** this feature is verified against **RXPTool's own Decrypt page**, including its existing Lua-derived cipher and chunk parser. It does **not** establish that a new export passes the third-party addon's full import-string framing, licence, or account validation workflow. An account ID is not a secret and this XOR-based format is not suitable for confidential data.

New API flow:

- `POST /api/encrypt` with JSON `{"battle_id":"Example#1234","filename":"guides.txt","content_base64":"..."}` → `encrypted_guides.txt` (checksum-prefixed Base64 chunk)
- `POST /api/decrypt` with JSON `{"battle_id":"Example#1234","payload":"<checksum>:<base64>%","format":"combined"}` → NUL-delimited plaintext
- `POST /api/open-package` with the original JSON input format → legacy v1.1.0 AES `.rxptool` recovery only

The backend stores neither payloads nor IDs on disk. Optional ID remembrance uses browser localStorage. HTTPS and a protected reverse proxy are strongly recommended.

## GitHub Actions → GHCR → Portainer

The workflow is at [`.github/workflows/publish.yml`](.github/workflows/publish.yml).

| Trigger | What happens | GHCR tags |
| --- | --- | --- |
| Pull request into `main` | Run unit/API tests | No image |
| Push to `main` | Test, build and push Linux `amd64` and `arm64` | `edge`, `sha-XXXXXXX` |
| Push a `vX.Y.Z` Git tag | Test, verify tag matches `VERSION`, build, push, create GitHub Release | `X.Y.Z`, `X.Y`, `X`, `latest`, `sha-XXXXXXX` |
| Manual workflow run on `main` | Test and rebuild edge image | `edge`, `sha-XXXXXXX` |

The GHCR image is **based on the repository's actual `owner/repo`**, converted to lowercase; for your current repository location that is:

```text
ghcr.io/zeragonii/rxptool:latest
ghcr.io/zeragonii/rxptool:edge
ghcr.io/zeragonii/rxptool:1.1.4
```

The GitHub Actions workflow uses the repository's built-in `GITHUB_TOKEN` with `packages: write` for GHCR and `contents: write` for GitHub Releases. **No PAT or container registry password is needed in repository secrets.** GitHub packages can initially be **private**; after the first successful publish, go to your package's **Package settings → Change visibility → Public** if you want Portainer to pull without a registry login. Alternatively, keep the image private and configure GHCR registry credentials in Portainer. Ensure the GHCR package grants this repository permission to publish if a package with the same name already exists. See [GitHub's GHCR guide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

### A. Update the existing RXPTool repository

Your existing repository is [`Zeragonii/RXPTool`](https://github.com/Zeragonii/RXPTool). Copy the updated files from this archive over your checked-out copy, preserving its `.git/` folder. Do **not** run `git init` or add a new remote.

This release changes `VERSION` to `1.1.4`. From the repository root:

```powershell
git add .
git commit -m "v1.1.2"
git push
git tag v1.1.2
git push origin v1.1.2
```

Pushing `main` builds `:edge`. The new tag builds `:1.1.4` and `:latest` and creates the release. Don't reuse an existing tag.

### B. Future releases (full copy/paste commands)

For the next release, change `VERSION` to `1.1.5` and make your code updates. Then:

```bash
git add .
git commit -m "v1.1.2"
git push
git tag v1.1.2
git push origin v1.1.2
```

`VERSION` and the Git tag must match *at the tagged commit* or the release workflow stops. Changing code on `main` without tagging publishes `:edge` only. Do not move existing release tags.

### C. Deploy to Portainer (image published by GitHub)

Once the `v1.1.2` workflow is green and the GHCR image is accessible to Portainer:

1. **Portainer → Stacks → Add stack → Web editor**.
2. Paste [`portainer-stack.yml`](portainer-stack.yml) into the editor.
3. Add Portainer **environment variables**: `RXP_USERNAME` and `RXP_PASSWORD` (set both for authentication). Optionally set `RXP_IMAGE` to `ghcr.io/zeragonii/rxptool:edge` to run the bleeding-edge branch instead of `latest`.
4. Deploy and open **http://YOUR-DOCKER-HOST:8787** (prefer HTTPS through your reverse proxy).
5. On a later release, use Portainer's **Pull latest image / Re-pull image and redeploy** option when updating the stack. If you use a version-pinned image such as `:1.0.3`, update the tag in `RXP_IMAGE` for each release.

The Compose stack **pulls the published container**, so no Python, Dockerfile upload, local Docker build, or bind-mounted source directory is required on your Portainer host. GHCR package visibility and Portainer registry credentials determine whether it can pull the image.

### D. Docker Compose on the server

Stable (pull from GHCR):

```sh
cp .env.example .env
# Change both username and password in .env first!
docker compose -f compose.ghcr.yml up -d
```

Local development (build from source):

```sh
docker compose up -d --build
```

The local `docker-compose.yml` retains its original local-build workflow, while `compose.ghcr.yml` and `portainer-stack.yml` now use the GHCR image. Default port: `8787/tcp`. Set `RXP_BIND_IP=127.0.0.1` for local-only exposure in `compose.ghcr.yml` or local `docker-compose.yml`. The Portainer stack publishes port 8787; restrict external exposure using firewall/reverse-proxy configuration.

### Run tests locally

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests use **synthetic** encrypted payloads and files (no purchased content or actual account identifiers). They verify combined NUL delimiters, ZIP outputs, account-key mismatches, package integrity/tampering, exact-byte recovery, and v1.0.0 decryptor backward compatibility.

## Security and operational limits

- This service **does not intentionally persist** submitted IDs, encrypted payloads, or recovered plaintext server-side; downloaded files remain on your device. When you choose a second export format, the browser resubmits the same input to the stateless API; the ID and encrypted payload remain in this page’s memory until you modify the inputs or close the page. Optional saved ID uses browser localStorage, readable by other scripts from the same site origin.
- Uvicorn access logs are disabled by default. Reverse proxies, logs, and browser downloads may retain content/metadata.
- Use HTTPS when accessing from other devices. **HTTP Basic authentication is not encryption**; don't expose port 8787 directly to the Internet. Putting it behind Nginx Proxy Manager + Authentik is also supported (ensure direct access to port 8787 is restricted).
- Request body limit: 24 MiB (encrypted payload limit unchanged; plaintext file limit 16 MiB); decompressed output total: 128 MiB; 1,000 guides; 512 chunks; 2 concurrent decryption requests. Reconfigure in `webapp/main.py` if necessary.
- Runtime uses Python 3.12, a nonroot UID, a read-only filesystem with `/tmp` tmpfs, dropped capabilities, and `no-new-privileges`.
- `.gitignore` and `.dockerignore` exclude `.env`, saved payload text and decrypted guide files. **Review `git status` before each push**, particularly if you have renamed sensitive files.
- No third-party source guide datasets are included. Review your right to publish the derived decoder before making the repository public.

## Repository layout

```text
RXPTool/
├── .github/
│   ├── workflows/publish.yml    # Tests, GHCR multiarch image, GitHub Release
│   └── dependabot.yml           # Dependency update PRs
├── webapp/
│   ├── main.py                  # API, encryption and output packaging
│   ├── package_crypto.py        # Independent AES-GCM package format
│   └── static/                  # Two HTML workspaces / CSS / JS
├── tests/test_app.py            # Synthetic API/decrypt tests
├── rxp_decrypt.py               # Python payload decoder
├── Dockerfile                   # Runtime image
├── docker-compose.yml           # Local build
├── compose.ghcr.yml             # Pull published GHCR image
├── portainer-stack.yml          # Paste into Portainer
├── requirements.txt             # Runtime Python dependencies
├── requirements-dev.txt         # CI/test Python dependencies
├── VERSION                      # Must equal the release tag without 'v'
└── .env.example                 # Example only; do not commit .env
```

## Export API (v1.0.1)

Use `POST /api/decrypt` with JSON:

```json
{
  "battle_id": "YourName#1234",
  "payload": "YOUR_ENCRYPTED_PAYLOAD_HERE",
  "format": "combined"
}
```

`format` supports `combined` (one `decrypted_guides.txt` with `0x00` delimiters), `split` (ZIP of separate text guides), and `auto` (default: old behaviour). The `X-Output-Format` response header identifies the format returned.

A combined file normalises guide boundaries to one NUL delimiter, which matches the input convention for guide splitting; it does not necessarily preserve redundant leading, repeated, or trailing NULs present in the original decompressed chunks. Both exports preserve each individual guide's bytes.

## Troubleshooting: frontend errors behind a proxy

- On v1.1.0 the page requests `/assets/app-v1.1.0.js` and `/assets/app-v1.1.0.css`. A browser or proxy serving the older `/assets/app.js` with newer HTML causes missing-element exceptions; hard-refresh and inspect Network > Disable cache if necessary.
- If `app.js:96` complains about a missing `downloadBtn`, that is specifically the **v1.0.0** frontend script. v1.0.1+ renamed this button to `downloadCombined` and `downloadSplit`. Pull the current GHCR image, redeploy and purge any proxy/CDN cache.
- A CSP warning about *inline* scripts is not generated by this application's HTML; all first-party scripts are loaded via `src` with the `script-src 'self'` policy. Inspect the delivered HTML for injected `<script>` blocks or browser extensions. Do not add `unsafe-inline` to the CSP.
- This release can't change headers or scripts injected by a reverse proxy, Cloudflare, authentication portal, or browser extension.
