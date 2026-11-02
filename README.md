# RXPTool v2.0.0

Self-hosted, account-keyed RestedXP import editor. **One document format, two screens.**

## Workflow

1. **Decrypt** (`/`): upload/paste the original, complete encrypted import and enter the matching account ID. Download **`editable_guides.txt`**.
2. Edit your guide text, including steps, names or tags. Keep document directives such as `#!RXPTOOL/1`, `#!guide`, `#!endguide`, `#!empty`, `#!chunk` and `#!endchunk` intact unless intentionally changing guide boundaries.
3. **Encrypt** (`/encrypt`): upload the edited `editable_guides.txt` and enter the **ID to use for output encryption**. Download **`rebuilt_import.txt`**.
4. RXPTool rebuilds native import framing, dynamically recalculates guide count, NUL slots and Adler-32 checksums, recompresses and freshly encrypts the chunks. It decrypts the rebuilt output again and checks the exact raw chunk bytes and guide count before returning it.

**Game compatibility:** guides can still be skipped by the RestedXP addon for incompatible game versions, factions or seasonal tags. The v1.1.x Retail test established that the native import pipeline can load correctly when guide metadata is compatible. RXPTool does not rewrite quests/zones for other game versions.

## Removed in v2.0.0

There is **no UI or API support** for Combined plaintext, Separate guides ZIP, Layout JSON, lossless metadata ZIP, manual manifest rebuild, standalone TXT/ZIP chunk encryption or AES `.rxptool` recovery. Their server routes, modules and UI logic were removed. Keep a v1.x checkout if you must access those historic formats.

**Account key handling:** the editable document retains its legacy `#!account_key_fingerprint` metadata for compatibility, but the Encrypt backend does **not** compare it with the supplied ID, matching the originally uploaded project's behaviour. The submitted ID determines output encryption; this is not Battle.net authentication. No server-side guide or account history is kept.

## Configuration

Set these variables through your Compose `.env` or Portainer's Stack Environment UI. Both Compose variants and the Portainer stack pass them into the container:

| Variable | Default | Purpose |
| --- | --- | --- |
| `RXP_HEADLINE` | `Guides, unlocked into plaintext.` | Large headline on **both** Decrypt and Encrypt screens; plain text, truncated at 160 characters, HTML escaped |
| `RXP_USERNAME` | unset | Optional HTTP Basic username |
| `RXP_PASSWORD` | unset | Optional HTTP Basic password (set both username and password) |
| `RXP_BIND_IP` | `0.0.0.0` | Host bind IP in the Compose files |
| `RXP_IMAGE` | `ghcr.io/zeragonii/rxptool:latest` | Container image for GHCR / Portainer stacks |

Example in Portainer's **Environment variables**:

```env
RXP_HEADLINE=My private guide workshop
```

Then redeploy the stack. The headline is read at startup; no rebuild needed. If you're using `portainer-stack.yml` or `compose.ghcr.yml`, make sure to replace your stack definition with the new file so `RXP_HEADLINE` actually reaches the container. Only trusted local admins should set it; content is escaped rather than treated as HTML.

## Deployment

### GHCR / Portainer

Use `portainer-stack.yml` in Portainer's stack editor, or run:

```sh
docker compose -f compose.ghcr.yml up -d
```

By default the UI listens on `http://HOST:8787`. Secure access with HTTPS and credentials before exposing it outside your private network.

### Local build

```sh
docker compose up --build -d
```

### Optional Python CLI

```sh
python rxp_decrypt.py --payload-file original_import.txt --id 'YourName#1234' --output editable_guides.txt
```

## API (v2.0.0)

- `GET /health`: status and version.
- `POST /api/decrypt`: JSON `{ "battle_id": "YourName#1234", "payload": "<full import>" }`. Only optional `"format": "editable"` is accepted. Returns `editable_guides.txt`.
- `POST /api/encrypt`: JSON `{ "battle_id": "YourName#1234", "content_base64": "<base64 of editable TXT>" }`. Returns `rebuilt_import.txt`.

Other formats or endpoints are no longer supported. API request limits, basic authentication, concurrency limits, CSP and read-only container settings remain enforced.

## Development

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q
node --check webapp/static/app.js
node --check webapp/static/encrypt.js
```

Tag/release:

```sh
git add .
git commit -m "v2.0.0"
git push
git tag v2.0.0
git push origin v2.0.0
```

The GitHub Actions workflow validates JavaScript and Python, tests the application and builds/publishes multi-architecture GHCR images. The image is published on a version tag; push code before tagging it.

**Independent project; not affiliated with RestedXP.** Use only on guide content you are authorised to process.
