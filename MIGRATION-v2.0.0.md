# v2.0.0 migration map

## Workflow

```text
BEFORE (v1.x)
Decrypt -> [Editable TXT] [Combined plaintext] [Separate ZIP] [Layout JSON] [Archive ZIP]
Encrypt -> [Editable TXT] [Combined TXT + layout] [Raw TXT/ZIP] [Legacy Recovery]

AFTER (v2.0.0)
Decrypt encrypted import ----> editable_guides.txt
                                    |
                              Edit guide steps
                                    |
Encrypt editable TXT --------> rebuilt_import.txt
```

## Removed / retained / added

| Feature | Status in v2.0.0 | Implementation |
| --- | --- | --- |
| Decrypt encrypted import | KEPT | `POST /api/decrypt` (editable only) |
| Editable guide TXT | KEPT | `webapp/editable_document.py` |
| Rebuild into native import | KEPT | `POST /api/encrypt` (editable only) |
| Account key fingerprint | FIXED | Explicitly checked during rebuild |
| Native integrity validation | KEPT | Adler-32, zlib, raw-chunk round trip |
| Upload / paste and download | KEPT | Streamlined browser pages |
| Basic auth / Docker / GHCR | KEPT | Same service approach |
| Combined plaintext TXT | REMOVED | Export path and button |
| Separate guides ZIP | REMOVED | Export path, UI and old CLI split |
| Layout JSON | REMOVED | JSON download/manifest processing |
| Lossless metadata bundle ZIP | REMOVED | Archive generation and exact restore |
| Legacy `.rxptool` recovery | REMOVED | Recovery UI, endpoint and crypto module |
| Standalone raw TXT / ZIP encryption | REMOVED | Only editable TXT is accepted |
| `RXP_HEADLINE` environment variable | ADDED | Both pages, default unchanged |
| Brand, page layout and version labels | UPDATED | Consistent v2.0.0 UI |

## Remove the old files from an existing Git checkout

Extract the update ZIP into the repository root, then run:

```sh
git rm --ignore-unmatch webapp/import_bundle.py webapp/manifest_rebuild.py webapp/native_encrypt.py webapp/package_crypto.py tests/test_app.py tests/test_rebuild.py
```

The update ZIP cannot delete existing files by itself. The **full-source ZIP contains no `.git` directory**, so for an existing repository preserve your own Git metadata and perform the removals above.

## Runtime settings

Set `RXP_HEADLINE` in Portainer's Stack Environment, using the updated `portainer-stack.yml` definition. Example: `RXP_HEADLINE=My guide library`. Redeploy the container. The value is escaped and displayed as plain text, on both pages, with a 160-character limit.
