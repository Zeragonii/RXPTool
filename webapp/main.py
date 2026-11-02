"""Stateless, self-hosted UI/API for the existing offline RXP decoder."""
from __future__ import annotations

import base64
import binascii
import io
import json
import os
import secrets
import threading
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response

from webapp.package_crypto import PackageError, decrypt_package
from webapp.import_bundle import BundleError, build_import_bundle, build_import_manifest, is_import_bundle, restore_original_import
from webapp.native_encrypt import EncryptError, encrypt_payload, prepare_guides
from webapp.manifest_rebuild import RebuildError, rebuild_from_manifest
from rxp_decrypt import (
    DecodeError,
    decode_chunk,
    derive_base,
    extract_chunks,
    guide_filename,
    initial_permutation,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC = BASE_DIR / "static"
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_PACKAGE_BYTES = 16 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 128 * 1024 * 1024
MAX_GUIDES = 1000
MAX_CHUNKS = 512
MAX_ACTIVE = 2

USERNAME = os.environ.get("RXP_USERNAME", "")
PASSWORD = os.environ.get("RXP_PASSWORD", "")
if bool(USERNAME) != bool(PASSWORD):
    raise RuntimeError("Set both RXP_USERNAME and RXP_PASSWORD, or neither")

slots = threading.BoundedSemaphore(MAX_ACTIVE)
app = FastAPI(title="RXP Guide Decoder", docs_url=None, redoc_url=None, openapi_url=None)


def failure(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers={"Cache-Control": "no-store"})


def authorized(header: str) -> bool:
    if not USERNAME:
        return True
    if not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        supplied_user, supplied_pass = decoded.split(":", 1)
    except (ValueError, UnicodeError, binascii.Error):
        return False
    # Equal-time comparison, even with two distinct inputs.
    matches_user = secrets.compare_digest(supplied_user.encode(), USERNAME.encode())
    matches_pass = secrets.compare_digest(supplied_pass.encode(), PASSWORD.encode())
    return matches_user and matches_pass


@app.middleware("http")
async def protect_access(request: Request, call_next):
    if request.url.path != "/health" and not authorized(request.headers.get("authorization", "")):
        return JSONResponse(
            {"error": "Authentication required"},
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="RXP Decoder", charset="UTF-8"',
                     "Cache-Control": "no-store"},
        )
    if request.url.path in ("/api/decrypt", "/api/encrypt", "/api/open-package", "/api/rebuild") and request.method == "POST":
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return failure(400, "Invalid request length")
        if length > MAX_REQUEST_BYTES:
            return failure(413, "Request too large (maximum 32 MiB)")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html", media_type="text/html")


@app.get("/encrypt")
async def encrypt_page():
    return FileResponse(STATIC / "encrypt.html", media_type="text/html")


@app.get("/favicon.ico")
async def favicon():
    return FileResponse(STATIC / "favicon.ico", media_type="image/x-icon")


@app.get("/assets/{asset}")
async def asset(asset: str):
    allowed_assets = {
        "app.css": "text/css",
        "app.js": "application/javascript",
        # Versioned asset URLs prevent old JS and new HTML from being mixed
        # by browser or reverse-proxy caches after a release.
        "app-v1.1.3.css": "text/css",
        "app-v1.1.4.css": "text/css",
        "encrypt-v1.1.3.js": "application/javascript",
        "encrypt-v1.1.4.js": "application/javascript",
        "app-v1.1.3.js": "application/javascript",
        "app-v1.1.4.js": "application/javascript",
        
        "favicon.svg": "image/svg+xml",
        "favicon-32.png": "image/png",
        "apple-touch-icon.png": "image/png",
    }
    media = allowed_assets.get(asset)
    if media is None:
        return failure(404, "Not found")
    # Both URLs serve the same canonical asset. Only the versioned URLs
    # are referenced by this release's HTML.
    canonical = {"app-v1.1.3.css": "app.css", "app-v1.1.3.js": "app.js", "encrypt-v1.1.3.js": "encrypt.js", "app-v1.1.4.css": "app.css", "app-v1.1.4.js": "app.js", "encrypt-v1.1.4.js": "encrypt.js"}.get(asset, asset)
    return FileResponse(STATIC / canonical, media_type=media)


def decode_payload(account_id: str, payload: str) -> tuple[list[bytes], int]:
    """Reuse the existing decryptor without persisting account data or plaintext."""
    chunks = extract_chunks(payload, None)
    if len(chunks) > MAX_CHUNKS:
        raise DecodeError(f"Too many encrypted chunks (maximum {MAX_CHUNKS})")
    permutation = initial_permutation(derive_base(account_id))
    remaining = MAX_PLAINTEXT_BYTES
    guides: list[bytes] = []
    for index, chunk in enumerate(chunks, 1):
        if remaining < 1:
            raise DecodeError("Decompressed data exceeds the 128 MiB total limit")
        try:
            plain = decode_chunk(chunk, permutation, remaining)
        except DecodeError as exc:
            raise DecodeError(f"Chunk {index}/{len(chunks)}: {exc}") from exc
        remaining -= len(plain)
        guides.extend(item for item in plain.split(b"\0") if item)
        if len(guides) > MAX_GUIDES:
            raise DecodeError(f"Too many guides (maximum {MAX_GUIDES})")
    if not guides:
        raise DecodeError("No guides found in the decrypted payload")
    return guides, len(chunks)


def package_output(
    guides: list[bytes], chunk_count: int, output_format: str = "auto"
) -> tuple[bytes, str, str, dict[str, str]]:
    files = [guide_filename(guide, index) for index, guide in enumerate(guides, 1)]
    # "auto" preserves the v1.0.0 API: single guide -> .txt, many -> .zip.
    # "combined" always returns one plaintext .txt with NUL guide delimiters.
    # "split" always returns a ZIP, even for a single guide.
    resolved_format = (
        ("combined" if len(guides) == 1 else "split")
        if output_format == "auto" else output_format
    )
    if resolved_format == "combined":
        filename = (
            files[0] if len(guides) == 1 and output_format == "auto"
            else "decrypted_guides.txt"
        )
        output = b"\0".join(guides)
        content_type = "application/octet-stream"
    elif resolved_format == "split":
        filename = "decrypted_guides.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for name, guide in zip(files, guides):
                archive.writestr(name, guide)
        output = buf.getvalue()
        content_type = "application/zip"
    else:
        raise ValueError("Unsupported output format")
    preview = base64.urlsafe_b64encode(
        json.dumps(files[:10], ensure_ascii=True, separators=(",", ":")).encode("ascii")
    ).decode("ascii")
    # The Content-Disposition filename always contains ASCII-safe characters.
    safe_filename = "".join(c if c.isascii() and (c.isalnum() or c in "._- ") else "_" for c in filename)
    headers = {
        "Content-Disposition": f'attachment; filename="{safe_filename}"',
        "X-Guide-Count": str(len(guides)),
        "X-Output-Format": resolved_format,
        "X-Chunk-Count": str(chunk_count),
        "X-Guide-Preview": preview,
    }
    return output, filename, content_type, headers


async def bounded_json(request: Request) -> Any:
    """Enforce total request size even for chunked requests lacking Content-Length."""
    data = bytearray()
    async for part in request.stream():
        if len(data) + len(part) > MAX_REQUEST_BYTES:
            raise DecodeError("Request too large (maximum 32 MiB)")
        data.extend(part)
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise DecodeError("Invalid request data; expected JSON") from None


def process_input(account_id: str, payload: str, output_format: str):
    try:
        guides, chunks = decode_payload(account_id, payload)
        if output_format == "manifest":
            output = build_import_manifest(
                payload, account_id, guides,
                max_output_bytes=MAX_PLAINTEXT_BYTES, max_chunks=MAX_CHUNKS,
            )
            return output, "manifest.json", "application/json", {
                "Content-Disposition": 'attachment; filename="manifest.json"',
                "X-Guide-Count": str(len(guides)),
                "X-Chunk-Count": str(chunks),
                "X-Output-Format": "manifest",
            }
        if output_format == "bundle":
            output = build_import_bundle(
                payload, account_id, guides,
                max_output_bytes=MAX_PLAINTEXT_BYTES, max_chunks=MAX_CHUNKS,
            )
            headers = {
                "Content-Disposition": 'attachment; filename="rxptool_import_bundle.zip"',
                "X-Guide-Count": str(len(guides)),
                "X-Chunk-Count": str(chunks),
                "X-Output-Format": "bundle",
            }
            return output, "rxptool_import_bundle.zip", "application/zip", headers
        return package_output(guides, chunks, output_format)
    finally:
        slots.release()


@app.post("/api/decrypt")
async def decrypt(request: Request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return failure(415, "Expected application/json")
    # No input, output, or account identifiers are written to server storage.
    try:
        body = await bounded_json(request)
    except DecodeError as exc:
        status = 413 if "too large" in str(exc).lower() else 400
        return failure(status, str(exc))
    if not isinstance(body, dict):
        return failure(400, "Expected a JSON object")
    account_id, payload = body.get("battle_id"), body.get("payload")
    output_format = body.get("format", "auto")
    if output_format not in ("auto", "combined", "split", "bundle", "manifest"):
        return failure(400, "Invalid export format; choose combined, split, manifest or bundle")
    if not isinstance(account_id, str) or not account_id.strip():
        return failure(400, "Enter the Battle.net ID used by the addon")
    if not 1 <= len(account_id.encode("utf-8")) <= 256:
        return failure(400, "Battle.net ID must be at most 256 UTF-8 bytes")
    if not isinstance(payload, str) or not payload.strip():
        return failure(400, "Upload or paste an encrypted payload")
    if not slots.acquire(blocking=False):
        return failure(429, "Decoder is busy; retry shortly")
    try:
        output, _filename, content_type, headers = await run_in_threadpool(
            process_input, account_id.strip(), payload, output_format
        )
    except (DecodeError, BundleError) as exc:
        return failure(422, str(exc))
    except Exception:
        # Don't reflect sensitive inputs or stack traces to the UI.
        return failure(500, "Unexpected server error while processing payload")
    return Response(content=output, media_type=content_type, headers=headers)


def _validate_package_input(body: Any) -> tuple[str, bytes, str]:
    if not isinstance(body, dict):
        raise PackageError("Expected a JSON object")
    account_id = body.get("battle_id")
    encoded = body.get("content_base64")
    filename = body.get("filename", "guide.txt")
    if not isinstance(account_id, str) or not account_id.strip():
        raise PackageError("Enter an ID for this package")
    if len(account_id.strip().encode("utf-8")) > 256:
        raise PackageError("ID must be at most 256 UTF-8 bytes")
    if not isinstance(filename, str) or len(filename.encode("utf-8")) > 255:
        raise PackageError("Invalid filename")
    if not isinstance(encoded, str) or not encoded:
        raise PackageError("Select a file first")
    # Check before base64 decoding to bound memory usage.
    if len(encoded) > ((MAX_PACKAGE_BYTES + 128 * 1024) * 4 // 3 + 8):
        raise PackageError("File too large (maximum 16 MiB)")
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise PackageError("Invalid file encoding") from None
    if not data or len(data) > MAX_PACKAGE_BYTES + 128 * 1024:
        raise PackageError("File must contain data and be no larger than 16 MiB")
    return account_id.strip(), data, filename


def _package_operation(action: str, account_id: str, data: bytes, filename: str):
    try:
        if action == "encrypt":
            # A metadata bundle from Decrypt can be restored *exactly*, but only
            # when both the original ID and all archived bytes still match.
            if filename.lower().endswith("rxptool_import_bundle.zip") or is_import_bundle(data):
                original, guide_count = restore_original_import(
                    data, account_id, decode_payload,
                )
                return original, "restored_original_payload.txt", "text/plain; charset=utf-8", {
                    "X-Package-Verified": "true", "X-Input-Bytes": str(len(data)),
                    "X-Guide-Count": str(guide_count), "X-Payload-Restored": "exact",
                }
            plain, guide_count = prepare_guides(data, filename)
            result = encrypt_payload(plain, account_id)
            # Verify using the exact decoder that powers the main Decrypt page.
            recovered, chunks = decode_payload(account_id, result)
            if chunks != 1 or b"\x00".join(recovered) != plain:
                raise RuntimeError("Native payload round-trip verification failed")
            return result.encode("ascii"), "encrypted_guides.txt", "text/plain; charset=utf-8", {
                "X-Package-Verified": "true", "X-Input-Bytes": str(len(data)),
                "X-Guide-Count": str(guide_count), "X-Chunk-Count": "1",
            }
        # Backward compatibility: previously encrypted v1.1.0 .rxptool files
        # can still be recovered, but are no longer produced by /api/encrypt.
        original, restored_name = decrypt_package(data, account_id)
        return original, restored_name, "application/octet-stream", {
            "X-Package-Verified": "true", "X-Input-Bytes": str(len(data))
        }
    finally:
        slots.release()


async def _package_endpoint(request: Request, action: str):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return failure(415, "Expected application/json")
    try:
        account_id, data, filename = _validate_package_input(await bounded_json(request))
    except (DecodeError, PackageError) as exc:
        return failure(413 if "too large" in str(exc).lower() else 400, str(exc))
    if not slots.acquire(blocking=False):
        return failure(429, "Server is busy; retry shortly")
    try:
        output, out_name, media, headers = await run_in_threadpool(
            _package_operation, action, account_id, data, filename
        )
    except (PackageError, EncryptError, DecodeError, BundleError) as exc:
        return failure(422, str(exc))
    except Exception:
        return failure(500, "Unexpected server error while handling package")
    safe_name = "".join(c if c.isascii() and (c.isalnum() or c in "._- " ) else "_" for c in out_name)[:180] or "package.bin"
    headers["Content-Disposition"] = f'attachment; filename="{safe_name}"'
    return Response(content=output, media_type=media, headers=headers)


@app.post("/api/encrypt")
async def encrypt_api(request: Request):
    return await _package_endpoint(request, "encrypt")


@app.post("/api/open-package")
async def open_package_api(request: Request):
    return await _package_endpoint(request, "open")


def _rebuild_operation(account_id: str, manifest: bytes, plain: bytes):
    try:
        result, count, chunks, edited = rebuild_from_manifest(manifest, plain, account_id)
        # Independent round-trip via the unchanged original decoder.
        recovered, recovered_count = decode_payload(account_id, result)
        if (recovered_count != chunks or b"\x00".join(recovered) != plain):
            raise RebuildError("Rebuilt import did not pass unchanged decoder verification")
        return result, count, chunks, edited
    finally:
        slots.release()


@app.post("/api/rebuild")
async def rebuild_api(request: Request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return failure(415, "Expected application/json")
    try:
        body = await bounded_json(request)
        if not isinstance(body, dict):
            raise RebuildError("Expected a JSON object")
        account = body.get("battle_id")
        if not isinstance(account, str) or not 1 <= len(account.strip().encode("utf-8")) <= 256:
            raise RebuildError("Enter the original account ID")
        source = body.get("content_base64")
        manifest = body.get("manifest_base64")
        if not isinstance(source, str) or not isinstance(manifest, str):
            raise RebuildError("Upload both the combined plaintext TXT and manifest JSON")
        if len(source) > 23 * 1024 * 1024 or len(manifest) > 6 * 1024 * 1024:
            raise RebuildError("Uploaded plaintext or manifest exceeds size limits")
        plain_data = base64.b64decode(source, validate=True)
        manifest_data = base64.b64decode(manifest, validate=True)
        if len(plain_data) > 16 * 1024 * 1024 or len(manifest_data) > 4 * 1024 * 1024:
            raise RebuildError("Uploaded plaintext or manifest exceeds size limits")
    except (DecodeError, RebuildError, binascii.Error, ValueError) as exc:
        return failure(400, str(exc))
    if not slots.acquire(blocking=False):
        return failure(429, "Server is busy; retry shortly")
    try:
        result, count, chunk_count, edited = await run_in_threadpool(
            _rebuild_operation, account.strip(), manifest_data, plain_data
        )
    except (RebuildError, DecodeError) as exc:
        return failure(422, str(exc))
    except Exception:
        return failure(500, "Unexpected server error while rebuilding import")
    return Response(
        content=result.encode("utf-8"), media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="rebuilt_import.txt"',
            "X-Guide-Count": str(count), "X-Chunk-Count": str(chunk_count),
            "X-Import-Rebuilt": "true", "X-Source-Plaintext-Edited": str(edited).lower(),
        },
    )
