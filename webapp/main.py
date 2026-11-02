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
MAX_REQUEST_BYTES = 16 * 1024 * 1024
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
    if request.url.path == "/api/decrypt" and request.method == "POST":
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return failure(400, "Invalid request length")
        if length > MAX_REQUEST_BYTES:
            return failure(413, "Upload too large (maximum 16 MiB)")
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
        "app-v1.0.3.css": "text/css",
        "app-v1.0.3.js": "application/javascript",
        "favicon.svg": "image/svg+xml",
        "favicon-32.png": "image/png",
        "apple-touch-icon.png": "image/png",
    }
    media = allowed_assets.get(asset)
    if media is None:
        return failure(404, "Not found")
    # Both URLs serve the same canonical asset. Only the versioned URLs
    # are referenced by this release's HTML.
    canonical = {"app-v1.0.3.css": "app.css", "app-v1.0.3.js": "app.js"}.get(asset, asset)
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
            raise DecodeError("Upload too large (maximum 16 MiB)")
        data.extend(part)
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise DecodeError("Invalid request data; expected JSON") from None


def process_input(account_id: str, payload: str, output_format: str):
    try:
        guides, chunks = decode_payload(account_id, payload)
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
    if output_format not in ("auto", "combined", "split"):
        return failure(400, "Invalid export format; choose combined or split")
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
    except DecodeError as exc:
        return failure(422, str(exc))
    except Exception:
        # Don't reflect sensitive inputs or stack traces to the UI.
        return failure(500, "Unexpected server error while processing payload")
    return Response(content=output, media_type=content_type, headers=headers)
