"""RXPTool 2.0 — only the self-contained Editable guide TXT workflow."""
from __future__ import annotations

import base64
import binascii
import html
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response

from rxp_decrypt import (DecodeError, decode_chunk, derive_base, extract_chunks,
                         guide_label, initial_permutation)
from webapp.editable_document import (DocumentError, is_editable_document,
                                      make_editable_document, rebuild_from_editable_document)

BASE_DIR = Path(__file__).resolve().parent
STATIC = BASE_DIR / 'static'
VERSION = '2.0.2'
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 128 * 1024 * 1024
MAX_GUIDES = 1000
MAX_CHUNKS = 512
MAX_ACTIVE = 2

USERNAME = os.environ.get('RXP_USERNAME', '')
PASSWORD = os.environ.get('RXP_PASSWORD', '')
if bool(USERNAME) != bool(PASSWORD):
    raise RuntimeError('Set both RXP_USERNAME and RXP_PASSWORD, or neither')

# Escaped at the HTML boundary; no user-provided markup is executed.
DEFAULT_HEADLINE = 'Guides, unlocked into plaintext.'
HEADLINE = os.environ.get('RXP_HEADLINE', DEFAULT_HEADLINE).strip() or DEFAULT_HEADLINE
HEADLINE = HEADLINE[:160]

slots = threading.BoundedSemaphore(MAX_ACTIVE)
app = FastAPI(title=f'RXPTool v{VERSION}', docs_url=None, redoc_url=None, openapi_url=None)


def failure(status: int, message: str) -> JSONResponse:
    return JSONResponse({'error': message}, status_code=status,
                        headers={'Cache-Control': 'no-store'})


def authorized(header: str) -> bool:
    if not USERNAME:
        return True
    if not header.startswith('Basic '):
        return False
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode('utf-8')
        username, password = decoded.split(':', 1)
    except (ValueError, UnicodeError, binascii.Error):
        return False
    return (secrets.compare_digest(username.encode(), USERNAME.encode()) and
            secrets.compare_digest(password.encode(), PASSWORD.encode()))


@app.middleware('http')
async def protect_access(request: Request, call_next):
    if request.url.path != '/health' and not authorized(request.headers.get('authorization', '')):
        return JSONResponse({'error': 'Authentication required'}, status_code=401,
                            headers={'WWW-Authenticate': 'Basic realm="RXPTool", charset="UTF-8"',
                                     'Cache-Control': 'no-store'})
    if request.url.path in ('/api/decrypt', '/api/encrypt') and request.method == 'POST':
        try:
            length = int(request.headers.get('content-length', '0'))
        except ValueError:
            return failure(400, 'Invalid request length')
        if length > MAX_REQUEST_BYTES:
            return failure(413, 'Request too large (maximum 32 MiB)')
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    )
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/health')
async def health():
    return {'status': 'ok', 'version': VERSION}


def render_page(name: str) -> Response:
    template = (STATIC / name).read_text('utf-8')
    content = template.replace('{{RXP_HEADLINE}}', html.escape(HEADLINE, quote=True))
    return Response(content, media_type='text/html; charset=utf-8')


@app.get('/')
async def index():
    return render_page('index.html')


@app.get('/encrypt')
async def encrypt_page():
    return render_page('encrypt.html')


@app.get('/favicon.ico')
async def favicon():
    return FileResponse(STATIC / 'favicon.ico', media_type='image/x-icon')


ASSETS = {
    'app-v2.0.2.css': ('app.css', 'text/css'),
    'app-v2.0.2.js': ('app.js', 'application/javascript'),
    'encrypt-v2.0.2.js': ('encrypt.js', 'application/javascript'),
    'favicon.svg': ('favicon.svg', 'image/svg+xml'),
    'favicon-32.png': ('favicon-32.png', 'image/png'),
    'apple-touch-icon.png': ('apple-touch-icon.png', 'image/png'),
}


@app.get('/assets/{asset}')
async def asset(asset: str):
    item = ASSETS.get(asset)
    if not item:
        return failure(404, 'Not found')
    filename, media_type = item
    return FileResponse(STATIC / filename, media_type=media_type)


def decode_payload(account_id: str, payload: str) -> tuple[list[bytes], int]:
    """Validate native payload and recover the nonempty guides in memory."""
    chunks = extract_chunks(payload, None)
    if len(chunks) > MAX_CHUNKS:
        raise DecodeError(f'Too many encrypted chunks (maximum {MAX_CHUNKS})')
    permutation = initial_permutation(derive_base(account_id))
    remaining = MAX_PLAINTEXT_BYTES
    guides: list[bytes] = []
    for index, chunk in enumerate(chunks, 1):
        if remaining < 1:
            raise DecodeError('Decompressed data exceeds 128 MiB')
        try:
            plain = decode_chunk(chunk, permutation, remaining)
        except DecodeError as exc:
            raise DecodeError(f'Chunk {index}/{len(chunks)}: {exc}') from exc
        remaining -= len(plain)
        guides.extend(item for item in plain.split(b'\x00') if item)
        if len(guides) > MAX_GUIDES:
            raise DecodeError(f'Too many guides (maximum {MAX_GUIDES})')
    if not guides:
        raise DecodeError('No guides found in the decrypted payload')
    return guides, len(chunks)


async def bounded_json(request: Request) -> Any:
    data = bytearray()
    async for part in request.stream():
        if len(data) + len(part) > MAX_REQUEST_BYTES:
            raise DecodeError('Request too large (maximum 32 MiB)')
        data.extend(part)
    try:
        return json.loads(data)
    except (ValueError, UnicodeError):
        raise DecodeError('Invalid request data; expected JSON') from None


def valid_account_id(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value.strip().encode('utf-8')) <= 256


def decrypt_operation(account_id: str, payload: str):
    try:
        guides, chunk_count = decode_payload(account_id, payload)
        editable, count, actual_chunks = make_editable_document(payload, account_id)
        if count != len(guides) or actual_chunks != chunk_count:
            raise DocumentError('Guide count mismatch while creating editable document')
        names = [guide_label(guide, n) for n, guide in enumerate(guides[:10], 1)]
        preview = base64.urlsafe_b64encode(json.dumps(names, ensure_ascii=True).encode()).decode()
        return editable, count, chunk_count, preview
    finally:
        slots.release()


@app.post('/api/decrypt')
async def decrypt(request: Request):
    if request.headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'application/json':
        return failure(415, 'Expected application/json')
    try:
        body = await bounded_json(request)
    except DecodeError as exc:
        return failure(413 if 'too large' in str(exc).lower() else 400, str(exc))
    if not isinstance(body, dict):
        return failure(400, 'Expected a JSON object')
    account, payload = body.get('battle_id'), body.get('payload')
    if body.get('format', 'editable') != 'editable':
        return failure(400, 'Only Editable guide TXT export is supported')
    if not valid_account_id(account):
        return failure(400, 'Enter a valid Battle.net ID (maximum 256 UTF-8 bytes)')
    if not isinstance(payload, str) or not payload.strip():
        return failure(400, 'Upload or paste an encrypted payload')
    if not slots.acquire(blocking=False):
        return failure(429, 'Decoder is busy; retry shortly')
    try:
        output, count, chunks, preview = await run_in_threadpool(
            decrypt_operation, account.strip(), payload)
    except (DecodeError, DocumentError) as exc:
        return failure(422, str(exc))
    except Exception:
        return failure(500, 'Unexpected server error while decrypting payload')
    return Response(content=output, media_type='text/plain; charset=utf-8', headers={
        'Content-Disposition': 'attachment; filename="editable_guides.txt"',
        'X-Guide-Count': str(count), 'X-Chunk-Count': str(chunks),
        'X-Guide-Preview': preview, 'X-Output-Format': 'editable',
    })


def parse_editable_upload(body: Any) -> tuple[str, bytes]:
    if not isinstance(body, dict):
        raise DocumentError('Expected a JSON object')
    account = body.get('battle_id')
    encoded = body.get('content_base64')
    if not valid_account_id(account):
        raise DocumentError('Enter the original matching Battle.net ID')
    if not isinstance(encoded, str) or not encoded:
        raise DocumentError('Upload an editable_guides.txt file')
    if len(encoded) > ((MAX_DOCUMENT_BYTES + 2) // 3 * 4 + 16):
        raise DocumentError('Editable TXT exceeds 16 MiB')
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise DocumentError('Invalid file encoding') from None
    if not data or len(data) > MAX_DOCUMENT_BYTES:
        raise DocumentError('Editable TXT must be between 1 byte and 16 MiB')
    if not is_editable_document(data):
        raise DocumentError('Only #!RXPTOOL/1 Editable guide TXT is supported')
    return account.strip(), data


def encrypt_operation(account: str, document: bytes):
    try:
        rebuilt, count, chunk_count, expected_raw = rebuild_from_editable_document(document, account)
        chunks = extract_chunks(rebuilt, None)
        permutation = initial_permutation(derive_base(account))
        raw = [decode_chunk(chunk, permutation, MAX_PLAINTEXT_BYTES) for chunk in chunks]
        if raw != expected_raw or len(raw) != chunk_count:
            raise DocumentError('Editable document raw-chunk verification failed')
        guides, decoded_chunks = decode_payload(account, rebuilt)
        if len(guides) != count or decoded_chunks != chunk_count:
            raise DocumentError('Editable document guide-count verification failed')
        return rebuilt.encode('utf-8'), count, chunk_count
    finally:
        slots.release()


@app.post('/api/encrypt')
async def encrypt(request: Request):
    if request.headers.get('content-type', '').split(';', 1)[0].strip().lower() != 'application/json':
        return failure(415, 'Expected application/json')
    try:
        account, document = parse_editable_upload(await bounded_json(request))
    except (DecodeError, DocumentError) as exc:
        return failure(413 if 'too large' in str(exc).lower() else 400, str(exc))
    if not slots.acquire(blocking=False):
        return failure(429, 'Server is busy; retry shortly')
    try:
        output, count, chunks = await run_in_threadpool(encrypt_operation, account, document)
    except (DecodeError, DocumentError) as exc:
        return failure(422, str(exc))
    except Exception:
        return failure(500, 'Unexpected server error while encrypting guides')
    return Response(content=output, media_type='text/plain; charset=utf-8', headers={
        'Content-Disposition': 'attachment; filename="rebuilt_import.txt"',
        'X-Guide-Count': str(count), 'X-Chunk-Count': str(chunks),
        'X-Import-Rebuilt': 'true', 'X-Package-Verified': 'true',
    })
