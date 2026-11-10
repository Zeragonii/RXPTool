"""Isolated RXPTool publishing and public download service (same GHCR image).

RXP_PORTAL_ROLE selects exactly one set of routes. Never import the original
webapp.main here: its decrypt/encrypt endpoints must not exist on public mode.
"""
from __future__ import annotations

import hashlib
import html
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.concurrency import run_in_threadpool

from rxp_decrypt import decode_chunk, derive_base, extract_chunks, initial_permutation
from webapp.editable_document import (
    DocumentError, is_editable_document, rebuild_from_editable_document,
)
from webapp.download_names import content_disposition, encrypted_filename

ROLE = os.environ.get("RXP_PORTAL_ROLE", "").strip().lower()
if ROLE not in {"admin", "public"}:
    raise RuntimeError("Set RXP_PORTAL_ROLE to admin or public")
DB = Path(os.environ.get("RXP_PORTAL_DB", "/data/portal.sqlite3"))
MAX_GUIDE = 16 * 1024 * 1024
MAX_OUTPUT = 24 * 1024 * 1024
PUBLIC_HEADLINE_DEFAULT = "Your guide, ready to import."
PUBLIC_MESSAGE_DEFAULT = ("Enter a whitelisted Battle.net ID to generate an "
                          "account-specific encrypted import of the latest published guide.")
MAX_HEADLINE = 160
MAX_MESSAGE = 1000
ADMIN_USER = os.environ.get("RXP_PORTAL_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("RXP_PORTAL_ADMIN_PASSWORD", "")
COOKIE_SECURE = os.environ.get("RXP_PORTAL_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
COOKIE_NAME = "rxptool_admin_session"
SESSION_LIFETIME = 8 * 60 * 60
_SESSION_CAP = 128
ID_PATTERN = re.compile(r"^[^#\x00-\x1f\x7f]{1,60}#[0-9]{4,10}$")
STATIC = Path(__file__).resolve().parent / "static"
LOG = logging.getLogger("rxptool.portal")
SLOTS = threading.BoundedSemaphore(1)
_lock = threading.Lock()
_attempts = defaultdict(deque)
_sessions: dict[bytes, float] = {}

if ROLE == "admin" and (not ADMIN_USER or ":" in ADMIN_USER or len(ADMIN_PASSWORD) < 20):
    raise RuntimeError("Admin needs username and 20+ character password")


def valid_id(value) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid Battle.net ID")
    value = value.strip()
    if not ID_PATTERN.fullmatch(value) or len(value.encode("utf-8")) > 128:
        raise ValueError("Invalid Battle.net ID")
    return value


def canonical(value: str) -> str:
    return valid_id(value).casefold()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def dbconnect():
    if ROLE == "public":
        conn = sqlite3.connect(DB.resolve().as_uri() + "?mode=ro", uri=True, timeout=8)
    else:
        conn = sqlite3.connect(DB, timeout=8)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=8000")
    return conn


def initialize():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with dbconnect() as db:
        db.executescript("""
        PRAGMA journal_mode=DELETE;
        CREATE TABLE IF NOT EXISTS approved (
            id_key TEXT PRIMARY KEY, battle_id TEXT NOT NULL, added_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS publication (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            version INTEGER NOT NULL, guide BLOB NOT NULL,
            title TEXT NOT NULL, sha256 TEXT NOT NULL,
            guides INTEGER NOT NULL, chunks INTEGER NOT NULL, published_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS history (
            version INTEGER PRIMARY KEY, guide BLOB NOT NULL,
            title TEXT NOT NULL, sha256 TEXT NOT NULL,
            guides INTEGER NOT NULL, chunks INTEGER NOT NULL, published_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS page_settings (
            name TEXT PRIMARY KEY, value TEXT NOT NULL
        );
        """)


if ROLE == "admin":
    initialize()
else:
    if not DB.is_file():
        raise RuntimeError("Publishing database does not exist; start admin first")


def metadata() -> dict | None:
    with dbconnect() as db:
        item = db.execute(
            "SELECT version,title,sha256,guides,chunks,published_at FROM publication WHERE singleton=1"
        ).fetchone()
        return dict(item) if item else None


def get_public_page_settings() -> dict[str, str]:
    """Get the latest saved public text on every request (no restart needed)."""
    settings = {
        "headline": PUBLIC_HEADLINE_DEFAULT,
        "message": PUBLIC_MESSAGE_DEFAULT,
    }
    with dbconnect() as db:
        rows = db.execute(
            "SELECT name, value FROM page_settings WHERE name IN ('headline', 'message')"
        ).fetchall()
    for row in rows:
        settings[row["name"]] = row["value"]
    return settings


def validate_public_page_settings(data: dict) -> dict[str, str]:
    values = {}
    for field, limit in (("headline", MAX_HEADLINE), ("message", MAX_MESSAGE)):
        value = data.get(field)
        if not isinstance(value, str):
            raise ValueError(f"{field} must be text")
        value = value.strip()
        if not value or len(value) > limit:
            raise ValueError(f"{field} must contain 1-{limit} characters")
        if any(ord(char) < 32 and char not in (chr(10), chr(13), chr(9)) for char in value):
            raise ValueError(f"{field} contains unsupported control characters")
        if field == "headline" and any(char in (chr(10), chr(13)) for char in value):
            raise ValueError("headline must be a single line")
        values[field] = value
    return values


def save_public_page_settings(data: dict) -> dict[str, str]:
    values = validate_public_page_settings(data)
    with dbconnect() as db:
        db.executemany(
            "INSERT INTO page_settings (name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value=excluded.value",
            list(values.items()),
        )
    return values


def state() -> dict:
    with dbconnect() as db:
        return {
            "current": metadata(),
            "public_page": get_public_page_settings(),
            "allowlist": [row[0] for row in db.execute(
                "SELECT battle_id FROM approved ORDER BY battle_id COLLATE NOCASE"
            )],
            "history": [dict(row) for row in db.execute(
                "SELECT version,title,published_at FROM history ORDER BY version DESC"
            )],
        }


def allowed(value: str) -> str | None:
    with dbconnect() as db:
        row = db.execute(
            "SELECT battle_id FROM approved WHERE id_key=?", (canonical(value),)
        ).fetchone()
        return row[0] if row else None


def upload(guide: bytes, title: str) -> dict:
    if not 0 < len(guide) <= MAX_GUIDE or not is_editable_document(guide):
        raise ValueError("Upload an RXPTool #!RXPTOOL/1 editable TXT (16 MiB maximum)")
    # Rebuild the COMPLETE guide before making it visible to the public.
    # A malformed document must never replace the last working publication.
    encoded, guides, chunks, expected = rebuild_from_editable_document(guide, "PortalValidation#1234")
    permutation = initial_permutation(derive_base("PortalValidation#1234"))
    observed = [decode_chunk(chunk, permutation, MAX_GUIDE) for chunk in extract_chunks(encoded, None)]
    if expected != observed or len(observed) != chunks:
        raise ValueError("Native guide verification failed")
    title = (Path(title.replace("\\", "/")).name[:120] or "editable_guides.txt")
    if not title.lower().endswith(".txt"):
        title = "editable_guides.txt"
    with dbconnect() as db:
        db.execute("BEGIN IMMEDIATE")
        previous = db.execute("SELECT * FROM publication WHERE singleton=1").fetchone()
        version = previous["version"] + 1 if previous else 1
        if previous:
            db.execute(
                "INSERT OR REPLACE INTO history VALUES (?,?,?,?,?,?,?)",
                tuple(previous[key] for key in ("version", "guide", "title", "sha256", "guides", "chunks", "published_at")),
            )
        db.execute(
            "INSERT OR REPLACE INTO publication VALUES (1,?,?,?,?,?,?,?)",
            (version, guide, title, hashlib.sha256(guide).hexdigest(), guides, chunks, now()),
        )
        db.execute("DELETE FROM history WHERE version NOT IN (SELECT version FROM history ORDER BY version DESC LIMIT 3)")
    return metadata() or {}


def restore(version: int) -> dict:
    with dbconnect() as db:
        db.execute("BEGIN IMMEDIATE")
        old = db.execute("SELECT * FROM history WHERE version=?", (version,)).fetchone()
        current = db.execute("SELECT * FROM publication WHERE singleton=1").fetchone()
        if old is None or current is None:
            raise ValueError("Version not found")
        db.execute(
            "INSERT OR REPLACE INTO history VALUES (?,?,?,?,?,?,?)",
            tuple(current[k] for k in ("version", "guide", "title", "sha256", "guides", "chunks", "published_at")),
        )
        db.execute(
            "UPDATE publication SET version=?,guide=?,title=?,sha256=?,guides=?,chunks=?,published_at=? WHERE singleton=1",
            (current["version"] + 1, old["guide"], old["title"], old["sha256"], old["guides"], old["chunks"], now()),
        )
        db.execute("DELETE FROM history WHERE version NOT IN (SELECT version FROM history ORDER BY version DESC LIMIT 3)")
    return metadata() or {}


def limit(key: str, maximum: int, period: int = 60) -> bool:
    current = time.monotonic()
    with _lock:
        if len(_attempts) >= 4096:
            for k in list(_attempts):
                while _attempts[k] and _attempts[k][0] < current - period:
                    _attempts[k].popleft()
                if not _attempts[k]:
                    del _attempts[k]
            if len(_attempts) >= 4096 and key not in _attempts:
                return False
        q = _attempts[key]
        while q and q[0] < current - period:
            q.popleft()
        if len(q) >= maximum:
            return False
        q.append(current)
        return True


def error(status: int, detail: str):
    return JSONResponse({"error": detail}, status_code=status)


async def body_bytes(request: Request, maxlen: int):
    declared = request.headers.get("content-length")
    if declared is None or not declared.isdecimal() or int(declared) > maxlen:
        raise ValueError("Invalid or oversized request")
    result = bytearray()
    async for chunk in request.stream():
        result.extend(chunk)
        if len(result) > maxlen:
            raise ValueError("Request too large")
    if len(result) != int(declared):
        raise ValueError("Incomplete request")
    return bytes(result)


async def body_json(request: Request, maxlen: int = 2048) -> dict:
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
        raise ValueError("Expected application/json")
    try:
        obj = json.loads(await body_bytes(request, maxlen))
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("Invalid JSON") from None
    if not isinstance(obj, dict):
        raise ValueError("Expected JSON object")
    return obj


def credentials_match(name: object, password: object) -> bool:
    """Compare both fields without echoing secrets or using HTTP Basic auth."""
    if not isinstance(name, str) or not isinstance(password, str):
        return False
    if len(name) > 256 or len(password) > 1024:
        return False
    return bool(
        hmac.compare_digest(hashlib.sha256(name.encode()).digest(), hashlib.sha256(ADMIN_USER.encode()).digest())
        & hmac.compare_digest(hashlib.sha256(password.encode()).digest(), hashlib.sha256(ADMIN_PASSWORD.encode()).digest())
    )


def session_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii")).digest()


def authenticated(request: Request) -> bool:
    """Sessions are volatile: process restart, timeout or logout revokes access."""
    token = request.cookies.get(COOKIE_NAME, "")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
        return False
    current = time.monotonic()
    with _lock:
        expiry = _sessions.get(session_digest(token))
        if expiry is not None and expiry <= current:
            _sessions.pop(session_digest(token), None)
        return expiry is not None and expiry > current


def create_session() -> str:
    current = time.monotonic()
    token = secrets.token_urlsafe(32)
    with _lock:
        for key, expiry in list(_sessions.items()):
            if expiry <= current:
                del _sessions[key]
        if len(_sessions) >= _SESSION_CAP:
            # Prefer oldest expiry when the administrator has many sessions.
            del _sessions[min(_sessions, key=_sessions.get)]
        _sessions[session_digest(token)] = current + SESSION_LIFETIME
    return token


def valid_origin(request: Request) -> bool:
    origin = request.headers.get("origin")
    return not origin or origin.rstrip("/").lower() == str(request.base_url).rstrip("/").lower()


app = FastAPI(title="RXPTool Portal", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security(request: Request, call_next):
    # Only these endpoints are accessible before logging into the private
    # publisher. The public service has an entirely separate route table.
    login_routes = {"/health", "/login", "/assets/style.css",
                    "/assets/login.js", "/api/login"}
    if ROLE == "admin" and request.url.path not in login_routes:
        if not authenticated(request):
            if request.method in {"GET", "HEAD"} and request.url.path in {"/", "/admin/publish"}:
                response = RedirectResponse("/login", status_code=303)
            else:
                response = error(401, "Authentication required")
        elif request.method not in {"GET", "HEAD"} and (
            request.headers.get("x-rxp-admin") != "1" or not valid_origin(request)
        ):
            response = error(403, "Request token or origin invalid")
        else:
            response = await call_next(request)
    else:
        response = await call_next(request)
    response.headers.update({
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'self'; script-src 'self'; "
            + ("img-src 'self'; " if ROLE == "public" else "")
            + "connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        ),
    })
    return response


@app.get("/health")
def health():
    try:
        metadata()
        return {"status": "ok"}
    except sqlite3.Error:
        return error(503, "Unavailable")


@app.get("/")
@app.get("/download" if ROLE == "public" else "/admin/publish")
def home():
    if ROLE == "admin":
        return FileResponse(STATIC / "admin.html", media_type="text/html")
    values = get_public_page_settings()
    template = (STATIC / "download.html").read_text(encoding="utf-8")
    content = (template.replace("{{PUBLIC_HEADLINE}}", html.escape(values["headline"], quote=True))
                       .replace("{{PUBLIC_MESSAGE}}", html.escape(values["message"], quote=True)))
    return Response(content, media_type="text/html; charset=utf-8")


@app.get("/assets/style.css")
def css():
    return FileResponse(STATIC / "style.css", media_type="text/css")


if ROLE == "admin":

    @app.get("/login")
    def login_page(request: Request):
        if authenticated(request):
            return RedirectResponse("/admin/publish", status_code=303)
        return FileResponse(STATIC / "login.html", media_type="text/html")

    @app.get("/assets/login.js")
    def login_script():
        return FileResponse(STATIC / "login.js", media_type="application/javascript")

    @app.post("/api/login")
    async def login(request: Request):
        # Do not allow a cross-site HTML form to perform login CSRF.
        if request.headers.get("x-rxp-login") != "1" or not valid_origin(request):
            return error(403, "Request origin invalid")
        peer = request.client.host if request.client else "unknown"
        if not limit("login:" + peer, 8, period=300):
            return error(429, "Too many login attempts. Try again later.")
        try:
            data = await body_json(request)
        except ValueError as exc:
            return error(400, str(exc))
        if not credentials_match(data.get("username"), data.get("password")):
            return error(401, "Invalid username or password")
        response = JSONResponse({"ok": True})
        response.set_cookie(COOKIE_NAME, create_session(), max_age=SESSION_LIFETIME,
                            httponly=True, secure=COOKIE_SECURE, samesite="strict", path="/")
        return response

    @app.post("/api/logout")
    def logout(request: Request):
        token = request.cookies.get(COOKIE_NAME, "")
        if isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
            with _lock:
                _sessions.pop(session_digest(token), None)
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE_NAME, path="/", secure=COOKIE_SECURE,
                               httponly=True, samesite="strict")
        return response

    @app.get("/assets/admin.js")
    def admin_script():
        return FileResponse(STATIC / "admin.js", media_type="application/javascript")

    @app.get("/assets/settings.js")
    def settings_script():
        return FileResponse(STATIC / "settings.js", media_type="application/javascript")

    @app.get("/api/state")
    def admin_state():
        return state()

    @app.post("/api/settings/public-page")
    async def update_public_page(request: Request):
        if not limit("admin-settings:" + (request.client.host if request.client else "unknown"), 30):
            return error(429, "Too many settings updates")
        try:
            values = save_public_page_settings(await body_json(request, maxlen=16384))
            return {"public_page": values}
        except ValueError as exc:
            return error(400, str(exc))

    @app.post("/api/allowlist/add")
    @app.post("/api/allowlist/remove")
    async def admin_allowlist(request: Request):
        if not limit("admin:" + request.client.host, 60):
            return error(429, "Too many requests")
        try:
            value = valid_id((await body_json(request)).get("battle_id"))
            with dbconnect() as db:
                if request.url.path.endswith("/add"):
                    db.execute(
                        "INSERT INTO approved VALUES (?,?,?) ON CONFLICT(id_key) DO UPDATE SET battle_id=excluded.battle_id",
                        (canonical(value), value, now()),
                    )
                else:
                    db.execute("DELETE FROM approved WHERE id_key=?", (canonical(value),))
            return {"ok": True}
        except ValueError as exc:
            return error(400, str(exc))

    @app.post("/api/publish")
    async def admin_publish(request: Request):
        if not limit("admin:" + request.client.host, 10):
            return error(429, "Too many requests")
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/octet-stream":
            return error(415, "Expected application/octet-stream")
        try:
            content = await body_bytes(request, MAX_GUIDE)
            info = await run_in_threadpool(upload, content, request.headers.get("x-guide-filename", "editable_guides.txt")[:256])
            return {"published": info}
        except (ValueError, DocumentError) as exc:
            return error(422, str(exc))
        except Exception:
            LOG.exception("Guide publication failed")
            return error(500, "Publication failed")

    @app.post("/api/publish/restore")
    async def admin_restore(request: Request):
        try:
            version = (await body_json(request)).get("version")
            if type(version) is not int or version < 1:
                raise ValueError("Invalid version")
            return {"published": restore(version)}
        except ValueError as exc:
            return error(400, str(exc))

else:

    @app.get("/assets/favicon.svg")
    def public_favicon():
        return FileResponse(STATIC / "favicon.svg", media_type="image/svg+xml")

    @app.get("/assets/download.js")
    def public_script():
        return FileResponse(STATIC / "download.js", media_type="application/javascript")

    def encode(data: bytes, battle_id: str) -> bytes:
        native, guides, chunks, raw = rebuild_from_editable_document(data, battle_id)
        if not native or len(native.encode()) > MAX_OUTPUT or not raw:
            raise ValueError("Output exceeds limits")
        permutation = initial_permutation(derive_base(battle_id))
        decoded = [decode_chunk(item, permutation, MAX_GUIDE) for item in extract_chunks(native, None)]
        if decoded != raw or len(decoded) != chunks:
            raise ValueError("Encoded guide failed roundtrip verification")
        return native.encode("utf-8")

    @app.post("/api/download")
    async def download(request: Request):
        # Reverse proxy must rate-limit per real client. App also limits traffic
        # by peer and account identifier without trusting forged X-Forwarded-For.
        if not limit("peer:" + request.client.host, 30):
            return error(429, "Too many requests")
        try:
            requested = valid_id((await body_json(request)).get("battle_id"))
        except ValueError as exc:
            return error(400, str(exc))
        if not limit("id:" + canonical(requested), 4):
            return error(429, "Too many requests")
        if not SLOTS.acquire(blocking=False):
            return error(503, "Encoder busy, retry shortly")
        try:
            approved = allowed(requested)
            if approved is None:
                return error(404, "No guide available for this ID")
            with dbconnect() as db:
                row = db.execute("SELECT guide FROM publication WHERE singleton=1").fetchone()
            if not row:
                return error(503, "No guide has been published")
            data = bytes(row[0])
            encoded = await run_in_threadpool(encode, data, approved)
            # Keep filenames consistent regardless of the uploaded guide's source name.
            # The shared helper preserves BattleTags (# included), escapes invalid
            # Windows filename characters, and uses a UTC date/time suffix.
            name = encrypted_filename("RXPTool", approved)
            return Response(encoded, media_type="application/octet-stream", headers={
                "Content-Disposition": content_disposition(name),
                "X-Import-Rebuilt": "true",
                "X-Package-Verified": "true",
            })
        except (DocumentError, ValueError):
            return error(503, "Guide could not be generated")
        except Exception:
            LOG.exception("Public guide operation failed")
            return error(503, "Guide temporarily unavailable")
        finally:
            SLOTS.release()
