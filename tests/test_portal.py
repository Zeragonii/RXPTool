"""RXPTool v2.1 secure portal integration and native roundtrip coverage."""
from __future__ import annotations

import importlib
import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from rxp_decrypt import decode_chunk, derive_base, extract_chunks, initial_permutation
from webapp.editable_document import rebuild_from_editable_document

DOCUMENT = (b'#!RXPTOOL/1\n'
            b'#!header="|1|"\n'
            b'#!footer="|1"\n'
            b'#!account_key_fingerprint="test"\n'
            b'#!chunk\n'
            b'#!guide trailing_lf=1\n'
            b'step\n'
            b'.goto 100/1,1.0,2.0\n'
            b'#!endguide\n'
            b'#!endchunk\n'
            b'#!end\n')


def load(role, tmp_path, monkeypatch):
    monkeypatch.setenv("RXP_PORTAL_ROLE", role)
    monkeypatch.setenv("RXP_PORTAL_DB", str(tmp_path / "data.db"))
    monkeypatch.setenv("RXP_PORTAL_ADMIN_USER", "administrator")
    monkeypatch.setenv("RXP_PORTAL_ADMIN_PASSWORD", "a-very-strong-private-test-password")
    import portal.entry
    return importlib.reload(portal.entry)


def sign_in(client):
    response = client.post("/api/login",
                           json={"username": "administrator",
                                 "password": "a-very-strong-private-test-password"},
                           headers={"X-RXP-Login": "1"})
    assert response.status_code == 200, response.text
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    assert "rxptool_admin_session" in client.cookies
    return {"X-RXP-Admin": "1"}


def test_native_encoder_roundtrip():
    account = "PortalTest#1234"
    encrypted, count, chunks, raw = rebuild_from_editable_document(DOCUMENT, account)
    perm = initial_permutation(derive_base(account))
    decoded = [decode_chunk(chunk, perm, 16 * 1024 * 1024)
               for chunk in extract_chunks(encrypted, None)]
    assert raw == decoded
    assert count == 1 and chunks == 1


def test_publisher_and_public_are_separate(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as a:
        assert a.get("/admin/publish", follow_redirects=False).status_code == 303
        assert a.get("/login").status_code == 200
        assert a.get("/api/state").status_code == 401
        headers = sign_in(a)
        assert a.get("/admin/publish", headers=headers).status_code == 200
        assert a.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                      headers=headers).status_code == 200
        result = a.post("/api/publish", content=DOCUMENT,
                        headers={**headers, "Content-Type": "application/octet-stream",
                                 "X-Guide-Filename": "Guide.txt"})
        assert result.status_code == 200, result.text
        assert result.json()["published"]["version"] == 1
        assert a.get("/api/state", headers=headers).json()["allowlist"] == ["PortalTest#1234"]
    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as c:
        assert c.get("/download").status_code == 200
        for path in ("/api/state", "/api/encrypt", "/api/decrypt", "/admin/publish",
                     "/assets/admin.js"):
            assert c.get(path).status_code == 404
        assert c.post("/api/publish", content=DOCUMENT).status_code == 404
        assert c.post("/api/download", json={"battle_id": "NotAllowed#1234"}).status_code == 404
        result = c.post("/api/download", json={"battle_id": "PortalTest#1234"})
        assert result.status_code == 200, result.text
        assert result.headers["X-Package-Verified"] == "true"
        output = result.content.decode()
        perm = initial_permutation(derive_base("PortalTest#1234"))
        assert [decode_chunk(chunk, perm, 16 * 1024 * 1024)
                for chunk in extract_chunks(output, None)] == [
                    b"step\n.goto 100/1,1.0,2.0\n"
                ]


def test_admin_auth_csrf_and_rollback(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers={"X-RXP-Admin": "1"}).status_code == 401
        assert client.post("/api/login",
                           json={"username": "administrator", "password": "wrong"},
                           headers={"X-RXP-Login": "1"}).status_code == 401
        assert client.post("/api/login",
                           json={"username": "administrator",
                                 "password": "a-very-strong-private-test-password"}).status_code == 403
        assert client.post("/api/login",
                           json={"username": "administrator",
                                 "password": "a-very-strong-private-test-password"},
                           headers={"X-RXP-Login": "1",
                                    "Origin": "https://evil.example"}).status_code == 403
        headers = sign_in(client)
        assert client.get("/login", follow_redirects=False).status_code == 303
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"}).status_code == 403
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers={**headers, "Origin": "https://evil.example"}).status_code == 403
        assert client.post("/api/allowlist/add", json={"battle_id": "PortalTest#1234"},
                           headers=headers).status_code == 200
        assert client.post("/api/publish", content=DOCUMENT,
                           headers={**headers, "Content-Type": "application/octet-stream"}).status_code == 200
        assert client.post("/api/publish", content=DOCUMENT,
                           headers={**headers, "Content-Type": "application/octet-stream"}).status_code == 200
        restored = client.post("/api/publish/restore", json={"version": 1}, headers=headers)
        assert restored.status_code == 200
        assert restored.json()["published"]["version"] == 3
        assert client.post("/api/allowlist/remove", json={"battle_id": "PortalTest#1234"},
                           headers=headers).status_code == 200
        assert client.get("/api/state", headers=headers).json()["allowlist"] == []
        assert client.post("/api/logout", headers=headers).status_code == 200
        assert client.get("/api/state").status_code == 401
        assert client.get("/admin/publish", follow_redirects=False).headers["location"] == "/login"

def test_admin_session_restarts_and_public_auth_isolation(tmp_path, monkeypatch):
    admin = load("admin", tmp_path, monkeypatch)
    with TestClient(admin.app) as client:
        sign_in(client)
        assert client.get("/api/state").status_code == 200
        # An application restart invalidates memory-resident sessions.
        new_app = load("admin", tmp_path, monkeypatch)
        with TestClient(new_app.app) as restarted:
            restarted.cookies.set("rxptool_admin_session",
                                  client.cookies.get("rxptool_admin_session"))
            assert restarted.get("/api/state").status_code == 401

    public = load("public", tmp_path, monkeypatch)
    with TestClient(public.app) as client:
        for url in ("/login", "/assets/login.js", "/api/login", "/api/logout"):
            assert client.get(url).status_code == 404
        assert client.post("/api/login", json={}).status_code == 404
